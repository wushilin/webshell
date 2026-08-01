use std::env;
use std::ffi::CStr;
use std::path::Path;
use std::time::Duration;

use base64::Engine;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

/// User-facing configuration, loaded from a YAML file (all fields optional —
/// missing ones fall back to the documented defaults).
///
/// Authentication is always PAM, and only the **process owner** may log in
/// (with both their username and system password).
#[derive(Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    /// Listen address, e.g. "0.0.0.0:9023".
    pub bind: String,
    /// PAM service name (file under /etc/pam.d).
    pub pam_service: String,
    /// Persistent terminal slots for the user.
    pub max_sessions: usize,
    /// Upper bound a share link may be valid for.
    pub max_sharing_duration_secs: u64,
    /// Master switch for read-only share links.
    pub sharing_enabled: bool,
    /// Externally-visible base URL, e.g. "https://shell.example.com". Used to
    /// build absolute share links, and accepted as a WebSocket Origin. A
    /// trailing slash is optional.
    pub public_base_url: Option<String>,
    /// Bytes of recent output retained per slot for replay on reattach.
    pub scrollback_bytes: usize,
    /// Absolute login-session lifetime.
    pub session_ttl_secs: u64,
    /// Mark the session cookie `Secure` (serve over HTTPS).
    pub cookie_secure: bool,
    /// *Extra* WebSocket Origins to accept, beyond the request's own Host and
    /// public_base_url. Only needed when the browser-facing origin cannot be
    /// recovered from the request — e.g. a reverse proxy that rewrites Host.
    pub allowed_origins: Vec<String>,
    /// Deprecated singular form of `allowed_origins`; still honoured so older
    /// configs keep loading (deny_unknown_fields would reject them otherwise).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_origin: Option<String>,
    /// Pin the accepted Origins to the configured set: drops the "Origin
    /// matches the request's Host" fallback. Refuses to serve WebSockets
    /// through any hostname not listed. Ignored when nothing is configured,
    /// which would lock out every client.
    pub strict_origin: bool,
    /// base64 cookie signing key (>=64 bytes). Empty = ephemeral (resets on restart).
    pub secret_base64: Option<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            bind: "127.0.0.1:8080".into(),
            pam_service: "login".into(),
            max_sessions: 10,
            max_sharing_duration_secs: 30 * 24 * 3600,
            sharing_enabled: true,
            public_base_url: None,
            scrollback_bytes: 128 * 1024,
            session_ttl_secs: 8 * 3600,
            cookie_secure: false,
            allowed_origins: Vec::new(),
            allowed_origin: None,
            strict_origin: false,
            secret_base64: None,
        }
    }
}

impl Settings {
    pub fn load(path: Option<&Path>) -> anyhow::Result<Settings> {
        match path {
            Some(p) => {
                let text = std::fs::read_to_string(p)
                    .map_err(|e| anyhow::anyhow!("reading config {}: {e}", p.display()))?;
                serde_yaml::from_str(&text)
                    .map_err(|e| anyhow::anyhow!("parsing config {}: {e}", p.display()))
            }
            None => Ok(Settings::default()),
        }
    }

    pub fn sample_yaml() -> String {
        serde_yaml::to_string(&Settings::default()).unwrap_or_default()
    }
}

/// Fully-resolved runtime configuration.
pub struct Config {
    pub bind_addr: String,
    pub pam_service: String,
    /// The only account permitted to log in: the user running this process.
    pub owner: String,
    /// The owner's home directory (from the passwd DB), for the spawned shell.
    pub owner_home: String,
    pub slots_per_user: usize,
    pub max_share_secs: u64,
    pub sharing_enabled: bool,
    /// Normalized (no trailing slash) external base URL, if set.
    pub public_base_url: Option<String>,
    /// Login-shell command: `login -f {user}` as root, else `$SHELL -l`.
    pub login_cmd: Vec<String>,
    pub scrollback_cap: usize,
    pub session_ttl: Duration,
    pub cookie_secure: bool,
    /// Origins accepted on top of the request's own Host: the configured
    /// extras plus public_base_url. Normalized — no path, no trailing slash —
    /// and each entry is either a full origin ("https://a.b", scheme must
    /// match) or a bare authority ("a.b", any scheme).
    pub allowed_origins: Vec<String>,
    /// Drop the Origin-matches-Host fallback and accept only `allowed_origins`.
    pub strict_origin: bool,
    /// Cap on a single WebSocket message, in bytes. Replaces tungstenite's
    /// 64 MiB default so a client cannot make the server buffer megabytes per
    /// frame — the share-link socket is reachable without a login. Derived
    /// from `scrollback_cap`, since the replay blob is sent as one message.
    pub ws_message_limit: usize,
    pub is_root: bool,
    pub secret_base64: Option<String>,
}

impl Config {
    pub fn from_settings(s: Settings) -> Self {
        let is_root = unsafe { libc::geteuid() } == 0;
        // Resolve identity from the passwd DB, NOT from the environment: when a
        // root supervisor (e.g. processmaster/systemd) setuids us to the owner,
        // HOME/USER are still root's, and chdir-ing the shell into $HOME=/root
        // fails with EACCES.
        let owner = owner_info();

        let public_base_url = s
            .public_base_url
            .as_deref()
            .map(|u| u.trim_end_matches('/').to_string());

        // Additive: the configured extras, the deprecated singular key, and the
        // public base URL all just widen what the Host fallback already allows.
        let allowed_origins = s
            .allowed_origins
            .iter()
            .map(String::as_str)
            .chain(s.allowed_origin.as_deref())
            .chain(public_base_url.as_deref())
            .map(normalize_origin)
            .filter(|o| !o.is_empty())
            .fold(Vec::new(), |mut acc, o| {
                if !acc.contains(&o) {
                    acc.push(o);
                }
                acc
            });

        let login_cmd = if is_root {
            // A genuine pre-authenticated login shell as {user}.
            vec!["/bin/login".into(), "-f".into(), "{user}".into()]
        } else {
            // The owner's actual login shell from the passwd DB.
            vec![owner.shell.clone(), "-l".into()]
        };

        let secret_base64 = env::var("WEBSHELL_SECRET").ok().or(s.secret_base64);

        // Bounded like every other sizing knob: this buffer is retained per
        // slot, so an unclamped value is an OOM waiting for a typo.
        let scrollback_cap = s.scrollback_bytes.clamp(4 * 1024, 16 * 1024 * 1024);
        // Room for the largest thing we legitimately send (a full replay)
        // plus slack for a generous paste from the client.
        let ws_message_limit = scrollback_cap.saturating_add(1024 * 1024);

        Config {
            bind_addr: s.bind,
            pam_service: s.pam_service,
            owner_home: owner.home,
            owner: owner.name,
            // Load-bearing for the wire format, not just a sanity bound: the
            // mux protocol tags each frame with a ONE-BYTE slot index
            // (pty::tagged), so this must stay <= 255.
            slots_per_user: s.max_sessions.clamp(1, 64),
            max_share_secs: s.max_sharing_duration_secs.max(1),
            sharing_enabled: s.sharing_enabled,
            public_base_url,
            login_cmd,
            scrollback_cap,
            session_ttl: Duration::from_secs(s.session_ttl_secs.max(60)),
            cookie_secure: s.cookie_secure,
            allowed_origins,
            strict_origin: s.strict_origin,
            ws_message_limit,
            is_root,
            secret_base64,
        }
    }

    /// Verify a login attempt via PAM. Only the process owner may log in (the
    /// username must match); blocks, so call from a blocking task. Returns the
    /// owner's username on success.
    pub fn authenticate(&self, username: &str, password: &str) -> Option<String> {
        let owner_ok: bool = username.as_bytes().ct_eq(self.owner.as_bytes()).into();
        if !owner_ok {
            tracing::warn!("login rejected: only {:?} may log in", self.owner);
            return None;
        }
        match crate::pam::authenticate(&self.pam_service, &self.owner, password) {
            Ok(()) => Some(self.owner.clone()),
            Err(e) => {
                tracing::warn!("PAM auth failed for {:?}: {e}", self.owner);
                None
            }
        }
    }
}

/// Identity of the user running this process (euid), resolved from the passwd
/// database rather than the (possibly root-inherited) environment.
struct OwnerInfo {
    name: String,
    home: String,
    shell: String,
}

fn owner_info() -> OwnerInfo {
    unsafe {
        let uid = libc::geteuid();
        let pw = libc::getpwuid(uid);
        if pw.is_null() {
            return OwnerInfo {
                name: env::var("USER").unwrap_or_else(|_| uid.to_string()),
                home: "/".to_string(),
                shell: "/bin/sh".to_string(),
            };
        }
        let cstr = |p: *const std::os::raw::c_char| CStr::from_ptr(p).to_string_lossy().into_owned();
        let name = cstr((*pw).pw_name);
        let home = {
            let h = cstr((*pw).pw_dir);
            if h.is_empty() { "/".to_string() } else { h }
        };
        let shell = {
            let s = cstr((*pw).pw_shell);
            if s.is_empty() { "/bin/sh".to_string() } else { s }
        };
        OwnerInfo { name, home, shell }
    }
}

/// Normalize a configured origin down to what an `Origin` header can carry:
/// drop any path and trailing slash, keeping the scheme only if one was
/// written. Both `https://shell.example.com/` and a bare `shell.example.com`
/// are valid entries — see `origin_matches` for how each is compared.
fn normalize_origin(url: &str) -> String {
    let url = url.trim();
    match url.find("://") {
        Some(i) => {
            let after = &url[i + 3..];
            let end = after.find('/').unwrap_or(after.len());
            format!("{}://{}", &url[..i], &after[..end])
        }
        None => {
            let end = url.find('/').unwrap_or(url.len());
            url[..end].to_string()
        }
    }
}

/// Does a browser-sent `Origin` satisfy one configured entry? A full entry
/// (`https://a.b`) must match scheme and authority; a bare authority (`a.b`)
/// matches that host under any scheme, so writing the hostname alone is
/// enough and works whether the site is reached over http or https.
pub fn origin_matches(allowed: &str, origin: &str) -> bool {
    if allowed == origin {
        return true;
    }
    !allowed.contains("://") && origin.split("://").nth(1) == Some(allowed)
}

pub fn random_token(bytes: usize) -> String {
    use rand::RngCore;
    let mut buf = vec![0u8; bytes];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_strips_path_and_trailing_slash() {
        assert_eq!(normalize_origin("https://a.b/"), "https://a.b");
        assert_eq!(normalize_origin(" https://a.b/webshell "), "https://a.b");
        assert_eq!(normalize_origin("https://a.b:8443"), "https://a.b:8443");
        assert_eq!(normalize_origin("a.b/webshell"), "a.b");
        assert_eq!(normalize_origin("a.b:8443"), "a.b:8443");
    }

    #[test]
    fn bare_authority_matches_any_scheme() {
        assert!(origin_matches("a.b", "https://a.b"));
        assert!(origin_matches("a.b", "http://a.b"));
        // Ports are part of the authority: they must still agree.
        assert!(!origin_matches("a.b", "https://a.b:8443"));
        assert!(!origin_matches("a.b", "https://evil.a.b"));
    }

    #[test]
    fn full_origin_pins_the_scheme() {
        assert!(origin_matches("https://a.b", "https://a.b"));
        assert!(!origin_matches("https://a.b", "http://a.b"));
    }

    #[test]
    fn public_base_url_is_an_allowed_origin() {
        let cfg = Config::from_settings(Settings {
            public_base_url: Some("https://shell.example.com/".into()),
            ..Settings::default()
        });
        assert_eq!(cfg.allowed_origins, vec!["https://shell.example.com"]);
        assert_eq!(cfg.public_base_url.as_deref(), Some("https://shell.example.com"));
    }

    #[test]
    fn deprecated_singular_key_still_counts_and_dedupes() {
        let cfg = Config::from_settings(Settings {
            public_base_url: Some("https://a.b".into()),
            allowed_origin: Some("https://a.b/".into()),
            allowed_origins: vec!["c.d".into(), "".into()],
            ..Settings::default()
        });
        assert_eq!(cfg.allowed_origins, vec!["c.d", "https://a.b"]);
    }
}
