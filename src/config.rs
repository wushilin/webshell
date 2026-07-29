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
    /// build absolute share links and (when allowed_origin is unset) to derive
    /// the accepted WebSocket Origin. A trailing slash is optional.
    pub public_base_url: Option<String>,
    /// Bytes of recent output retained per slot for replay on reattach.
    pub scrollback_bytes: usize,
    /// Absolute login-session lifetime.
    pub session_ttl_secs: u64,
    /// Mark the session cookie `Secure` (serve over HTTPS).
    pub cookie_secure: bool,
    /// Exact WebSocket Origin to accept; overrides the public_base_url derivation.
    pub allowed_origin: Option<String>,
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
            allowed_origin: None,
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
    /// Effective accepted Origin (explicit, or derived from public_base_url).
    pub allowed_origin: Option<String>,
    pub is_root: bool,
    pub secret_base64: Option<String>,
}

impl Config {
    pub fn from_settings(s: Settings) -> Self {
        let is_root = unsafe { libc::geteuid() } == 0;
        let owner = process_owner();

        let public_base_url = s
            .public_base_url
            .as_deref()
            .map(|u| u.trim_end_matches('/').to_string());

        let allowed_origin = s
            .allowed_origin
            .clone()
            .or_else(|| public_base_url.as_deref().map(origin_of));

        let login_cmd = if is_root {
            // A genuine pre-authenticated login shell as {user}.
            vec!["/bin/login".into(), "-f".into(), "{user}".into()]
        } else {
            // Dev fallback: login shell as the current (only) user.
            let sh = env::var("SHELL").unwrap_or_else(|_| "/bin/bash".into());
            vec![sh, "-l".into()]
        };

        let secret_base64 = env::var("WEBSHELL_SECRET").ok().or(s.secret_base64);

        Config {
            bind_addr: s.bind,
            pam_service: s.pam_service,
            owner,
            slots_per_user: s.max_sessions.clamp(1, 64),
            max_share_secs: s.max_sharing_duration_secs.max(1),
            sharing_enabled: s.sharing_enabled,
            public_base_url,
            login_cmd,
            scrollback_cap: s.scrollback_bytes,
            session_ttl: Duration::from_secs(s.session_ttl_secs.max(60)),
            cookie_secure: s.cookie_secure,
            allowed_origin,
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

/// The username of the user running this process (euid).
fn process_owner() -> String {
    unsafe {
        let uid = libc::geteuid();
        let pw = libc::getpwuid(uid);
        if pw.is_null() {
            return env::var("USER").unwrap_or_else(|_| uid.to_string());
        }
        CStr::from_ptr((*pw).pw_name).to_string_lossy().into_owned()
    }
}

/// Extract `scheme://authority` from a URL, dropping any path.
fn origin_of(url: &str) -> String {
    match url.find("://") {
        Some(i) => {
            let after = &url[i + 3..];
            let end = after.find('/').unwrap_or(after.len());
            format!("{}://{}", &url[..i], &after[..end])
        }
        None => url.to_string(),
    }
}

pub fn random_token(bytes: usize) -> String {
    use rand::RngCore;
    let mut buf = vec![0u8; bytes];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
}
