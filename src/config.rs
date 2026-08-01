use std::env;
use std::ffi::CStr;
use std::path::Path;
use std::time::Duration;

use base64::Engine;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

/// User-facing configuration, loaded from a TOML file (all fields optional —
/// missing ones fall back to the documented defaults).
///
/// Authentication is always PAM, and only the **process owner** may log in
/// (with both their username and system password).
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    /// Listen address, e.g. "0.0.0.0:9023".
    pub bind: String,
    /// PAM service name (file under /etc/pam.d).
    pub pam_service: String,
    /// Enable application-managed TOTP MFA.
    pub mfa_enabled: bool,
    /// Base32 TOTP seed. Generated after the first successful password login.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mfa_token_seed: Option<String>,
    /// Persistent terminal slots for the user.
    pub max_sessions: usize,
    /// Upper bound a share link may be valid for.
    pub max_sharing_duration_secs: u64,
    /// Master switch for read-only share links.
    pub sharing_enabled: bool,
    /// Externally-visible base URL, e.g. "https://shell.example.com". Used to
    /// build absolute share links, and accepted as a WebSocket Origin. A
    /// trailing slash is optional.
    #[serde(skip_serializing_if = "Option::is_none")]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_base64: Option<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            bind: "127.0.0.1:8080".into(),
            pam_service: "login".into(),
            mfa_enabled: false,
            mfa_token_seed: None,
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

/// Preferred config filename. A sibling `config.yaml` is still accepted; see
/// `resolve_path`.
pub const DEFAULT_CONFIG: &str = "config.toml";

/// Pick the config file to use. An explicit path that exists always wins; if it
/// does not, and a same-named legacy YAML file sits beside it, use that. This
/// is what lets an existing deployment keep starting after the switch to TOML
/// without its command line or working directory changing.
pub fn resolve_path(path: &Path) -> std::path::PathBuf {
    if path.exists() {
        return path.to_path_buf();
    }
    for legacy in ["yaml", "yml"] {
        let candidate = path.with_extension(legacy);
        if candidate.exists() {
            return candidate;
        }
    }
    path.to_path_buf()
}

pub fn is_legacy(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("yaml") | Some("yml")
    )
}

/// Convert a legacy YAML config to TOML and move the original aside, returning
/// the path now in force.
///
/// This is a one-way door by design: the next start with `-c config.yaml` finds
/// nothing and fails, which is what forces the flag to be updated. A start that
/// names the TOML file — including the default, which is why `run.sh` needs no
/// `-c` — keeps working across the conversion without interruption.
pub fn migrate_legacy(path: &Path) -> anyhow::Result<std::path::PathBuf> {
    let settings = Settings::load(Some(path))?;
    let target = path.with_extension("toml");
    if !target.exists() {
        settings.save(&target)?;
    }
    let retired = path.with_extension(format!(
        "{}.old",
        path.extension().and_then(|e| e.to_str()).unwrap_or("yaml")
    ));
    std::fs::rename(path, &retired)
        .map_err(|e| anyhow::anyhow!("moving {} aside: {e}", path.display()))?;
    tracing::warn!(
        "converted {} to {}; the original is now {}. \
         Update your start command to use {} — the old path will not work again.",
        path.display(),
        target.display(),
        retired.display(),
        target.display()
    );
    Ok(target)
}

/// Explain a missing config when the TOML replacement is sitting right there,
/// so the failure says what to do instead of just "not found". Covers both the
/// automatic conversion and a manual `configrewrite` where the YAML was
/// deleted afterwards.
pub fn migration_hint(path: &Path) -> Option<String> {
    if !is_legacy(path) {
        return None;
    }
    let target = path.with_extension("toml");
    if !target.exists() {
        return None;
    }
    let retired = path.with_extension(format!(
        "{}.old",
        path.extension().and_then(|e| e.to_str()).unwrap_or("yaml")
    ));
    let converted = if retired.exists() {
        format!(" It was converted by an earlier run; the original is {}.", retired.display())
    } else {
        String::new()
    };
    Some(format!(
        "{} does not exist, but {} does.{} Start with -c {} instead.",
        path.display(),
        target.display(),
        converted,
        target.display()
    ))
}

impl Settings {
    /// Parse a config file. TOML is the format; YAML is still read so an
    /// existing deployment keeps working, with a warning pointing at
    /// `configrewrite`. YAML support exists only for that migration.
    pub fn load(path: Option<&Path>) -> anyhow::Result<Settings> {
        let Some(p) = path else {
            return Ok(Settings::default());
        };
        let text = std::fs::read_to_string(p)
            .map_err(|e| anyhow::anyhow!("reading config {}: {e}", p.display()))?;
        match toml::from_str(&text) {
            Ok(settings) => Ok(settings),
            Err(toml_err) => match serde_yaml_ng::from_str(&text) {
                Ok(settings) => {
                    tracing::warn!(
                        "{} is YAML; webshell now uses TOML. Run \
                         `webshell configrewrite -c {}` to convert it — YAML support will go away.",
                        p.display(),
                        p.display()
                    );
                    Ok(settings)
                }
                // Report the TOML error: that is the format the file should be
                // in, so its message is the useful one.
                Err(_) => Err(anyhow::anyhow!("parsing config {}: {toml_err}", p.display())),
            },
        }
    }

    pub fn sample_toml() -> String {
        toml::to_string_pretty(&Settings::default()).unwrap_or_default()
    }

    /// Write these settings to `path` as TOML, atomically and mode-0600. The
    /// file carries the cookie key and TOTP seed, so it is never world-readable
    /// and never a partially-written file another process could load.
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let text = toml::to_string_pretty(self)?;
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(DEFAULT_CONFIG);
        let tmp = parent.join(format!(".{name}.{}.tmp", random_token(8)));
        let result = (|| -> anyhow::Result<()> {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)?;
            file.write_all(text.as_bytes())?;
            file.sync_all()?;
            std::fs::rename(&tmp, path)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        result
    }

    /// Record a completed MFA enrollment. Always written as TOML: if the file
    /// on disk is still legacy YAML, rewriting it in place would leave a
    /// `.yaml` holding TOML, so the seed goes to the `.toml` name instead and
    /// the stale YAML is left for the operator to delete.
    pub fn persist_mfa_seed(path: &Path, seed: &str) -> anyhow::Result<()> {
        let mut settings = if path.exists() {
            Self::load(Some(path))?
        } else {
            Self::default()
        };
        settings.mfa_enabled = true;
        settings.mfa_token_seed = Some(seed.to_string());

        let is_legacy = matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("yaml") | Some("yml")
        );
        let target = if is_legacy {
            path.with_extension("toml")
        } else {
            path.to_path_buf()
        };
        settings.save(&target)?;
        if is_legacy {
            tracing::warn!(
                "MFA enrollment written to {} (TOML). {} is now stale — delete it.",
                target.display(),
                path.display()
            );
        }
        Ok(())
    }
}

/// Fully-resolved runtime configuration.
pub struct Config {
    pub bind_addr: String,
    pub pam_service: String,
    pub mfa_enabled: bool,
    pub mfa_token_seed: Option<String>,
    /// The only account permitted to log in: the user running this process.
    pub owner: String,
    /// The owner's home directory (from the passwd DB), for the spawned shell.
    pub owner_home: String,
    pub slots_per_user: usize,
    pub max_share_secs: u64,
    pub sharing_enabled: bool,
    /// Normalized (no trailing slash) external base URL, if set.
    pub public_base_url: Option<String>,
    /// The process owner's login shell, invoked with `-l`.
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
    /// Cap on a single inbound WebSocket message. Replay messages are outbound
    /// and do not need to widen this attacker-controlled allocation limit.
    pub ws_message_limit: usize,
    pub secret_base64: Option<String>,
}

impl Config {
    pub fn from_settings(s: Settings) -> Self {
        // Resolve identity from the passwd DB, NOT from the environment: when a
        // supervisor starts the service with a stale environment, HOME/USER may
        // still name another account. The shell must use the effective user's
        // real passwd entry instead.
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

        let login_cmd = vec![owner.shell.clone(), "-l".into()];

        let secret_base64 = env::var("WEBSHELL_SECRET").ok().or(s.secret_base64);

        // Bounded like every other sizing knob: this buffer is retained per
        // slot, so an unclamped value is an OOM waiting for a typo.
        let slots_per_user = s.max_sessions.clamp(1, 64);
        let requested_scrollback = s.scrollback_bytes.clamp(4 * 1024, 16 * 1024 * 1024);
        // Bound aggregate retained scrollback, not just each slot independently.
        // This prevents a valid-looking max/max configuration from reserving
        // roughly a GiB once all slots have produced output.
        let aggregate_budget = 256 * 1024 * 1024;
        let scrollback_cap = requested_scrollback.min(aggregate_budget / slots_per_user);
        let ws_message_limit = 64 * 1024;

        Config {
            bind_addr: s.bind,
            pam_service: s.pam_service,
            mfa_enabled: s.mfa_enabled,
            mfa_token_seed: s.mfa_token_seed,
            owner_home: owner.home,
            owner: owner.name,
            // Load-bearing for the wire format, not just a sanity bound: the
            // mux protocol tags each frame with a ONE-BYTE slot index
            // (pty::tagged), so this must stay <= 255.
            slots_per_user,
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

/// Refuse the privileged execution mode before the server creates any state or
/// starts listening. Webshell is deliberately a single-user service: the only
/// account that may authenticate is the unprivileged account running it.
pub fn ensure_unprivileged() -> anyhow::Result<()> {
    ensure_unprivileged_uid(unsafe { libc::geteuid() })
}

fn ensure_unprivileged_uid(euid: libc::uid_t) -> anyhow::Result<()> {
    if euid == 0 {
        anyhow::bail!(
            "refusing to run as root; run webshell as the unprivileged account that will use it"
        );
    }
    Ok(())
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
        let cstr =
            |p: *const std::os::raw::c_char| CStr::from_ptr(p).to_string_lossy().into_owned();
        let name = cstr((*pw).pw_name);
        let home = {
            let h = cstr((*pw).pw_dir);
            if h.is_empty() {
                "/".to_string()
            } else {
                h
            }
        };
        let shell = {
            let s = cstr((*pw).pw_shell);
            if s.is_empty() {
                "/bin/sh".to_string()
            } else {
                s
            }
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
    fn root_execution_is_rejected() {
        assert!(ensure_unprivileged_uid(0).is_err());
        assert!(ensure_unprivileged_uid(1000).is_ok());
    }

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
        assert_eq!(
            cfg.public_base_url.as_deref(),
            Some("https://shell.example.com")
        );
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
