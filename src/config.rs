use std::env;
use std::ffi::CStr;
use std::path::Path;
use std::time::Duration;

use base64::Engine;
use serde::{Deserialize, Serialize};

/// User-facing configuration, loaded from a TOML file.
///
/// Grouped into tables by concern rather than one flat list: a config file is
/// read far more often than it is written, and `[auth]` / `[network]` says
/// what a key is *for* in a way a prefix never quite does. Every table and
/// every key is optional — a missing one falls back to the documented default.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub network: Network,
    pub auth: Auth,
    pub mfa: Mfa,
    pub google: Google,
    pub terminals: TerminalSettings,
    pub sharing: Sharing,
    pub certs: Certs,
    /// Passwords for `local:` identities, keyed by full identity string.
    /// Declared last: a TOML table absorbs every key that follows it.
    #[serde(skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub local_passwords: std::collections::HashMap<String, String>,
}

/// Where the server listens and how it is reached.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Network {
    /// Listen address, e.g. "0.0.0.0:9023".
    pub bind: String,
    /// Externally-visible base URL, e.g. "https://shell.example.com". Builds
    /// absolute share links, is accepted as a WebSocket Origin, and is what the
    /// Google redirect URI is derived from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_base_url: Option<String>,
    /// *Extra* WebSocket Origins to accept, beyond the request's own Host and
    /// public_base_url. Only needed behind a proxy that rewrites Host.
    pub allowed_origins: Vec<String>,
    /// Pin the accepted Origins to the configured set, dropping the
    /// Origin-matches-Host fallback. Ignored when nothing is configured, which
    /// would lock out every client.
    pub strict_origin: bool,
    /// Mark the session cookie `Secure` (set this when served over HTTPS).
    pub cookie_secure: bool,
}

impl Default for Network {
    fn default() -> Self {
        Network {
            bind: "127.0.0.1:8080".into(),
            public_base_url: None,
            allowed_origins: Vec::new(),
            strict_origin: false,
            cookie_secure: false,
        }
    }
}

/// Who may log in, and by which methods.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Auth {
    /// Exactly who may log in, as `provider:subject`.
    pub users: Vec<crate::identity::Identity>,
    /// Methods offered: "local" and/or "google". A method is only shown when
    /// it is also fully configured.
    pub login_methods: Vec<String>,
    /// Absolute login-session lifetime, seconds.
    pub session_ttl_secs: u64,
    /// Where restart-surviving login sessions are kept. Relative paths resolve
    /// against the config file's directory. Unset = in-memory only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_path: Option<String>,
    /// base64 cookie signing key (>=64 bytes). In config-backed mode, unset is
    /// generated and persisted on startup.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_base64: Option<String>,
}

impl Default for Auth {
    fn default() -> Self {
        Auth {
            users: Vec::new(),
            login_methods: vec!["local".into()],
            session_ttl_secs: 8 * 3600,
            session_path: None,
            secret_base64: None,
        }
    }
}

/// TOTP second factor.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Mfa {
    /// Require a code. Users with no enrolled secret are sent through
    /// enrollment on their next login.
    pub required: bool,
    /// Where per-identity enrollment state is kept. Relative paths resolve
    /// against the config file's directory.
    pub enrollment_path: String,
}

impl Default for Mfa {
    fn default() -> Self {
        Mfa {
            required: true,
            enrollment_path: "enrollment.toml".into(),
        }
    }
}

/// Google sign-in. Only the non-sensitive `openid email profile` scopes are
/// requested, so the OAuth client needs no Google review.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Google {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
}

/// The persistent terminal slots themselves.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct TerminalSettings {
    /// Persistent slots per user.
    pub max_sessions: usize,
    /// Bytes of recent output retained per slot for replay on reattach.
    pub scrollback_bytes: usize,
    /// Login command override, as an argv array, e.g. ["/usr/bin/fish", "-l"].
    /// Empty = the owner's passwd login shell, run with "-l".
    pub login_cmd: Vec<String>,
    /// Extra environment for every spawned shell, applied after the built-ins
    /// (TERM, HOME, USER, LOGNAME) so a key here overrides them. Declared
    /// last: this serializes as the [terminals.envs] sub-table, and TOML
    /// wants scalar keys before sub-tables.
    pub envs: std::collections::BTreeMap<String, String>,
}

impl Default for TerminalSettings {
    fn default() -> Self {
        TerminalSettings {
            max_sessions: 10,
            scrollback_bytes: 128 * 1024,
            login_cmd: Vec::new(),
            envs: std::collections::BTreeMap::new(),
        }
    }
}

/// Read-only share links.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Sharing {
    /// Master switch.
    pub enabled: bool,
    /// Cap on a single link's lifetime, seconds.
    pub max_duration_secs: u64,
}

impl Default for Sharing {
    fn default() -> Self {
        Sharing {
            enabled: true,
            max_duration_secs: 30 * 24 * 3600,
        }
    }
}

/// Automatic TLS: obtain and renew a Let's Encrypt certificate in-process.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Certs {
    /// Master switch. When true, webshell terminates TLS itself with an
    /// automatically obtained and renewed Let's Encrypt certificate, and the
    /// bind/public_base_url combination is validated at startup.
    pub lets_encrypt_enabled: bool,
    /// ACME account key and certificate cache. Relative paths resolve
    /// against the config file's directory.
    pub store_dir: String,
    /// Use the Let's Encrypt staging endpoint: untrusted certificates but
    /// generous rate limits. For first-time setup on a new host — a failed
    /// production attempt counts against strict per-domain limits.
    pub lets_encrypt_staging: bool,
    /// Optional ACME account contact. Let's Encrypt mails expiry warnings
    /// here if renewal silently breaks.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact_email: Option<String>,
}

impl Default for Certs {
    fn default() -> Self {
        Certs {
            lets_encrypt_enabled: false,
            store_dir: "certs".into(),
            lets_encrypt_staging: false,
            contact_email: None,
        }
    }
}

/// Default config filename.
pub const DEFAULT_CONFIG: &str = "config.toml";

/// What `run` should do about the config files it can see.
pub enum ConfigChoice {
    /// Load this file and start.
    Use(std::path::PathBuf),
    /// Nothing usable on disk.
    Missing(std::path::PathBuf),
}

/// Decide which config to run from: use it if it exists, otherwise report that
/// there is nothing to serve.
pub fn choose(requested: &Path) -> anyhow::Result<ConfigChoice> {
    if requested.exists() {
        Ok(ConfigChoice::Use(requested.to_path_buf()))
    } else {
        Ok(ConfigChoice::Missing(requested.to_path_buf()))
    }
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
        toml::from_str(&text).map_err(|e| anyhow::anyhow!("parsing config {}: {e}", p.display()))
    }

    /// A starter config. The table layout does the grouping now, so this is
    /// just a faithful serialization of the defaults.
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
}

/// Fully-resolved runtime configuration.
pub struct Config {
    pub bind_addr: String,
    /// The allowlist. Every login must match one of these exactly.
    pub users: Vec<crate::identity::Identity>,
    pub login_methods: Vec<crate::identity::Provider>,
    pub local_passwords: std::collections::HashMap<String, String>,
    pub mfa_required: bool,
    pub google_client_id: Option<String>,
    pub google_client_secret: Option<String>,
    pub mfa_enrollment_path: std::path::PathBuf,
    /// The OS account every shell runs as — the user running this process.
    /// Logins are Google identities; they all share this account.
    pub owner: String,
    /// The owner's home directory (from the passwd DB), for the spawned shell.
    pub owner_home: String,
    pub slots_per_user: usize,
    pub max_share_secs: u64,
    pub sharing_enabled: bool,
    /// Normalized (no trailing slash) external base URL, if set.
    pub public_base_url: Option<String>,
    /// The spawn command: `[terminals] login_cmd` when set, else the process
    /// owner's passwd login shell invoked with `-l`.
    pub login_cmd: Vec<String>,
    /// Extra environment seeded into every spawned shell ([terminals.envs]).
    pub envs: std::collections::BTreeMap<String, String>,
    pub scrollback_cap: usize,
    pub session_ttl: Duration,
    pub session_path: Option<std::path::PathBuf>,
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
    /// Zero-config local-only setup for `webshell simple`: one `local:` user
    /// with the given password, MFA off, Google off, everything else defaulted.
    /// The password is stored verbatim — `localauth::verify` accepts a plaintext
    /// value, so this mode trades the config file for two environment variables.
    pub fn simple(user: &str, password: &str, bind: &str) -> Self {
        let identity = crate::identity::Identity::new(crate::identity::Provider::Local, user);
        let mut local_passwords = std::collections::HashMap::new();
        local_passwords.insert(identity.to_string(), password.to_string());
        Config::from_settings(Settings {
            network: Network {
                bind: bind.to_string(),
                ..Network::default()
            },
            auth: Auth {
                users: vec![identity],
                login_methods: vec!["local".to_string()],
                ..Auth::default()
            },
            mfa: Mfa {
                required: false,
                ..Mfa::default()
            },
            local_passwords,
            ..Settings::default()
        })
    }

    pub fn from_settings(s: Settings) -> Self {
        // Resolve identity from the passwd DB, NOT from the environment: when a
        // supervisor starts the service with a stale environment, HOME/USER may
        // still name another account. The shell must use the effective user's
        // real passwd entry instead.
        let owner = owner_info();

        let public_base_url = s
            .network
            .public_base_url
            .as_deref()
            .map(|u| u.trim_end_matches('/').to_string());

        // Additive: the configured extras and the public base URL both just
        // widen what the Host fallback already allows.
        let allowed_origins = s
            .network
            .allowed_origins
            .iter()
            .map(String::as_str)
            .chain(public_base_url.as_deref())
            .map(normalize_origin)
            .filter(|o| !o.is_empty())
            .fold(Vec::new(), |mut acc, o| {
                if !acc.contains(&o) {
                    acc.push(o);
                }
                acc
            });

        // The configured override wins verbatim; empty means the passwd shell.
        let login_cmd = if s.terminals.login_cmd.is_empty() {
            vec![owner.shell.clone(), "-l".into()]
        } else {
            s.terminals.login_cmd.clone()
        };

        // Parse once, at load: an unknown method name should be a startup
        // error, not a login page that silently offers nothing.
        let login_methods: Vec<crate::identity::Provider> = s
            .auth
            .login_methods
            .iter()
            .filter_map(|name| match name.trim().to_lowercase().as_str() {
                "local" => Some(crate::identity::Provider::Local),
                "google" => Some(crate::identity::Provider::Google),
                other => {
                    tracing::error!("unknown login method {other:?}; ignoring it");
                    None
                }
            })
            .fold(Vec::new(), |mut acc, m| {
                if !acc.contains(&m) {
                    acc.push(m);
                }
                acc
            });

        let secret_base64 = env::var("WEBSHELL_SECRET").ok().or(s.auth.secret_base64);

        // Bounded like every other sizing knob: this buffer is retained per
        // slot, so an unclamped value is an OOM waiting for a typo.
        let slots_per_user = s.terminals.max_sessions.clamp(1, 64);
        let requested_scrollback = s
            .terminals
            .scrollback_bytes
            .clamp(4 * 1024, 16 * 1024 * 1024);
        // Bound aggregate retained scrollback, not just each slot independently.
        // This prevents a valid-looking max/max configuration from reserving
        // roughly a GiB once all slots have produced output.
        let aggregate_budget = 256 * 1024 * 1024;
        let scrollback_cap = requested_scrollback.min(aggregate_budget / slots_per_user);
        let ws_message_limit = 64 * 1024;

        Config {
            bind_addr: s.network.bind,
            users: s.auth.users,
            login_methods,
            local_passwords: s.local_passwords,
            mfa_required: s.mfa.required,
            google_client_id: s.google.client_id,
            google_client_secret: s.google.client_secret,
            mfa_enrollment_path: std::path::PathBuf::from(s.mfa.enrollment_path),
            owner_home: owner.home,
            owner: owner.name,
            // Load-bearing for the wire format, not just a sanity bound: the
            // mux protocol tags each frame with a ONE-BYTE slot index
            // (pty::tagged), so this must stay <= 255.
            slots_per_user,
            max_share_secs: s.sharing.max_duration_secs.max(1),
            sharing_enabled: s.sharing.enabled,
            public_base_url,
            login_cmd,
            envs: s.terminals.envs,
            scrollback_cap,
            session_ttl: Duration::from_secs(s.auth.session_ttl_secs.max(60)),
            session_path: s.auth.session_path.map(Into::into),
            cookie_secure: s.network.cookie_secure,
            allowed_origins,
            strict_origin: s.network.strict_origin,
            ws_message_limit,
            secret_base64,
        }
    }

    /// Verify a login attempt via PAM. Only the process owner may log in (the
    /// username must match); blocks, so call from a blocking task. Returns the
    /// owner's username on success.
    /// Whether this identity is on the allowlist. Comparison is on the
    /// normalized form, so capitalisation in the config cannot cause a
    /// mysterious denial.
    /// The stored hash for a local identity, if one is configured.
    pub fn local_password(&self, id: &crate::identity::Identity) -> Option<&str> {
        let wanted = id.to_string();
        self.local_passwords
            .iter()
            .find(|(k, _)| k.trim().to_lowercase() == wanted)
            .map(|(_, v)| v.as_str())
    }

    /// Local login can work: enabled, and at least one local identity exists.
    pub fn local_usable(&self) -> bool {
        self.login_methods
            .contains(&crate::identity::Provider::Local)
            && self
                .users
                .iter()
                .any(|u| u.provider() == crate::identity::Provider::Local)
    }

    /// Google login can work: enabled, and every piece it needs is configured.
    pub fn google_usable(&self) -> bool {
        self.login_methods
            .contains(&crate::identity::Provider::Google)
            && self.google_client_id.is_some()
            && self.google_client_secret.is_some()
            && self.redirect_uri().is_some()
    }

    pub fn permits(&self, id: &crate::identity::Identity) -> bool {
        self.users.contains(id)
    }

    /// Where Google should send the browser back. Derived rather than
    /// configured: it must match what is registered in the Cloud Console, and
    /// two sources of truth for one URL is a support burden.
    pub fn redirect_uri(&self) -> Option<String> {
        self.public_base_url
            .as_ref()
            .map(|base| format!("{base}/webshell/oauth/callback"))
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
            network: Network {
                public_base_url: Some("https://shell.example.com/".into()),
                ..Network::default()
            },
            ..Settings::default()
        });
        assert_eq!(cfg.allowed_origins, vec!["https://shell.example.com"]);
        assert_eq!(
            cfg.public_base_url.as_deref(),
            Some("https://shell.example.com")
        );
    }

    #[test]
    fn custom_login_cmd_and_envs_pass_through() {
        let cfg = Config::from_settings(Settings {
            terminals: TerminalSettings {
                login_cmd: vec!["/usr/bin/fish".into(), "-l".into()],
                envs: [("EDITOR".to_string(), "vim".to_string())].into(),
                ..TerminalSettings::default()
            },
            ..Settings::default()
        });
        assert_eq!(cfg.login_cmd, vec!["/usr/bin/fish", "-l"]);
        assert_eq!(cfg.envs.get("EDITOR").map(String::as_str), Some("vim"));
    }

    #[test]
    fn unset_login_cmd_and_envs_keep_the_default_behavior() {
        let cfg = Config::from_settings(Settings::default());
        // The default is the runner's passwd shell (unknowable here) + "-l".
        assert_eq!(cfg.login_cmd.len(), 2);
        assert_eq!(cfg.login_cmd[1], "-l");
        assert!(cfg.envs.is_empty());
    }

    #[test]
    fn sample_config_documents_login_cmd_and_envs() {
        let sample = Settings::sample_toml();
        assert!(sample.contains("login_cmd = []"));
        assert!(sample.contains("[terminals.envs]"));
    }

    #[test]
    fn sample_config_documents_certs() {
        let sample = Settings::sample_toml();
        assert!(sample.contains("[certs]"));
        assert!(sample.contains("lets_encrypt_enabled = false"));
        assert!(sample.contains("store_dir = \"certs\""));
        assert!(sample.contains("lets_encrypt_staging = false"));
        // Ordering is only observable when local_passwords serializes at all.
        let mut s = Settings::default();
        s.local_passwords
            .insert("local:alice".to_string(), "x".to_string());
        let text = toml::to_string_pretty(&s).unwrap();
        assert!(text.find("[certs]").unwrap() < text.find("[local_passwords]").unwrap());
    }

    #[test]
    fn certs_table_parses() {
        let s: Settings = toml::from_str(
            "[certs]\nlets_encrypt_enabled = true\nstore_dir = \"/var/lib/webshell/certs\"\ncontact_email = \"ops@example.com\"\n",
        )
        .unwrap();
        assert!(s.certs.lets_encrypt_enabled);
        assert_eq!(s.certs.store_dir, "/var/lib/webshell/certs");
        assert!(!s.certs.lets_encrypt_staging);
        assert_eq!(s.certs.contact_email.as_deref(), Some("ops@example.com"));
    }

    #[test]
    fn extra_origins_and_the_base_url_merge_without_duplicates() {
        let cfg = Config::from_settings(Settings {
            network: Network {
                public_base_url: Some("https://a.b".into()),
                allowed_origins: vec!["c.d".into(), "".into(), "https://a.b/".into()],
                ..Network::default()
            },
            ..Settings::default()
        });
        // Empty entries dropped, trailing slash normalized, no repeats.
        assert_eq!(cfg.allowed_origins, vec!["c.d", "https://a.b"]);
    }
}
