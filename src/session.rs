use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;

use crate::config::random_token;
use crate::util::lock;

/// Unauthenticated (login-page) sessions only exist to hold a CSRF token, so
/// they expire quickly — this bounds memory from anonymous session creation.
///
/// Not *too* quickly, though: with MFA the user opens this page, walks to their
/// phone, and comes back. At five minutes that round trip routinely expired the
/// form, and the failure looked like a dead button. Thirty still bounds the
/// anonymous-session pool (which is capped by MAX_SESSIONS anyway) while
/// comfortably covering a human fetching a code.
const PREAUTH_TTL: Duration = Duration::from_secs(30 * 60);

/// Hard ceiling on stored sessions, so a flood of anonymous requests cannot
/// exhaust memory no matter the rate. Authenticated sessions are few (one user).
const MAX_SESSIONS: usize = 10_000;

/// Server-side session state. The cookie only carries the opaque session id;
/// everything trust-bearing lives here.
#[derive(Clone)]
pub struct Session {
    pub authenticated: bool,
    pub mfa_pending: bool,
    /// The login identity (`google:you@example.com`) once known. Terminal
    /// pools and share grants key off this, so each identity gets its own
    /// slots even though every shell runs as the same OS account.
    pub username: String,
    /// In-flight OIDC login. Held here rather than in a shared map because the
    /// session cookie is what proves a callback belongs to this browser.
    pub oauth: Option<crate::oidc::Flow>,
    /// Synchronizer token embedded in forms and required on the WebSocket.
    pub csrf: String,
    created: Instant,
    created_unix: u64,
    revoked: watch::Sender<bool>,
}

impl Session {
    /// How long this session may live: short for anonymous, configured for
    /// authenticated.
    fn ttl(&self, auth_ttl: Duration) -> Duration {
        if self.authenticated {
            auth_ttl
        } else {
            PREAUTH_TTL
        }
    }
    fn expired(&self, auth_ttl: Duration) -> bool {
        self.created.elapsed() >= self.ttl(auth_ttl)
    }

    pub fn remaining(&self, auth_ttl: Duration) -> Duration {
        self.ttl(auth_ttl).saturating_sub(self.created.elapsed())
    }

    pub fn revocation(&self) -> watch::Receiver<bool> {
        self.revoked.subscribe()
    }

    fn revoke(&self) {
        let _ = self.revoked.send(true);
    }
}

pub struct SessionStore {
    inner: Mutex<HashMap<String, Session>>,
    ttl: Duration,
    path: Option<PathBuf>,
}

impl SessionStore {
    pub fn new(ttl: Duration) -> Self {
        SessionStore {
            inner: Mutex::new(HashMap::new()),
            ttl,
            path: None,
        }
    }

    pub fn load(path: PathBuf, ttl: Duration) -> anyhow::Result<Self> {
        let store = SessionStore {
            inner: Mutex::new(HashMap::new()),
            ttl,
            path: Some(path.clone()),
        };
        if !path.exists() {
            return Ok(store);
        }
        let text = std::fs::read_to_string(&path)
            .map_err(|e| anyhow::anyhow!("reading sessions {}: {e}", path.display()))?;
        let disk: DiskStore = toml::from_str(&text)
            .map_err(|e| anyhow::anyhow!("parsing sessions {}: {e}", path.display()))?;
        {
            let now = now_unix();
            let mut guard = lock(&store.inner);
            for (key, d) in disk.sessions {
                if !d.meaningful() {
                    continue;
                }
                let ttl_secs = if d.authenticated {
                    ttl.as_secs()
                } else {
                    PREAUTH_TTL.as_secs()
                };
                if now.saturating_sub(d.created_unix) >= ttl_secs {
                    continue;
                }
                let age = Duration::from_secs(now.saturating_sub(d.created_unix));
                let created = Instant::now().checked_sub(age).unwrap_or_else(Instant::now);
                let (revoked, _) = watch::channel(false);
                guard.insert(
                    key,
                    Session {
                        authenticated: d.authenticated,
                        mfa_pending: d.mfa_pending,
                        username: d.username,
                        oauth: d.oauth,
                        csrf: d.csrf,
                        created,
                        created_unix: d.created_unix,
                        revoked,
                    },
                );
            }
        }
        store.persist();
        Ok(store)
    }

    /// Create a fresh, unauthenticated session and return its id.
    pub fn create(&self) -> String {
        let id = random_token(24);
        let (revoked, _) = watch::channel(false);
        let session = Session {
            authenticated: false,
            mfa_pending: false,
            username: String::new(),
            oauth: None,
            csrf: random_token(24),
            created: Instant::now(),
            created_unix: now_unix(),
            revoked,
        };
        let mut guard = lock(&self.inner);
        if guard.len() >= MAX_SESSIONS {
            // Evict the oldest anonymous session (fall back to oldest overall).
            let victim = guard
                .iter()
                .filter(|(_, s)| !s.authenticated)
                .min_by_key(|(_, s)| s.created)
                .or_else(|| guard.iter().min_by_key(|(_, s)| s.created))
                .map(|(k, _)| k.clone());
            if let Some(k) = victim {
                if let Some(session) = guard.remove(&k) {
                    session.revoke();
                }
            }
        }
        guard.insert(session_key(&id), session);
        id
    }

    /// Fetch a non-expired session by id, evicting it if it has expired.
    pub fn get(&self, id: &str) -> Option<Session> {
        let mut guard = lock(&self.inner);
        let key = session_key(id);
        match guard.get(&key) {
            Some(s) if !s.expired(self.ttl) => Some(s.clone()),
            Some(_) => {
                if let Some(session) = guard.remove(&key) {
                    session.revoke();
                }
                drop(guard);
                self.persist();
                None
            }
            None => None,
        }
    }

    pub fn remove(&self, id: &str) {
        let removed = lock(&self.inner).remove(&session_key(id));
        if let Some(session) = removed {
            session.revoke();
            self.persist();
        }
    }

    /// Promote a session to authenticated under a *new* id (session-fixation
    /// defense). The old id is invalidated and a fresh CSRF token is issued.
    /// Returns the new session id.
    pub fn login(&self, old_id: &str, username: &str) -> String {
        let mut guard = lock(&self.inner);
        if let Some(session) = guard.remove(&session_key(old_id)) {
            session.revoke();
        }
        let new_id = random_token(24);
        let (revoked, _) = watch::channel(false);
        guard.insert(
            session_key(&new_id),
            Session {
                authenticated: true,
                mfa_pending: false,
                oauth: None,
                username: username.to_string(),
                csrf: random_token(24),
                created: Instant::now(),
                created_unix: now_unix(),
                revoked,
            },
        );
        drop(guard);
        self.persist();
        new_id
    }

    pub fn begin_mfa(&self, old_id: &str, username: &str) -> String {
        let mut guard = lock(&self.inner);
        if let Some(session) = guard.remove(&session_key(old_id)) {
            session.revoke();
        }
        let new_id = random_token(24);
        let (revoked, _) = watch::channel(false);
        guard.insert(
            session_key(&new_id),
            Session {
                authenticated: false,
                mfa_pending: true,
                oauth: None,
                username: username.to_string(),
                csrf: random_token(24),
                created: Instant::now(),
                created_unix: now_unix(),
                revoked,
            },
        );
        drop(guard);
        self.persist();
        new_id
    }

    /// Drop every expired session. Intended to be called periodically.
    pub fn sweep(&self) {
        let ttl = self.ttl;
        let changed = {
            let mut changed = false;
            lock(&self.inner).retain(|_, s| {
                let keep = !s.expired(ttl);
                if !keep {
                    s.revoke();
                    changed = true;
                }
                keep
            });
            changed
        };
        if changed {
            self.persist();
        }
    }

    /// Attach an in-flight OIDC login to a pre-auth session.
    pub fn set_oauth(&self, id: &str, flow: Option<crate::oidc::Flow>) {
        let changed = {
            let mut guard = lock(&self.inner);
            if let Some(session) = guard.get_mut(&session_key(id)) {
                session.oauth = flow;
                true
            } else {
                false
            }
        };
        if changed {
            self.persist();
        }
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    fn persist(&self) {
        let Some(path) = &self.path else {
            return;
        };
        let sessions = {
            lock(&self.inner)
                .iter()
                .filter(|(_, s)| meaningful(s) && !s.expired(self.ttl))
                .map(|(k, s)| {
                    (
                        k.clone(),
                        DiskSession {
                            authenticated: s.authenticated,
                            mfa_pending: s.mfa_pending,
                            username: s.username.clone(),
                            oauth: s.oauth.clone(),
                            csrf: s.csrf.clone(),
                            created_unix: s.created_unix,
                        },
                    )
                })
                .collect()
        };
        let disk = DiskStore {
            version: 1,
            sessions,
        };
        if let Err(e) = write_atomic(path, &disk) {
            tracing::error!("could not persist sessions {}: {e}", path.display());
        }
    }
}

#[derive(Default, Deserialize, Serialize)]
#[serde(default)]
struct DiskStore {
    version: u32,
    sessions: HashMap<String, DiskSession>,
}

#[derive(Deserialize, Serialize)]
struct DiskSession {
    authenticated: bool,
    mfa_pending: bool,
    username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    oauth: Option<crate::oidc::Flow>,
    csrf: String,
    created_unix: u64,
}

impl DiskSession {
    fn meaningful(&self) -> bool {
        self.authenticated || self.mfa_pending || self.oauth.is_some()
    }
}

fn meaningful(s: &Session) -> bool {
    s.authenticated || s.mfa_pending || s.oauth.is_some()
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn session_key(id: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(id.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

fn write_atomic(path: &Path, disk: &DiskStore) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let text = toml::to_string_pretty(disk)?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("sessions.toml");
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
