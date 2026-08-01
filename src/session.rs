use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::sync::watch;

use crate::config::random_token;
use crate::util::lock;

/// Unauthenticated (login-page) sessions only exist to hold a CSRF token, so
/// they expire quickly — this bounds memory from anonymous session creation.
const PREAUTH_TTL: Duration = Duration::from_secs(5 * 60);

/// Hard ceiling on stored sessions, so a flood of anonymous requests cannot
/// exhaust memory no matter the rate. Authenticated sessions are few (one user).
const MAX_SESSIONS: usize = 10_000;

/// Server-side session state. The cookie only carries the opaque session id;
/// everything trust-bearing lives here.
#[derive(Clone)]
pub struct Session {
    pub authenticated: bool,
    pub username: String,
    /// Synchronizer token embedded in forms and required on the WebSocket.
    pub csrf: String,
    created: Instant,
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
}

impl SessionStore {
    pub fn new(ttl: Duration) -> Self {
        SessionStore {
            inner: Mutex::new(HashMap::new()),
            ttl,
        }
    }

    /// Create a fresh, unauthenticated session and return its id.
    pub fn create(&self) -> String {
        let id = random_token(24);
        let (revoked, _) = watch::channel(false);
        let session = Session {
            authenticated: false,
            username: String::new(),
            csrf: random_token(24),
            created: Instant::now(),
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
        guard.insert(id.clone(), session);
        id
    }

    /// Fetch a non-expired session by id, evicting it if it has expired.
    pub fn get(&self, id: &str) -> Option<Session> {
        let mut guard = lock(&self.inner);
        match guard.get(id) {
            Some(s) if !s.expired(self.ttl) => Some(s.clone()),
            Some(_) => {
                if let Some(session) = guard.remove(id) {
                    session.revoke();
                }
                None
            }
            None => None,
        }
    }

    pub fn remove(&self, id: &str) {
        if let Some(session) = lock(&self.inner).remove(id) {
            session.revoke();
        }
    }

    /// Promote a session to authenticated under a *new* id (session-fixation
    /// defense). The old id is invalidated and a fresh CSRF token is issued.
    /// Returns the new session id.
    pub fn login(&self, old_id: &str, username: &str) -> String {
        let mut guard = lock(&self.inner);
        if let Some(session) = guard.remove(old_id) {
            session.revoke();
        }
        let new_id = random_token(24);
        let (revoked, _) = watch::channel(false);
        guard.insert(
            new_id.clone(),
            Session {
                authenticated: true,
                username: username.to_string(),
                csrf: random_token(24),
                created: Instant::now(),
                revoked,
            },
        );
        new_id
    }

    /// Drop every expired session. Intended to be called periodically.
    pub fn sweep(&self) {
        let ttl = self.ttl;
        lock(&self.inner).retain(|_, s| {
            let keep = !s.expired(ttl);
            if !keep {
                s.revoke();
            }
            keep
        });
    }


    pub fn ttl(&self) -> Duration {
        self.ttl
    }
}
