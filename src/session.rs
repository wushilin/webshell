use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::config::random_token;

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
        let session = Session {
            authenticated: false,
            username: String::new(),
            csrf: random_token(24),
            created: Instant::now(),
        };
        let mut guard = self.inner.lock().unwrap();
        if guard.len() >= MAX_SESSIONS {
            // Evict the oldest anonymous session (fall back to oldest overall).
            let victim = guard
                .iter()
                .filter(|(_, s)| !s.authenticated)
                .min_by_key(|(_, s)| s.created)
                .or_else(|| guard.iter().min_by_key(|(_, s)| s.created))
                .map(|(k, _)| k.clone());
            if let Some(k) = victim {
                guard.remove(&k);
            }
        }
        guard.insert(id.clone(), session);
        id
    }

    /// Fetch a non-expired session by id, evicting it if it has expired.
    pub fn get(&self, id: &str) -> Option<Session> {
        let mut guard = self.inner.lock().unwrap();
        match guard.get(id) {
            Some(s) if !s.expired(self.ttl) => Some(s.clone()),
            Some(_) => {
                guard.remove(id);
                None
            }
            None => None,
        }
    }

    pub fn remove(&self, id: &str) {
        self.inner.lock().unwrap().remove(id);
    }

    /// Promote a session to authenticated under a *new* id (session-fixation
    /// defense). The old id is invalidated and a fresh CSRF token is issued.
    /// Returns the new session id.
    pub fn login(&self, old_id: &str, username: &str) -> String {
        let mut guard = self.inner.lock().unwrap();
        guard.remove(old_id);
        let new_id = random_token(24);
        guard.insert(
            new_id.clone(),
            Session {
                authenticated: true,
                username: username.to_string(),
                csrf: random_token(24),
                created: Instant::now(),
            },
        );
        new_id
    }

    /// Drop every expired session. Intended to be called periodically.
    pub fn sweep(&self) {
        let ttl = self.ttl;
        self.inner.lock().unwrap().retain(|_, s| !s.expired(ttl));
    }
}
