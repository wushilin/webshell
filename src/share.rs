//! Read-only share tokens: unguessable, time-limited capabilities that grant
//! login-free, read-only access to one user's terminal slot.
//!
//! Each token carries its own expiry (chosen when the link is created) and is
//! independent of the creator's login session — the link keeps working until it
//! expires, even after the owner logs out. It resolves to the owner's slot as
//! long as that slot's shell is still running.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::config::random_token;

struct ShareGrant {
    username: String,
    index: usize,
    created: Instant,
    ttl: Duration,
}

impl ShareGrant {
    fn remaining(&self) -> Option<Duration> {
        self.ttl.checked_sub(self.created.elapsed())
    }
}

/// Ceiling on live share tokens, so token creation can't grow memory without
/// bound (a single user, so this is generous).
const MAX_SHARES: usize = 64;

pub struct ShareStore {
    inner: Mutex<HashMap<String, ShareGrant>>,
}

impl ShareStore {
    pub fn new() -> Self {
        ShareStore {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Mint a token granting read-only access to `username`'s slot `index`,
    /// valid for `ttl`.
    pub fn create(&self, username: &str, index: usize, ttl: Duration) -> String {
        let token = random_token(24);
        let mut guard = self.inner.lock().unwrap();
        // Reclaim expired grants first, then enforce the ceiling by dropping the
        // oldest if still full.
        guard.retain(|_, g| g.remaining().is_some());
        while guard.len() >= MAX_SHARES {
            let oldest = guard
                .iter()
                .min_by_key(|(_, g)| g.created)
                .map(|(k, _)| k.clone());
            match oldest {
                Some(k) => {
                    guard.remove(&k);
                }
                None => break,
            }
        }
        guard.insert(
            token.clone(),
            ShareGrant {
                username: username.to_string(),
                index,
                created: Instant::now(),
                ttl,
            },
        );
        token
    }

    /// Resolve a non-expired token to `(username, index)`, pruning it if expired.
    pub fn resolve(&self, token: &str) -> Option<(String, usize)> {
        let mut guard = self.inner.lock().unwrap();
        match guard.get(token) {
            Some(g) if g.remaining().is_some() => Some((g.username.clone(), g.index)),
            Some(_) => {
                guard.remove(token);
                None
            }
            None => None,
        }
    }

    /// Seconds until the token expires, or `None` if expired/unknown.
    pub fn remaining_secs(&self, token: &str) -> Option<u64> {
        self.inner
            .lock()
            .unwrap()
            .get(token)
            .and_then(|g| g.remaining())
            .map(|d| d.as_secs())
    }

    /// Drop expired tokens.
    pub fn sweep(&self) {
        self.inner
            .lock()
            .unwrap()
            .retain(|_, g| g.remaining().is_some());
    }
}
