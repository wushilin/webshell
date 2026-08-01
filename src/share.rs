//! Read-only share tokens: unguessable, time-limited capabilities that grant
//! login-free, read-only access to one user's terminal slot.
//!
//! Tokens carry a random grant id plus `(username, slot, expiry)` and are
//! authenticated by an HMAC. The corresponding grant is tracked in memory so
//! the owner can revoke it and active viewers are disconnected immediately.
//! Grants intentionally do not survive a server restart.
//!
//! A token is independent of the creator's login session (it survives logout)
//! and resolves to the owner's slot as long as that slot's shell is running.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Mints, verifies, lists, and revokes HMAC-signed share grants.
pub struct ShareStore {
    key: Vec<u8>,
    grants: Mutex<HashMap<String, Grant>>,
}

#[derive(Clone, serde::Serialize)]
pub struct Grant {
    pub id: String,
    pub username: String,
    pub index: usize,
    pub expires_at: u64,
    #[serde(skip_serializing)]
    revoked: tokio::sync::watch::Sender<bool>,
}

impl ShareStore {
    /// `key` is domain-separated signing material derived from the master key.
    pub fn new(key: Vec<u8>) -> Self {
        ShareStore {
            key,
            grants: Mutex::new(HashMap::new()),
        }
    }

    fn mac(&self, msg: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("HMAC accepts any key length");
        mac.update(msg);
        mac.finalize().into_bytes().to_vec()
    }

    /// Mint a token granting read-only access to `username`'s slot `index`,
    /// valid for `ttl`. The token is `base64url(payload).base64url(hmac)`.
    pub fn create(&self, username: &str, index: usize, ttl: Duration) -> (String, String) {
        let exp = now_unix().saturating_add(ttl.as_secs());
        let id = crate::config::random_token(18);
        let payload = format!("{id}:{index}:{exp}:{username}");
        let sig = self.mac(payload.as_bytes());
        let token = format!("{}.{}", B64.encode(payload.as_bytes()), B64.encode(sig));
        let (revoked, _) = tokio::sync::watch::channel(false);
        crate::util::lock(&self.grants).insert(
            id.clone(),
            Grant {
                id: id.clone(),
                username: username.to_string(),
                index,
                expires_at: exp,
                revoked,
            },
        );
        (token, id)
    }

    /// Verify a token's signature and decode its payload (username, slot, expiry
    /// unix-secs). Signature check is constant-time. Does not check expiry.
    fn verify(&self, token: &str) -> Option<(String, String, usize, u64)> {
        let (p_b64, s_b64) = token.split_once('.')?;
        let payload = B64.decode(p_b64).ok()?;
        let sig = B64.decode(s_b64).ok()?;
        let mut mac = HmacSha256::new_from_slice(&self.key).ok()?;
        mac.update(&payload);
        mac.verify_slice(&sig).ok()?; // constant-time; rejects any tampering
        let text = std::str::from_utf8(&payload).ok()?;
        let mut parts = text.splitn(4, ':');
        let id = parts.next()?.to_string();
        let index: usize = parts.next()?.parse().ok()?;
        let exp: u64 = parts.next()?.parse().ok()?;
        let user = parts.next()?.to_string();
        Some((id, user, index, exp))
    }

    /// Resolve a valid, non-expired token to `(username, index)`.
    pub fn resolve(&self, token: &str) -> Option<(String, usize)> {
        let (id, user, index, exp) = self.verify(token)?;
        if now_unix() >= exp {
            crate::util::lock(&self.grants).remove(&id);
            return None;
        }
        let grants = crate::util::lock(&self.grants);
        let grant = grants.get(&id)?;
        if grant.username != user || grant.index != index || grant.expires_at != exp {
            return None;
        }
        Some((user, index))
    }

    /// Seconds until the token expires, or `None` if invalid/expired.
    pub fn remaining_secs(&self, token: &str) -> Option<u64> {
        let (id, _, _, exp) = self.verify(token)?;
        if !crate::util::lock(&self.grants).contains_key(&id) {
            return None;
        }
        exp.checked_sub(now_unix()).filter(|&r| r > 0)
    }

    pub fn revoke(&self, username: &str, id: &str) -> bool {
        let mut grants = crate::util::lock(&self.grants);
        if grants.get(id).is_some_and(|g| g.username == username) {
            if let Some(grant) = grants.remove(id) {
                let _ = grant.revoked.send(true);
            }
            true
        } else {
            false
        }
    }

    pub fn lease(
        &self,
        token: &str,
    ) -> Option<(String, usize, tokio::sync::watch::Receiver<bool>)> {
        let (id, user, index, exp) = self.verify(token)?;
        if now_unix() >= exp {
            return None;
        }
        let grants = crate::util::lock(&self.grants);
        let grant = grants.get(&id)?;
        if grant.username != user || grant.index != index || grant.expires_at != exp {
            return None;
        }
        Some((user, index, grant.revoked.subscribe()))
    }

    pub fn list(&self, username: &str) -> Vec<Grant> {
        let now = now_unix();
        let mut grants = crate::util::lock(&self.grants);
        grants.retain(|_, g| g.expires_at > now);
        grants
            .values()
            .filter(|g| g.username == username)
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> ShareStore {
        ShareStore::new(vec![7u8; 64])
    }

    #[test]
    fn active_grant_round_trips() {
        let a = store();
        let (token, _) = a.create("wushilin", 3, Duration::from_secs(3600));
        assert_eq!(a.resolve(&token), Some(("wushilin".to_string(), 3)));
        assert!(a.remaining_secs(&token).unwrap() > 3500);
    }

    #[test]
    fn username_with_colons_is_preserved() {
        let s = store();
        let (token, _) = s.create("a:b:c", 0, Duration::from_secs(60));
        assert_eq!(s.resolve(&token), Some(("a:b:c".to_string(), 0)));
    }

    #[test]
    fn expired_token_is_rejected() {
        let s = store();
        let (token, _) = s.create("u", 0, Duration::from_secs(0));
        assert_eq!(s.resolve(&token), None);
        assert_eq!(s.remaining_secs(&token), None);
    }

    #[test]
    fn tampering_and_wrong_key_are_rejected() {
        let s = store();
        let (token, _) = s.create("u", 2, Duration::from_secs(60));
        // Flip a character in the payload segment.
        let (p, sig) = token.split_once('.').unwrap();
        let mut bad = p.to_string();
        let last = bad.pop().unwrap();
        bad.push(if last == 'A' { 'B' } else { 'A' });
        assert_eq!(s.resolve(&format!("{bad}.{sig}")), None);
        // A different signing key cannot validate the token.
        let other = ShareStore::new(vec![9u8; 64]);
        assert_eq!(other.resolve(&token), None);
    }

    #[test]
    fn revoked_and_restarted_grants_are_rejected() {
        let s = store();
        let (token, id) = s.create("u", 1, Duration::from_secs(60));
        assert!(s.revoke("u", &id));
        assert_eq!(s.resolve(&token), None);
        assert_eq!(store().resolve(&token), None);
    }
}
