//! Read-only share tokens: unguessable, time-limited capabilities that grant
//! login-free, read-only access to one user's terminal slot.
//!
//! Tokens are **stateless and self-describing**: each carries `(username, slot,
//! expiry)` and is authenticated by an HMAC over that payload, keyed by the
//! server's signing key. Nothing is stored server-side, so a link keeps working
//! across server restarts as long as the signing key is stable (i.e. a
//! `secret_base64` is configured) — an ephemeral key invalidates old links on
//! restart, the same way it resets login sessions.
//!
//! A token is independent of the creator's login session (it survives logout)
//! and resolves to the owner's slot as long as that slot's shell is running.

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

/// Mints and verifies stateless, HMAC-signed share tokens.
pub struct ShareStore {
    key: Vec<u8>,
}

impl ShareStore {
    /// `key` is the server's signing-key material (the cookie master key); the
    /// HMAC binds tokens to this server so they can't be forged.
    pub fn new(key: Vec<u8>) -> Self {
        ShareStore { key }
    }

    fn mac(&self, msg: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("HMAC accepts any key length");
        mac.update(msg);
        mac.finalize().into_bytes().to_vec()
    }

    /// Mint a token granting read-only access to `username`'s slot `index`,
    /// valid for `ttl`. The token is `base64url(payload).base64url(hmac)`.
    pub fn create(&self, username: &str, index: usize, ttl: Duration) -> String {
        let exp = now_unix().saturating_add(ttl.as_secs());
        // `index` and `exp` are digits only, so splitting on ':' with a 3-way
        // limit leaves the (possibly ':'-containing) username intact.
        let payload = format!("{index}:{exp}:{username}");
        let sig = self.mac(payload.as_bytes());
        format!("{}.{}", B64.encode(payload.as_bytes()), B64.encode(sig))
    }

    /// Verify a token's signature and decode its payload (username, slot, expiry
    /// unix-secs). Signature check is constant-time. Does not check expiry.
    fn verify(&self, token: &str) -> Option<(String, usize, u64)> {
        let (p_b64, s_b64) = token.split_once('.')?;
        let payload = B64.decode(p_b64).ok()?;
        let sig = B64.decode(s_b64).ok()?;
        let mut mac = HmacSha256::new_from_slice(&self.key).ok()?;
        mac.update(&payload);
        mac.verify_slice(&sig).ok()?; // constant-time; rejects any tampering
        let text = std::str::from_utf8(&payload).ok()?;
        let mut parts = text.splitn(3, ':');
        let index: usize = parts.next()?.parse().ok()?;
        let exp: u64 = parts.next()?.parse().ok()?;
        let user = parts.next()?.to_string();
        Some((user, index, exp))
    }

    /// Resolve a valid, non-expired token to `(username, index)`.
    pub fn resolve(&self, token: &str) -> Option<(String, usize)> {
        let (user, index, exp) = self.verify(token)?;
        if now_unix() >= exp {
            return None;
        }
        Some((user, index))
    }

    /// Seconds until the token expires, or `None` if invalid/expired.
    pub fn remaining_secs(&self, token: &str) -> Option<u64> {
        let (_, _, exp) = self.verify(token)?;
        exp.checked_sub(now_unix()).filter(|&r| r > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> ShareStore {
        ShareStore::new(vec![7u8; 64])
    }

    #[test]
    fn round_trips_and_survives_a_fresh_store() {
        let a = store();
        let token = a.create("wushilin", 3, Duration::from_secs(3600));
        // A brand-new store with the SAME key (as after a restart) resolves it.
        let b = store();
        assert_eq!(b.resolve(&token), Some(("wushilin".to_string(), 3)));
        assert!(b.remaining_secs(&token).unwrap() > 3500);
    }

    #[test]
    fn username_with_colons_is_preserved() {
        let s = store();
        let token = s.create("a:b:c", 0, Duration::from_secs(60));
        assert_eq!(s.resolve(&token), Some(("a:b:c".to_string(), 0)));
    }

    #[test]
    fn expired_token_is_rejected() {
        let s = store();
        let token = s.create("u", 0, Duration::from_secs(0));
        assert_eq!(s.resolve(&token), None);
        assert_eq!(s.remaining_secs(&token), None);
    }

    #[test]
    fn tampering_and_wrong_key_are_rejected() {
        let s = store();
        let token = s.create("u", 2, Duration::from_secs(60));
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
}
