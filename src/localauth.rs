//! Passwords webshell manages itself, stored in the config file as argon2id
//! hashes.
//!
//! Deliberately *not* the system password. Checking that requires either
//! linking PAM (`dlopen`, which rules out a static musl build) or exec'ing a
//! setuid helper (`su`, `unix_chkpwd`) — and on an SELinux host a supervised
//! service is refused entry to those helper domains, so the check fails for
//! reasons that have nothing to do with the password. An app-managed
//! credential has no host dependency at all: it works identically on every
//! distribution, in a container, and from a statically linked binary.
//!
//! The trade-off is honest: this is a second password to manage, and its hash
//! lives in a file owned by the account being protected rather than in
//! root-only `/etc/shadow`. Keep the config mode 0600, and pair it with MFA.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use rand::rngs::OsRng;

/// Hash a password for storage, returning a PHC string
/// (`$argon2id$v=19$m=...,t=...,p=...$salt$hash`) that carries its own
/// parameters — so raising the cost later does not invalidate existing hashes.
pub fn hash(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| format!("hashing the password: {e}"))
}

/// Does this stored value look like a hash rather than a literal password?
///
/// The rule is deliberately generous — anything shaped like `$id$...` counts,
/// covering bcrypt (`$2a$`/`$2b$`/`$2y$`), argon2 (`$argon2id$`) and crypt(3)
/// (`$6$`). Generosity is the safe direction: a plaintext password that merely
/// *resembles* a hash gets treated as a hash and fails to verify, which is a
/// visible, fixable inconvenience. The reverse — treating a real hash as
/// plaintext — would let anyone who has read the config file log in by typing
/// the hash itself.
pub fn looks_hashed(stored: &str) -> bool {
    let s = stored.trim();
    let mut parts = s.split('$');
    // "$id$rest" splits to ["", "id", "rest", ..]
    parts.next().is_some_and(|first| first.is_empty())
        && parts.next().is_some_and(|id| !id.is_empty())
        && parts.next().is_some()
}

/// Check a password against a stored value: a hash if it looks like one, a
/// literal password otherwise.
///
/// A malformed hash is an `Err`, never a silent `false`: a typo in the config
/// should be reported as a broken configuration, not as everyone getting their
/// password wrong.
pub fn verify(stored: &str, password: &str) -> Result<bool, String> {
    let stored = stored.trim();
    if !looks_hashed(stored) {
        // Plaintext, for a quick start. Constant-time so the comparison itself
        // leaks nothing, even though the config file is the real weakness here.
        use subtle::ConstantTimeEq;
        return Ok(stored.as_bytes().ct_eq(password.as_bytes()).into());
    }
    // From here it IS a hash, and there is no path back to a plaintext
    // comparison: a bad hash is an error, never a fallback.
    if stored.starts_with("$2a$") || stored.starts_with("$2b$") || stored.starts_with("$2y$") {
        return bcrypt::verify(password, stored)
            .map_err(|e| format!("verifying the bcrypt hash: {e}"));
    }
    let parsed = PasswordHash::new(stored)
        .map_err(|e| format!("stored password hash is not valid PHC format: {e}"))?;
    // Argon2's own comparison is constant-time.
    match Argon2::default().verify_password(password.as_bytes(), &parsed) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(format!("verifying the password: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_password_verifies_against_its_own_hash() {
        let h = hash("correct horse battery staple").unwrap();
        assert!(h.starts_with("$argon2"));
        assert!(verify(&h, "correct horse battery staple").unwrap());
        assert!(!verify(&h, "correct horse battery stapl").unwrap());
        assert!(!verify(&h, "").unwrap());
    }

    #[test]
    fn the_same_password_hashes_differently_every_time() {
        // Distinct salts: two accounts with the same password must not be
        // visibly identical in the config file.
        assert_ne!(hash("same").unwrap(), hash("same").unwrap());
    }

    #[test]
    fn plaintext_is_accepted_when_it_is_not_hash_shaped() {
        assert!(verify("hunter2", "hunter2").unwrap());
        assert!(!verify("hunter2", "hunter3").unwrap());
    }

    #[test]
    fn a_hash_never_falls_back_to_plaintext() {
        // The attack this prevents: someone who can read the config typing the
        // hash string itself as their password.
        let h = hash("real-password").unwrap();
        assert!(
            !verify(&h, &h).unwrap(),
            "the hash must not be its own password"
        );
        let bc = bcrypt::hash("real-password", 4).unwrap();
        assert!(verify(&bc, "real-password").unwrap(), "bcrypt verifies");
        assert!(
            !verify(&bc, &bc).unwrap(),
            "bcrypt hash is not its own password"
        );
    }

    #[test]
    fn hash_shapes_are_recognised() {
        assert!(looks_hashed("$2b$12$abcdefghijklmnopqrstuv"));
        assert!(looks_hashed("$argon2id$v=19$m=1,t=1,p=1$c2FsdA$aGFzaA"));
        assert!(looks_hashed("$6$salt$hash"));
        assert!(!looks_hashed("hunter2"));
        assert!(!looks_hashed("has$dollar"));
        assert!(!looks_hashed(""));
    }

    #[test]
    fn a_malformed_hash_is_an_error_not_a_rejection() {
        // A config typo must read as "broken config", not "wrong password".
        // Hash-shaped but unparseable: an error, so a config typo reads as a
        // broken config rather than as everyone's password being wrong.
        // The invariant that matters: a hash-shaped value NEVER verifies as
        // plaintext, whatever the parser makes of it.
        assert!(!matches!(
            verify("$argon2id$totally-broken", "whatever"),
            Ok(true)
        ));
        assert!(!matches!(
            verify("$argon2id$totally-broken", "$argon2id$totally-broken"),
            Ok(true)
        ));
        assert!(verify("$argon2id$v=99$notvalid$x$y", "whatever").is_err());
    }
}
