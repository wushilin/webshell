//! Who is allowed to log in, and how that is written down.
//!
//! An identity is `provider:subject` — e.g. `google:someone@gmail.com`. The
//! provider prefix is load-bearing rather than decorative: the same email can
//! name different people at different issuers (an Apple ID may *be* a Gmail
//! address), so an unprefixed allowlist would let a weaker account stand in for
//! a stronger one. Only Google is implemented today; the other names are
//! recognised so a config written for them fails loudly instead of silently
//! denying access.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Issuers the identity format knows about. Recognising a provider is not the
/// same as supporting it — see `Provider::supported`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum Provider {
    /// A system account on this host, verified by its password.
    Local,
    Google,
    Microsoft,
    Apple,
}

impl Provider {
    pub fn as_str(self) -> &'static str {
        match self {
            Provider::Local => "local",
            Provider::Google => "google",
            Provider::Microsoft => "microsoft",
            Provider::Apple => "apple",
        }
    }

    /// Whether webshell can actually authenticate against this issuer.
    pub fn supported(self) -> bool {
        matches!(self, Provider::Local | Provider::Google)
    }

    fn parse(s: &str) -> Option<Provider> {
        match s {
            "local" => Some(Provider::Local),
            "google" => Some(Provider::Google),
            "microsoft" => Some(Provider::Microsoft),
            "apple" => Some(Provider::Apple),
            _ => None,
        }
    }
}

/// A login identity, always stored and compared in normalized form.
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct Identity {
    provider: Provider,
    /// The provider's handle for this person: an email for the social
    /// providers, a system account name for `local`. Lowercased, so a config
    /// entry cannot miss by capitalisation.
    subject: String,
}

impl Identity {
    pub fn new(provider: Provider, subject: &str) -> Identity {
        Identity {
            provider,
            subject: subject.trim().to_lowercase(),
        }
    }

    pub fn provider(&self) -> Provider {
        self.provider
    }

    pub fn subject(&self) -> &str {
        &self.subject
    }
}

impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.provider.as_str(), self.subject)
    }
}

impl FromStr for Identity {
    type Err = String;

    fn from_str(s: &str) -> Result<Identity, String> {
        let s = s.trim();
        // split_once, not splitn: an email cannot contain ':' but a future
        // provider's subject might, and only the FIRST colon separates.
        let Some((provider, subject)) = s.split_once(':') else {
            return Err(format!(
                "{s:?} is missing a provider prefix — write it as \
                 \"google:you@example.com\""
            ));
        };
        let provider = provider.trim().to_lowercase();
        let Some(provider) = Provider::parse(&provider) else {
            return Err(format!(
                "unknown provider {provider:?} in {s:?} — expected one of \
                 local, google, microsoft, apple"
            ));
        };
        if subject.trim().is_empty() {
            return Err(format!("{s:?} has an empty subject after the prefix"));
        }
        Ok(Identity::new(provider, subject))
    }
}

// Serialized as the flat "google:you@example.com" string, so config and
// enrollment files stay readable and hand-editable.
impl Serialize for Identity {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Identity {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Identity, D::Error> {
        let raw = String::deserialize(d)?;
        raw.parse().map_err(serde::de::Error::custom)
    }
}

/// The allowlist: exactly who may log in. Rejecting an unusable entry at load
/// time is the whole point — a typo like `gogle:` would otherwise become a
/// permanent, silent access denial that looks like a broken login.
pub fn validate(users: &[Identity]) -> anyhow::Result<()> {
    if users.is_empty() {
        anyhow::bail!(
            "no users configured; nobody can log in. Add at least one, e.g. \
             users = [\"google:you@example.com\"]"
        );
    }
    for user in users {
        if !user.provider().supported() {
            anyhow::bail!(
                "user {user} uses provider {:?}, which is recognised but not \
                 implemented yet; only google works today",
                user.provider().as_str()
            );
        }
    }
    // A duplicate is harmless at runtime but always a mistake worth naming.
    for (i, user) in users.iter().enumerate() {
        if users[..i].contains(user) {
            anyhow::bail!("user {user} is listed more than once");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(s: &str) -> Identity {
        s.parse().unwrap()
    }

    #[test]
    fn round_trips_through_its_string_form() {
        let parsed = id("google:someone@gmail.com");
        assert_eq!(parsed.provider(), Provider::Google);
        assert_eq!(parsed.subject(), "someone@gmail.com");
        assert_eq!(parsed.to_string(), "google:someone@gmail.com");
    }

    #[test]
    fn case_and_padding_are_normalized() {
        // Config written by hand must not miss by capitalisation.
        assert_eq!(
            id("  Google:Someone@Gmail.COM  "),
            id("google:someone@gmail.com")
        );
    }

    #[test]
    fn the_same_address_at_two_providers_is_two_identities() {
        // The reason the prefix exists: an Apple ID can be a Gmail address.
        assert_ne!(id("google:a@gmail.com"), id("apple:a@gmail.com"));
    }

    #[test]
    fn malformed_entries_are_rejected_with_a_usable_message() {
        assert!("someone@gmail.com".parse::<Identity>().is_err());
        assert!("gogle:someone@gmail.com".parse::<Identity>().is_err());
        assert!("google:".parse::<Identity>().is_err());
        assert!("google:   ".parse::<Identity>().is_err());
    }

    #[test]
    fn only_the_first_colon_separates() {
        let parsed = id("google:weird:subject");
        assert_eq!(parsed.subject(), "weird:subject");
    }

    #[test]
    fn validate_rejects_empty_unsupported_and_duplicate() {
        assert!(validate(&[]).is_err());
        assert!(validate(&[id("apple:a@gmail.com")]).is_err());
        assert!(validate(&[id("google:a@gmail.com"), id("google:A@gmail.com")]).is_err());
        assert!(validate(&[id("google:a@gmail.com"), id("google:b@gmail.com")]).is_ok());
    }
}
