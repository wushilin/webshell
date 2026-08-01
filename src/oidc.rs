//! Google sign-in (OpenID Connect authorization code flow with PKCE).
//!
//! Only the identity is wanted: `openid email profile`, which are
//! non-sensitive scopes, so the client needs no Google review or approval —
//! just an OAuth client ID from the Cloud Console.
//!
//! The ID token's signature is deliberately not verified here, and that is
//! sound rather than lazy: we receive it as the response to our own HTTPS POST
//! to Google's token endpoint, authenticated with our client secret. OIDC Core
//! §3.1.3.7 says a token obtained by direct communication with the token
//! endpoint may be validated by TLS instead of its signature. That removes a
//! JWT/JWKS dependency and a key-rotation cache from the login path. It would
//! NOT be safe for the implicit flow, where the token arrives via the browser.

use base64::Engine;
use serde::Deserialize;

use crate::identity::{Identity, Provider};

const AUTH_ENDPOINT: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";
/// Google mints tokens under both spellings; either is legitimate.
const ISSUERS: [&str; 2] = ["https://accounts.google.com", "accounts.google.com"];

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// The per-login secrets that tie a callback to the browser that started it.
/// Held in the caller's pre-auth session, never in a shared map: the cookie is
/// what proves the callback belongs to this browser.
#[derive(Clone, Debug)]
pub struct Flow {
    /// CSRF for the redirect: echoed by Google, compared on return.
    pub state: String,
    /// Replay defence: embedded in the ID token, compared on return.
    pub nonce: String,
    /// PKCE verifier; its S256 hash went out with the authorization request.
    pub verifier: String,
}

impl Flow {
    pub fn new() -> Flow {
        Flow {
            state: crate::config::random_token(24),
            nonce: crate::config::random_token(24),
            // PKCE verifiers are 43–128 chars of unreserved ASCII; 32 random
            // bytes base64url-encoded lands at 43.
            verifier: crate::config::random_token(32),
        }
    }
}

impl Default for Flow {
    fn default() -> Self {
        Self::new()
    }
}

fn s256(verifier: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    B64.encode(hasher.finalize())
}

fn urlencode(s: &str) -> String {
    s.bytes()
        .flat_map(|b| {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
                vec![b as char]
            } else {
                format!("%{b:02X}").chars().collect()
            }
        })
        .collect()
}

/// Where to send the browser to sign in.
pub fn authorize_url(client_id: &str, redirect_uri: &str, flow: &Flow) -> String {
    format!(
        "{AUTH_ENDPOINT}?client_id={}&redirect_uri={}&response_type=code\
         &scope={}&state={}&nonce={}&code_challenge={}&code_challenge_method=S256\
         &access_type=online&prompt=select_account",
        urlencode(client_id),
        urlencode(redirect_uri),
        urlencode("openid email profile"),
        urlencode(&flow.state),
        urlencode(&flow.nonce),
        urlencode(&s256(&flow.verifier)),
    )
}

#[derive(Deserialize)]
struct TokenResponse {
    id_token: String,
}

/// The claims we care about out of the ID token.
#[derive(Deserialize)]
struct Claims {
    iss: String,
    aud: String,
    exp: u64,
    sub: String,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    email_verified: bool,
}

/// A verified Google login.
pub struct Verified {
    pub identity: Identity,
    /// Google's stable subject for this account.
    pub sub: String,
}

/// Exchange the callback code for an ID token and validate it.
pub async fn exchange(
    client: &reqwest::Client,
    client_id: &str,
    client_secret: &str,
    redirect_uri: &str,
    code: &str,
    flow: &Flow,
) -> anyhow::Result<Verified> {
    let response = client
        .post(TOKEN_ENDPOINT)
        .form(&[
            ("code", code),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("redirect_uri", redirect_uri),
            ("grant_type", "authorization_code"),
            ("code_verifier", flow.verifier.as_str()),
        ])
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("reaching Google's token endpoint: {e}"))?;

    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|e| anyhow::anyhow!("reading token response: {e}"))?;
    if !status.is_success() {
        // Google puts a machine-readable reason in the body; it is the only
        // useful thing to log when a login mysteriously fails.
        anyhow::bail!("token endpoint returned {status}: {body}");
    }
    let token: TokenResponse =
        serde_json::from_str(&body).map_err(|e| anyhow::anyhow!("token response: {e}"))?;

    let claims = decode_claims(&token.id_token)?;
    validate(&claims, client_id, flow)?;

    let email = claims
        .email
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("ID token carries no email claim"))?;
    Ok(Verified {
        identity: Identity::new(Provider::Google, email),
        sub: claims.sub,
    })
}

/// Pull the payload out of a JWT. Signature intentionally unchecked — see the
/// module docs for why that is safe on this path.
fn decode_claims(id_token: &str) -> anyhow::Result<Claims> {
    let mut parts = id_token.split('.');
    let (_header, payload) = (
        parts
            .next()
            .ok_or_else(|| anyhow::anyhow!("malformed ID token"))?,
        parts
            .next()
            .ok_or_else(|| anyhow::anyhow!("malformed ID token"))?,
    );
    let raw = B64
        .decode(payload)
        .map_err(|e| anyhow::anyhow!("ID token payload is not base64url: {e}"))?;
    serde_json::from_slice(&raw).map_err(|e| anyhow::anyhow!("ID token claims: {e}"))
}

fn validate(claims: &Claims, client_id: &str, flow: &Flow) -> anyhow::Result<()> {
    if !ISSUERS.contains(&claims.iss.as_str()) {
        anyhow::bail!("ID token issuer {:?} is not Google", claims.iss);
    }
    // Without this an ID token minted for a DIFFERENT application would be
    // accepted — the classic OIDC audience confusion.
    if claims.aud != client_id {
        anyhow::bail!("ID token audience is not this client");
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if claims.exp <= now {
        anyhow::bail!("ID token has expired");
    }
    if claims.nonce.as_deref() != Some(flow.nonce.as_str()) {
        anyhow::bail!("ID token nonce does not match this login attempt");
    }
    // An unverified address proves nothing: without this, anyone could put any
    // address on an account and match the allowlist.
    if !claims.email_verified {
        anyhow::bail!("Google has not verified this account's email address");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims(f: &Flow) -> Claims {
        Claims {
            iss: "https://accounts.google.com".into(),
            aud: "client-abc".into(),
            exp: u64::MAX,
            sub: "sub-1".into(),
            nonce: Some(f.nonce.clone()),
            email: Some("a@gmail.com".into()),
            email_verified: true,
        }
    }

    #[test]
    fn pkce_challenge_matches_the_rfc_example() {
        // RFC 7636 Appendix B.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(
            s256(verifier),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn a_valid_token_passes() {
        let f = Flow::new();
        assert!(validate(&claims(&f), "client-abc", &f).is_ok());
    }

    #[test]
    fn a_token_for_another_client_is_rejected() {
        let f = Flow::new();
        assert!(validate(&claims(&f), "someone-elses-client", &f).is_err());
    }

    #[test]
    fn a_replayed_or_foreign_nonce_is_rejected() {
        let f = Flow::new();
        let mut c = claims(&f);
        c.nonce = Some("a different login".into());
        assert!(validate(&c, "client-abc", &f).is_err());
        c.nonce = None;
        assert!(validate(&c, "client-abc", &f).is_err());
    }

    #[test]
    fn unverified_email_expired_and_wrong_issuer_are_rejected() {
        let f = Flow::new();
        let mut c = claims(&f);
        c.email_verified = false;
        assert!(validate(&c, "client-abc", &f).is_err());

        let mut c = claims(&f);
        c.exp = 0;
        assert!(validate(&c, "client-abc", &f).is_err());

        let mut c = claims(&f);
        c.iss = "https://evil.example".into();
        assert!(validate(&c, "client-abc", &f).is_err());
    }

    #[test]
    fn authorize_url_carries_the_flow_and_escapes_the_redirect() {
        let f = Flow::new();
        let url = authorize_url("id-1", "https://h.example/webshell/oauth/callback", &f);
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains(&format!("state={}", f.state)));
        assert!(url.contains("redirect_uri=https%3A%2F%2Fh.example%2Fwebshell%2Foauth%2Fcallback"));
        assert!(url.contains("scope=openid%20email%20profile"));
    }
}
