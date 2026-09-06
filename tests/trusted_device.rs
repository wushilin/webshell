//! End-to-end checks for "remember this device".
//!
//! The property under test is the one that makes the feature defensible: a
//! trusted browser skips the *authenticator code* and nothing else. If a trust
//! cookie ever let a bad password through, the second factor would have been
//! traded for a downgrade of the first.
//!
//! These run against a real server started from a config file, because the
//! `simple` mode the other integration tests use has MFA switched off.

use std::process::{Child, Command, Stdio};
use std::time::Duration;

use hmac::{Hmac, Mac};
use reqwest::header::{COOKIE, LOCATION, SET_COOKIE};
use reqwest::{Client, StatusCode};
use sha1::Sha1;
use tokio::time::{sleep, Instant};

/// The RFC 4226 test key, base32-encoded as an authenticator would hold it.
const SEED_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const SEED_RAW: &[u8] = b"12345678901234567890";
const ENROLLED_AT: u64 = 1_700_000_000;
const PASSWORD: &str = "test-password";

/// The code an authenticator holding `SEED_RAW` would be showing right now.
/// Deliberately a reimplementation rather than a call into the server's own
/// TOTP module — a test that shares its subject's arithmetic proves less, and
/// a binary crate's internals are not importable anyway.
fn current_code() -> String {
    let counter = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / 30;
    let mut mac = Hmac::<Sha1>::new_from_slice(SEED_RAW).unwrap();
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = (digest[19] & 0x0f) as usize;
    let value = (u32::from_be_bytes(digest[offset..offset + 4].try_into().unwrap()) & 0x7fff_ffff)
        % 1_000_000;
    format!("{value:06}")
}

/// Seconds left in the current TOTP step. Used to avoid starting a flow that
/// would straddle a step boundary and fail for reasons that are not the code
/// under test.
fn secs_left_in_step() -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    30 - (now % 30)
}

struct TestServer {
    child: Child,
    http: String,
    #[allow(dead_code)]
    dir: std::path::PathBuf,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl TestServer {
    async fn start(name: &str, remember_device: bool) -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let dir = std::env::temp_dir().join(format!("webshell-td-{name}-{port}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // A fixed cookie key, so the trust cookie the server signs stays
        // verifiable across the several clients one test drives.
        const COOKIE_KEY: &str = "d2Vic2hlbGwtdHJ1c3RlZC1kZXZpY2UtaW50ZWdyYXRpb24tdGVzdC1jb29raWUta2V5LTAxMjM0NTY3ODlhYg==";
        std::fs::write(
            dir.join("config.toml"),
            format!(
                r#"[network]
bind = "127.0.0.1:{port}"

[auth]
users = ["local:integration"]
login_methods = ["local"]
session_ttl_secs = 3600
secret_base64 = "{COOKIE_KEY}"

[mfa]
required = true
enrollment_path = "enrollment.toml"
remember_device = {remember_device}
remember_device_days = 30
device_path = "devices.toml"

[local_passwords]
"local:integration" = "{PASSWORD}"
"#
            ),
        )
        .unwrap();

        // Pre-enrolled, so the flow under test is verification rather than
        // enrollment — the checkbox only exists on the verify screen.
        std::fs::write(
            dir.join("enrollment.toml"),
            format!(
                "[[enrollment]]\nid = \"local:integration\"\nmfa_secret = \"{SEED_B32}\"\n\
                 enrolled_at = {ENROLLED_AT}\n"
            ),
        )
        .unwrap();

        let child = Command::new(env!("CARGO_BIN_EXE_webshell"))
            .arg("run")
            .arg("-c")
            .arg(dir.join("config.toml"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start test server");

        let server = TestServer {
            child,
            http: format!("http://127.0.0.1:{port}"),
            dir,
        };
        let client = http_client();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if client
                .get(format!("{}/webshell/login", server.http))
                .send()
                .await
                .is_ok()
            {
                return server;
            }
            assert!(Instant::now() < deadline, "test server did not start");
            sleep(Duration::from_millis(25)).await;
        }
    }

    /// Submit the password. Returns `(Location, session cookie)`.
    async fn password_step(
        &self,
        password: &str,
        device_cookie: Option<&str>,
    ) -> (String, String, reqwest::Response) {
        let client = http_client();
        let page = client
            .get(format!("{}/webshell/login", self.http))
            .send()
            .await
            .unwrap();
        let mut cookie = response_cookie(&page, "webshell_sid").expect("a session cookie");
        let csrf = hidden_value(&page.text().await.unwrap(), "csrf");
        if let Some(td) = device_cookie {
            cookie = format!("{cookie}; {td}");
        }
        let response = client
            .post(format!("{}/webshell/login/local", self.http))
            .header(COOKIE, &cookie)
            .form(&[
                ("csrf", csrf.as_str()),
                ("username", "integration"),
                ("password", password),
            ])
            .send()
            .await
            .unwrap();
        let location = response
            .headers()
            .get(LOCATION)
            .map(|v| v.to_str().unwrap().to_string())
            .unwrap_or_default();
        let session = response_cookie(&response, "webshell_sid").unwrap_or(cookie);
        (location, session, response)
    }
}

/// Cookies are driven by hand throughout: the tests care about exactly which
/// cookie is presented on which request, which an automatic jar would hide.
/// Redirects are not followed, so the `Location` of each step is observable.
fn http_client() -> Client {
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

/// The `name=value` pair for one cookie in a response, ready to send back.
fn response_cookie(response: &reqwest::Response, name: &str) -> Option<String> {
    response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|v| v.starts_with(&format!("{name}=")))
        .and_then(|v| v.split(';').next())
        .filter(|v| !v.ends_with('='))
        .map(|v| v.to_string())
}

fn hidden_value(html: &str, name: &str) -> String {
    let needle = format!("name=\"{name}\" value=\"");
    let start = html.find(&needle).expect("hidden field") + needle.len();
    html[start..].split('"').next().unwrap().to_string()
}

/// Password, then code, ticking "remember this device". Returns the trust
/// cookie the server set.
async fn login_and_remember(server: &TestServer) -> String {
    let (location, session, _) = server.password_step(PASSWORD, None).await;
    assert_eq!(location, "/webshell/mfa", "password alone must not log in");

    let client = http_client();
    let page = client
        .get(format!("{}/webshell/mfa", server.http))
        .header(COOKIE, &session)
        .send()
        .await
        .unwrap();
    let body = page.text().await.unwrap();
    assert!(
        body.contains("name=\"remember\""),
        "the verify page should offer the checkbox when the feature is on"
    );
    let csrf = hidden_value(&body, "csrf");

    let response = client
        .post(format!("{}/webshell/mfa", server.http))
        .header(COOKIE, &session)
        .form(&[
            ("csrf", csrf.as_str()),
            ("otp", current_code().as_str()),
            ("remember", "1"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers()[LOCATION], "/webshell/private/");
    response_cookie(&response, "webshell_td").expect("a trusted-device cookie")
}

#[tokio::test]
async fn a_trusted_device_skips_the_code_but_never_the_password() {
    // Don't start a flow that would cross a TOTP step boundary mid-test.
    if secs_left_in_step() < 10 {
        sleep(Duration::from_secs(secs_left_in_step() + 1)).await;
    }
    let server = TestServer::start("skip", true).await;
    let td = login_and_remember(&server).await;

    // The whole point: a fresh session on this browser goes straight in.
    let (location, _, _) = server.password_step(PASSWORD, Some(&td)).await;
    assert_eq!(
        location, "/webshell/private/",
        "a trusted device should not be asked for a code"
    );

    // And the part that makes that safe — the first factor still runs.
    let (location, _, response) = server.password_step("wrong-password", Some(&td)).await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "a wrong password re-renders the login page"
    );
    assert_ne!(
        location, "/webshell/private/",
        "a trust cookie must never stand in for the password"
    );

    // A browser without the cookie is challenged as before.
    let (location, _, _) = server.password_step(PASSWORD, None).await;
    assert_eq!(location, "/webshell/mfa");
}

#[tokio::test]
async fn revoking_the_device_brings_the_code_back() {
    if secs_left_in_step() < 10 {
        sleep(Duration::from_secs(secs_left_in_step() + 1)).await;
    }
    let server = TestServer::start("revoke", true).await;
    let td = login_and_remember(&server).await;

    // Log in on the trusted browser, then revoke it from inside the session.
    let (location, session, _) = server.password_step(PASSWORD, Some(&td)).await;
    assert_eq!(location, "/webshell/private/");
    let both = format!("{session}; {td}");

    let client = http_client();
    let listed = client
        .get(format!("{}/webshell/private/api/devices", server.http))
        .header(COOKIE, &both)
        .send()
        .await
        .unwrap();
    assert_eq!(listed.status(), StatusCode::OK);
    let body: serde_json::Value = listed.json().await.unwrap();
    assert_eq!(body["enabled"], true);
    let devices = body["devices"].as_array().unwrap();
    assert_eq!(devices.len(), 1, "exactly the browser we just trusted");
    assert_eq!(
        devices[0]["current"], true,
        "the caller's own browser is flagged"
    );
    // The listing describes devices; it never hands one out.
    assert!(
        !listed_text(&body).contains(td.trim_start_matches("webshell_td=")),
        "the API must not echo the cookie value"
    );

    let page = client
        .get(format!("{}/webshell/private/", server.http))
        .header(COOKIE, &both)
        .send()
        .await
        .unwrap();
    let csrf = hidden_value(&page.text().await.unwrap(), "csrf");

    let revoked = client
        .post(format!(
            "{}/webshell/private/api/device/revoke",
            server.http
        ))
        .header(COOKIE, &both)
        .form(&[
            ("csrf", csrf.as_str()),
            ("device_id", devices[0]["id"].as_str().unwrap()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(revoked.status(), StatusCode::NO_CONTENT);

    // Same cookie, no longer trusted.
    let (location, _, _) = server.password_step(PASSWORD, Some(&td)).await;
    assert_eq!(
        location, "/webshell/mfa",
        "a revoked device is challenged again"
    );
}

#[tokio::test]
async fn the_option_is_absent_when_the_feature_is_off() {
    let server = TestServer::start("off", false).await;
    let (location, session, _) = server.password_step(PASSWORD, None).await;
    assert_eq!(location, "/webshell/mfa");

    let body = http_client()
        .get(format!("{}/webshell/mfa", server.http))
        .header(COOKIE, &session)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        !body.contains("name=\"remember\""),
        "a disabled option should be absent from the page, not merely hidden"
    );
}

fn listed_text(v: &serde_json::Value) -> String {
    serde_json::to_string(v).unwrap()
}
