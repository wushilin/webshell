# Let's Encrypt Auto-Certificates Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Opt-in HTTPS serving with automatically obtained and renewed Let's Encrypt certificates via TLS-ALPN-01, all certificate events logged; default behavior unchanged.

**Architecture:** A new `[certs]` config table feeds a new `src/certs.rs` module that validates the settings into an `Option<TlsConfig>` at startup (refusing to start with a clear reason on bad combinations). When present, `serve()` swaps `axum::serve` for `axum_server` with `rustls-acme`'s ACME acceptor; a spawned task polls the ACME state stream and logs every event.

**Tech Stack:** Rust, axum 0.7, `rustls-acme` 0.14 (`axum` + `ring` features), `axum-server` 0.7, rustls 0.23 (already in tree via reqwest, ring provider).

**Spec:** `docs/superpowers/specs/2026-08-05-lets-encrypt-design.md`

## Global Constraints

- Default behavior (certs disabled) must be byte-for-byte identical to today: plain HTTP via `axum::serve`, `127.0.0.1:8080` default bind untouched.
- `rustls-acme` must be `version = "0.14"`, `default-features = false`, `features = ["axum", "ring", "tls12", "webpki-roots"]` — **never** the default `aws-lc-rs` (its C/cmake build breaks the cargo-zigbuild cross-link in `build-x86_64.sh`).
- Startup refusals use `eprintln!("startup error: …")` + `std::process::exit(1)` — never `panic!`.
- In `Settings`, the `certs` field must be declared **before** `local_passwords` (a TOML table absorbs every key after it; `local_passwords` must stay last).
- Comment style: comments state constraints the code can't show, matching the existing codebase voice. No "added for feature X" comments.
- Simple mode (`webshell simple`) always runs with certs disabled (`tls: None`).
- Rust edition/toolchain: whatever `cargo build` already uses; no toolchain changes.

---

### Task 1: `[certs]` settings table

**Files:**
- Modify: `src/config.rs` (Settings struct ~line 17-28, new struct after `Sharing` ~line 175, tests ~line 642)

**Interfaces:**
- Produces: `pub struct Certs { pub lets_encrypt_enabled: bool, pub store_dir: String, pub lets_encrypt_staging: bool, pub contact_email: Option<String> }` as `Settings::certs`, with defaults `false` / `"certs"` / `false` / `None`. Task 2 reads these fields.

- [ ] **Step 1: Write the failing test**

In `src/config.rs`, extend the existing `sample_config_documents_login_cmd_and_envs`-style tests with a new test in `mod tests`:

```rust
#[test]
fn sample_config_documents_certs() {
    let sample = Settings::sample_toml();
    assert!(sample.contains("[certs]"));
    assert!(sample.contains("lets_encrypt_enabled = false"));
    assert!(sample.contains("store_dir = \"certs\""));
    assert!(sample.contains("lets_encrypt_staging = false"));
    // [certs] must serialize before [local_passwords] — the TOML
    // table-absorbs-what-follows trap.
    let certs_pos = sample.find("[certs]").unwrap();
    assert!(Settings::default().local_passwords.is_empty() || certs_pos < sample.find("[local_passwords]").unwrap_or(usize::MAX));
}

#[test]
fn certs_table_parses() {
    let s: Settings = toml::from_str(
        "[certs]\nlets_encrypt_enabled = true\nstore_dir = \"/var/lib/webshell/certs\"\ncontact_email = \"ops@example.com\"\n",
    )
    .unwrap();
    assert!(s.certs.lets_encrypt_enabled);
    assert_eq!(s.certs.store_dir, "/var/lib/webshell/certs");
    assert!(!s.certs.lets_encrypt_staging);
    assert_eq!(s.certs.contact_email.as_deref(), Some("ops@example.com"));
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib config::tests::sample_config_documents_certs config::tests::certs_table_parses 2>&1 | tail -20`
(If the crate is a plain binary, `cargo test certs_table` works too.)
Expected: FAIL to compile — `Settings` has no field `certs`.

- [ ] **Step 3: Add the Certs struct and Settings field**

In `src/config.rs`, after the `Sharing` impl (~line 175), add:

```rust
/// Automatic TLS: obtain and renew a Let's Encrypt certificate in-process.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Certs {
    /// Master switch. When true, webshell terminates TLS itself with an
    /// automatically obtained and renewed Let's Encrypt certificate, and the
    /// bind/public_base_url combination is validated at startup.
    pub lets_encrypt_enabled: bool,
    /// ACME account key and certificate cache. Relative paths resolve
    /// against the config file's directory.
    pub store_dir: String,
    /// Use the Let's Encrypt staging endpoint: untrusted certificates but
    /// generous rate limits. For first-time setup on a new host — a failed
    /// production attempt counts against strict per-domain limits.
    pub lets_encrypt_staging: bool,
    /// Optional ACME account contact. Let's Encrypt mails expiry warnings
    /// here if renewal silently breaks.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact_email: Option<String>,
}

impl Default for Certs {
    fn default() -> Self {
        Certs {
            lets_encrypt_enabled: false,
            store_dir: "certs".into(),
            lets_encrypt_staging: false,
            contact_email: None,
        }
    }
}
```

In `Settings` (~line 17), add the field **between `sharing` and `local_passwords`** (order is load-bearing — see the comment already on `local_passwords`):

```rust
    pub sharing: Sharing,
    pub certs: Certs,
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test 2>&1 | tail -5`
Expected: all tests PASS (including the two new ones and every pre-existing test).

- [ ] **Step 5: Commit**

```bash
git add src/config.rs
git commit -m "Add [certs] config table for Let's Encrypt settings"
```

---

### Task 2: `certs::validate` — startup validation into `TlsConfig`

**Files:**
- Create: `src/certs.rs`
- Modify: `src/main.rs:1-11` (add `mod certs;` to the mod list, alphabetical: after `mod config;`)

**Interfaces:**
- Consumes: `Settings.certs` fields from Task 1; `Settings.network.{bind, public_base_url}`.
- Produces:
  - `#[derive(Clone, Debug)] pub struct TlsConfig { pub hostname: String, pub store_dir: PathBuf, pub staging: bool, pub contact_email: Option<String> }`
  - `pub fn validate(s: &Settings, config_dir: &Path) -> anyhow::Result<Option<TlsConfig>>`
  - Task 3 stores `Option<TlsConfig>` on `Config`; Task 4 consumes the fields.

- [ ] **Step 1: Create `src/certs.rs` with the failing tests**

Write the module skeleton with tests first (functions `todo!()`d so tests compile but fail):

```rust
//! Automatic TLS via Let's Encrypt (rustls-acme, TLS-ALPN-01).
//!
//! Validation lives here rather than in `Config::from_settings` because a bad
//! `[certs]` combination must refuse startup with a reason, and
//! `from_settings` is deliberately infallible.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use crate::config::Settings;

/// Fully-validated TLS runtime configuration. Existence of a value means
/// every startup precondition already held.
#[derive(Clone, Debug)]
pub struct TlsConfig {
    /// The one certificate hostname, derived from `network.public_base_url`.
    pub hostname: String,
    /// ACME account key + certificate cache directory, absolute.
    pub store_dir: PathBuf,
    /// Let's Encrypt staging endpoint instead of production.
    pub staging: bool,
    /// ACME account contact, without the `mailto:` prefix.
    pub contact_email: Option<String>,
}

/// Decide whether TLS mode is on, and refuse plainly-wrong combinations.
///
/// TLS-ALPN-01 means Let's Encrypt validates by connecting to port 443 of the
/// public hostname and speaking TLS to *this* listener — so the bind must be
/// a reachable :443, and the hostname must be a real DNS name.
pub fn validate(s: &Settings, config_dir: &Path) -> anyhow::Result<Option<TlsConfig>> {
    if !s.certs.lets_encrypt_enabled {
        return Ok(None);
    }
    let hostname = public_hostname(s.network.public_base_url.as_deref())?;
    check_bind(&s.network.bind)?;
    let store_dir = {
        let p = PathBuf::from(&s.certs.store_dir);
        if p.is_absolute() {
            p
        } else {
            config_dir.join(p)
        }
    };
    let contact_email = s
        .certs
        .contact_email
        .as_deref()
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .map(str::to_string);
    Ok(Some(TlsConfig {
        hostname,
        store_dir,
        staging: s.certs.lets_encrypt_staging,
        contact_email,
    }))
}

/// The certificate hostname comes from `public_base_url` — one source of
/// truth, like the Google redirect URI. It must be an https DNS name:
/// Let's Encrypt does not issue for IPs or `localhost`.
fn public_hostname(base: Option<&str>) -> anyhow::Result<String> {
    let Some(base) = base else {
        anyhow::bail!(
            "certs.lets_encrypt_enabled requires network.public_base_url — \
             the certificate hostname is derived from it"
        );
    };
    let rest = base.trim().strip_prefix("https://").ok_or_else(|| {
        anyhow::anyhow!(
            "network.public_base_url must be https:// when Let's Encrypt is \
             enabled, got {base:?}"
        )
    })?;
    let authority = rest.split('/').next().unwrap_or("");
    let host = match authority.rsplit_once(':') {
        Some((h, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => {
            if port != "443" {
                anyhow::bail!(
                    "network.public_base_url must use the default https port \
                     when Let's Encrypt is enabled (the certificate listener \
                     is :443), got :{port}"
                );
            }
            h
        }
        _ => authority,
    };
    if host.is_empty() {
        anyhow::bail!("network.public_base_url {base:?} has no hostname");
    }
    if host.starts_with('[') || host.parse::<IpAddr>().is_ok() {
        anyhow::bail!(
            "network.public_base_url must name a DNS hostname when Let's \
             Encrypt is enabled — certificates are not issued for IP \
             addresses (got {host:?})"
        );
    }
    if host.eq_ignore_ascii_case("localhost") {
        anyhow::bail!(
            "network.public_base_url must name a public DNS hostname when \
             Let's Encrypt is enabled, not localhost"
        );
    }
    Ok(host.to_ascii_lowercase())
}

/// The listener itself is the challenge responder, so the bind must be the
/// port Let's Encrypt connects to (443) on an externally-reachable address.
fn check_bind(bind: &str) -> anyhow::Result<()> {
    let addr: SocketAddr = bind.parse().map_err(|_| {
        anyhow::anyhow!(
            "network.bind {bind:?} must be an IP:port address when Let's \
             Encrypt is enabled, e.g. \"0.0.0.0:443\" or \"[::]:443\""
        )
    })?;
    if addr.port() != 443 {
        anyhow::bail!(
            "network.bind must use port 443 when Let's Encrypt is enabled — \
             TLS-ALPN-01 validation connects to port 443 of the public \
             hostname (got port {})",
            addr.port()
        );
    }
    if addr.ip().is_loopback() {
        anyhow::bail!(
            "network.bind {bind:?} is loopback — Let's Encrypt must be able \
             to reach this listener; bind 0.0.0.0:443, [::]:443 or a public IP"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Settings;

    fn enabled(bind: &str, base: Option<&str>) -> Settings {
        let mut s = Settings::default();
        s.certs.lets_encrypt_enabled = true;
        s.network.bind = bind.into();
        s.network.public_base_url = base.map(Into::into);
        s
    }

    const BASE: Option<&str> = Some("https://shell.example.com");
    const DIR: &str = "/etc/webshell";

    #[test]
    fn disabled_is_none_and_checks_nothing() {
        // Garbage bind and no base URL: irrelevant while the switch is off.
        let mut s = enabled("not-an-addr", None);
        s.certs.lets_encrypt_enabled = false;
        assert!(validate(&s, Path::new(DIR)).unwrap().is_none());
    }

    #[test]
    fn valid_binds_pass() {
        for bind in ["0.0.0.0:443", "[::]:443", "203.0.113.5:443"] {
            let tls = validate(&enabled(bind, BASE), Path::new(DIR))
                .unwrap()
                .unwrap();
            assert_eq!(tls.hostname, "shell.example.com");
        }
    }

    #[test]
    fn bad_binds_are_refused() {
        for bind in ["127.0.0.1:443", "[::1]:443", "0.0.0.0:8443", "localhost:443"] {
            let err = validate(&enabled(bind, BASE), Path::new(DIR)).unwrap_err();
            assert!(err.to_string().contains("network.bind"), "{bind}: {err}");
        }
    }

    #[test]
    fn hostname_is_derived_and_validated() {
        // Trailing slash / path and an explicit :443 are all fine.
        for base in [
            "https://shell.example.com/",
            "https://shell.example.com:443",
            "https://Shell.Example.Com/webshell",
        ] {
            let tls = validate(&enabled("0.0.0.0:443", Some(base)), Path::new(DIR))
                .unwrap()
                .unwrap();
            assert_eq!(tls.hostname, "shell.example.com", "{base}");
        }
        for base in [
            "http://shell.example.com",  // not https
            "https://203.0.113.5",       // IP literal
            "https://[2001:db8::1]",     // IPv6 literal
            "https://localhost",         // not public
            "https://shell.example.com:8443", // non-default port
            "https://",                  // no host
        ] {
            assert!(
                validate(&enabled("0.0.0.0:443", Some(base)), Path::new(DIR)).is_err(),
                "{base} should be refused"
            );
        }
        // Missing entirely.
        assert!(validate(&enabled("0.0.0.0:443", None), Path::new(DIR)).is_err());
    }

    #[test]
    fn store_dir_resolves_beside_the_config() {
        let tls = validate(&enabled("0.0.0.0:443", BASE), Path::new(DIR))
            .unwrap()
            .unwrap();
        assert_eq!(tls.store_dir, Path::new("/etc/webshell/certs"));

        let mut s = enabled("0.0.0.0:443", BASE);
        s.certs.store_dir = "/var/lib/webshell/certs".into();
        let tls = validate(&s, Path::new(DIR)).unwrap().unwrap();
        assert_eq!(tls.store_dir, Path::new("/var/lib/webshell/certs"));
    }

    #[test]
    fn contact_email_passes_through_and_blank_is_none() {
        let mut s = enabled("0.0.0.0:443", BASE);
        s.certs.contact_email = Some("ops@example.com".into());
        let tls = validate(&s, Path::new(DIR)).unwrap().unwrap();
        assert_eq!(tls.contact_email.as_deref(), Some("ops@example.com"));

        s.certs.contact_email = Some("   ".into());
        let tls = validate(&s, Path::new(DIR)).unwrap().unwrap();
        assert_eq!(tls.contact_email, None);
    }
}
```

Add `mod certs;` to `src/main.rs` line 2 (after `mod config;` — the list is alphabetical).

Note: write the real implementation directly as above (the functions are small and the tests were designed first); the TDD cycle here is at file granularity — tests and implementation land together, and Step 2 proves the tests actually exercise the behavior by running them.

- [ ] **Step 2: Run the tests**

Run: `cargo test certs:: 2>&1 | tail -15`
Expected: all 6 new tests PASS.

To prove the tests can fail (guard against tautology): temporarily flip `if addr.port() != 443` to `!= 444`, run `cargo test certs::` — `bad_binds_are_refused` and `valid_binds_pass` must FAIL — then revert.

- [ ] **Step 3: Run the full suite**

Run: `cargo test 2>&1 | tail -5`
Expected: PASS, no warnings from `cargo build` about unused code (validate is `pub` and referenced from tests; `main.rs` wiring comes in Task 3 — if an `unused` warning appears for `validate`/`TlsConfig`, that's expected until Task 3 and acceptable for this commit).

- [ ] **Step 4: Commit**

```bash
git add src/certs.rs src/main.rs
git commit -m "Add certs::validate: startup checks for Let's Encrypt mode"
```

---

### Task 3: Wire validation into startup; force `cookie_secure`

**Files:**
- Modify: `src/config.rs` (Config struct ~line 250-290, `from_settings` ~line 394-423)
- Modify: `src/certs.rs` (add `attach` + test)
- Modify: `src/main.rs` `run()` (~line 293, around `let config = Config::from_settings(settings);`)

**Interfaces:**
- Consumes: `certs::validate`, `certs::TlsConfig` (Task 2).
- Produces: `Config.tls: Option<crate::certs::TlsConfig>` (read by Task 4's `serve()`), `pub fn certs::attach(config: &mut Config, tls: Option<TlsConfig>)`.

- [ ] **Step 1: Write the failing test**

In `src/certs.rs` `mod tests`, add:

```rust
    #[test]
    fn attach_forces_the_secure_cookie_flag() {
        let mut config = crate::config::Config::from_settings(Settings::default());
        assert!(!config.cookie_secure);
        let tls = validate(&enabled("0.0.0.0:443", BASE), Path::new(DIR)).unwrap();
        attach(&mut config, tls);
        assert!(config.cookie_secure);
        assert!(config.tls.is_some());

        let mut config = crate::config::Config::from_settings(Settings::default());
        attach(&mut config, None);
        assert!(!config.cookie_secure);
        assert!(config.tls.is_none());
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test certs::tests::attach_forces 2>&1 | tail -10`
Expected: FAIL to compile — no `attach`, no `Config.tls`.

- [ ] **Step 3: Implement**

In `src/config.rs`, add to the `Config` struct (after `secret_base64`):

```rust
    /// Validated Let's Encrypt mode; None serves plain HTTP exactly as before.
    pub tls: Option<crate::certs::TlsConfig>,
```

and `tls: None,` at the end of the struct literal in `from_settings` (both `Config::simple` and `run()` flow through `from_settings`, so simple mode stays `None` for free).

In `src/certs.rs`, add:

```rust
/// Attach a validated TLS mode to the runtime config. Serving HTTPS directly
/// means the session cookie must never travel plaintext, so the Secure flag
/// stops being the operator's choice here.
pub fn attach(config: &mut crate::config::Config, tls: Option<TlsConfig>) {
    if let Some(t) = &tls {
        if !config.cookie_secure {
            tracing::info!("certs: forcing network.cookie_secure = true (serving HTTPS directly)");
            config.cookie_secure = true;
        }
        tracing::info!(
            "certs: Let's Encrypt enabled for {} ({}), store {}",
            t.hostname,
            if t.staging { "staging" } else { "production" },
            t.store_dir.display()
        );
    }
    config.tls = tls;
}
```

In `src/main.rs` `run()`, replace:

```rust
    let config = Config::from_settings(settings);
```

with:

```rust
    // TLS-mode preconditions are checked here, at startup, for the same
    // reason the login checks below are: a bad [certs] combination must be a
    // refusal with a reason, not a mystery at first connect.
    let config_dir = config_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .to_path_buf();
    let tls = match certs::validate(&settings, &config_dir) {
        Ok(tls) => tls,
        Err(e) => {
            eprintln!("startup error: {e}");
            std::process::exit(1);
        }
    };
    let mut config = Config::from_settings(settings);
    certs::attach(&mut config, tls);
```

(`config` stays usable immutably below; the later `serve(config, …)` call is unchanged.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test 2>&1 | tail -5`
Expected: all PASS. Also `cargo build 2>&1 | tail -3` — no warnings.

- [ ] **Step 5: Commit**

```bash
git add src/config.rs src/certs.rs src/main.rs
git commit -m "Wire Let's Encrypt validation into startup"
```

---

### Task 4: Serve HTTPS via rustls-acme + log every ACME event

**Files:**
- Modify: `Cargo.toml` (dependencies)
- Modify: `src/certs.rs` (add `serve_https` + `bind_443`)
- Modify: `src/main.rs` `serve()` tail (~line 494-506, the `TcpListener::bind` … `axum::serve` block)

**Interfaces:**
- Consumes: `Config.tls` (Task 3), `TlsConfig` fields (Task 2).
- Produces: `pub async fn certs::serve_https(app: axum::Router, bind: &str, tls: TlsConfig)` — serves forever or exits the process with a startup error.

- [ ] **Step 1: Add dependencies**

In `Cargo.toml` `[dependencies]` (keep the list's existing ordering style):

```toml
axum-server = "0.7"
rustls-acme = { version = "0.14", default-features = false, features = ["axum", "ring", "tls12", "webpki-roots"] }
```

Run: `cargo tree -i aws-lc-sys 2>&1 | head -3`
Expected: `error: package ID specification ... did not match any packages` — aws-lc must NOT be in the tree (it would break the zigbuild cross-link).

- [ ] **Step 2: Implement `serve_https` in `src/certs.rs`**

Append to `src/certs.rs` (above the tests module):

```rust
/// Serve the app over TLS with an auto-managed Let's Encrypt certificate.
/// Mirrors the plain-HTTP tail of `serve()`: runs forever, or exits with a
/// startup error if the socket cannot be bound.
pub async fn serve_https(app: axum::Router, bind: &str, tls: TlsConfig) {
    use futures::StreamExt;
    use rustls_acme::caches::DirCache;
    use rustls_acme::futures_rustls::rustls::ServerConfig;
    use rustls_acme::AcmeConfig;

    // The store holds the ACME account private key — same posture as the
    // config file: never world-readable. recursive() also makes this a no-op
    // when the directory already exists.
    {
        use std::os::unix::fs::DirBuilderExt;
        if let Err(e) = std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&tls.store_dir)
        {
            eprintln!(
                "startup error: cannot create certs.store_dir {}: {e}",
                tls.store_dir.display()
            );
            std::process::exit(1);
        }
    }

    let mut acme = AcmeConfig::new([tls.hostname.clone()])
        .cache(DirCache::new(tls.store_dir.clone()))
        .directory_lets_encrypt(!tls.staging);
    if let Some(email) = &tls.contact_email {
        acme = acme.contact_push(format!("mailto:{email}"));
    }
    let mut state = acme.state();

    let mut rustls_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(state.resolver());
    rustls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acceptor = state.axum_acceptor(std::sync::Arc::new(rustls_config));

    // The state object IS the event stream — order progress, issuance,
    // renewals, failures all arrive here. Log every one: renewals happen
    // months after anyone was watching the terminal.
    tokio::spawn(async move {
        while let Some(event) = state.next().await {
            match event {
                Ok(ok) => tracing::info!("acme: {ok:?}"),
                Err(err) => tracing::error!("acme: {err:?}"),
            }
        }
    });

    let listener = bind_443(bind);
    axum_server::from_tcp(listener)
        .acceptor(acceptor)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

/// Bind the TLS socket, translating the classic first-deploy failure —
/// unprivileged processes may not bind 443 — into instructions rather than
/// a bare EACCES. Webshell refuses to run as root by design, so granting
/// the capability is the supported path.
fn bind_443(bind: &str) -> std::net::TcpListener {
    let listener = match std::net::TcpListener::bind(bind) {
        Ok(l) => l,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("startup error: cannot bind {bind}: {e}");
            eprintln!("  binding port 443 as an unprivileged user needs one of:");
            eprintln!("    sudo setcap cap_net_bind_service=+ep \"$(command -v webshell)\"");
            eprintln!("    systemd unit: AmbientCapabilities=CAP_NET_BIND_SERVICE");
            eprintln!("    sysctl net.ipv4.ip_unprivileged_port_start=443");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("startup error: cannot bind {bind}: {e}");
            std::process::exit(1);
        }
    };
    // axum-server drives this through tokio; a blocking std listener would
    // wedge the accept loop.
    listener
        .set_nonblocking(true)
        .expect("setting the TLS listener non-blocking");
    listener
}
```

- [ ] **Step 3: Branch `serve()` in `src/main.rs`**

Near the top of `serve()` where `let bind = config.bind_addr.clone();` already exists (~line 414), add:

```rust
    let tls = config.tls.clone();
```

Replace the current tail (~lines 494-506):

```rust
    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .unwrap_or_else(|e| panic!("cannot bind {bind}: {e}"));
    if simple {
        // A clean, clickable line for the ad-hoc operator — the tracing log
        // below still fires for anyone watching structured output.
        println!("Web Shell listening on http://{bind}{BASE_PATH}/");
    }
    tracing::info!("webshell listening on http://{bind}{BASE_PATH}/");
    axum::serve(listener, app).await.unwrap();
```

with:

```rust
    if let Some(tls) = tls {
        // Simple mode has no config file and therefore no [certs]; only the
        // config-backed path can get here.
        tracing::info!("webshell listening on https://{}{BASE_PATH}/", tls.hostname);
        certs::serve_https(app, &bind, tls).await;
        return;
    }
    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .unwrap_or_else(|e| panic!("cannot bind {bind}: {e}"));
    if simple {
        // A clean, clickable line for the ad-hoc operator — the tracing log
        // below still fires for anyone watching structured output.
        println!("Web Shell listening on http://{bind}{BASE_PATH}/");
    }
    tracing::info!("webshell listening on http://{bind}{BASE_PATH}/");
    axum::serve(listener, app).await.unwrap();
```

- [ ] **Step 4: Build and test**

Run: `cargo build 2>&1 | tail -5 && cargo test 2>&1 | tail -5`
Expected: clean build (no warnings), all tests PASS.

API-drift note for the implementer: the `rustls-acme` 0.14 calls used here (`AcmeConfig::new`, `.cache(DirCache::new(…))`, `.directory_lets_encrypt(bool)`, `.contact_push(…)`, `.state()`, `state.resolver()`, `state.axum_acceptor(Arc<ServerConfig>)`) match its docs; if the compiler disagrees, check `docs.rs/rustls-acme/0.14.1` and the crate's `examples/` directory rather than guessing — and if `ServerConfig::builder()` panics about an ambiguous crypto provider at runtime smoke-test, switch to `ServerConfig::builder_with_provider(Arc::new(rustls_acme::futures_rustls::rustls::crypto::ring::default_provider()))` (then `.with_safe_default_protocol_versions().unwrap()`).

- [ ] **Step 5: Runtime smoke test (no real ACME)**

A real certificate needs a public DNS name pointing at this machine — not available here. Smoke-test that TLS mode starts, binds, and logs ACME activity against staging (it will fail validation, which is fine — we're verifying the plumbing, not issuance). Port 443 is unbindable unprivileged, so this check uses the loopback-refusal and startup paths instead:

(`[local_passwords]` must stay the last table, so `[certs]` goes above it:)

```bash
cd "$(mktemp -d)"
printf '%s\n' \
  '[network]' 'bind = "127.0.0.1:443"' 'public_base_url = "https://demo.invalid"' \
  '[auth]' 'users = ["local:smoke"]' \
  '[certs]' 'lets_encrypt_enabled = true' \
  '[local_passwords]' '"local:smoke" = "x"' > config.toml
cargo run --manifest-path /home/code/workspace/webshell/Cargo.toml -- run -c config.toml; echo "exit=$?"
```
Expected: `startup error: network.bind "127.0.0.1:443" is loopback — …`, exit=1.

Then flip `bind` to `"0.0.0.0:8443"` and rerun: expected `startup error: network.bind must use port 443 …`, exit=1.

Then remove the `[certs]` lines and set `bind = "127.0.0.1:0"`: expected the server starts plain-HTTP as before (kill it with Ctrl-C / timeout). Run with `timeout 5 cargo run … ; test $? -eq 124` to confirm it stayed up.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock src/certs.rs src/main.rs
git commit -m "Serve HTTPS with Let's Encrypt auto-certs via rustls-acme"
```

---

### Task 5: Documentation + cross-build verification

**Files:**
- Modify: `README.md` (config table ~line 252-274, security notes ~line 466-486)

**Interfaces:**
- Consumes: everything above; no code changes.

- [ ] **Step 1: Document `[certs]` in the README config table**

Add rows after the `[sharing]` rows (before `[local_passwords]`, mirroring file order):

```markdown
| `[certs]` | `lets_encrypt_enabled` | `false` | Terminate TLS in-process with an auto-obtained/renewed Let's Encrypt certificate — see below. |
| | `store_dir` | `certs` | ACME account key + certificate cache, relative to the config file. |
| | `lets_encrypt_staging` | `false` | Use the staging endpoint (untrusted certs, generous rate limits) for first-time setup. |
| | `contact_email` | *(none)* | ACME contact; Let's Encrypt mails expiry warnings if renewal breaks. |
```

- [ ] **Step 2: Add a "Let's Encrypt" section**

After the `### WebSocket Origin` section (or beside the Security notes — wherever reads naturally), add:

```markdown
### Built-in TLS with Let's Encrypt

Instead of a TLS proxy in front, webshell can terminate TLS itself:

```toml
[network]
bind = "0.0.0.0:443"                       # must be :443, non-loopback
public_base_url = "https://shell.example.com"  # the certificate hostname

[certs]
lets_encrypt_enabled = true
contact_email = "you@example.com"          # optional: expiry warnings
```

The certificate hostname is derived from `public_base_url` (which must be
`https://` and a real DNS name — no IPs, no localhost). Validation is
TLS-ALPN-01 on the same listener: no port 80, no separate challenge server,
but Let's Encrypt must be able to reach **this** machine on port 443 of that
hostname, so DNS has to point here and the bind is checked at startup —
anything other than a non-loopback `:443` refuses to start with the reason.
`cookie_secure` is forced on. Certificates renew automatically; every ACME
event is logged under an `acme:` prefix.

Binding port 443 as an unprivileged user (webshell refuses to run as root)
needs one of:

```sh
sudo setcap cap_net_bind_service=+ep "$(command -v webshell)"   # or:
# systemd unit:  AmbientCapabilities=CAP_NET_BIND_SERVICE
# or:            sysctl net.ipv4.ip_unprivileged_port_start=443
```

First time on a new host, set `lets_encrypt_staging = true`, confirm issuance
in the log (the browser will warn — staging certs are untrusted), then flip
it off and delete the contents of `store_dir`. A failed production attempt
counts against Let's Encrypt's strict rate limits; staging's are generous.
```

Also update the first Security-notes bullet ("Serve over TLS.") to mention the built-in option: "Terminate TLS in front (tlsproxy/nginx/caddy) — or let webshell do it, see *Built-in TLS with Let's Encrypt* — set `[network].cookie_secure = true`, and restrict who can reach it."

- [ ] **Step 3: Verify the cross-build**

Run: `./build-x86_64.sh 2>&1 | tail -6`
Expected: `>> Built target/x86_64-unknown-linux-gnu/release/webshell` with the ELF checks passing. If zig is unavailable in this environment, run `cargo build --release 2>&1 | tail -3` instead and note in the commit message that the zigbuild check is deferred to the next deploy.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "Document built-in Let's Encrypt TLS"
```
