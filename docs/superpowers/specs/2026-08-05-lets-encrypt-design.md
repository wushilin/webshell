# Let's Encrypt Auto-Certificates — Design

**Date:** 2026-08-05
**Status:** Approved

## Goal

Let webshell serve HTTPS directly with automatically obtained and renewed
Let's Encrypt certificates, as an opt-in mode. When the mode is off (the
default), behavior is byte-for-byte identical to today's plain-HTTP serving.
All certificate lifecycle events are logged.

## Background

Webshell currently serves plain HTTP via `axum::serve` and expects a reverse
proxy to terminate TLS. The `network.bind` default of `127.0.0.1:8080` is a
deliberate security choice and stays untouched. This feature adds a second,
explicit path: bind a public 443, terminate TLS in-process, and let the ACME
TLS-ALPN-01 challenge ride the same listener — no port 80, no separate
challenge server.

Crate: `rustls-acme`. It answers TLS-ALPN-01 challenges inside the TLS
handshake, caches account keys and certificates via `DirCache`, integrates
with axum through its `axum-server` feature, and exposes the certificate
lifecycle as a `Stream` of events.

## Config surface

A new `[certs]` table in `Settings` (declared before `local_passwords`, which
must remain the last field — a TOML table absorbs every key that follows it):

```toml
[certs]
lets_encrypt_enabled = false   # master switch; default off
store_dir = "certs"            # ACME account key + cert cache; relative paths
                               # resolve against the config file's directory
lets_encrypt_staging = false   # true = Let's Encrypt staging endpoint
                               # (untrusted certs, generous rate limits) for
                               # safe first-time setup on a new host
# contact_email = "you@example.com"  # optional; Let's Encrypt sends expiry
                               # warnings here if renewal silently breaks
```

There is deliberately **no** `certs.public_host_name` key. The certificate
hostname is derived from `network.public_base_url`, following the same
single-source-of-truth philosophy as `Config::redirect_uri()`: two sources of
truth for one hostname is a support burden, and the cert must match the URL
users actually visit.

Simple mode (`webshell simple`) has no config file, so it always runs with
certs disabled.

## Validation

A new `src/certs.rs` module owns:

```rust
pub struct TlsConfig {
    pub hostname: String,          // derived from public_base_url
    pub store_dir: PathBuf,        // resolved against the config dir
    pub staging: bool,
    pub contact_email: Option<String>,
}

pub fn validate(settings: &Settings) -> anyhow::Result<Option<TlsConfig>>
```

Called from `run()` before serving. Failures use the existing startup-error
pattern (`eprintln!("startup error: …")` + `exit(1)`), not `panic!`.

When `lets_encrypt_enabled = false`: returns `Ok(None)`. No other key in
`[certs]` is even inspected.

When `lets_encrypt_enabled = true`, refuse to start unless all of:

1. **`network.public_base_url` is set, uses `https://`, and its host is a DNS
   name** — not an IP literal, not `localhost`. Error explains the cert must
   be issued for a real public hostname and that `public_base_url` is where
   it comes from.
2. **`network.bind` port is exactly 443 and its host is not loopback.**
   `0.0.0.0:443`, `[::]:443`, and any specific non-loopback IP all pass;
   `127.0.0.1:443`, `[::1]:443`, and any port other than 443 are rejected.
   Error explains that TLS-ALPN-01 requires Let's Encrypt to reach *this*
   listener on port 443 of the public hostname.

Additionally, `cookie_secure` is forced to `true` (with an `info` log when it
was configured false): when webshell itself serves HTTPS, the session cookie
must never travel plaintext.

The result lands on the runtime `Config` as `tls: Option<TlsConfig>`.
`None` selects today's plain-HTTP path, unchanged.

## Serving

In `serve()`, when `config.tls` is `Some`:

```rust
let mut state = AcmeConfig::new([hostname])
    .cache(DirCache::new(store_dir))          // dir created 0700 if missing
    .directory_lets_encrypt(!staging)
    // .contact_push("mailto:…") when contact_email is set
    .state();
// spawn the event-logging task (below), then:
let acceptor = state.axum_acceptor(rustls_server_config);
axum_server::from_tcp(std_listener)
    .acceptor(acceptor)
    .serve(app.into_make_service())
    .await
```

The startup log line becomes `https://<hostname>/webshell/`. When the 443
bind fails with a permission error, the message notes the unprivileged-bind
options (`setcap cap_net_bind_service=+ep` on the binary, systemd
`AmbientCapabilities=CAP_NET_BIND_SERVICE`, or the
`net.ipv4.ip_unprivileged_port_start` sysctl) — webshell refuses to run as
root by design, so this is the expected first-deploy trap.

## Certificate event logging

`rustls-acme`'s state object *is* the event stream — there is no separate
`subscribe()` method. Before serving, spawn a task that polls the stream
forever and logs every item under an `acme:` prefix:

- `Ok` events (cached cert deployed, order placed, cert issued and stored,
  renewal) → `tracing::info!`
- `Err` events (challenge failure, rate limit, cache I/O error) →
  `tracing::error!`

This satisfies "log all cert events": nothing is filtered.

## Dependencies

- `rustls-acme` 0.14 (its `axum` feature pulls `axum-server` 0.7, matching
  the existing axum 0.7; the 0.15 line moved to axum-server 0.8) with the
  **ring** crypto backend — explicitly not the default aws-lc-rs, because
  release builds cross-compile with cargo-zigbuild (`build-x86_64.sh`) and
  aws-lc-sys's C/cmake build breaks zig cross-linking, while ring is already
  in the dependency tree via reqwest and demonstrably cross-builds.
- `axum-server` 0.7 as a direct dependency (for `from_tcp` + `.acceptor()`).

The implementation must verify the cross-build (`build-x86_64.sh`) still
succeeds.

## Testing

Unit tests on `certs::validate`:

- disabled → `Ok(None)` regardless of other keys
- each rejection: loopback bind host, port ≠ 443, missing `public_base_url`,
  `http://` scheme, IP-literal host, `localhost` host
- each acceptance: `0.0.0.0:443`, `[::]:443`, a public IP bind
- `cookie_secure` forced true when enabled
- `store_dir` resolves relative paths against the config dir
- `Settings::sample_toml()` documents the `[certs]` table

Real ACME issuance is not testable in CI. The staging toggle exists for
manual verification on a real host before switching to production.

## Out of scope

- No port-80 HTTP→HTTPS redirect listener (decided against: modern browsers
  default to https; one listener is simpler).
- No multi-domain / SAN support; one hostname, from `public_base_url`.
- No custom ACME directory URL (staging/production toggle only).
- No manual (bring-your-own-file) TLS certificate mode.
