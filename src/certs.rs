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
    /// ACME account key + certificate cache directory; relative `store_dir`
    /// already resolved against the config file's directory.
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
    // An https URL admits userinfo ("user@host"), but a certificate hostname
    // never does — refuse rather than mis-parse.
    if authority.contains('@') {
        anyhow::bail!(
            "network.public_base_url {base:?} must not contain userinfo — \
             use plain https://hostname"
        );
    }
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
            "https://user@shell.example.com", // userinfo
            "https://user:pass@shell.example.com", // userinfo with password
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
