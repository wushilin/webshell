mod certs;
mod config;
mod enrollment;
mod identity;
mod localauth;
mod oidc;
mod pty;
mod session;
mod share;
mod terminals;
mod totp;
mod util;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{Query, Request, State};
use axum::http::header::{ACCEPT, HOST, ORIGIN};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use axum_extra::extract::cookie::{Cookie, Key, SameSite, SignedCookieJar};
use base64::Engine;
use serde::Deserialize;
use subtle::ConstantTimeEq;

use config::{Config, Settings};
use enrollment::EnrollmentStore;
use identity::Identity;
use session::SessionStore;
use share::ShareStore;
use terminals::Terminals;

const COOKIE_NAME: &str = "webshell_sid";
const BASE_PATH: &str = "/webshell";

/// Display preferences the owner sets, mirrored to read-only viewers so their
/// rendering matches the owner's.
#[derive(Clone, serde::Serialize)]
struct ClientPrefs {
    font_size: u16,
    font_family: String,
}

/// Tarpit for login attempts: each recent failure adds delay before the next
/// attempt is processed, throttling brute-force without ever locking out the
/// legitimate user (a success clears it). Failures older than a minute decay.
struct LoginGuard {
    inner: Mutex<(u32, Instant)>,
    permit: tokio::sync::Semaphore,
}

impl LoginGuard {
    fn new() -> Self {
        LoginGuard {
            inner: Mutex::new((0, Instant::now())),
            // PAM is intentionally serialized. This is a single-user service,
            // and unbounded spawn_blocking calls are an easy authentication DoS.
            permit: tokio::sync::Semaphore::new(1),
        }
    }
    fn recent_failures(g: &(u32, Instant)) -> u32 {
        if g.1.elapsed() > Duration::from_secs(60) {
            0
        } else {
            g.0
        }
    }
    /// Delay to impose before the next attempt (grows with recent failures).
    fn delay(&self) -> Duration {
        let g = util::lock(&self.inner);
        Duration::from_millis((Self::recent_failures(&g) as u64 * 300).min(5000))
    }
    fn record_failure(&self) {
        let mut g = util::lock(&self.inner);
        *g = (Self::recent_failures(&g) + 1, Instant::now());
    }
    fn record_success(&self) {
        *util::lock(&self.inner) = (0, Instant::now());
    }

    async fn acquire(&self) -> tokio::sync::SemaphorePermit<'_> {
        self.permit.acquire().await.expect("login semaphore closed")
    }
}

#[derive(Clone)]
struct AppState {
    config: Arc<Config>,
    sessions: Arc<SessionStore>,
    terminals: Arc<Terminals>,
    shares: Arc<ShareStore>,
    /// The owner's font prefs, keyed by username (for viewers to mirror).
    prefs: Arc<Mutex<HashMap<String, ClientPrefs>>>,
    /// Brute-force throttle for the login endpoint.
    login_guard: Arc<LoginGuard>,
    /// Per-identity `sub` pin and TOTP secret.
    enrollment: Arc<EnrollmentStore>,
    /// Outbound client for the Google token exchange. Reused so TLS sessions
    /// and connections are pooled across logins.
    http: reqwest::Client,
    /// One replay guard per identity. A single shared guard would let one
    /// user's spent code reject another user whose authenticator happens to
    /// show the same six digits — a false denial, and a cross-user leak.
    otp_used: Arc<Mutex<HashMap<String, Arc<totp::ReplayGuard>>>>,
    key: Key,
}

impl axum::extract::FromRef<AppState> for Key {
    fn from_ref(state: &AppState) -> Self {
        state.key.clone()
    }
}

/// webshell — a browser-based, PAM-authenticated login shell.
#[derive(clap::Parser)]
#[command(name = "webshell", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(clap::Subcommand)]
enum Command {
    /// Run the server (default).
    Run(ConfigArgs),
    /// Run with no config file: a single local user from WEBSHELL_USER /
    /// WEBSHELL_PASSWORD, no MFA and no Google. WEBSHELL_BIND overrides the
    /// listen address (default 127.0.0.1:9023).
    Simple,
    /// Write a default config file.
    Genconfig(ConfigArgs),
    /// Load a config file and report whether it is valid.
    Validate(ConfigArgs),
    /// Hash a password for a local identity, to paste into the config.
    Passwd {
        /// The identity, e.g. local:alice
        id: String,
    },
}

#[derive(clap::Args)]
struct ConfigArgs {
    /// Path to the TOML config file.
    #[arg(short, long, default_value = config::DEFAULT_CONFIG, env = "WEBSHELL_CONFIG")]
    config: std::path::PathBuf,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "webshell=info,tower_http=info".into()),
        )
        .init();

    use clap::Parser;
    let cli = Cli::parse();
    let command = cli.command.unwrap_or(Command::Run(ConfigArgs {
        config: config::DEFAULT_CONFIG.into(),
    }));

    match command {
        // genconfig writes a NEW file, so it takes the path literally: falling
        // back to an existing legacy name would be a request to overwrite it.
        Command::Genconfig(a) => genconfig(&a.config),
        Command::Validate(a) => validate(&a.config.clone()),
        Command::Passwd { id } => passwd(&id),
        Command::Simple => run_simple().await,
        Command::Run(a) => run_server(&a.config.clone()).await,
    }
}

/// Hash a password and print the config line for it. The plaintext is read
/// from stdin and never written anywhere — the operator pastes only the hash.
fn passwd(id: &str) {
    let identity: Identity = match id.parse() {
        Ok(i) => i,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };
    if identity.provider() != identity::Provider::Local {
        eprintln!("only local: identities have a webshell-managed password");
        std::process::exit(1);
    }
    eprint!("password for {identity}: ");
    let mut password = String::new();
    if std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut password).is_err() {
        eprintln!("could not read the password");
        std::process::exit(1);
    }
    let password = password.trim_end_matches(['\n', '\r']);
    if password.is_empty() {
        eprintln!("refusing to set an empty password");
        std::process::exit(1);
    }
    match localauth::hash(password) {
        Ok(hash) => {
            eprintln!();
            println!("[local_passwords]");
            println!("\"{identity}\" = \"{hash}\"");
        }
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}

/// Write a default config file (refusing to clobber an existing one).
fn genconfig(path: &std::path::Path) {
    if path.exists() {
        eprintln!("refusing to overwrite existing {}", path.display());
        std::process::exit(1);
    }
    match std::fs::write(path, Settings::sample_toml()) {
        Ok(()) => println!("wrote default config to {}", path.display()),
        Err(e) => {
            eprintln!("could not write {}: {e}", path.display());
            std::process::exit(1);
        }
    }
}

/// Load and validate a config file, echoing the normalized settings.
fn validate(path: &std::path::Path) {
    match Settings::load(Some(path)) {
        Ok(_) => println!("OK: {} is valid", path.display()),
        Err(e) => {
            eprintln!("INVALID: {e}");
            std::process::exit(1);
        }
    }
}

async fn run_server(config_path: &std::path::Path) {
    if let Err(e) = config::ensure_unprivileged() {
        eprintln!("startup error: {e}");
        std::process::exit(1);
    }

    // A command line that names a YAML file which is already gone gets the
    // migration story rather than a bare "not found" — this is the start
    // command that has to be updated.
    let config_path = match config::choose(config_path) {
        Ok(config::ConfigChoice::Use(p)) => p,
        Ok(config::ConfigChoice::Missing(looked_for)) => {
            eprintln!(
                "no config found at {}\n\nwrite one with: webshell genconfig -c {}",
                looked_for.display(),
                looked_for.display()
            );
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("config error: {e}");
            std::process::exit(1);
        }
    };
    let config_path = config_path.as_path();

    let mut settings = match Settings::load(Some(config_path)) {
        Ok(s) => {
            tracing::info!("loaded config {}", config_path.display());
            s
        }
        Err(e) => {
            eprintln!("config error: {e}");
            std::process::exit(1);
        }
    };
    if std::env::var("WEBSHELL_SECRET").is_err() && settings.auth.secret_base64.is_none() {
        settings.auth.secret_base64 = Some(generate_cookie_secret());
        if let Err(e) = settings.save(config_path) {
            eprintln!(
                "startup error: could not persist generated auth.secret_base64 to {}: {e}",
                config_path.display()
            );
            std::process::exit(1);
        }
        tracing::info!(
            "generated and persisted auth.secret_base64 in {}",
            config_path.display()
        );
    }

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

    // Everything a login depends on is checked here, at startup, rather than
    // discovered by the first person who tries to sign in.
    if let Err(e) = identity::validate(&config.users) {
        eprintln!("startup error: {e}");
        std::process::exit(1);
    }
    // A method is "usable" only if it is both enabled AND configured. Listing
    // it without the pieces it needs would show a button that cannot work.
    let google_enabled = config.login_methods.contains(&identity::Provider::Google);
    if !config.local_usable() && !config.google_usable() {
        eprintln!("invalid config: No login methods possible.");
        eprintln!("  local:  needs \"local\" in login_methods and at least one local: user");
        eprintln!(
            "  google: needs \"google\" in login_methods, google_client_id, \
             google_client_secret and public_base_url"
        );
        std::process::exit(1);
    }
    if google_enabled
        && (config.google_client_id.is_none() || config.google_client_secret.is_none())
    {
        eprintln!(
            "startup error: google_client_id and google_client_secret are required \n\
             (Cloud Console -> APIs & Services -> Credentials -> OAuth client ID -> Web application)"
        );
        std::process::exit(1);
    }
    let redirect = config.redirect_uri();
    if google_enabled && redirect.is_none() {
        eprintln!(
            "startup error: public_base_url is required — it is what the Google \n\
             redirect URI is derived from, and it must match the one registered \n\
             in the Cloud Console"
        );
        std::process::exit(1);
    }
    if let Some(uri) = &redirect {
        tracing::info!("google sign-in redirect URI: {uri}");
    }
    tracing::info!(
        "login methods: {}",
        config
            .login_methods
            .iter()
            .map(|m| m.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    for user in &config.users {
        tracing::info!("permitted user: {user}");
    }

    serve(config, config_path.to_path_buf(), false).await;
}

/// Build the app state and serve until shutdown. Shared by `run` (config file)
/// and `simple` (env vars): both produce a `Config`, and everything from here
/// down — enrollment state, sessions, routing, listening — is identical. The
/// `simple` flag only changes the startup line printed to the operator.
async fn serve(config: Config, config_path: std::path::PathBuf, simple: bool) {
    let config_path = config_path.as_path();
    // Enrollment lives beside the config unless an absolute path is given.
    let enrollment_path = if config.mfa_enrollment_path.is_absolute() {
        config.mfa_enrollment_path.clone()
    } else {
        config_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join(&config.mfa_enrollment_path)
    };
    let enrollment = match EnrollmentStore::load(&enrollment_path) {
        Ok(store) => Arc::new(store),
        Err(e) => {
            eprintln!("startup error: {e}");
            std::process::exit(1);
        }
    };
    tracing::info!("enrollment state: {}", enrollment_path.display());

    let sessions = if simple {
        Arc::new(SessionStore::new(config.session_ttl))
    } else if let Some(configured_path) = &config.session_path {
        let session_path = if configured_path.is_absolute() {
            configured_path.clone()
        } else {
            config_path
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .join(configured_path)
        };
        let sessions = match SessionStore::load(session_path.clone(), config.session_ttl) {
            Ok(store) => Arc::new(store),
            Err(e) => {
                eprintln!("startup error: {e}");
                std::process::exit(1);
            }
        };
        tracing::info!("login session state: {}", session_path.display());
        sessions
    } else {
        tracing::info!("login session state: in-memory only");
        Arc::new(SessionStore::new(config.session_ttl))
    };
    tracing::info!("login command: {:?}", config.login_cmd);
    let terminals = Arc::new(Terminals::new(
        config.slots_per_user,
        config.login_cmd.clone(),
        config.envs.clone(),
        config.owner.clone(),
        config.owner_home.clone(),
        config.scrollback_cap,
    ));
    let key = load_signing_key(config.secret_base64.as_deref());
    // Derive a distinct share-token key; cookie and capability authentication
    // must not reuse the same key directly.
    let shares = Arc::new(ShareStore::new(derive_key(
        key.master(),
        b"webshell/share-token/v1",
    )));
    let bind = config.bind_addr.clone();
    let tls = config.tls.clone();

    let state = AppState {
        config: Arc::new(config),
        sessions: sessions.clone(),
        terminals,
        shares: shares.clone(),
        prefs: Arc::new(Mutex::new(HashMap::new())),
        login_guard: Arc::new(LoginGuard::new()),
        enrollment,
        http: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .expect("building the HTTP client"),
        otp_used: Arc::new(Mutex::new(HashMap::new())),
        key,
    };

    // Expire auth sessions and share grants (terminal slots are persistent by
    // design). Grants are also pruned when listed or resolved, but a user can
    // mint links and never look at them again — this is what bounds the map
    // over a long-running process.
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            ticker.tick().await;
            sessions.sweep();
            shares.sweep();
        }
    });

    // Public namespace: reachable WITHOUT authentication, by construction.
    let public = Router::new()
        .route("/webshell/public/access", get(access_page))
        .route("/webshell/public/access/ws", get(access_ws))
        .route("/webshell/public/access/status", get(access_status))
        .route("/webshell/public/access/meta", get(access_meta));

    // Private namespace: a single auth layer wraps every route in this router,
    // so protection is structural — a route added here is protected by rule,
    // not by the handler remembering to check.
    let private = Router::new()
        .route("/webshell/private/", get(terminal_page))
        .route("/webshell/private/ws", get(ws_handler))
        .route("/webshell/private/logout", post(logout))
        .route("/webshell/private/api/terminals", get(list_terminals))
        .route("/webshell/private/api/reset", post(reset_terminal))
        .route("/webshell/private/api/share", post(create_share))
        .route("/webshell/private/api/shares", get(list_shares))
        .route("/webshell/private/api/share/revoke", post(revoke_share))
        .route("/webshell/private/api/prefs", post(set_prefs))
        .layer(middleware::from_fn_with_state(state.clone(), require_auth));

    let app = Router::new()
        .route("/webshell/login", get(login_page))
        .route("/webshell/login/local", post(local_login))
        .route("/webshell/oauth/start", post(oauth_start))
        .route("/webshell/oauth/callback", get(oauth_callback))
        .route("/webshell/mfa", get(mfa_page).post(mfa_submit))
        .route("/webshell/mfa/cancel", post(mfa_cancel))
        .route("/favicon.ico", get(favicon))
        .route("/webshell/favicon.ico", get(favicon))
        // Vendored browser assets. Public by necessity — the share-link viewer
        // page is unauthenticated. Separate routes rather than a path
        // parameter, so there is no filename to traverse out of.
        .route("/webshell/static/xterm.js", get(asset_xterm_js))
        .route("/webshell/static/xterm.css", get(asset_xterm_css))
        .route("/webshell/static/addon-fit.js", get(asset_addon_fit_js))
        .merge(public)
        .merge(private)
        .route(
            "/webshell",
            get(|| async { Redirect::to("/webshell/private/") }),
        )
        .route(
            "/webshell/",
            get(|| async { Redirect::to("/webshell/private/") }),
        )
        .with_state(state);

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
}

/// Zero-config local mode: read a single user and password from the
/// environment and serve immediately — no config file, no MFA, no Google.
/// Meant for a quick `WEBSHELL_USER=… WEBSHELL_PASSWORD=… webshell simple`.
async fn run_simple() {
    if let Err(e) = config::ensure_unprivileged() {
        eprintln!("startup error: {e}");
        std::process::exit(1);
    }

    let user = std::env::var("WEBSHELL_USER").unwrap_or_default();
    let password = std::env::var("WEBSHELL_PASSWORD").unwrap_or_default();
    if user.trim().is_empty() || password.is_empty() {
        eprintln!(
            "Err: You need to specify WEBSHELL_USER and WEBSHELL_PASSWORD to run in simple mode"
        );
        std::process::exit(1);
    }
    let bind = std::env::var("WEBSHELL_BIND").unwrap_or_else(|_| "127.0.0.1:9023".to_string());

    // No config file to anchor relative paths against; the enrollment store is
    // never written in this mode (MFA is off), so the cwd is a fine base.
    serve(
        Config::simple(&user, &password, &bind),
        std::path::PathBuf::from("."),
        true,
    )
    .await;
}

fn load_signing_key(secret_base64: Option<&str>) -> Key {
    match secret_base64 {
        Some(s) => {
            let raw = base64::engine::general_purpose::STANDARD
                .decode(s.trim())
                .unwrap_or_else(|e| panic!("secret_base64 is not valid base64: {e}"));
            Key::try_from(raw.as_slice())
                .unwrap_or_else(|e| panic!("secret_base64 must decode to >=64 bytes: {e}"))
        }
        None => {
            // Share links die on restart regardless of the key (grants are
            // in-memory), so only sessions are worth mentioning here.
            tracing::warn!(
                "no secret_base64 set; generating ephemeral key \
                 (login sessions reset on restart)"
            );
            Key::generate()
        }
    }
}

fn generate_cookie_secret() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 64];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    base64::engine::general_purpose::STANDARD.encode(buf)
}

fn derive_key(master: &[u8], context: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = Hmac::<Sha256>::new_from_slice(master).expect("HMAC accepts any key length");
    mac.update(context);
    mac.finalize().into_bytes().to_vec()
}

// ---- static assets ---------------------------------------------------------

/// Terminal-style favicon, embedded in the binary and served without auth.
const FAVICON: &[u8] = include_bytes!("../static/favicon.ico");

async fn favicon() -> Response {
    (
        [
            (axum::http::header::CONTENT_TYPE, "image/x-icon"),
            (axum::http::header::CACHE_CONTROL, "public, max-age=604800"),
        ],
        FAVICON,
    )
        .into_response()
}

// Browser assets, compiled in. They are deliberately NOT loaded from a CDN:
// this page is a root-capable terminal, so a third-party script tag on it is a
// remote-code-execution dependency — one bad CDN response owns the shell. It
// also keeps the binary genuinely self-contained (air-gapped installs work).
// Refresh with ./update_js.sh, which pulls from the npm registry and verifies
// each tarball against npm's published integrity hash.
const XTERM_JS: &[u8] = include_bytes!("../static/vendor/xterm.js");
const XTERM_CSS: &[u8] = include_bytes!("../static/vendor/xterm.css");
const ADDON_FIT_JS: &[u8] = include_bytes!("../static/vendor/addon-fit.js");

/// Serve an embedded asset with a content-derived ETag. `must-revalidate` with
/// a zero lifetime keeps a stale xterm.js from surviving an upgrade, while the
/// 304 path keeps the cost of that revalidation to a bare round trip.
fn embedded_asset(
    bytes: &'static [u8],
    content_type: &'static str,
    etag: &'static std::sync::OnceLock<String>,
    headers: &HeaderMap,
) -> Response {
    use axum::http::header::{
        CACHE_CONTROL, CONTENT_TYPE, ETAG, IF_NONE_MATCH, X_CONTENT_TYPE_OPTIONS,
    };
    const CACHE: &str = "public, max-age=0, must-revalidate";
    let tag = etag.get_or_init(|| {
        use sha2::{Digest, Sha256};
        use std::fmt::Write;
        let digest = Sha256::digest(bytes);
        let mut s = String::with_capacity(34);
        s.push('"');
        for b in &digest[..16] {
            let _ = write!(s, "{b:02x}");
        }
        s.push('"');
        s
    });
    if headers
        .get(IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v == tag)
    {
        // A 304 must carry the same validators a 200 would (RFC 9110 §15.4.5);
        // a bare 304 invites caches to drop the validator and refetch in full.
        return (
            StatusCode::NOT_MODIFIED,
            [
                (CACHE_CONTROL, CACHE),
                (ETAG, tag.as_str()),
                (X_CONTENT_TYPE_OPTIONS, "nosniff"),
            ],
        )
            .into_response();
    }
    (
        [
            (CONTENT_TYPE, content_type),
            (CACHE_CONTROL, CACHE),
            (ETAG, tag.as_str()),
            // This is the response that actually serves JavaScript — it wants
            // nosniff more than the HTML pages do.
            (X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        bytes,
    )
        .into_response()
}

const JS_TYPE: &str = "application/javascript; charset=utf-8";

async fn asset_xterm_js(headers: HeaderMap) -> Response {
    static ETAG: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    embedded_asset(XTERM_JS, JS_TYPE, &ETAG, &headers)
}

async fn asset_addon_fit_js(headers: HeaderMap) -> Response {
    static ETAG: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    embedded_asset(ADDON_FIT_JS, JS_TYPE, &ETAG, &headers)
}

async fn asset_xterm_css(headers: HeaderMap) -> Response {
    static ETAG: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    embedded_asset(XTERM_CSS, "text/css; charset=utf-8", &ETAG, &headers)
}

/// Same-origin WebSocket sources for `connect-src`.
///
/// CSP3 says `'self'` covers ws:/wss: on the page's own origin, and current
/// browsers implement that — but this was CSP2-era breakage territory, and if
/// the reading is wrong the terminal never connects at all. Naming the origin
/// removes the interpretation. The `Host` header is attacker-controlled, so it
/// is charset-checked before it can reach a response header; anything odd
/// falls back to bare `'self'` rather than emitting an attacker's string.
fn ws_sources(headers: &HeaderMap) -> String {
    let Some(host) = headers.get(HOST).and_then(|v| v.to_str().ok()) else {
        return String::new();
    };
    let plausible = !host.is_empty()
        && host.len() <= 255
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']'));
    if plausible {
        format!(" ws://{host} wss://{host}")
    } else {
        String::new()
    }
}

/// CSP for the HTML pages. Scripts are same-origin plus one per-response nonce
/// for the page's own inline block, so an injected `<script>` cannot execute.
/// Styles need 'unsafe-inline': xterm injects stylesheets at runtime.
/// `form-action` is enforced across the whole redirect chain, not just a
/// form's immediate target. The sign-in POST goes to us, but our 303 hands the
/// browser to Google — without naming Google here, browsers block that redirect
/// silently and the button simply appears dead.
fn csp_header(nonce: &str, ws: &str) -> String {
    format!(
        "default-src 'none'; \
         script-src 'self' 'nonce-{nonce}'; \
         style-src 'self' 'unsafe-inline'; \
         img-src 'self' data:; \
         font-src 'self'; \
         connect-src 'self'{ws}; \
         form-action 'self' https://accounts.google.com; \
         base-uri 'none'; \
         frame-ancestors 'none'"
    )
}

/// Headers for an authenticated HTML page: no-store because the markup carries
/// the CSRF token and username, plus the usual sniffing/framing/referrer set.
fn html_headers(
    nonce: &str,
    no_store: bool,
    req_headers: &HeaderMap,
) -> [(axum::http::HeaderName, String); 5] {
    use axum::http::header::{
        CACHE_CONTROL, CONTENT_SECURITY_POLICY, REFERRER_POLICY, X_CONTENT_TYPE_OPTIONS,
        X_FRAME_OPTIONS,
    };
    [
        (
            CONTENT_SECURITY_POLICY,
            csp_header(nonce, &ws_sources(req_headers)),
        ),
        (X_CONTENT_TYPE_OPTIONS, "nosniff".to_string()),
        (X_FRAME_OPTIONS, "DENY".to_string()),
        (REFERRER_POLICY, "no-referrer".to_string()),
        (
            CACHE_CONTROL,
            if no_store {
                "no-store".to_string()
            } else {
                "no-cache".to_string()
            },
        ),
    ]
}

// ---- cookie / session helpers ---------------------------------------------

/// `Lax`, not `Strict`, and that is forced by the OIDC callback: Google sends
/// the browser back to us as a cross-site top-level navigation, and `Strict`
/// withholds the cookie on exactly that, so the login would arrive with no
/// session and no way to reach its own `state`/`nonce`.
///
/// Lax still withholds the cookie on cross-site POSTs and subresource requests,
/// which is where CSRF lives — and every state-changing route here carries an
/// explicit CSRF token besides, so the token is the real defence and SameSite
/// is defence in depth.
fn session_cookie(state: &AppState, id: String) -> Cookie<'static> {
    Cookie::build((COOKIE_NAME, id))
        .path(BASE_PATH)
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(state.config.cookie_secure)
        .build()
}

fn ensure_session(state: &AppState, jar: SignedCookieJar) -> (SignedCookieJar, String) {
    if let Some(cookie) = jar.get(COOKIE_NAME) {
        let id = cookie.value().to_string();
        if state.sessions.get(&id).is_some() {
            return (jar, id);
        }
    }
    let id = state.sessions.create();
    let jar = jar.add(session_cookie(state, id.clone()));
    (jar, id)
}

fn current_session(state: &AppState, jar: &SignedCookieJar) -> Option<(String, session::Session)> {
    let id = jar.get(COOKIE_NAME)?.value().to_string();
    let session = state.sessions.get(&id)?;
    Some((id, session))
}

/// Return the authenticated session, or None if unauthenticated.
fn authed_session(state: &AppState, jar: &SignedCookieJar) -> Option<session::Session> {
    current_session(state, jar)
        .map(|(_, s)| s)
        .filter(|s| s.authenticated)
}

fn csrf_matches(expected: &str, provided: &str) -> bool {
    expected.as_bytes().ct_eq(provided.as_bytes()).into()
}

/// Structural auth gate for the whole `/webshell/private` subtree. Runs once
/// per request as a layer, so protection does not depend on each handler
/// remembering to check. Browser navigations that fail are redirected to the
/// login page; programmatic clients (fetch/WebSocket) get a 401.
async fn require_auth(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    headers: HeaderMap,
    req: Request,
    next: Next,
) -> Response {
    if authed_session(&state, &jar).is_some() {
        return next.run(req).await;
    }
    let wants_html = headers
        .get(ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|a| a.contains("text/html"))
        .unwrap_or(false);
    if wants_html {
        Redirect::to("/webshell/login").into_response()
    } else {
        (StatusCode::UNAUTHORIZED, "not authenticated").into_response()
    }
}

// ---- page handlers ---------------------------------------------------------

async fn login_page(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    headers: HeaderMap,
) -> Response {
    if let Some((_, session)) = current_session(&state, &jar) {
        if session.authenticated {
            return Redirect::to("/webshell/private/").into_response();
        }
        if session.mfa_pending {
            return Redirect::to("/webshell/mfa").into_response();
        }
    }
    let (jar, id) = ensure_session(&state, jar);
    let csrf = state.sessions.get(&id).map(|s| s.csrf).unwrap_or_default();
    let nonce = config::random_token(16);
    let html = render_login(&state, &csrf, &nonce, "");
    (jar, html_headers(&nonce, true, &headers), Html(html)).into_response()
}

#[derive(Deserialize)]
struct LocalLoginForm {
    csrf: String,
    username: String,
    password: String,
}

/// Log in with a system account's password, verified by `su` on a pty. Nothing
/// here links to PAM, which is what lets this binary be statically linked.
async fn local_login(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    headers: HeaderMap,
    Form(form): Form<LocalLoginForm>,
) -> Response {
    let Some((id, session)) = current_session(&state, &jar) else {
        return login_error(
            &state,
            &jar,
            &headers,
            "Your login page expired. Try again.",
        );
    };
    if !csrf_matches(&session.csrf, &form.csrf) {
        return (StatusCode::FORBIDDEN, "invalid CSRF token").into_response();
    }
    if !state.config.local_usable() {
        return (StatusCode::FORBIDDEN, "local login is disabled").into_response();
    }

    // Check the allowlist BEFORE spending a password check: no reason to let an
    // unlisted name drive su, and it keeps the tarpit for real attempts.
    let who = Identity::new(identity::Provider::Local, &form.username);
    if !state.config.permits(&who) {
        state.login_guard.record_failure();
        tracing::warn!("login refused: {who} is not on the allowlist");
        return login_error(&state, &jar, &headers, "Wrong username or password.");
    }

    let _permit = state.login_guard.acquire().await;
    tokio::time::sleep(state.login_guard.delay()).await;

    // Argon2 is deliberately slow; keep it off the async runtime.
    let stored = state.config.local_password(&who).map(|h| h.to_string());
    let password = form.password.clone();
    let verified = match stored {
        Some(hash) => tokio::task::spawn_blocking(move || localauth::verify(&hash, &password))
            .await
            .unwrap_or_else(|e| Err(format!("password check task failed: {e}"))),
        // Allowlisted but no password set: a configuration gap, not a wrong
        // password, and it must not read as one.
        None => Err(format!("no password is configured for {who}")),
    };

    match verified {
        Ok(true) => {}
        Ok(false) => {
            state.login_guard.record_failure();
            tracing::warn!("failed local login for {who}");
            return login_error(&state, &jar, &headers, "Wrong username or password.");
        }
        Err(e) => {
            // A broken checker is not a wrong password, and must not read as one.
            tracing::error!("local password check failed to run: {e}");
            return login_error(
                &state,
                &jar,
                &headers,
                "The server could not check that password. See the log.",
            );
        }
    }

    let user = who.to_string();
    if !state.config.mfa_required {
        state.login_guard.record_success();
        let new_id = state.sessions.login(&id, &user);
        let jar = jar.add(session_cookie(&state, new_id));
        tracing::info!("login success for {user}");
        return (jar, Redirect::to("/webshell/private/")).into_response();
    }
    let new_id = state.sessions.begin_mfa(&id, &user);
    let jar = jar.add(session_cookie(&state, new_id));
    (jar, Redirect::to("/webshell/mfa")).into_response()
}

/// Start a Google sign-in. POST (not GET) so it carries the CSRF token and
/// cannot be triggered by a third-party page linking at us.
async fn oauth_start(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Form(form): Form<CsrfForm>,
) -> Response {
    if !state.config.google_usable() {
        return (StatusCode::FORBIDDEN, "Google sign-in is disabled").into_response();
    }
    let Some((id, session)) = current_session(&state, &jar) else {
        return Redirect::to("/webshell/login").into_response();
    };
    if !csrf_matches(&session.csrf, &form.csrf) {
        return (StatusCode::FORBIDDEN, "invalid CSRF token").into_response();
    }
    let (Some(client_id), Some(redirect_uri)) = (
        state.config.google_client_id.as_deref(),
        state.config.redirect_uri(),
    ) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Google sign-in is not configured",
        )
            .into_response();
    };
    // state/nonce/verifier live on the session, so only this browser can
    // complete the login they started.
    let flow = oidc::Flow::new();
    let url = oidc::authorize_url(client_id, &redirect_uri, &flow);
    state.sessions.set_oauth(&id, Some(flow));
    Redirect::to(&url).into_response()
}

#[derive(Deserialize)]
struct CallbackQuery {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

/// Where Google sends the browser back. Everything that can go wrong here is
/// answered with the same page and a generic message; the specific reason goes
/// to the log, so a failed login never tells an attacker which check tripped.
async fn oauth_callback(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    headers: HeaderMap,
    Query(q): Query<CallbackQuery>,
) -> Response {
    if !state.config.google_usable() {
        return (StatusCode::FORBIDDEN, "Google sign-in is disabled").into_response();
    }
    let Some((id, session)) = current_session(&state, &jar) else {
        return login_error(
            &state,
            &jar,
            &headers,
            "Your login session expired. Try again.",
        );
    };
    if let Some(error) = q.error.as_deref() {
        tracing::warn!("google sign-in returned error {error:?}");
        return login_error(&state, &jar, &headers, "Google declined the sign-in.");
    }
    let (Some(flow), Some(code), Some(returned_state)) =
        (session.oauth.clone(), q.code.as_deref(), q.state.as_deref())
    else {
        return login_error(
            &state,
            &jar,
            &headers,
            "That sign-in did not complete. Try again.",
        );
    };
    // Constant-time: `state` is a per-login secret like any other.
    if !csrf_matches(&flow.state, returned_state) {
        tracing::warn!("google callback: state mismatch");
        return login_error(
            &state,
            &jar,
            &headers,
            "That sign-in did not complete. Try again.",
        );
    }
    // One-shot: a code, and this flow, are good for exactly one attempt.
    state.sessions.set_oauth(&id, None);

    let (Some(client_id), Some(client_secret), Some(redirect_uri)) = (
        state.config.google_client_id.as_deref(),
        state.config.google_client_secret.as_deref(),
        state.config.redirect_uri(),
    ) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Google sign-in is not configured",
        )
            .into_response();
    };

    let verified = match oidc::exchange(
        &state.http,
        client_id,
        client_secret,
        &redirect_uri,
        code,
        &flow,
    )
    .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("google sign-in failed: {e}");
            return login_error(
                &state,
                &jar,
                &headers,
                "Could not verify that Google account.",
            );
        }
    };

    if !state.config.permits(&verified.identity) {
        tracing::warn!(
            "login refused: {} is not on the allowlist",
            verified.identity
        );
        return login_error(
            &state,
            &jar,
            &headers,
            "That account is not permitted to use this server.",
        );
    }
    // Same address, different Google account: refuse rather than hand over the
    // previous holder's slots and enrollment.
    match state
        .enrollment
        .pin_subject(&verified.identity, &verified.sub)
    {
        Ok(true) => {}
        Ok(false) => {
            tracing::warn!(
                "login refused: {} now resolves to a different Google account",
                verified.identity
            );
            return login_error(
                &state,
                &jar,
                &headers,
                "That address now belongs to a different Google account.",
            );
        }
        Err(e) => {
            tracing::error!("could not record enrollment: {e}");
            return login_error(
                &state,
                &jar,
                &headers,
                "Server could not record this login.",
            );
        }
    }

    let user = verified.identity.to_string();
    if !state.config.mfa_required {
        let new_id = state.sessions.login(&id, &user);
        let jar = jar.add(session_cookie(&state, new_id));
        tracing::info!("login success for {user}");
        return (jar, Redirect::to("/webshell/private/")).into_response();
    }
    // MFA is required: hand off to enrollment or verification, still unauthenticated.
    let new_id = state.sessions.begin_mfa(&id, &user);
    let jar = jar.add(session_cookie(&state, new_id));
    (jar, Redirect::to("/webshell/mfa")).into_response()
}

/// Re-render the login page with a message. Used for every callback failure so
/// the browser lands somewhere useful instead of on a bare status code.
fn login_error(
    state: &AppState,
    jar: &SignedCookieJar,
    headers: &HeaderMap,
    message: &str,
) -> Response {
    let csrf = current_session(state, jar)
        .map(|(_, s)| s.csrf)
        .unwrap_or_default();
    let nonce = config::random_token(16);
    let html = render_login(
        state,
        &csrf,
        &nonce,
        &format!("<p class=\"error\">{}</p>", html_escape(message)),
    );
    (html_headers(&nonce, true, headers), Html(html)).into_response()
}

fn render_login(state: &AppState, csrf: &str, nonce: &str, error: &str) -> String {
    let local = state.config.local_usable();
    let google = state.config.google_usable();
    let csrf_field = format!(
        "<input type=\"hidden\" name=\"csrf\" value=\"{}\" />",
        html_escape(csrf)
    );
    // Built, not commented out: a disabled method should be absent from the
    // page, not merely invisible in it.
    let local_form = if local {
        format!(
            "<form method=\"post\" action=\"/webshell/login/local\" autocomplete=\"off\">\
             <label for=\"username\">Username</label>\
             <input id=\"username\" name=\"username\" autocomplete=\"username\" autofocus required />\
             <label for=\"password\">Password</label>\
             <input id=\"password\" name=\"password\" type=\"password\" autocomplete=\"current-password\" required />\
             {csrf_field}<button type=\"submit\">Sign in</button></form>"
        )
    } else {
        String::new()
    };
    let google_form = if google {
        format!(
            "<form method=\"post\" action=\"/webshell/oauth/start\">{csrf_field}\
             <button class=\"google\" type=\"submit\">\
             <span class=\"g\">G</span> Continue with Google</button></form>"
        )
    } else {
        String::new()
    };
    let divider = if local && google {
        "<p class=\"or\">or</p>"
    } else {
        ""
    };
    include_str!("../static/login.html")
        .replace("<!--LOCALFORM-->", &local_form)
        .replace("<!--GOOGLEFORM-->", &google_form)
        .replace("<!--OR-->", divider)
        .replace("{{NONCE}}", &html_escape(nonce))
        .replace("<!--ERROR-->", error)
}

#[derive(Deserialize)]
struct MfaForm {
    csrf: String,
    otp: String,
    /// Candidate secret during enrollment; absent when already enrolled.
    #[serde(default)]
    seed: Option<String>,
}

/// The TOTP step: enrollment for an identity with no secret yet, verification
/// for one that has. Reached only with an `mfa_pending` session, which is
/// issued solely by a completed Google sign-in.
async fn mfa_page(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    headers: HeaderMap,
) -> Response {
    let Some((_, session)) = current_session(&state, &jar).filter(|(_, s)| s.mfa_pending) else {
        return Redirect::to("/webshell/login").into_response();
    };
    render_mfa(&state, &session, &headers, "")
}

fn render_mfa(
    state: &AppState,
    session: &session::Session,
    headers: &HeaderMap,
    error: &str,
) -> Response {
    let Ok(id) = session.username.parse::<Identity>() else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "malformed identity").into_response();
    };
    let record = state.enrollment.get(&id).unwrap_or_default();
    let nonce = config::random_token(16);

    // Already enrolled: ask for a code, and never re-show the secret.
    if record.enrolled() {
        let html = include_str!("../static/mfa_verify.html")
            .replace("{{CSRF}}", &html_escape(&session.csrf))
            .replace("{{NONCE}}", &html_escape(&nonce))
            .replace("{{USER}}", &html_escape(id.subject()))
            .replace("<!--ERROR-->", error);
        return (html_headers(&nonce, true, headers), Html(html)).into_response();
    }

    // Not enrolled: show a QR for a secret that is NOT stored until a code
    // proves the authenticator has it. The pending secret rides in the form so
    // no half-finished enrollment is ever persisted.
    let seed = totp::generate_seed();
    let uri = totp::provisioning_uri(&seed, id.subject());
    let qr = match totp::qr_svg(&uri) {
        Ok(qr) => qr,
        Err(e) => {
            tracing::error!("could not render MFA QR: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "could not render MFA QR").into_response();
        }
    };
    let html = include_str!("../static/mfa.html")
        .replace("{{CSRF}}", &html_escape(&session.csrf))
        .replace("{{NONCE}}", &html_escape(&nonce))
        .replace("{{QR}}", &qr)
        .replace("{{SEED}}", &html_escape(&seed))
        .replace("<!--ERROR-->", error);
    (html_headers(&nonce, true, headers), Html(html)).into_response()
}

/// Per-identity replay guard, created on first use.
fn replay_guard(state: &AppState, user: &str) -> Arc<totp::ReplayGuard> {
    util::lock(&state.otp_used)
        .entry(user.to_string())
        .or_insert_with(|| Arc::new(totp::ReplayGuard::new()))
        .clone()
}

async fn mfa_submit(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    headers: HeaderMap,
    Form(form): Form<MfaForm>,
) -> Response {
    let Some((id, session)) = current_session(&state, &jar).filter(|(_, s)| s.mfa_pending) else {
        return Redirect::to("/webshell/login").into_response();
    };
    if !csrf_matches(&session.csrf, &form.csrf) {
        return (StatusCode::FORBIDDEN, "invalid CSRF token").into_response();
    }
    let Ok(identity) = session.username.parse::<Identity>() else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "malformed identity").into_response();
    };
    // Guessing a six-digit code is exactly the thing a tarpit is for.
    let _permit = state.login_guard.acquire().await;
    tokio::time::sleep(state.login_guard.delay()).await;

    let record = state.enrollment.get(&identity).unwrap_or_default();
    let enrolling = !record.enrolled();
    let secret = match record.mfa_secret.clone() {
        Some(secret) => secret,
        // Enrollment: the candidate secret comes back with the form, and is
        // only written once a code proves the authenticator holds it.
        None => form.seed.clone().unwrap_or_default(),
    };

    let verified = totp::valid_seed(&secret) && totp::verify(&secret, &form.otp);
    let accepted = verified && replay_guard(&state, &session.username).accept(&form.otp);
    if !accepted {
        state.login_guard.record_failure();
        let message = if verified {
            "<p class=\"error\">That code has already been used. \
             Wait for your authenticator to show the next one.</p>"
        } else {
            "<p class=\"error\">That code is not right. Wait for a new one and try again.</p>"
        };
        return render_mfa(&state, &session, &headers, message);
    }

    if enrolling {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if let Err(e) = state.enrollment.enroll(&identity, &secret, now) {
            tracing::error!("could not persist enrollment: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not save enrollment",
            )
                .into_response();
        }
        tracing::info!("MFA enrollment completed for {identity}");
    }

    state.login_guard.record_success();
    let new_id = state.sessions.login(&id, &session.username);
    let jar = jar.add(session_cookie(&state, new_id));
    tracing::info!("login success for {identity}");
    (jar, Redirect::to("/webshell/private/")).into_response()
}

async fn mfa_cancel(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Form(form): Form<CsrfForm>,
) -> Response {
    if let Some((id, session)) = current_session(&state, &jar).filter(|(_, s)| s.mfa_pending) {
        if !csrf_matches(&session.csrf, &form.csrf) {
            return (StatusCode::FORBIDDEN, "invalid CSRF token").into_response();
        }
        state.sessions.remove(&id);
    }
    let jar = jar.remove(Cookie::from(COOKIE_NAME));
    (jar, Redirect::to("/webshell/login")).into_response()
}

#[derive(Deserialize)]
struct LogoutForm {
    csrf: String,
}

/// A form carrying nothing but its CSRF token.
#[derive(Deserialize)]
struct CsrfForm {
    csrf: String,
}

async fn logout(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Form(form): Form<LogoutForm>,
) -> Response {
    if let Some((id, session)) = current_session(&state, &jar) {
        if !csrf_matches(&session.csrf, &form.csrf) {
            return (StatusCode::FORBIDDEN, "invalid CSRF token").into_response();
        }
        // Share grants remain independent of login sessions and can be revoked
        // individually through the shares API.
        state.sessions.remove(&id);
    }
    let jar = jar.remove(Cookie::from(COOKIE_NAME));
    (jar, Redirect::to("/webshell/login")).into_response()
}

async fn terminal_page(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    headers: HeaderMap,
) -> Response {
    let Some((_, session)) = current_session(&state, &jar).filter(|(_, s)| s.authenticated) else {
        return Redirect::to("/webshell/login").into_response();
    };
    let nonce = config::random_token(16);
    let html = include_str!("../static/terminal.html")
        .replace("{{CSRF}}", &html_escape(&session.csrf))
        .replace("{{USER}}", &html_escape(&session.username))
        .replace("{{SLOTS}}", &state.config.slots_per_user.to_string())
        .replace("{{NONCE}}", &html_escape(&nonce));
    // no-store: this markup carries the CSRF token and the username.
    (html_headers(&nonce, true, &headers), Html(html)).into_response()
}

// ---- terminal APIs ---------------------------------------------------------

async fn list_terminals(State(state): State<AppState>, jar: SignedCookieJar) -> Response {
    let Some(session) = authed_session(&state, &jar) else {
        return (StatusCode::UNAUTHORIZED, "not authenticated").into_response();
    };
    Json(state.terminals.list(&session.username)).into_response()
}

#[derive(Deserialize)]
struct ResetForm {
    csrf: String,
    index: usize,
}

async fn reset_terminal(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Form(form): Form<ResetForm>,
) -> Response {
    let Some(session) = authed_session(&state, &jar) else {
        return (StatusCode::UNAUTHORIZED, "not authenticated").into_response();
    };
    if !csrf_matches(&session.csrf, &form.csrf) {
        return (StatusCode::FORBIDDEN, "invalid CSRF token").into_response();
    }
    state.terminals.reset(&session.username, form.index);
    StatusCode::NO_CONTENT.into_response()
}

#[derive(Deserialize)]
struct PrefsForm {
    csrf: String,
    font_size: u16,
    font_family: String,
}

/// Store the owner's display prefs so read-only viewers can mirror them.
async fn set_prefs(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Form(form): Form<PrefsForm>,
) -> Response {
    let Some(session) = authed_session(&state, &jar) else {
        return (StatusCode::UNAUTHORIZED, "not authenticated").into_response();
    };
    if !csrf_matches(&session.csrf, &form.csrf) {
        return (StatusCode::FORBIDDEN, "invalid CSRF token").into_response();
    }
    let font_family: String = form.font_family.chars().take(200).collect();
    util::lock(&state.prefs).insert(
        session.username.clone(),
        ClientPrefs {
            font_size: form.font_size.clamp(8, 40),
            font_family,
        },
    );
    StatusCode::NO_CONTENT.into_response()
}

// ---- read-only share links -------------------------------------------------

#[derive(Deserialize)]
struct ShareForm {
    csrf: String,
    index: usize,
    ttl_secs: u64,
    /// Owner-visible reminder of what the link is for. Optional so older
    /// clients (and curl) keep working.
    #[serde(default)]
    note: String,
}

#[derive(serde::Serialize)]
struct ShareResponse {
    url: String,
    grant_id: String,
    expires_in_secs: u64,
}

/// Mint a read-only share link for one of the caller's slots, valid for the
/// requested duration (independent of the caller's login session).
async fn create_share(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Form(form): Form<ShareForm>,
) -> Response {
    if !state.config.sharing_enabled {
        return (StatusCode::FORBIDDEN, "sharing is disabled").into_response();
    }
    let Some((_, session)) = current_session(&state, &jar) else {
        return (StatusCode::UNAUTHORIZED, "not authenticated").into_response();
    };
    if !session.authenticated {
        return (StatusCode::UNAUTHORIZED, "not authenticated").into_response();
    }
    if !csrf_matches(&session.csrf, &form.csrf) {
        return (StatusCode::FORBIDDEN, "invalid CSRF token").into_response();
    }
    if form.index >= state.config.slots_per_user {
        return (StatusCode::BAD_REQUEST, "slot out of range").into_response();
    }
    let ttl_secs = form.ttl_secs.clamp(1, state.config.max_share_secs);
    let (token, grant_id) = match state.shares.create(
        &session.username,
        form.index,
        std::time::Duration::from_secs(ttl_secs),
        &form.note,
    ) {
        Ok(v) => v,
        Err(share::CreateError::TooMany) => {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                format!(
                    "you already have {} active share links; revoke one first",
                    share::MAX_GRANTS_PER_USER
                ),
            )
                .into_response();
        }
    };
    let url = share_url(&state, &token);
    Json(ShareResponse {
        url,
        grant_id,
        expires_in_secs: ttl_secs,
    })
    .into_response()
}

#[derive(Deserialize)]
struct RevokeShareForm {
    csrf: String,
    grant_id: String,
}

/// Absolute when a public base URL is configured (correct behind a proxy);
/// otherwise a path the page resolves against its own origin.
fn share_url(state: &AppState, token: &str) -> String {
    let path = format!("/webshell/public/access?token={token}");
    match &state.config.public_base_url {
        Some(base) => format!("{base}{path}"),
        None => path,
    }
}

/// One live share link, as the manage dialog needs it.
#[derive(serde::Serialize)]
struct ShareEntry {
    grant_id: String,
    index: usize,
    expires_in_secs: u64,
    note: String,
    /// Rebuilt from the grant rather than stored — the owner can re-copy a
    /// link instead of minting a duplicate one.
    url: String,
}

async fn list_shares(State(state): State<AppState>, jar: SignedCookieJar) -> Response {
    let Some(session) = authed_session(&state, &jar) else {
        return (StatusCode::UNAUTHORIZED, "not authenticated").into_response();
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut entries: Vec<ShareEntry> = state
        .shares
        .list(&session.username)
        .iter()
        .map(|g| ShareEntry {
            grant_id: g.id.clone(),
            index: g.index,
            expires_in_secs: g.expires_at.saturating_sub(now),
            note: g.note.clone(),
            url: share_url(&state, &state.shares.token_for(g)),
        })
        .collect();
    // Soonest to expire first, then by slot, so the list is stable between
    // polls instead of following HashMap iteration order.
    entries.sort_by(|a, b| {
        a.expires_in_secs
            .cmp(&b.expires_in_secs)
            .then(a.index.cmp(&b.index))
    });
    Json(entries).into_response()
}

async fn revoke_share(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Form(form): Form<RevokeShareForm>,
) -> Response {
    let Some(session) = authed_session(&state, &jar) else {
        return (StatusCode::UNAUTHORIZED, "not authenticated").into_response();
    };
    if !csrf_matches(&session.csrf, &form.csrf) {
        return (StatusCode::FORBIDDEN, "invalid CSRF token").into_response();
    }
    if state.shares.revoke(&session.username, &form.grant_id) {
        StatusCode::NO_CONTENT.into_response()
    } else {
        (StatusCode::NOT_FOUND, "share grant not found").into_response()
    }
}

#[derive(Deserialize)]
struct AccessQuery {
    token: String,
    #[serde(default)]
    epoch: Option<u64>,
    #[serde(default)]
    offset: Option<u64>,
}

/// Resolve a non-expired share token to `(username, index)`, honoring the
/// global sharing switch.
fn resolve_share(state: &AppState, token: &str) -> Option<(String, usize)> {
    if !state.config.sharing_enabled {
        return None;
    }
    state.shares.resolve(token)
}

#[derive(serde::Serialize)]
struct AccessStatus {
    valid: bool,
    expires_in_secs: u64,
}

/// Report whether a share token is still valid and how long it has left. Used
/// by the viewer page to detect expiry precisely and stop reconnecting.
async fn access_status(State(state): State<AppState>, Query(q): Query<AccessQuery>) -> Response {
    let remaining = if state.config.sharing_enabled {
        state.shares.remaining_secs(&q.token)
    } else {
        None
    };
    match remaining {
        Some(secs) => Json(AccessStatus {
            valid: true,
            expires_in_secs: secs,
        }),
        None => Json(AccessStatus {
            valid: false,
            expires_in_secs: 0,
        }),
    }
    .into_response()
}

#[derive(serde::Serialize)]
struct AccessMeta {
    /// Which slot this link points at, 0-based, so the viewer can say *which*
    /// terminal it is watching instead of just "shared". It comes out of the
    /// token itself, so every link minted before this field existed reports it
    /// too — nothing about the token format changed.
    slot: usize,
    /// Owner of the shared slot, for the same reason. Not a disclosure: the
    /// holder of the link already has read-only sight of that user's shell.
    owner: String,
    cols: u16,
    rows: u16,
    font_size: u16,
    font_family: String,
}

/// Metadata a viewer needs to mirror the owner's terminal: which slot it is,
/// the live PTY grid, and the owner's font prefs.
async fn access_meta(State(state): State<AppState>, Query(q): Query<AccessQuery>) -> Response {
    let Some((user, index)) = resolve_share(&state, &q.token) else {
        return (StatusCode::FORBIDDEN, "invalid or expired share link").into_response();
    };
    let (cols, rows) = state
        .terminals
        .current_size(&user, index)
        .unwrap_or((80, 24));
    let prefs = util::lock(&state.prefs).get(&user).cloned();
    let (font_size, font_family) = match prefs {
        Some(p) => (p.font_size, p.font_family),
        None => (
            14,
            "ui-monospace, SFMono-Regular, Menlo, monospace".to_string(),
        ),
    };
    Json(AccessMeta {
        slot: index,
        owner: user,
        cols,
        rows,
        font_size,
        font_family,
    })
    .into_response()
}

const SHARE_INVALID_HTML: &str = "<!doctype html><meta charset=utf-8>\
<title>webshell</title><link rel=icon href=/webshell/favicon.ico>\
<body style=\"font-family:system-ui;background:#0f1115;\
color:#e6e6e6;display:grid;place-items:center;height:100vh;margin:0\">\
<p>This share link is invalid or has expired.</p>";

/// Serve the read-only viewer page (no login required); the token lives in the
/// URL and is read by the page's script.
async fn access_page(
    State(state): State<AppState>,
    Query(q): Query<AccessQuery>,
    headers: HeaderMap,
) -> Response {
    let nonce = config::random_token(16);
    if resolve_share(&state, &q.token).is_none() {
        return (
            StatusCode::GONE,
            html_headers(&nonce, false, &headers),
            Html(SHARE_INVALID_HTML.replace("{{NONCE}}", &html_escape(&nonce))),
        )
            .into_response();
    }
    let html = include_str!("../static/access.html").replace("{{NONCE}}", &html_escape(&nonce));
    // no-store: the page is reached with a capability token in its URL.
    (html_headers(&nonce, true, &headers), Html(html)).into_response()
}

/// Read-only WebSocket for a share link. The token is the credential (no cookie,
/// no CSRF); attachment is view-only and never spawns or resizes the shell.
async fn access_ws(
    State(state): State<AppState>,
    Query(q): Query<AccessQuery>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    tracing::info!("access ws: upgrade request");
    // The global switch gates the *data path*, not just the viewer page: this
    // socket is the only thing that actually streams the terminal, and it is
    // reachable without a login. `resolve_share` applies the same check on the
    // page and status routes.
    if !state.config.sharing_enabled {
        tracing::warn!("access ws: rejected — sharing is disabled");
        return (StatusCode::FORBIDDEN, "sharing is disabled").into_response();
    }
    let Some((user, index, revoked)) = state.shares.lease(&q.token) else {
        tracing::warn!("access ws: rejected — invalid or expired share token");
        return (StatusCode::FORBIDDEN, "invalid or expired share link").into_response();
    };
    if !origin_allowed(&state, &headers) {
        tracing::warn!(
            "access ws: rejected — origin not allowed: Origin={:?} Host={:?} allowed_origins={:?} strict={}",
            header_str(&headers, ORIGIN),
            header_str(&headers, HOST),
            state.config.allowed_origins,
            state.config.strict_origin
        );
        return (StatusCode::FORBIDDEN, "origin not allowed").into_response();
    }
    // Force-close the viewer exactly when the token expires.
    let deadline = state
        .shares
        .remaining_secs(&q.token)
        .map(|s| tokio::time::Instant::now() + std::time::Duration::from_secs(s));
    let resume = match (q.epoch, q.offset) {
        (Some(e), Some(o)) => Some((e, o)),
        _ => None,
    };
    match state.terminals.attach_view(&user, index, resume) {
        Ok(attachment) => {
            tracing::info!("access ws: attached (viewer) user={user:?} term={index}");
            // Bound what an unauthenticated share-link holder can make us buffer.
            ws.max_message_size(state.config.ws_message_limit)
                .max_frame_size(state.config.ws_message_limit)
                .on_upgrade(move |socket| {
                    pty::bridge(socket, attachment, true, deadline, Some(revoked))
                })
        }
        Err(e) => {
            tracing::warn!("access ws: attach_view failed user={user:?} term={index}: {e}");
            (StatusCode::BAD_REQUEST, e).into_response()
        }
    }
}

// ---- websocket -------------------------------------------------------------

#[derive(Deserialize)]
struct WsQuery {
    csrf: String,
}

async fn ws_handler(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Query(q): Query<WsQuery>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    tracing::info!("ws: mux upgrade request");
    let Some(session) = authed_session(&state, &jar) else {
        tracing::warn!("ws: rejected — not authenticated (no valid session cookie)");
        return (StatusCode::UNAUTHORIZED, "not authenticated").into_response();
    };
    if !csrf_matches(&session.csrf, &q.csrf) {
        tracing::warn!(
            "ws: rejected — CSRF mismatch for user {:?}",
            session.username
        );
        return (StatusCode::FORBIDDEN, "invalid CSRF token").into_response();
    }
    if !origin_allowed(&state, &headers) {
        let origin = header_str(&headers, ORIGIN);
        let host = header_str(&headers, HOST);
        tracing::warn!(
            "ws: rejected — origin not allowed: Origin={origin:?} Host={host:?} allowed_origins={:?} strict={}",
            state.config.allowed_origins,
            state.config.strict_origin
        );
        return (StatusCode::FORBIDDEN, "origin not allowed").into_response();
    }

    let terminals = state.terminals.clone();
    let revoked = session.revocation();
    let deadline = tokio::time::Instant::now() + session.remaining(state.sessions.ttl());
    let user = session.username;
    ws.max_message_size(state.config.ws_message_limit)
        .max_frame_size(state.config.ws_message_limit)
        .on_upgrade(move |socket| pty::mux_bridge(socket, terminals, user, revoked, deadline))
}

fn header_str(headers: &HeaderMap, name: axum::http::HeaderName) -> String {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("<none>")
        .to_string()
}

/// Reject cross-site WebSocket upgrades. A missing `Origin` is rejected.
///
/// The default needs no configuration: the page's `Origin` must be the `Host`
/// it asked for, which holds for every hostname the server is legitimately
/// reached on, and never for a third-party page (the browser sends *its* origin
/// with *our* host). `allowed_origins` only widens this, for proxies that
/// rewrite `Host` and leave nothing to compare against. `strict_origin` drops
/// the fallback to pin the accepted hostnames — ignored when no origin is
/// configured, since that would reject every client.
fn origin_allowed(state: &AppState, headers: &HeaderMap) -> bool {
    let Some(origin) = headers.get(ORIGIN).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let allowed = &state.config.allowed_origins;
    if allowed.iter().any(|a| config::origin_matches(a, origin)) {
        return true;
    }
    if state.config.strict_origin && !allowed.is_empty() {
        return false;
    }
    let origin_authority = origin.split("://").nth(1);
    let host = headers.get(HOST).and_then(|v| v.to_str().ok());
    matches!((origin_authority, host), (Some(o), Some(h)) if o == h)
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
