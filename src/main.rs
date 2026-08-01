mod config;
mod pam;
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
    mfa_seed: Arc<Mutex<Option<String>>>,
    mfa_initialized: Arc<std::sync::atomic::AtomicBool>,
    /// Makes each accepted OTP single-use; see `totp::ReplayGuard`.
    otp_used: Arc<totp::ReplayGuard>,
    config_path: Arc<std::path::PathBuf>,
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
    /// Write a default config file.
    Genconfig(ConfigArgs),
    /// Load a config file and report whether it is valid.
    Validate(ConfigArgs),
    /// Rewrite a config file as TOML (converts a legacy YAML one).
    Configrewrite(ConfigArgs),
}

#[derive(clap::Args)]
struct ConfigArgs {
    /// Path to the TOML config file. If it is missing, a legacy `.yaml`/`.yml`
    /// file of the same name is used instead.
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
        Command::Validate(a) => validate(&config::resolve_path(&a.config)),
        Command::Configrewrite(a) => configrewrite(&config::resolve_path(&a.config)),
        Command::Run(a) => run_server(&config::resolve_path(&a.config)).await,
    }
}

/// Read a config in either format and write it back out as TOML. The source is
/// left alone: converting is not the moment to delete the only copy of a file
/// holding the cookie key and TOTP seed.
fn configrewrite(path: &std::path::Path) {
    let settings = match Settings::load(Some(path)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("INVALID: {e}");
            std::process::exit(1);
        }
    };
    let target = path.with_extension("toml");
    if target != path && target.exists() {
        eprintln!("refusing to overwrite existing {}", target.display());
        std::process::exit(1);
    }
    match settings.save(&target) {
        Ok(()) => {
            println!("wrote {}", target.display());
            if target != path {
                println!("{} is no longer used; delete it once you are happy.", path.display());
            }
        }
        Err(e) => {
            eprintln!("could not write {}: {e}", target.display());
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
    if config::is_legacy(config_path) && !config_path.exists() {
        if let Some(hint) = config::migration_hint(config_path) {
            eprintln!("config error: {hint}");
            std::process::exit(1);
        }
    }

    let config_path = match config::choose(config_path) {
        Ok(config::ConfigChoice::Use(p)) => p,
        // Converted: stop rather than serve from a file written moments ago.
        Ok(config::ConfigChoice::Converted { converted, retired }) => {
            eprintln!(
                "converted {} to {}\n\
                 the original is kept as {}\n\n\
                 not starting the server: review {}, then start again",
                config_path.display(),
                converted.display(),
                retired.display(),
                converted.display()
            );
            std::process::exit(1);
        }
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

    let settings = match Settings::load(Some(config_path)) {
        Ok(s) => {
            tracing::info!("loaded config {}", config_path.display());
            s
        }
        Err(e) => {
            eprintln!("config error: {e}");
            std::process::exit(1);
        }
    };

    let config = Config::from_settings(settings);
    if config.mfa_enabled
        && config
            .mfa_token_seed
            .as_deref()
            .is_some_and(|seed| !totp::valid_seed(seed))
    {
        eprintln!("startup error: mfa_token_seed is not a valid base32 TOTP seed");
        std::process::exit(1);
    }
    let mfa_initialized = Arc::new(std::sync::atomic::AtomicBool::new(
        config.mfa_token_seed.is_some(),
    ));
    let mfa_seed = Arc::new(Mutex::new(config.mfa_token_seed.clone()));
    let sessions = Arc::new(SessionStore::new(config.session_ttl));
    let terminals = Arc::new(Terminals::new(
        config.slots_per_user,
        config.login_cmd.clone(),
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

    let state = AppState {
        config: Arc::new(config),
        sessions: sessions.clone(),
        terminals,
        shares: shares.clone(),
        prefs: Arc::new(Mutex::new(HashMap::new())),
        login_guard: Arc::new(LoginGuard::new()),
        mfa_seed,
        mfa_initialized,
        otp_used: Arc::new(totp::ReplayGuard::new()),
        config_path: Arc::new(config_path.to_path_buf()),
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
        .route("/webshell/login", get(login_page).post(login_submit))
        .route("/webshell/mfa", get(mfa_setup_page).post(mfa_setup_submit))
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

    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .unwrap_or_else(|e| panic!("cannot bind {bind}: {e}"));
    tracing::info!("webshell listening on http://{bind}{BASE_PATH}/");
    axum::serve(listener, app).await.unwrap();
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
fn csp_header(nonce: &str, ws: &str) -> String {
    format!(
        "default-src 'none'; \
         script-src 'self' 'nonce-{nonce}'; \
         style-src 'self' 'unsafe-inline'; \
         img-src 'self' data:; \
         font-src 'self'; \
         connect-src 'self'{ws}; \
         form-action 'self'; \
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

fn session_cookie(state: &AppState, id: String) -> Cookie<'static> {
    Cookie::build((COOKIE_NAME, id))
        .path(BASE_PATH)
        .http_only(true)
        .same_site(SameSite::Strict)
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
    if authed_session(&state, &jar).is_some() {
        return Redirect::to("/webshell/private/").into_response();
    }
    let (jar, id) = ensure_session(&state, jar);
    let csrf = state.sessions.get(&id).map(|s| s.csrf).unwrap_or_default();
    let nonce = config::random_token(16);
    let html = render_login(&state, &csrf, &nonce, "");
    (jar, html_headers(&nonce, true, &headers), Html(html)).into_response()
}

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
    #[serde(default)]
    otp: String,
    csrf: String,
}

async fn login_submit(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    let Some((id, session)) = current_session(&state, &jar) else {
        // The pre-auth session expired (PREAUTH_TTL) or its cookie was lost.
        // This used to bounce back to the login page with no log line and no
        // message, which reads as "the button did nothing" — and the retry
        // only worked because the reload minted a fresh session. Hand back a
        // usable form with a new session and say what happened, so the very
        // next attempt succeeds.
        tracing::info!("login: submit with no live session (expired or missing cookie)");
        let (jar, id) = ensure_session(&state, jar);
        let csrf = state.sessions.get(&id).map(|s| s.csrf).unwrap_or_default();
        let nonce = config::random_token(16);
        let html = render_login(
            &state,
            &csrf,
            &nonce,
            "<p class=\"error\">This page had been open too long, so the login form expired. \
             Please enter your details again — including a fresh authenticator code.</p>",
        );
        return (jar, html_headers(&nonce, true, &headers), Html(html)).into_response();
    };
    if !csrf_matches(&session.csrf, &form.csrf) {
        tracing::warn!("login: rejected — CSRF mismatch");
        return (StatusCode::FORBIDDEN, "invalid CSRF token").into_response();
    }

    // Serialize PAM calls before calculating the delay, so a burst cannot race
    // past the failure counter and exhaust the blocking pool.
    let _login_permit = state.login_guard.acquire().await;
    tokio::time::sleep(state.login_guard.delay()).await;

    // PAM auth may block; run it off the async runtime.
    let cfg = state.config.clone();
    let username = form.username.clone();
    let password = form.password.clone();
    let result = tokio::task::spawn_blocking(move || cfg.authenticate(&username, &password))
        .await
        .ok()
        .flatten();

    let Some(canonical_user) = result else {
        state.login_guard.record_failure();
        tracing::warn!("failed login for user {:?}", form.username);
        let nonce = config::random_token(16);
        let html = render_login(
            &state,
            &session.csrf,
            &nonce,
            "<p class=\"error\">Invalid username or password.</p>",
        );
        return (
            StatusCode::UNAUTHORIZED,
            html_headers(&nonce, true, &headers),
            Html(html),
        )
            .into_response();
    };

    if state.config.mfa_enabled {
        let initialized = state
            .mfa_initialized
            .load(std::sync::atomic::Ordering::Acquire);
        let existing_seed = util::lock(&state.mfa_seed).clone();
        if initialized {
            let Some(seed) = existing_seed else {
                tracing::error!("MFA is initialized but its seed is unavailable");
                return (StatusCode::INTERNAL_SERVER_ERROR, "MFA configuration error")
                    .into_response();
            };
            // Evaluate once: the time window can roll between two calls, and
            // re-checking after consuming the code could reject a login whose
            // code has already been spent. Short-circuit order also means only
            // a code that verified is consumed, so a wrong guess cannot evict
            // the record of a real one.
            let verified = totp::verify(&seed, &form.otp);
            let accepted = verified && state.otp_used.accept(&form.otp);
            if !accepted {
                state.login_guard.record_failure();
                let nonce = config::random_token(16);
                // A replay is named explicitly: the holder already had a valid
                // code, so this tells them nothing they did not know, and it is
                // the difference between "try again" and "wait 30 seconds".
                let message = if verified {
                    "<p class=\"error\">That code has already been used. \
                     Wait for your authenticator to show the next one.</p>"
                } else {
                    "<p class=\"error\">Invalid username, password, or OTP.</p>"
                };
                let html = render_login(&state, &session.csrf, &nonce, message);
                return (
                    StatusCode::UNAUTHORIZED,
                    html_headers(&nonce, true, &headers),
                    Html(html),
                )
                    .into_response();
            }
        } else {
            if existing_seed.is_none() {
                *util::lock(&state.mfa_seed) = Some(totp::generate_seed());
            }
            let new_id = state.sessions.begin_mfa(&id, &canonical_user);
            let jar = jar.add(session_cookie(&state, new_id));
            return (jar, Redirect::to("/webshell/mfa")).into_response();
        }
    }

    // Success: rotate the session id (fixation defense).
    state.login_guard.record_success();
    let new_id = state.sessions.login(&id, &canonical_user);
    let jar = jar.add(session_cookie(&state, new_id));
    tracing::info!("login success for user {:?}", canonical_user);
    (jar, Redirect::to("/webshell/private/")).into_response()
}

fn otp_field(show: bool) -> &'static str {
    if show {
        "<label for=\"otp\">Authenticator code</label>\
         <input id=\"otp\" name=\"otp\" type=\"text\" inputmode=\"numeric\" \
         autocomplete=\"one-time-code\" pattern=\"[0-9]{6}\" maxlength=\"6\" required />"
    } else {
        ""
    }
}

fn render_login(state: &AppState, csrf: &str, nonce: &str, error: &str) -> String {
    let initialized = state
        .mfa_initialized
        .load(std::sync::atomic::Ordering::Acquire);
    include_str!("../static/login.html")
        .replace("{{CSRF}}", &html_escape(csrf))
        .replace("{{NONCE}}", &html_escape(nonce))
        .replace(
            "{{OTP_FIELD}}",
            otp_field(state.config.mfa_enabled && initialized),
        )
        .replace("<!--ERROR-->", error)
}

#[derive(Deserialize)]
struct MfaSetupForm {
    csrf: String,
    otp: String,
}

async fn mfa_setup_page(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    headers: HeaderMap,
) -> Response {
    let Some((_, session)) = current_session(&state, &jar).filter(|(_, s)| s.mfa_pending) else {
        return Redirect::to("/webshell/login").into_response();
    };
    render_mfa_setup(&state, &session, &headers, "")
}

fn render_mfa_setup(
    state: &AppState,
    session: &session::Session,
    headers: &HeaderMap,
    error: &str,
) -> Response {
    let Some(seed) = util::lock(&state.mfa_seed).clone() else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "MFA seed unavailable").into_response();
    };
    let uri = totp::provisioning_uri(&seed, &session.username);
    let qr = match totp::qr_svg(&uri) {
        Ok(qr) => qr,
        Err(e) => {
            tracing::error!("could not render MFA QR: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "could not render MFA QR").into_response();
        }
    };
    let nonce = config::random_token(16);
    let html = include_str!("../static/mfa.html")
        .replace("{{CSRF}}", &html_escape(&session.csrf))
        .replace("{{NONCE}}", &html_escape(&nonce))
        .replace("{{QR}}", &qr)
        .replace("{{SEED}}", &html_escape(&seed))
        .replace("<!--ERROR-->", error);
    (html_headers(&nonce, true, headers), Html(html)).into_response()
}

async fn mfa_setup_submit(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    headers: HeaderMap,
    Form(form): Form<MfaSetupForm>,
) -> Response {
    let Some((id, session)) = current_session(&state, &jar).filter(|(_, s)| s.mfa_pending) else {
        return Redirect::to("/webshell/login").into_response();
    };
    if !csrf_matches(&session.csrf, &form.csrf) {
        return (StatusCode::FORBIDDEN, "invalid CSRF token").into_response();
    }
    // Enrollment verification has the same online-guessing risk as normal OTP
    // login, so it shares the serialized tarpit instead of exposing an
    // unthrottled six-digit endpoint.
    let _login_permit = state.login_guard.acquire().await;
    tokio::time::sleep(state.login_guard.delay()).await;
    let verified = util::lock(&state.mfa_seed)
        .as_deref()
        .is_some_and(|seed| totp::verify(seed, &form.otp));
    // Enrollment consumes the code too: the seed is live from here on, so a
    // code proven here must not also work on the login form.
    if !(verified && state.otp_used.accept(&form.otp)) {
        state.login_guard.record_failure();
        let message = if verified {
            "<p class=\"error\">That code has already been used. \
             Wait for a new code and try again.</p>"
        } else {
            "<p class=\"error\">Invalid code. Wait for a new code and try again.</p>"
        };
        return render_mfa_setup(&state, &session, &headers, message);
    }
    let seed = util::lock(&state.mfa_seed)
        .clone()
        .expect("verified seed exists");
    if let Err(e) = Settings::persist_mfa_seed(&state.config_path, &seed) {
        tracing::error!("could not persist MFA seed: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not save MFA configuration",
        )
            .into_response();
    }
    state
        .mfa_initialized
        .store(true, std::sync::atomic::Ordering::Release);
    state.login_guard.record_success();
    let new_id = state.sessions.login(&id, &session.username);
    let jar = jar.add(session_cookie(&state, new_id));
    tracing::info!("MFA enrollment completed for user {:?}", session.username);
    (jar, Redirect::to("/webshell/private/")).into_response()
}

#[derive(Deserialize)]
struct LogoutForm {
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
