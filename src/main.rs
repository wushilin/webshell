mod config;
mod pam;
mod pty;
mod session;
mod share;
mod terminals;

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
}

impl LoginGuard {
    fn new() -> Self {
        LoginGuard {
            inner: Mutex::new((0, Instant::now())),
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
        let g = self.inner.lock().unwrap();
        Duration::from_millis((Self::recent_failures(&g) as u64 * 300).min(5000))
    }
    fn record_failure(&self) {
        let mut g = self.inner.lock().unwrap();
        *g = (Self::recent_failures(&g) + 1, Instant::now());
    }
    fn record_success(&self) {
        *self.inner.lock().unwrap() = (0, Instant::now());
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
}

#[derive(clap::Args)]
struct ConfigArgs {
    /// Path to the YAML config file.
    #[arg(short, long, default_value = "config.yaml", env = "WEBSHELL_CONFIG")]
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
        config: "config.yaml".into(),
    }));

    match command {
        Command::Genconfig(a) => genconfig(&a.config),
        Command::Validate(a) => validate(&a.config),
        Command::Run(a) => run_server(&a.config).await,
    }
}

/// Write a default config file (refusing to clobber an existing one).
fn genconfig(path: &std::path::Path) {
    if path.exists() {
        eprintln!("refusing to overwrite existing {}", path.display());
        std::process::exit(1);
    }
    match std::fs::write(path, Settings::sample_yaml()) {
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
        Ok(s) => {
            println!("OK: {} is valid\n", path.display());
            print!("{}", serde_yaml::to_string(&s).unwrap_or_default());
        }
        Err(e) => {
            eprintln!("INVALID: {e}");
            std::process::exit(1);
        }
    }
}

async fn run_server(config_path: &std::path::Path) {
    let settings = if config_path.exists() {
        match Settings::load(Some(config_path)) {
            Ok(s) => {
                tracing::info!("loaded config {}", config_path.display());
                s
            }
            Err(e) => {
                eprintln!("config error: {e}");
                std::process::exit(1);
            }
        }
    } else {
        tracing::warn!(
            "config {} not found; using built-in defaults",
            config_path.display()
        );
        Settings::default()
    };

    let config = Config::from_settings(settings);
    if !config.is_root {
        tracing::warn!(
            "not running as root: shells spawn as the current user (dev mode). \
             Run as root for PAM auth + per-user login shells."
        );
    }

    let sessions = Arc::new(SessionStore::new(config.session_ttl));
    let terminals = Arc::new(Terminals::new(
        config.slots_per_user,
        config.login_cmd.clone(),
        config.owner_home.clone(),
        config.scrollback_cap,
    ));
    let key = load_signing_key(config.secret_base64.as_deref());
    // Share tokens are HMAC-signed with the cookie master key, so they survive
    // restarts as long as the key is stable (a configured secret_base64).
    let shares = Arc::new(ShareStore::new(key.master().to_vec()));
    let bind = config.bind_addr.clone();

    let state = AppState {
        config: Arc::new(config),
        sessions: sessions.clone(),
        terminals,
        shares: shares.clone(),
        prefs: Arc::new(Mutex::new(HashMap::new())),
        login_guard: Arc::new(LoginGuard::new()),
        key,
    };

    // Expire auth sessions (terminal slots are persistent by design). Share
    // tokens are stateless and self-expiring, so there is nothing to sweep.
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            ticker.tick().await;
            sessions.sweep();
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
        .route("/webshell/private/api/prefs", post(set_prefs))
        .layer(middleware::from_fn_with_state(state.clone(), require_auth));

    let app = Router::new()
        .route("/webshell/login", get(login_page).post(login_submit))
        .route("/favicon.ico", get(favicon))
        .route("/webshell/favicon.ico", get(favicon))
        .merge(public)
        .merge(private)
        .route("/webshell", get(|| async { Redirect::to("/webshell/private/") }))
        .route("/webshell/", get(|| async { Redirect::to("/webshell/private/") }))
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
            tracing::warn!(
                "no secret_base64 set; generating ephemeral key \
                 (login sessions AND share links reset on restart)"
            );
            Key::generate()
        }
    }
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

async fn login_page(State(state): State<AppState>, jar: SignedCookieJar) -> Response {
    if authed_session(&state, &jar).is_some() {
        return Redirect::to("/webshell/private/").into_response();
    }
    let (jar, id) = ensure_session(&state, jar);
    let csrf = state.sessions.get(&id).map(|s| s.csrf).unwrap_or_default();
    let html = include_str!("../static/login.html").replace("{{CSRF}}", &html_escape(&csrf));
    (jar, Html(html)).into_response()
}

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
    csrf: String,
}

async fn login_submit(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Form(form): Form<LoginForm>,
) -> Response {
    let Some((id, session)) = current_session(&state, &jar) else {
        return Redirect::to("/webshell/login").into_response();
    };
    if !csrf_matches(&session.csrf, &form.csrf) {
        return (StatusCode::FORBIDDEN, "invalid CSRF token").into_response();
    }

    // Throttle: recent failures add delay before this attempt is processed.
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
        let html = include_str!("../static/login.html")
            .replace("{{CSRF}}", &html_escape(&session.csrf))
            .replace(
                "<!--ERROR-->",
                "<p class=\"error\">Invalid username or password.</p>",
            );
        return (StatusCode::UNAUTHORIZED, Html(html)).into_response();
    };

    // Success: rotate the session id (fixation defense).
    state.login_guard.record_success();
    let new_id = state.sessions.login(&id, &canonical_user);
    let jar = jar.add(session_cookie(&state, new_id));
    tracing::info!("login success for user {:?}", canonical_user);
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
        // Share links are decoupled from the session: they persist until their
        // own TTL expires, so we intentionally do not revoke them here.
        state.sessions.remove(&id);
    }
    let jar = jar.remove(Cookie::from(COOKIE_NAME));
    (jar, Redirect::to("/webshell/login")).into_response()
}

async fn terminal_page(State(state): State<AppState>, jar: SignedCookieJar) -> Response {
    let Some(session) = authed_session(&state, &jar) else {
        return Redirect::to("/webshell/login").into_response();
    };
    let html = include_str!("../static/terminal.html")
        .replace("{{CSRF}}", &html_escape(&session.csrf))
        .replace("{{USER}}", &html_escape(&session.username))
        .replace("{{SLOTS}}", &state.config.slots_per_user.to_string());
    Html(html).into_response()
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
    state.prefs.lock().unwrap().insert(
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
}

#[derive(serde::Serialize)]
struct ShareResponse {
    url: String,
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
    let token = state.shares.create(
        &session.username,
        form.index,
        std::time::Duration::from_secs(ttl_secs),
    );
    let path = format!("/webshell/public/access?token={token}");
    // Absolute URL when a public base URL is configured (correct behind a proxy);
    // otherwise a path the page resolves against its own origin.
    let url = match &state.config.public_base_url {
        Some(base) => format!("{base}{path}"),
        None => path,
    };
    Json(ShareResponse {
        url,
        expires_in_secs: ttl_secs,
    })
    .into_response()
}

#[derive(Deserialize)]
struct AccessQuery {
    token: String,
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
    cols: u16,
    rows: u16,
    font_size: u16,
    font_family: String,
}

/// Metadata a viewer needs to mirror the owner's terminal: the live PTY grid
/// and the owner's font prefs.
async fn access_meta(State(state): State<AppState>, Query(q): Query<AccessQuery>) -> Response {
    let Some((user, index)) = resolve_share(&state, &q.token) else {
        return (StatusCode::FORBIDDEN, "invalid or expired share link").into_response();
    };
    let (cols, rows) = state.terminals.current_size(&user, index).unwrap_or((80, 24));
    let prefs = state.prefs.lock().unwrap().get(&user).cloned();
    let (font_size, font_family) = match prefs {
        Some(p) => (p.font_size, p.font_family),
        None => (14, "ui-monospace, SFMono-Regular, Menlo, monospace".to_string()),
    };
    Json(AccessMeta {
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
async fn access_page(State(state): State<AppState>, Query(q): Query<AccessQuery>) -> Response {
    if resolve_share(&state, &q.token).is_none() {
        return (StatusCode::GONE, Html(SHARE_INVALID_HTML)).into_response();
    }
    Html(include_str!("../static/access.html")).into_response()
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
    let Some((user, index)) = resolve_share(&state, &q.token) else {
        tracing::warn!("access ws: rejected — invalid or expired share token");
        return (StatusCode::FORBIDDEN, "invalid or expired share link").into_response();
    };
    if !origin_allowed(&state, &headers) {
        tracing::warn!(
            "access ws: rejected — origin not allowed: Origin={:?} Host={:?} allowed_origin={:?}",
            header_str(&headers, ORIGIN),
            header_str(&headers, HOST),
            state.config.allowed_origin
        );
        return (StatusCode::FORBIDDEN, "origin not allowed").into_response();
    }
    // Force-close the viewer exactly when the token expires.
    let deadline = state
        .shares
        .remaining_secs(&q.token)
        .map(|s| tokio::time::Instant::now() + std::time::Duration::from_secs(s));
    match state.terminals.attach_view(&user, index) {
        Ok(attachment) => {
            tracing::info!("access ws: attached (viewer) user={user:?} term={index}");
            ws.on_upgrade(move |socket| pty::bridge(socket, attachment, true, deadline))
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
    #[serde(default)]
    term: usize,
    #[serde(default)]
    mode: Option<String>,
    cols: Option<u16>,
    rows: Option<u16>,
}

async fn ws_handler(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Query(q): Query<WsQuery>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    tracing::info!("ws: upgrade request term={} mode={:?}", q.term, q.mode);
    let Some(session) = authed_session(&state, &jar) else {
        tracing::warn!("ws: rejected — not authenticated (no valid session cookie)");
        return (StatusCode::UNAUTHORIZED, "not authenticated").into_response();
    };
    if !csrf_matches(&session.csrf, &q.csrf) {
        tracing::warn!("ws: rejected — CSRF mismatch for user {:?}", session.username);
        return (StatusCode::FORBIDDEN, "invalid CSRF token").into_response();
    }
    if !origin_allowed(&state, &headers) {
        let origin = header_str(&headers, ORIGIN);
        let host = header_str(&headers, HOST);
        tracing::warn!(
            "ws: rejected — origin not allowed: Origin={origin:?} Host={host:?} allowed_origin={:?}",
            state.config.allowed_origin
        );
        return (StatusCode::FORBIDDEN, "origin not allowed").into_response();
    }

    let read_only = q.mode.as_deref() == Some("ro");
    let cols = q.cols.unwrap_or(80);
    let rows = q.rows.unwrap_or(24);

    let attachment = match state
        .terminals
        .attach(&session.username, q.term, cols, rows)
    {
        Ok(a) => {
            tracing::info!("ws: attached user={:?} term={}", session.username, q.term);
            a
        }
        Err(e) => {
            tracing::error!(
                "ws: attach/spawn failed for user {:?} term {}: {e}",
                session.username,
                q.term
            );
            return (StatusCode::BAD_REQUEST, e).into_response();
        }
    };

    ws.on_upgrade(move |socket| pty::bridge(socket, attachment, read_only, None))
}

fn header_str(headers: &HeaderMap, name: axum::http::HeaderName) -> String {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("<none>")
        .to_string()
}

/// Reject cross-site WebSocket upgrades: `Origin` must match the configured
/// allowed origin, or the request `Host`. A missing `Origin` is rejected.
fn origin_allowed(state: &AppState, headers: &HeaderMap) -> bool {
    let Some(origin) = headers.get(ORIGIN).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    if let Some(allowed) = &state.config.allowed_origin {
        return origin == allowed;
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
