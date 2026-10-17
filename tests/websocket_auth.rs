use std::process::{Child, Command, Stdio};
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use reqwest::header::{COOKIE, LOCATION, SET_COOKIE};
use reqwest::{Client, StatusCode};
use serde_json::{json, Value};
use tokio::time::{sleep, timeout, Instant};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::http::Request as WsRequest;
use tokio_tungstenite::tungstenite::Message;

struct TestServer {
    child: Child,
    http: String,
    ws: String,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl TestServer {
    async fn start() -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let child = Command::new(env!("CARGO_BIN_EXE_webshell"))
            .arg("simple")
            .env("WEBSHELL_BIND", format!("127.0.0.1:{port}"))
            .env("WEBSHELL_USER", "integration")
            .env("WEBSHELL_PASSWORD", "test-password")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start test server");
        let server = Self {
            child,
            http: format!("http://127.0.0.1:{port}"),
            ws: format!("ws://127.0.0.1:{port}"),
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

    async fn login(&self) -> (String, String) {
        let client = http_client();
        let login = client
            .get(format!("{}/webshell/login", self.http))
            .send()
            .await
            .unwrap();
        assert_eq!(login.status(), StatusCode::OK);
        let cookie = response_cookie(&login);
        let csrf = hidden_value(&login.text().await.unwrap(), "csrf");

        let response = client
            .post(format!("{}/webshell/login/local", self.http))
            .header(COOKIE, &cookie)
            .form(&[
                ("csrf", csrf.as_str()),
                ("username", "integration"),
                ("password", "test-password"),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers()[LOCATION], "/webshell/private/");
        let cookie = response_cookie(&response);

        let terminal = client
            .get(format!("{}/webshell/private/", self.http))
            .header(COOKIE, &cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(terminal.status(), StatusCode::OK);
        let csrf = js_constant(&terminal.text().await.unwrap(), "CSRF");
        (cookie, csrf)
    }
}

fn http_client() -> Client {
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

fn response_cookie(response: &reqwest::Response) -> String {
    response.headers()[SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string()
}

fn hidden_value(html: &str, name: &str) -> String {
    let marker = format!("name=\"{name}\" value=\"");
    let rest = html.split_once(&marker).expect("hidden input").1;
    rest.split_once('"').unwrap().0.to_string()
}

fn js_constant(html: &str, name: &str) -> String {
    let marker = format!("const {name} = \"");
    let rest = html.split_once(&marker).expect("JavaScript constant").1;
    rest.split_once('"').unwrap().0.to_string()
}

fn ws_request(url: String, cookie: Option<&str>, origin: &str) -> WsRequest<()> {
    let mut request = url.into_client_request().unwrap();
    request
        .headers_mut()
        .insert("Origin", HeaderValue::from_str(origin).unwrap());
    if let Some(cookie) = cookie {
        request
            .headers_mut()
            .insert("Cookie", HeaderValue::from_str(cookie).unwrap());
    }
    request
}

async fn expect_ws_status(request: WsRequest<()>, expected: StatusCode) {
    let error = tokio_tungstenite::connect_async(request).await.unwrap_err();
    let status = match error {
        tokio_tungstenite::tungstenite::Error::Http(response) => response.status(),
        other => panic!("expected HTTP rejection, got {other}"),
    };
    assert_eq!(status.as_u16(), expected.as_u16());
}

async fn recv_hello<S>(ws: &mut tokio_tungstenite::WebSocketStream<S>, term: usize) -> Value
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    loop {
        let message = timeout(Duration::from_secs(10), ws.next())
            .await
            .expect("hello timeout")
            .expect("socket closed")
            .expect("websocket read");
        if let Message::Text(text) = message {
            let value: Value = serde_json::from_str(&text).unwrap();
            if value["type"] == "hello" && value["term"] == term {
                return value;
            }
        }
    }
}

async fn run_command<S>(
    ws: &mut tokio_tungstenite::WebSocketStream<S>,
    term: u8,
    command: &str,
    marker: &str,
) -> Vec<u8>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut input = vec![term];
    input.extend_from_slice(command.as_bytes());
    ws.send(Message::Binary(input)).await.unwrap();

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut output = Vec::new();
    while Instant::now() < deadline {
        // Generous per-frame wait: every test here boots its own server and
        // login shell, and they all run in parallel on the same box.
        let message = timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("command output timeout")
            .expect("socket closed")
            .expect("websocket read");
        if let Message::Binary(bytes) = message {
            if bytes.first() == Some(&term) {
                output.extend_from_slice(&bytes[1..]);
                if output.windows(marker.len()).any(|w| w == marker.as_bytes()) {
                    return output;
                }
            }
        }
    }
    panic!(
        "did not receive command marker; output={:?}",
        String::from_utf8_lossy(&output)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authentication_guards_http_and_websocket() {
    let server = TestServer::start().await;
    let client = http_client();
    let private = client
        .get(format!("{}/webshell/private/api/terminals", server.http))
        .send()
        .await
        .unwrap();
    assert_eq!(private.status(), StatusCode::UNAUTHORIZED);

    expect_ws_status(
        ws_request(
            format!("{}/webshell/private/ws?csrf=missing", server.ws),
            None,
            &server.http,
        ),
        StatusCode::UNAUTHORIZED,
    )
    .await;

    let (cookie, csrf) = server.login().await;
    expect_ws_status(
        ws_request(
            format!("{}/webshell/private/ws?csrf=wrong", server.ws),
            Some(&cookie),
            &server.http,
        ),
        StatusCode::FORBIDDEN,
    )
    .await;
    expect_ws_status(
        ws_request(
            format!("{}/webshell/private/ws?csrf={csrf}", server.ws),
            Some(&cookie),
            "https://attacker.invalid",
        ),
        StatusCode::FORBIDDEN,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mux_runs_commands_in_two_terminal_slots() {
    let server = TestServer::start().await;
    let (cookie, csrf) = server.login().await;

    // Font preferences are browser rendering state, but the authenticated API
    // that publishes them to read-only viewers must accept the update.
    let prefs = http_client()
        .post(format!("{}/webshell/private/api/prefs", server.http))
        .header(COOKIE, &cookie)
        .form(&[
            ("csrf", csrf.as_str()),
            ("font_size", "17"),
            ("font_family", "monospace"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(prefs.status(), StatusCode::NO_CONTENT);

    let request = ws_request(
        format!("{}/webshell/private/ws?csrf={csrf}", server.ws),
        Some(&cookie),
        &server.http,
    );
    let (mut ws, _) = tokio_tungstenite::connect_async(request).await.unwrap();

    for term in 0..=1 {
        ws.send(Message::Text(
            json!({"type":"open", "term":term, "cols":80, "rows":24}).to_string(),
        ))
        .await
        .unwrap();
        recv_hello(&mut ws, term).await;
    }

    let plain = run_command(
        &mut ws,
        0,
        "command ls /; printf '\\n\\105\\116\\104\\060\\n'\n",
        "END0",
    )
    .await;
    assert!(plain.windows(3).any(|w| w == b"tmp"));

    let colored = run_command(
        &mut ws,
        1,
        "command ls --color=always /; printf '\\n\\105\\116\\104\\061\\n'\n",
        "END1",
    )
    .await;
    assert!(colored.windows(3).any(|w| w == b"tmp"));
    assert!(colored.windows(2).any(|w| w == b"\x1b["));

    // Exercise the same resize control frames emitted by xterm's fit addon,
    // and ask the PTY itself to report its geometry after each transition.
    ws.send(Message::Text(
        json!({"type":"resize", "term":0, "cols":101, "rows":31}).to_string(),
    ))
    .await
    .unwrap();
    let resized = run_command(
        &mut ws,
        0,
        "stty size; printf '\\n\\122\\123\\132\\061\\n'\n",
        "RSZ1",
    )
    .await;
    assert!(resized.windows(6).any(|w| w == b"31 101"));

    ws.send(Message::Text(
        json!({"type":"resize", "term":0, "cols":80, "rows":24}).to_string(),
    ))
    .await
    .unwrap();
    let restored = run_command(
        &mut ws,
        0,
        "stty size; printf '\\n\\122\\123\\132\\062\\n'\n",
        "RSZ2",
    )
    .await;
    assert!(restored.windows(5).any(|w| w == b"24 80"));

    let slots: Value = http_client()
        .get(format!("{}/webshell/private/api/terminals", server.http))
        .header(COOKIE, &cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(slots[0]["running"], true);
    assert_eq!(slots[1]["running"], true);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replay_hello_reinstates_alt_screen_scrolled_out_of_the_ring() {
    let server = TestServer::start().await;
    let (cookie, csrf) = server.login().await;

    let request = ws_request(
        format!("{}/webshell/private/ws?csrf={csrf}", server.ws),
        Some(&cookie),
        &server.http,
    );
    let (mut ws, _) = tokio_tungstenite::connect_async(request).await.unwrap();
    ws.send(Message::Text(
        json!({"type":"open", "term":0, "cols":80, "rows":24}).to_string(),
    ))
    .await
    .unwrap();
    recv_hello(&mut ws, 0).await;

    // A fullscreen app enters the alt screen (octal escapes, so the command's
    // own echo carries no real ESC), then floods well past the 128 KiB
    // scrollback ring, trimming the enable sequence out of the replay window.
    run_command(
        &mut ws,
        0,
        "printf '\\033[?1049h'; head -c 200000 /dev/zero | tr '\\0' x; printf '\\n\\104\\117\\116\\105\\060\\n'\n",
        "DONE0",
    )
    .await;

    // A fresh attachment (no resume state) gets a full replay. Its hello must
    // reinstate the still-active alt screen that the ring no longer shows —
    // otherwise the app redraws into the primary buffer and its exit leaves
    // the screen unrestored.
    let request = ws_request(
        format!("{}/webshell/private/ws?csrf={csrf}", server.ws),
        Some(&cookie),
        &server.http,
    );
    let (mut ws2, _) = tokio_tungstenite::connect_async(request).await.unwrap();
    ws2.send(Message::Text(
        json!({"type":"open", "term":0, "cols":80, "rows":24}).to_string(),
    ))
    .await
    .unwrap();
    let hello = recv_hello(&mut ws2, 0).await;
    assert_eq!(hello["mode"], "replay");
    let init = hello["init"].as_str().expect("replay hello carries init");
    assert!(init.contains("\u{1b}[?1049h"), "init={init:?}");
}

/// Wait for a server-sent `redraw` control frame, returning how long it took
/// and the frame. Everything else (output, other control frames) is drained
/// meanwhile.
async fn wait_for_redraw<S>(
    ws: &mut tokio_tungstenite::WebSocketStream<S>,
    term: Option<u64>,
    max: Duration,
) -> (Duration, Value)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let started = Instant::now();
    loop {
        let remaining = max.saturating_sub(started.elapsed());
        let message = timeout(remaining, ws.next())
            .await
            .expect("no redraw tick within the deadline")
            .expect("socket closed")
            .expect("websocket read");
        if let Message::Text(text) = message {
            let value: Value = serde_json::from_str(&text).unwrap();
            if value["type"] == "redraw" {
                match term {
                    Some(t) => assert_eq!(value["term"], t, "tick names its slot"),
                    None => assert!(value.get("term").is_none(), "viewer ticks carry no slot"),
                }
                return (started.elapsed(), value);
            }
        }
    }
}

/// The screen a `redraw` frame carries, decoded and rendered to plain text
/// by feeding it to a fresh emulator of the advertised size.
fn redraw_screen_text(frame: &Value) -> String {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(frame["screen"].as_str().expect("redraw carries a screen"))
        .unwrap();
    let rows = frame["rows"].as_u64().unwrap() as u16;
    let cols = frame["cols"].as_u64().unwrap() as u16;
    let mut parser = vt100::Parser::new(rows, cols, 0);
    parser.process(&bytes);
    parser.screen().contents()
}

/// The server-initiated redraw: after a slot is opened, the mux carries a
/// `redraw` control frame for it once per `redraw_interval_secs` (the default
/// 30s in simple mode), holding the server's own rendering of the visible
/// screen. It rides outside the byte stream, so it cannot disturb the shell
/// or the stream offset.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mux_sends_a_periodic_redraw_with_the_servers_screen() {
    let server = TestServer::start().await;
    let (cookie, csrf) = server.login().await;
    let mut ws = open_slot_zero(&server, &cookie, &csrf).await;

    // Put something recognisable on the screen. Not waited for: the first
    // redraw is a full period out, long after any shell has run this.
    ws.send(Message::Binary(b"\x00echo REDRAW-MARKER-7\n".to_vec()))
        .await
        .unwrap();

    // The first tick is one full period out, never immediately after the
    // hello. (One period is as long as this test can afford to wait; the
    // ticker's cadence beyond that is unit-tested in pty.rs.)
    let (first, frame) = wait_for_redraw(&mut ws, Some(0), Duration::from_secs(45)).await;
    assert!(
        first >= Duration::from_secs(25),
        "first tick after {first:?}"
    );
    assert_eq!(frame["cols"], 80);
    assert_eq!(frame["rows"], 24);
    let screen = redraw_screen_text(&frame);
    assert!(
        screen.contains("REDRAW-MARKER-7"),
        "the server's screen shows what the shell printed: {screen:?}"
    );

    // Not a resize in disguise: the PTY geometry is untouched by the ticks.
    let size = run_command(
        &mut ws,
        0,
        "stty size; printf '\\n\\122\\104\\127\\061\\n'\n",
        "RDW1",
    )
    .await;
    assert!(size.windows(5).any(|w| w == b"24 80"));
}

/// A read-only share viewer gets the same tick on its single-channel socket,
/// without a slot index.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn share_viewer_receives_the_redraw_tick() {
    let server = TestServer::start().await;
    let (cookie, csrf) = server.login().await;
    let _owner = open_slot_zero(&server, &cookie, &csrf).await;

    let share = create_share(&server, &cookie, &csrf, 3600).await;
    let token = share_token(&share);
    let mut viewer = connect_viewer(&server, &token).await;
    let (took, frame) = wait_for_redraw(&mut viewer, None, Duration::from_secs(45)).await;
    assert!(took >= Duration::from_secs(25), "tick after {took:?}");
    assert!(frame["screen"].is_string() && frame["cols"] == 80 && frame["rows"] == 24);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shells_do_not_inherit_the_servers_secrets() {
    // Simple mode is started with WEBSHELL_PASSWORD in its environment; a
    // shell that could print it would hand it to every share viewer.
    let server = TestServer::start().await;
    let (cookie, csrf) = server.login().await;
    let mut ws = open_slot_zero(&server, &cookie, &csrf).await;
    let output = run_command(
        &mut ws,
        0,
        // The marker is spelled in octal so the echoed command line, which
        // also comes back, cannot satisfy it.
        "env | grep -c '^WEBSHELL_'; printf '\\n\\105\\116\\126\\060\\n'\n",
        "ENV0",
    )
    .await;
    let text = String::from_utf8_lossy(&output);
    assert!(!text.contains("test-password"), "secret leaked: {text:?}");
    // grep's count, then printf's blank line and marker, through the tty.
    assert!(
        text.contains("0\r\n\r\nENV0"),
        "expected no WEBSHELL_ variables; output={text:?}"
    );
}

/// Open slot 0 on the authenticated mux so a viewer has something to attach
/// to, and keep the mux socket alive for the caller.
async fn open_slot_zero(
    server: &TestServer,
    cookie: &str,
    csrf: &str,
) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>> {
    let request = ws_request(
        format!("{}/webshell/private/ws?csrf={csrf}", server.ws),
        Some(cookie),
        &server.http,
    );
    let (mut ws, _) = tokio_tungstenite::connect_async(request).await.unwrap();
    ws.send(Message::Text(
        json!({"type":"open", "term":0, "cols":80, "rows":24}).to_string(),
    ))
    .await
    .unwrap();
    recv_hello(&mut ws, 0).await;
    ws
}

async fn create_share(server: &TestServer, cookie: &str, csrf: &str, ttl_secs: u64) -> Value {
    let response = http_client()
        .post(format!("{}/webshell/private/api/share", server.http))
        .header(COOKIE, cookie)
        .form(&[
            ("csrf", csrf),
            ("index", "0"),
            ("ttl_secs", &ttl_secs.to_string()),
            ("note", "test"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response.json().await.unwrap()
}

fn share_token(share: &Value) -> String {
    let url = share["url"].as_str().unwrap();
    url.split_once("token=").unwrap().1.to_string()
}

/// Connect a read-only viewer and consume the hello + replay frames.
async fn connect_viewer(
    server: &TestServer,
    token: &str,
) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>> {
    let request = ws_request(
        format!("{}/webshell/public/access/ws?token={token}", server.ws),
        None,
        &server.http,
    );
    let (mut viewer, _) = tokio_tungstenite::connect_async(request).await.unwrap();
    let hello = timeout(Duration::from_secs(5), viewer.next())
        .await
        .expect("viewer hello timeout")
        .expect("viewer closed")
        .unwrap();
    assert!(
        matches!(hello, Message::Text(_)),
        "first frame is the hello"
    );
    let replay = timeout(Duration::from_secs(5), viewer.next())
        .await
        .expect("viewer replay timeout")
        .expect("viewer closed")
        .unwrap();
    assert!(
        matches!(replay, Message::Binary(_)),
        "second frame is the replay"
    );
    viewer
}

/// Drain a viewer until the server closes it, returning how long that took
/// and whether the close came from the server (a Close frame or EOF) rather
/// than from anything the client did.
async fn wait_for_server_close<S>(
    viewer: &mut tokio_tungstenite::WebSocketStream<S>,
    max: Duration,
) -> Duration
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let started = Instant::now();
    loop {
        match timeout(max, viewer.next()).await {
            Err(_) => panic!("server did not close the viewer within {max:?}"),
            Ok(None) | Ok(Some(Ok(Message::Close(_)))) | Ok(Some(Err(_))) => {
                return started.elapsed();
            }
            Ok(Some(Ok(_))) => continue,
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn share_viewer_is_closed_by_the_server_at_expiry() {
    let server = TestServer::start().await;
    let (cookie, csrf) = server.login().await;
    let mut owner = open_slot_zero(&server, &cookie, &csrf).await;

    let share = create_share(&server, &cookie, &csrf, 2).await;
    let token = share_token(&share);
    let mut viewer = connect_viewer(&server, &token).await;

    // Keep the shell producing output the whole time, so a viewer that was
    // still allowed to stream would have frames to receive.
    // Through `sh` so it works whatever the login shell is.
    owner
        .send(Message::Binary(
            b"\x00sh -c 'while :; do echo tick; sleep 0.1; done'\n".to_vec(),
        ))
        .await
        .unwrap();

    // The viewer never polls status and never disconnects on its own: the
    // server has to end it, and within the token's lifetime plus slack.
    let took = wait_for_server_close(&mut viewer, Duration::from_secs(6)).await;
    assert!(took <= Duration::from_millis(3500), "closed after {took:?}");

    // Once expired, no new stream can be opened with that token...
    let request = ws_request(
        format!("{}/webshell/public/access/ws?token={token}", server.ws),
        None,
        &server.http,
    );
    expect_ws_status(request, StatusCode::FORBIDDEN).await;

    // ...and the status/meta endpoints agree.
    let status: Value = http_client()
        .get(format!(
            "{}/webshell/public/access/status?token={token}",
            server.http
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(status["valid"], false);
    let meta = http_client()
        .get(format!(
            "{}/webshell/public/access/meta?token={token}",
            server.http
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(meta.status(), StatusCode::FORBIDDEN);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn share_viewer_is_closed_by_the_server_on_revocation() {
    let server = TestServer::start().await;
    let (cookie, csrf) = server.login().await;
    let _owner = open_slot_zero(&server, &cookie, &csrf).await;

    let share = create_share(&server, &cookie, &csrf, 3600).await;
    let token = share_token(&share);
    let grant_id = share["grant_id"].as_str().unwrap().to_string();
    let mut viewer = connect_viewer(&server, &token).await;

    let revoke = http_client()
        .post(format!("{}/webshell/private/api/share/revoke", server.http))
        .header(COOKIE, &cookie)
        .form(&[("csrf", csrf.as_str()), ("grant_id", grant_id.as_str())])
        .send()
        .await
        .unwrap();
    assert!(revoke.status().is_success(), "revoke: {}", revoke.status());

    // Revocation is pushed to the live viewer, not discovered at next poll.
    let took = wait_for_server_close(&mut viewer, Duration::from_secs(5)).await;
    assert!(took <= Duration::from_secs(2), "closed after {took:?}");

    let request = ws_request(
        format!("{}/webshell/public/access/ws?token={token}", server.ws),
        None,
        &server.http,
    );
    expect_ws_status(request, StatusCode::FORBIDDEN).await;
}
