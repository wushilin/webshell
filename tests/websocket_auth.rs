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

async fn recv_hello<S>(ws: &mut tokio_tungstenite::WebSocketStream<S>, term: usize)
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
                return;
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
        let message = timeout(Duration::from_secs(2), ws.next())
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
