use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket};
use futures::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio::sync::mpsc;

use crate::terminals::{AttachMode, Attachment, PtyCmd, Terminals};

/// Control messages the browser may send as text frames on the mux socket.
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum MuxControl {
    Open {
        term: usize,
        cols: u16,
        rows: u16,
        epoch: Option<u64>,
        offset: Option<u64>,
        #[serde(default)]
        ro: bool,
    },
    Resize { term: usize, cols: u16, rows: u16 },
    Mode { term: usize, ro: bool },
    Close { term: usize },
}

/// One attached slot on a mux connection.
struct Channel {
    input_tx: std::sync::mpsc::Sender<PtyCmd>,
    read_only: bool,
    forward: tokio::task::JoinHandle<()>,
}

impl Channel {
    fn stop(&self) {
        self.forward.abort();
    }
}

fn mode_str(m: AttachMode) -> &'static str {
    match m {
        AttachMode::Resume => "resume",
        AttachMode::Replay => "replay",
    }
}

fn hello_json(term: Option<usize>, a: &Attachment) -> String {
    match term {
        Some(t) => format!(
            r#"{{"type":"hello","term":{},"mode":"{}","epoch":{},"offset":{}}}"#,
            t, mode_str(a.mode), a.epoch, a.base_offset
        ),
        None => format!(
            r#"{{"type":"hello","mode":"{}","epoch":{},"offset":{}}}"#,
            mode_str(a.mode), a.epoch, a.base_offset
        ),
    }
}

fn closed_json(term: usize, reason: &str) -> String {
    format!(r#"{{"type":"closed","term":{},"reason":"{}"}}"#, term, reason)
}

/// Slot-tagged data frame: byte 0 = slot index, rest = payload.
fn tagged(term: usize, bytes: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(bytes.len() + 1);
    v.push(term as u8);
    v.extend_from_slice(bytes);
    v
}

/// Spawn the per-channel forward task: terminal output -> tagged frames,
/// shutdown -> closed frame. All frames go through `out_tx`, the connection's
/// single FIFO writer queue, so hello/replay (queued by the caller BEFORE
/// spawning this task) can never be overtaken by live output.
fn spawn_forward(
    term: usize,
    attachment_parts: (
        tokio::sync::broadcast::Receiver<Vec<u8>>,
        tokio::sync::watch::Receiver<bool>,
    ),
    out_tx: mpsc::Sender<Message>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let (mut output_rx, mut shutdown_rx) = attachment_parts;
        loop {
            tokio::select! {
                // Terminal died or was reset: tell the client; a re-open
                // respawns a fresh shell.
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        let _ = out_tx.send(Message::Text(closed_json(term, "exit"))).await;
                        break;
                    }
                },
                out = output_rx.recv() => match out {
                    Ok(bytes) => {
                        if out_tx.send(Message::Binary(tagged(term, &bytes))).await.is_err() {
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        // Frames were dropped: the byte stream has a hole, so
                        // the client's offset is no longer honest. Close the
                        // channel; the client re-opens with its offset and the
                        // ring heals it (delta or full replay).
                        let _ = out_tx.send(Message::Text(closed_json(term, "error"))).await;
                        break;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                },
            }
        }
    })
}

/// Multiplexed bridge: one WebSocket carrying every opened slot for `user`.
/// Binary frames route by their slot-index prefix; JSON text frames carry
/// control. Attachments drop when the connection dies; shells keep running.
pub async fn mux_bridge(socket: WebSocket, terminals: Arc<Terminals>, user: String) {
    let (mut sink, mut stream) = socket.split();
    let (out_tx, mut out_rx) = mpsc::channel::<Message>(512);

    // Single writer: everything sent to the client funnels through here.
    let writer = tokio::spawn(async move {
        while let Some(m) = out_rx.recv().await {
            if sink.send(m).await.is_err() {
                break;
            }
        }
    });

    let mut channels: HashMap<usize, Channel> = HashMap::new();

    while let Some(msg) = stream.next().await {
        match msg {
            Ok(Message::Binary(b)) => {
                if b.is_empty() {
                    continue;
                }
                let term = b[0] as usize;
                if let Some(ch) = channels.get(&term) {
                    if !ch.read_only {
                        let _ = ch.input_tx.send(PtyCmd::Input(b[1..].to_vec()));
                    }
                }
            }
            Ok(Message::Text(t)) => {
                // Malformed control frames are ignored, never fatal.
                let Ok(ctl) = serde_json::from_str::<MuxControl>(&t) else {
                    tracing::warn!("mux: ignoring malformed control frame");
                    continue;
                };
                match ctl {
                    MuxControl::Open { term, cols, rows, epoch, offset, ro } => {
                        // Last open wins: a re-open replaces the old channel.
                        if let Some(old) = channels.remove(&term) {
                            old.forward.abort();
                            // Ensure the old forward task is fully gone before cutting the new
                            // attachment: an in-flight send after the new hello would corrupt
                            // the client's stream and offset accounting.
                            let _ = old.forward.await;
                        }
                        let resume = match (epoch, offset) {
                            (Some(e), Some(o)) => Some((e, o)),
                            _ => None,
                        };
                        match terminals.attach(&user, term, cols, rows, resume) {
                            Ok(att) => {
                                tracing::info!(
                                    "mux: open user={user:?} term={term} mode={:?}",
                                    att.mode
                                );
                                let hello = hello_json(Some(term), &att);
                                let Attachment {
                                    input_tx,
                                    output_rx,
                                    shutdown_rx,
                                    replay,
                                    ..
                                } = att;
                                // hello + replay queue BEFORE the forward task
                                // exists: FIFO ordering does the rest.
                                if out_tx.send(Message::Text(hello)).await.is_err() {
                                    break;
                                }
                                if out_tx
                                    .send(Message::Binary(tagged(term, &replay)))
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                                let forward =
                                    spawn_forward(term, (output_rx, shutdown_rx), out_tx.clone());
                                channels.insert(
                                    term,
                                    Channel { input_tx, read_only: ro, forward },
                                );
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "mux: attach failed user={user:?} term={term}: {e}"
                                );
                                if out_tx
                                    .send(Message::Text(closed_json(term, "error")))
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                            }
                        }
                    }
                    MuxControl::Resize { term, cols, rows } => {
                        if let Some(ch) = channels.get(&term) {
                            if !ch.read_only {
                                let _ = ch.input_tx.send(PtyCmd::Resize { cols, rows });
                            }
                        }
                    }
                    MuxControl::Mode { term, ro } => {
                        if let Some(ch) = channels.get_mut(&term) {
                            ch.read_only = ro;
                        }
                    }
                    MuxControl::Close { term } => {
                        if let Some(ch) = channels.remove(&term) {
                            ch.stop();
                        }
                    }
                }
            }
            Ok(Message::Close(_)) | Err(_) => break,
            _ => {}
        }
    }

    for (_, ch) in channels {
        ch.stop();
    }
    writer.abort();
    // Do NOT kill any shell here — slots are persistent and resumable.
}

/// Control messages a single-channel (share viewer) client may send.
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum ClientControl {
    Resize { cols: u16, rows: u16 },
}

/// Bridge a WebSocket to ONE attached terminal (share viewers). Sends a
/// hello text frame, then the replay/delta as the first binary frame (even
/// if empty — this keeps the frame sequence uniform: hello, replay, live),
/// then live output. When `read_only` is set, all input and resize frames
/// from this client are dropped (server-enforced). When `deadline` is set
/// (share links), the connection is force-closed at that time so an expired
/// token cannot keep watching a connection it opened before expiry.
pub async fn bridge(
    socket: WebSocket,
    attachment: Attachment,
    read_only: bool,
    deadline: Option<tokio::time::Instant>,
) {
    let hello = hello_json(None, &attachment);
    let Attachment {
        input_tx,
        mut output_rx,
        mut shutdown_rx,
        replay,
        ..
    } = attachment;

    let (mut sink, mut stream) = socket.split();

    if sink.send(Message::Text(hello)).await.is_err() {
        return;
    }
    if sink.send(Message::Binary(replay)).await.is_err() {
        return;
    }

    // Fires at `deadline`, or never when there is none.
    let expiry = async move {
        match deadline {
            Some(d) => tokio::time::sleep_until(d).await,
            None => std::future::pending::<()>().await,
        }
    };
    tokio::pin!(expiry);

    loop {
        tokio::select! {
            // Share token expired mid-session: disconnect the viewer.
            _ = &mut expiry => {
                let _ = sink.send(Message::Close(None)).await;
                break;
            },
            // Terminal died or was reset: disconnect so the client reconnects
            // to the fresh shell instead of staring at a dead one.
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    let _ = sink.send(Message::Close(None)).await;
                    break;
                }
            },
            // Shell output -> browser.
            out = output_rx.recv() => match out {
                Ok(bytes) => {
                    if sink.send(Message::Binary(bytes)).await.is_err() {
                        break;
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                    // The byte stream now has a hole and the viewer's offset
                    // is dishonest: drop the connection; the reconnect heals
                    // via the ring (delta or replay).
                    let _ = sink.send(Message::Close(None)).await;
                    break;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            },
            // Browser -> shell (ignored entirely for read-only viewers).
            msg = stream.next() => match msg {
                Some(Ok(Message::Binary(b))) => {
                    if !read_only {
                        let _ = input_tx.send(PtyCmd::Input(b));
                    }
                }
                Some(Ok(Message::Text(t))) => {
                    if !read_only {
                        if let Ok(ClientControl::Resize { cols, rows }) =
                            serde_json::from_str(&t)
                        {
                            let _ = input_tx.send(PtyCmd::Resize { cols, rows });
                        }
                    }
                }
                Some(Ok(Message::Close(_))) | None => break,
                Some(Err(_)) => break,
                _ => {}
            },
        }
    }

    // Do NOT kill the shell here — slots are persistent and resumable.
}
