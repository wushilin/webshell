use axum::extract::ws::{Message, WebSocket};
use futures::{SinkExt, StreamExt};
use serde::Deserialize;

use crate::terminals::{Attachment, PtyCmd};

/// Control messages the browser may send as text frames.
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum ClientControl {
    Resize { cols: u16, rows: u16 },
}

/// Bridge a WebSocket to an attached terminal. When `read_only` is set, all
/// input and resize frames from this client are dropped (server-enforced) so a
/// viewer can watch without affecting the shared shell. When `deadline` is set
/// (share links), the connection is force-closed at that time so an expired
/// token cannot keep watching a connection it opened before expiry.
pub async fn bridge(
    socket: WebSocket,
    attachment: Attachment,
    read_only: bool,
    deadline: Option<tokio::time::Instant>,
) {
    let Attachment {
        input_tx,
        mut output_rx,
        mut shutdown_rx,
        replay,
        ..
    } = attachment;

    let (mut sink, mut stream) = socket.split();

    // Always send the replay as the FIRST frame (even if empty). The client
    // uses "first frame == replay" to suppress terminal report replies while it
    // processes historical output — otherwise xterm.js answers color/status
    // QUERIES embedded in the scrollback and those answers get injected into
    // the live shell as bogus input.
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
                    // Slow client dropped some frames; keep going with live data.
                    continue;
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
