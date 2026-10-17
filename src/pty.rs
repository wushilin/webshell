use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket};
use futures::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio::sync::mpsc;

use crate::terminals::{AttachMode, Attachment, PtyCmd, Redraw, ScreenHandle, Terminals};

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
    Resize {
        term: usize,
        cols: u16,
        rows: u16,
    },
    Mode {
        term: usize,
        ro: bool,
    },
    Close {
        term: usize,
    },
}

/// One attached slot on a mux connection.
struct Channel {
    input_tx: std::sync::mpsc::SyncSender<PtyCmd>,
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

/// Optional `init` member: mode-reinstating sequences the client writes after
/// its reset, before the replay blob. Out-of-band on purpose — inside the
/// replay these bytes would inflate the client's stream offset. The bytes are
/// synthesized DECSETs (ESC, `[?;hl`, digits), so ESC is the only character
/// needing a JSON escape.
fn init_json(init: &[u8]) -> String {
    if init.is_empty() {
        return String::new();
    }
    let ascii: String = init.iter().map(|&b| b as char).collect();
    format!(r#","init":"{}""#, ascii.replace('\u{1b}', "\\u001b"))
}

fn hello_json(term: Option<usize>, a: &Attachment) -> String {
    match term {
        Some(t) => format!(
            r#"{{"type":"hello","term":{},"mode":"{}","epoch":{},"offset":{}{}}}"#,
            t,
            mode_str(a.mode),
            a.epoch,
            a.base_offset,
            init_json(&a.init)
        ),
        None => format!(
            r#"{{"type":"hello","mode":"{}","epoch":{},"offset":{}{}}}"#,
            mode_str(a.mode),
            a.epoch,
            a.base_offset,
            init_json(&a.init)
        ),
    }
}

/// Server-initiated redraw. `screen` is the server's own rendering of the
/// visible grid (see `Scrollback::screen_snapshot`), base64 because it is
/// raw terminal bytes inside a JSON control frame; `cols`/`rows` let the
/// client refuse a snapshot taken at a size it no longer has. Sent as a
/// control frame rather than tagged output on purpose: it is not part of
/// the stream, so it never moves the client's offset, and the client can
/// decide whether to apply it. `term` is present on the mux socket, absent
/// for a viewer.
fn redraw_json(term: Option<usize>, r: &Redraw) -> String {
    use base64::Engine as _;
    let screen = base64::engine::general_purpose::STANDARD.encode(&r.screen);
    match term {
        Some(t) => format!(
            r#"{{"type":"redraw","term":{t},"cols":{},"rows":{},"screen":"{screen}"}}"#,
            r.cols, r.rows
        ),
        None => format!(
            r#"{{"type":"redraw","cols":{},"rows":{},"screen":"{screen}"}}"#,
            r.cols, r.rows
        ),
    }
}

/// A periodic tick that never fires when `period` is `None`. Unlike a bare
/// `interval`, the first tick is one full period out — a redraw straight
/// after the hello would land in the middle of the replay parse.
fn redraw_ticker(period: Option<std::time::Duration>) -> Option<tokio::time::Interval> {
    let period = period?;
    let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    Some(tick)
}

/// Await the next redraw tick, or park forever when there is no ticker.
async fn next_redraw(tick: &mut Option<tokio::time::Interval>) {
    match tick {
        Some(t) => {
            t.tick().await;
        }
        None => std::future::pending::<()>().await,
    }
}

fn closed_json(term: usize, reason: &str) -> String {
    format!(
        r#"{{"type":"closed","term":{},"reason":"{}"}}"#,
        term, reason
    )
}

/// Slot-tagged data frame: byte 0 = slot index, rest = payload.
///
/// The one-byte index is why `slots_per_user` is clamped (see Config): above
/// 255 this cast would silently wrap and route a frame to the wrong terminal.
fn tagged(term: usize, bytes: &[u8]) -> Vec<u8> {
    debug_assert!(
        term <= u8::MAX as usize,
        "slot index must fit in the frame tag"
    );
    let mut v = Vec::with_capacity(bytes.len() + 1);
    v.push(term as u8);
    v.extend_from_slice(bytes);
    v
}

/// Spawn the per-channel forward task: terminal output -> tagged frames,
/// shutdown -> closed frame, and the periodic redraw. All frames go through
/// `out_tx`, the connection's single FIFO writer queue, so hello/replay
/// (queued by the caller BEFORE spawning this task) can never be overtaken
/// by live output.
///
/// The redraw lives here rather than in the connection loop because only
/// this task knows where `output_rx` stands in the stream: the snapshot has
/// to be queued after every byte it already reflects, which
/// `ScreenHandle::redraw` guarantees by draining the receiver under the
/// same lock the reader thread broadcasts under.
fn spawn_forward(
    term: usize,
    attachment_parts: (
        tokio::sync::broadcast::Receiver<Vec<u8>>,
        tokio::sync::watch::Receiver<bool>,
    ),
    screen: ScreenHandle,
    redraw: Option<std::time::Duration>,
    out_tx: mpsc::Sender<Message>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let (mut output_rx, mut shutdown_rx) = attachment_parts;
        let mut redraw_tick = redraw_ticker(redraw);
        loop {
            tokio::select! {
                _ = next_redraw(&mut redraw_tick) => {
                    let r = screen.redraw(&mut output_rx);
                    let mut gone = false;
                    for bytes in &r.pending {
                        if out_tx.send(Message::Binary(tagged(term, bytes))).await.is_err() {
                            gone = true;
                            break;
                        }
                    }
                    if gone {
                        break;
                    }
                    if r.lagged {
                        // Same hole in the stream as the Lagged arm below.
                        let _ = out_tx.send(Message::Text(closed_json(term, "error"))).await;
                        break;
                    }
                    if out_tx.send(Message::Text(redraw_json(Some(term), &r))).await.is_err() {
                        break;
                    }
                },
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
///
/// `redraw` is the period of the server-initiated redraw (see
/// `redraw_json`); every open channel gets one per period.
pub async fn mux_bridge(
    socket: WebSocket,
    terminals: Arc<Terminals>,
    user: String,
    mut revoked: tokio::sync::watch::Receiver<bool>,
    deadline: tokio::time::Instant,
    redraw: Option<std::time::Duration>,
) {
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

    loop {
        let msg = tokio::select! {
            _ = tokio::time::sleep_until(deadline) => break,
            changed = revoked.changed() => {
                if changed.is_err() || *revoked.borrow() { break; }
                continue;
            }
            msg = stream.next() => match msg {
                Some(msg) => msg,
                None => break,
            },
        };
        match msg {
            Ok(Message::Binary(b)) => {
                if b.is_empty() {
                    continue;
                }
                let term = b[0] as usize;
                if let Some(ch) = channels.get(&term) {
                    if !ch.read_only
                        && ch
                            .input_tx
                            .try_send(PtyCmd::Input(b[1..].to_vec()))
                            .is_err()
                    {
                        tracing::warn!(
                            "mux: closing overloaded connection; terminal input queue is full"
                        );
                        break;
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
                    MuxControl::Open {
                        term,
                        cols,
                        rows,
                        epoch,
                        offset,
                        ro,
                    } => {
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
                        // Off the runtime: a cold slot makes this openpty +
                        // fork + exec of the owner's login shell, all while
                        // holding the slot lock. On a reconnect the client
                        // re-opens every slot it had, so those land here
                        // back-to-back — enough to stall a worker for a
                        // visible fraction of a second.
                        let attached = {
                            let terminals = terminals.clone();
                            let user = user.clone();
                            tokio::task::spawn_blocking(move || {
                                let (cols, rows) = valid_size(cols, rows);
                                terminals.attach(&user, term, cols, rows, resume)
                            })
                            .await
                        };
                        // A panic inside the spawn is reported like any other
                        // attach failure rather than taking down the socket.
                        let attached = match attached {
                            Ok(r) => r,
                            Err(e) => Err(format!("spawn task failed: {e}")),
                        };
                        match attached {
                            Ok(att) => {
                                tracing::info!(
                                    "mux: open user={user:?} term={term} mode={:?}",
                                    att.mode
                                );
                                let hello = hello_json(Some(term), &att);
                                let Attachment {
                                    input_tx,
                                    output_rx,
                                    screen,
                                    shutdown_rx,
                                    replay,
                                    ..
                                } = att;
                                // hello + replay queue BEFORE the forward task
                                // exists: FIFO ordering does the rest.
                                //
                                // Note this awaits the writer queue from the
                                // MAIN loop: if a slow client has filled it,
                                // this socket stops reading input for every
                                // slot until it drains. Head-of-line blocking
                                // is self-inflicted (the stalled client is the
                                // one penalised), which is why it is accepted
                                // rather than worked around with a side queue.
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
                                let forward = spawn_forward(
                                    term,
                                    (output_rx, shutdown_rx),
                                    screen,
                                    redraw,
                                    out_tx.clone(),
                                );
                                channels.insert(
                                    term,
                                    Channel {
                                        input_tx,
                                        read_only: ro,
                                        forward,
                                    },
                                );
                            }
                            Err(e) => {
                                tracing::warn!("mux: attach failed user={user:?} term={term}: {e}");
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
                                let (cols, rows) = valid_size(cols, rows);
                                let _ = ch.input_tx.try_send(PtyCmd::Resize { cols, rows });
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

fn valid_size(cols: u16, rows: u16) -> (u16, u16) {
    (cols.clamp(2, 500), rows.clamp(2, 300))
}

/// Bridge a WebSocket to ONE attached terminal (share viewers). Sends a
/// hello text frame, then the replay/delta as the first binary frame (even
/// if empty — this keeps the frame sequence uniform: hello, replay, live),
/// then live output. When `read_only` is set, all input and resize frames
/// from this client are dropped (server-enforced).
///
/// When `lease` is set (share links), the server ends the stream itself, with
/// no help from the client:
///
/// - a timer force-closes the socket at the lease deadline, so a socket opened
///   before expiry cannot keep watching past it;
/// - the wall clock is re-checked against the lease before every frame is
///   forwarded, so nothing is streamed once expired even if the timer and the
///   monotonic clock disagree with wall time (e.g. after a clock step);
/// - the `select!` is `biased` toward the expiry and revocation arms, so a
///   busy output stream cannot win the race against a deadline that has
///   already fired;
/// - revocation closes the socket immediately, and the minute sweep in
///   `ShareStore::sweep` revokes every expired grant, so a socket that somehow
///   outlived its own timer is closed by the scheduler;
/// - the socket also re-checks its own lease on a fixed tick, so it does not
///   depend on any of the above events arriving.
///
/// A viewer that reconnects afterwards is refused at the upgrade, before any
/// attachment exists.
/// How often a share viewer socket re-checks its own lease against the wall
/// clock, as a safety net behind the exact deadline timer.
const SHARE_AUDIT_SECS: u64 = 15;

/// Longest a viewer socket may take to accept one frame before it is dropped.
/// A connected browser drains its socket continuously; one that has stopped
/// for this long is gone or hostile, and holding it pins its attachment.
const VIEWER_STALL_LIMIT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long a closing viewer gets to take the Close frame.
const VIEWER_CLOSE_GRACE: std::time::Duration = std::time::Duration::from_secs(1);

/// Why a [`ViewerOutput`] refused to forward a frame.
enum Stop {
    /// The lease is no longer valid (expired or revoked); a Close frame has
    /// been sent and nothing more will be.
    Invalid,
    /// The peer went away.
    Gone,
}

/// RAII guard over a viewer socket's write half.
///
/// The `SplitSink` is *owned* by this guard and reachable only through
/// [`ViewerOutput::send`], which refuses every frame once the lease is no
/// longer valid — expired *or* revoked, the same check for both, so every
/// way of invalidating a link fails the client identically. Validity is
/// one-way: the wall clock does not run backwards past an expiry, and a
/// revocation is never un-sent, so an invalid guard can never be reactivated.
///
/// The termination paths call [`ViewerOutput::close`], which takes `self` by
/// value: after that, no handle to the socket exists anywhere, so streaming
/// further is not a runtime check but a compile error. Dropping the guard
/// without `close` (a panic, an early return) also drops the sink, which
/// tears the connection down.
struct ViewerOutput {
    sink: futures::stream::SplitSink<WebSocket, Message>,
    lease: Option<crate::share::Lease>,
}

impl ViewerOutput {
    fn new(
        sink: futures::stream::SplitSink<WebSocket, Message>,
        lease: Option<crate::share::Lease>,
    ) -> Self {
        Self { sink, lease }
    }

    /// False once the lease (if any) has expired or been revoked.
    fn valid(&self) -> bool {
        self.lease.as_ref().is_none_or(|l| l.valid())
    }

    /// Forward one frame, unless the lease is no longer valid — in which case
    /// the frame is dropped, a Close is sent instead, and `Err(Stop::Invalid)`
    /// tells the caller to consume the guard. Validity is re-evaluated on
    /// every call, so this holds even if no timer or channel ever fired.
    ///
    /// The write itself is bounded too. A peer that stops reading would
    /// otherwise park this await forever, and while it is parked nothing else
    /// in the bridge runs — no deadline, no revocation. So the write races the
    /// lease ending and a stall limit, and loses the socket to either.
    async fn send(&mut self, msg: Message) -> Result<(), Stop> {
        if !self.valid() {
            let _ = tokio::time::timeout(VIEWER_CLOSE_GRACE, self.sink.send(Message::Close(None)))
                .await;
            return Err(Stop::Invalid);
        }
        let write = tokio::time::timeout(VIEWER_STALL_LIMIT, self.sink.send(msg));
        let Some(lease) = &self.lease else {
            return match write.await {
                Ok(Ok(())) => Ok(()),
                _ => Err(Stop::Gone),
            };
        };
        let mut revoked = lease.revoked.clone();
        tokio::select! {
            r = write => match r {
                Ok(Ok(())) => Ok(()),
                _ => Err(Stop::Gone),
            },
            _ = tokio::time::sleep_until(lease.deadline()) => Err(Stop::Invalid),
            // Revoked, or the sender dropped by a sweep: the same thing here.
            _ = revoked.wait_for(|r| *r) => Err(Stop::Invalid),
        }
    }

    /// End the stream: send Close and give up the sink for good. A peer that
    /// is not reading gets a moment for the Close, then just the drop.
    async fn close(mut self) {
        let _ =
            tokio::time::timeout(VIEWER_CLOSE_GRACE, self.sink.send(Message::Close(None))).await;
        // `self.sink` drops here; the guard is gone.
    }
}

/// Bridge a WebSocket to ONE attached terminal (share viewers). Sends a
/// hello text frame, then the replay/delta as the first binary frame (even
/// if empty — this keeps the frame sequence uniform: hello, replay, live),
/// then live output. When `read_only` is set, all input and resize frames
/// from this client are dropped (server-enforced).
///
/// When `lease` is set (share links), the server ends the stream itself, with
/// no help from the client. The write half of the socket is held by a
/// [`ViewerOutput`] guard that is the only way to emit a frame:
///
/// - the guard checks the lease — wall-clock expiry *and* revocation — before
///   every frame, so nothing is forwarded once it is invalid even if a timer
///   or the monotonic clock disagrees with wall time (e.g. after a clock
///   step), and every invalidation fails the client the same way;
/// - a timer fires at the lease deadline and consumes the guard, so a socket
///   opened before expiry cannot keep watching past it;
/// - the `select!` is `biased` toward the termination arms, so a busy output
///   stream cannot win the race against a deadline that has already fired;
/// - revocation consumes the guard immediately, and the minute sweep in
///   `ShareStore::sweep` revokes every expired grant, so a socket that somehow
///   outlived its own timer is closed by the scheduler;
/// - the socket re-checks its own lease on a fixed tick as well, so it does
///   not depend on any of the above events arriving.
///
/// A viewer that reconnects afterwards is refused at the upgrade, before any
/// attachment exists.
pub async fn bridge(
    socket: WebSocket,
    attachment: Attachment,
    read_only: bool,
    lease: Option<crate::share::Lease>,
    redraw: Option<std::time::Duration>,
) {
    let hello = hello_json(None, &attachment);
    let Attachment {
        input_tx,
        mut output_rx,
        screen,
        mut shutdown_rx,
        replay,
        ..
    } = attachment;

    let (sink, mut stream) = socket.split();

    let deadline = lease.as_ref().map(|l| l.deadline());
    let mut revoked = lease.as_ref().map(|l| l.revoked.clone());
    let mut out = ViewerOutput::new(sink, lease);

    // Nothing leaves the server on an expired lease — not even the hello.
    if out.send(Message::Text(hello)).await.is_err() {
        return;
    }
    if out.send(Message::Binary(replay)).await.is_err() {
        return;
    }

    // Fires at the lease deadline, or never when there is no lease.
    let expiry = async move {
        match deadline {
            Some(d) => tokio::time::sleep_until(d).await,
            None => std::future::pending::<()>().await,
        }
    };
    tokio::pin!(expiry);

    // Resolves when the grant is revoked, or when its sender is dropped —
    // both mean the viewer must go.
    let revocation = async move {
        match revoked.as_mut() {
            Some(rx) => {
                if *rx.borrow() {
                    return;
                }
                let _ = rx.changed().await;
            }
            None => std::future::pending::<()>().await,
        }
    };
    tokio::pin!(revocation);

    // Scheduled self-check: independent of the one-shot deadline, the
    // revocation channel, and any client traffic.
    let leased = out.lease.is_some();
    let mut audit = tokio::time::interval(std::time::Duration::from_secs(SHARE_AUDIT_SECS));
    audit.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut redraw_tick = redraw_ticker(redraw);

    // Every arm below ends the task by `return`, and none of them kills the
    // shell: slots are persistent and resumable.
    loop {
        tokio::select! {
            // Poll in declaration order: the termination arms are checked
            // before any output is forwarded.
            biased;

            // Share token expired mid-session: the guard is consumed here, and
            // the sink with it.
            _ = &mut expiry => {
                out.close().await;
                return;
            },
            _ = &mut revocation => {
                out.close().await;
                return;
            },
            _ = audit.tick(), if leased => {
                if !out.valid() {
                    out.close().await;
                    return;
                }
            },
            // Server-initiated redraw: through the guard like any other
            // frame, so an expired lease gets nothing. Output the snapshot
            // already reflects goes first (see `ScreenHandle::redraw`).
            _ = next_redraw(&mut redraw_tick) => {
                let r = screen.redraw(&mut output_rx);
                for bytes in &r.pending {
                    if out.send(Message::Binary(bytes.clone())).await.is_err() {
                        return;
                    }
                }
                if r.lagged {
                    out.close().await;
                    return;
                }
                if out.send(Message::Text(redraw_json(None, &r))).await.is_err() {
                    return;
                }
            },
            // Terminal died or was reset: disconnect so the client reconnects
            // to the fresh shell instead of staring at a dead one.
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    out.close().await;
                    return;
                }
            },
            // Shell output -> browser, through the guard.
            recv = output_rx.recv() => match recv {
                Ok(bytes) => {
                    if out.send(Message::Binary(bytes)).await.is_err() {
                        // Expired (Close already sent) or peer gone: either
                        // way, drop the guard.
                        return;
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                    // The byte stream now has a hole and the viewer's offset
                    // is dishonest: drop the connection; the reconnect heals
                    // via the ring (delta or replay).
                    out.close().await;
                    return;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
            },
            // Browser -> shell (ignored entirely for read-only viewers).
            msg = stream.next() => match msg {
                Some(Ok(Message::Binary(b))) => {
                    if !read_only {
                        let _ = input_tx.try_send(PtyCmd::Input(b));
                    }
                }
                Some(Ok(Message::Text(t))) => {
                    if !read_only {
                        if let Ok(ClientControl::Resize { cols, rows }) =
                            serde_json::from_str(&t)
                        {
                            let (cols, rows) = valid_size(cols, rows);
                            let _ = input_tx.try_send(PtyCmd::Resize { cols, rows });
                        }
                    }
                }
                Some(Ok(Message::Close(_))) | None => return,
                Some(Err(_)) => return,
                _ => {}
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_init_is_omitted_from_the_hello() {
        assert_eq!(init_json(b""), "");
    }

    #[test]
    fn redraw_frames_carry_the_screen_and_the_slot_only_on_the_mux() {
        use base64::Engine as _;
        let r = Redraw {
            pending: Vec::new(),
            lagged: false,
            cols: 80,
            rows: 24,
            screen: b"\x1b[H\x1b[Jhello".to_vec(),
        };
        let mux: serde_json::Value = serde_json::from_str(&redraw_json(Some(3), &r)).unwrap();
        assert_eq!(mux["type"], "redraw");
        assert_eq!(mux["term"], 3);
        assert_eq!(mux["cols"], 80);
        assert_eq!(mux["rows"], 24);
        let screen = base64::engine::general_purpose::STANDARD
            .decode(mux["screen"].as_str().unwrap())
            .unwrap();
        assert_eq!(screen, r.screen);
        let viewer: serde_json::Value = serde_json::from_str(&redraw_json(None, &r)).unwrap();
        assert_eq!(viewer["type"], "redraw");
        assert!(viewer.get("term").is_none());
    }

    #[tokio::test]
    async fn redraw_ticker_is_silent_when_disabled_and_skips_the_immediate_tick() {
        use std::time::Duration;
        let mut off = redraw_ticker(None);
        assert!(
            tokio::time::timeout(Duration::from_millis(150), next_redraw(&mut off))
                .await
                .is_err(),
            "a disabled ticker never fires"
        );

        // Real time, generous bounds: the point is that the first tick is a
        // full period out rather than immediate, and that ticks keep coming.
        let period = Duration::from_millis(100);
        let mut on = redraw_ticker(Some(period));
        let started = tokio::time::Instant::now();
        next_redraw(&mut on).await;
        let first = started.elapsed();
        assert!(
            first >= period && first < 4 * period,
            "first tick at {first:?}"
        );
        next_redraw(&mut on).await;
        let second = started.elapsed();
        assert!(
            second >= 2 * period && second < 6 * period,
            "second tick at {second:?}"
        );
    }

    #[test]
    fn init_escapes_esc_for_json() {
        let frag = init_json(b"\x1b[?1049h");
        assert_eq!(frag, r#","init":"\u001b[?1049h""#);
        let json = format!(r#"{{"type":"hello"{frag}}}"#);
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(v["init"], "\u{1b}[?1049h");
    }
}
