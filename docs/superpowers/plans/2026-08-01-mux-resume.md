# Single-socket mux + offset resume — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** All terminal slots ride one WebSocket; on reconnect each slot resumes from a client-held byte offset (delta from the scrollback ring) instead of a full replay.

**Architecture:** Server: `Scrollback` gains a monotonic `total` counter and a `cut()` resume decision; `Terminal` gains a per-spawn `epoch`; a new mux bridge in `pty.rs` owns per-slot channels over one socket, all outbound frames funneled through one FIFO queue. Client: a `Conn` singleton owns the socket + reconnect/status/logout logic; each `Session` becomes a channel with `epoch`/`offset` resume state. The share page keeps its endpoint but gains the same hello/offset exchange (untagged frames, single implicit channel).

**Tech Stack:** Rust (axum 0.7, tokio, portable-pty), xterm.js 5.5 (CDN), vanilla JS inline in HTML.

**Spec:** `docs/superpowers/specs/2026-08-01-mux-resume-design.md` — read it first.

## Global Constraints

- Client JS syntax gate after EVERY terminal.html or access.html change:

  ```bash
  python3 - <<'EOF'
  import re
  for f in ("static/terminal.html", "static/access.html"):
      html = open(f).read()
      js = re.findall(r'<script>(.*?)</script>', html, re.S)[0]
      open("/tmp/claude-1001/-home-code-workspace-webshell/fc588ed8-b320-457e-b81a-0b8c14cc16b7/scratchpad/chk.js", "w").write(js)
      import subprocess, sys
      r = subprocess.run(["node", "--check", "/tmp/claude-1001/-home-code-workspace-webshell/fc588ed8-b320-457e-b81a-0b8c14cc16b7/scratchpad/chk.js"])
      if r.returncode: sys.exit(f"SYNTAX FAIL {f}")
  print("SYNTAX-OK")
  EOF
  ```

- Rust gate after every server change: `cargo test` (links locally; verified).
- Commit after each task. Commit messages end with:

  ```
  Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_014JpU84cXrJ8o5zuhafCCGw
  ```

- Wire protocol (normative, from the spec):
  - Binary frame = terminal data, byte 0 = slot index, rest = payload.
  - Text frame = JSON control. Client→server: `open` (`term`, `cols`, `rows`, optional `epoch`+`offset`, `ro` bool defaulting false), `resize` (`term`, `cols`, `rows`), `mode` (`term`, `ro`), `close` (`term`). Server→client: `hello` (`term`, `mode`:"resume"|"replay", `epoch`, `offset`), `closed` (`term`, `reason`:"exit"|"error").
  - `hello.offset` = stream position where the data that follows begins. The server ALWAYS sends one (possibly empty) tagged replay/delta frame immediately after each hello, before any live output.
  - Access (share) endpoint: same hello/closed JSON without the `term` field; binary frames untagged (single implicit channel); resume state travels as `&epoch=E&offset=N` query params.
- Deviations from spec (agreed): `closed.reason` has no separate `"reset"` value (server cannot distinguish reset from exit; the client treats them identically). After the 30-failure give-up, only a page reload revives (read-only toggle and reset no longer touch the socket, so they can no longer serve as revival actions).
- DO NOT deploy or restart the remote server in Tasks 1–5. Task 6 gates deploy on explicit user approval (a restart kills live shell sessions).

---

### Task 1: terminals.rs — epoch, total counter, resume cut (TDD)

**Files:**
- Modify: `src/terminals.rs`
- Test: `src/terminals.rs` (`#[cfg(test)] mod tests` at the bottom)

**Interfaces:**
- Consumes: existing `Scrollback`, `Terminal`, `Attachment`, `Terminals::attach`, `Terminals::attach_view`.
- Produces (later tasks rely on these exact shapes):

  ```rust
  #[derive(Clone, Copy, PartialEq, Eq, Debug)]
  pub enum AttachMode { Resume, Replay }

  pub struct Attachment {
      pub input_tx: std::sync::mpsc::Sender<PtyCmd>,
      pub output_rx: broadcast::Receiver<Vec<u8>>,
      pub shutdown_rx: watch::Receiver<bool>,
      pub replay: Vec<u8>,          // full snapshot (Replay) or missed tail (Resume); may be empty
      pub mode: AttachMode,
      pub epoch: u64,               // identity of this shell spawn
      pub base_offset: u64,         // stream position where `replay` begins
  }

  pub fn attach(&self, user: &str, index: usize, cols: u16, rows: u16,
                resume: Option<(u64, u64)>) -> Result<Attachment, String>
  pub fn attach_view(&self, user: &str, index: usize,
                     resume: Option<(u64, u64)>) -> Result<Attachment, String>
  ```

  `resume` is `(epoch, offset)` from the client; a mismatched epoch or `None` forces `Replay`.

- [ ] **Step 1: Write the failing tests**

At the bottom of `src/terminals.rs` add:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_open_is_full_replay() {
        let mut s = Scrollback::new(10);
        s.push(b"hello");
        let (mode, base, bytes) = s.cut(None);
        assert_eq!(mode, AttachMode::Replay);
        assert_eq!(base, 0);
        assert_eq!(bytes, b"hello");
    }

    #[test]
    fn resume_within_window_returns_missed_tail() {
        let mut s = Scrollback::new(10);
        s.push(b"hello"); // client saw these 5 bytes
        s.push(b"world"); // client missed these 5
        let (mode, base, bytes) = s.cut(Some(5));
        assert_eq!(mode, AttachMode::Resume);
        assert_eq!(base, 5);
        assert_eq!(bytes, b"world");
    }

    #[test]
    fn resume_up_to_date_returns_empty_delta() {
        let mut s = Scrollback::new(10);
        s.push(b"hello");
        let (mode, base, bytes) = s.cut(Some(5));
        assert_eq!(mode, AttachMode::Resume);
        assert_eq!(base, 5);
        assert!(bytes.is_empty());
    }

    #[test]
    fn missing_more_than_the_ring_replays() {
        let mut s = Scrollback::new(4);
        s.push(b"hello"); // total 5, ring holds "ello"
        let (mode, base, bytes) = s.cut(Some(0)); // missed 5 > ring 4
        assert_eq!(mode, AttachMode::Replay);
        assert_eq!(base, 1);
        assert_eq!(bytes, b"ello");
    }

    #[test]
    fn exact_window_fit_resumes() {
        let mut s = Scrollback::new(4);
        s.push(b"hello"); // total 5, ring "ello"
        let (mode, base, bytes) = s.cut(Some(1)); // missed 4 == ring len
        assert_eq!(mode, AttachMode::Resume);
        assert_eq!(base, 1);
        assert_eq!(bytes, b"ello");
    }

    #[test]
    fn bogus_future_offset_replays() {
        let mut s = Scrollback::new(10);
        s.push(b"hello");
        let (mode, base, bytes) = s.cut(Some(99)); // offset > total: bogus client
        assert_eq!(mode, AttachMode::Replay);
        assert_eq!(base, 0);
        assert_eq!(bytes, b"hello");
    }

    #[test]
    fn total_keeps_counting_past_the_cap() {
        let mut s = Scrollback::new(4);
        s.push(b"aaaa");
        s.push(b"bbbb");
        s.push(b"cc");
        let (mode, base, bytes) = s.cut(None);
        assert_eq!(mode, AttachMode::Replay);
        assert_eq!(base, 6);              // total 10 − ring 4
        assert_eq!(bytes, b"bbcc");
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test`
Expected: compile errors — `cut` and `AttachMode` do not exist yet. That IS the failing state for compiled languages.

- [ ] **Step 3: Implement**

In `src/terminals.rs`:

3a. Extend imports (top of file): change the atomic import line to

```rust
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
```

3b. Below the `PtyCmd` enum add:

```rust
/// Identity of a shell spawn. A client resuming with a stale epoch (the
/// shell was reset/respawned meanwhile) gets a full replay, never a delta
/// spliced across two different shells.
static NEXT_EPOCH: AtomicU64 = AtomicU64::new(1);

/// How an attachment's `replay` bytes relate to what the client already has.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AttachMode {
    /// `replay` is exactly the bytes the client is missing; no reset needed.
    Resume,
    /// `replay` is the full ring; the client must reset and redraw.
    Replay,
}
```

3c. Extend `Scrollback` with the monotonic counter and the resume decision:

```rust
struct Scrollback {
    buf: VecDeque<u8>,
    cap: usize,
    /// Total bytes ever pushed since spawn (monotonic, not capped). The
    /// client mirrors this count; resume = serving the difference.
    total: u64,
}
```

`new` gains `total: 0`; `push` becomes:

```rust
    fn push(&mut self, data: &[u8]) {
        self.total += data.len() as u64;
        self.buf.extend(data.iter().copied());
        while self.buf.len() > self.cap {
            self.buf.pop_front();
        }
    }
```

Add after `snapshot()`:

```rust
    /// Cut point for a new attachment. `offset` is the client's stream
    /// position (None = no resume state / epoch mismatch). Returns
    /// (mode, base_offset, bytes-to-send): Resume with exactly the missed
    /// tail when the offset is valid and within the ring, else Replay with
    /// the full ring. Checked arithmetic: an offset beyond `total` (bogus
    /// client) can never underflow — it degrades to Replay.
    fn cut(&self, offset: Option<u64>) -> (AttachMode, u64, Vec<u8>) {
        if let Some(off) = offset {
            if let Some(missed) = self.total.checked_sub(off) {
                if missed <= self.buf.len() as u64 {
                    let start = self.buf.len() - missed as usize;
                    let bytes: Vec<u8> = self.buf.iter().skip(start).copied().collect();
                    return (AttachMode::Resume, off, bytes);
                }
            }
        }
        let bytes = self.snapshot();
        (AttachMode::Replay, self.total - bytes.len() as u64, bytes)
    }
```

3d. `Terminal` struct gains `epoch: u64` (doc comment: `/// Identity of this spawn; see NEXT_EPOCH.`). In `spawn_terminal`'s final struct literal add `epoch: NEXT_EPOCH.fetch_add(1, Ordering::Relaxed),`.

3e. `Attachment` becomes the shape shown in **Interfaces** (add `mode`, `epoch`, `base_offset` fields with the doc comments shown there).

3f. `attach` gains the `resume: Option<(u64, u64)>` parameter. Replace its final section (from `let sb = term.scrollback...` to the `Ok(Attachment {...})`) with:

```rust
        // Resume only against the same shell instance; a stale epoch means
        // the client's offset counts a different shell's stream.
        let client_offset = match resume {
            Some((e, off)) if e == term.epoch => Some(off),
            _ => None,
        };
        // Cut + subscribe under the same lock the reader thread uses, so
        // there is no gap/overlap at the cut point.
        let sb = term.scrollback.lock().unwrap();
        let (mode, base_offset, replay) = sb.cut(client_offset);
        let output_rx = term.output_tx.subscribe();
        drop(sb);

        Ok(Attachment {
            input_tx: term.input_tx.clone(),
            output_rx,
            shutdown_rx: term.shutdown_tx.subscribe(),
            replay,
            mode,
            epoch: term.epoch,
            base_offset,
        })
```

(The existing `let _ = term.input_tx.send(PtyCmd::Resize { cols, rows });` line stays, before this block.)

3g. `attach_view` gains the same `resume: Option<(u64, u64)>` parameter and the same replacement of its snapshot/subscribe block (identical code to 3f, using its own `term` binding).

3h. Fix the two existing callers in `src/main.rs` so the crate compiles — pass `None` for now (Task 3 wires the real values):
- line ~751: `.attach(&session.username, q.term, cols, rows)` → `.attach(&session.username, q.term, cols, rows, None)`
- line ~694: `.attach_view(&user, index)` → `.attach_view(&user, index, None)`

Also `src/pty.rs` destructures `Attachment` — update its destructuring to ignore the new fields for now:

```rust
    let Attachment {
        input_tx,
        mut output_rx,
        mut shutdown_rx,
        replay,
        ..
    } = attachment;
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test`
Expected: all 7 new tests PASS, no warnings about unused `mode`/`epoch`/`base_offset` (they are `pub`).

- [ ] **Step 5: Commit**

```bash
git add src/terminals.rs src/main.rs src/pty.rs
git commit -m "Resume core: per-spawn epoch, monotonic output counter, ring cut"
```

---

### Task 2: pty.rs — mux bridge + hello on the single-channel bridge

**Files:**
- Modify: `src/pty.rs`

**Interfaces:**
- Consumes (from Task 1): `Attachment { input_tx, output_rx, shutdown_rx, replay, mode, epoch, base_offset }`, `AttachMode`, `Terminals::attach(user, index, cols, rows, resume)`.
- Produces (Task 3 relies on):

  ```rust
  /// Multiplexed bridge: one WebSocket carrying every opened slot for `user`.
  pub async fn mux_bridge(socket: WebSocket, terminals: Arc<Terminals>, user: String)

  /// Single-channel bridge (share viewers): unchanged signature, but now
  /// sends a hello text frame, then the replay frame, then live output.
  pub async fn bridge(socket: WebSocket, attachment: Attachment,
                      read_only: bool, deadline: Option<tokio::time::Instant>)
  ```

- [ ] **Step 1: Rewrite `src/pty.rs`**

Replace the whole file with:

```rust
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
                            old.stop();
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
/// if empty — the client keys report-suppression off it), then live output.
/// When `read_only` is set, all input and resize frames from this client are
/// dropped (server-enforced). When `deadline` is set (share links), the
/// connection is force-closed at that time so an expired token cannot keep
/// watching a connection it opened before expiry.
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
```

Note the behavior change in `bridge`: `Lagged` now disconnects (it used to skip frames silently). With offset accounting, silently skipped frames would corrupt the client's counter — disconnecting and letting the ring heal is the only honest option.

- [ ] **Step 2: Compile**

Run: `cargo test`
Expected: compiles; Task 1 tests still pass. (`mux_bridge` is not referenced yet — a dead-code warning for it is acceptable until Task 3; silence nothing.)

- [ ] **Step 3: Commit**

```bash
git add src/pty.rs
git commit -m "Mux bridge: per-slot channels over one socket; hello frame on share bridge"
```

---

### Task 3: main.rs — wire mux + access resume

**Files:**
- Modify: `src/main.rs`

**Interfaces:**
- Consumes: `pty::mux_bridge(socket, Arc<Terminals>, String)`, `pty::bridge(...)` (unchanged signature), `attach_view(user, index, resume)`.
- Produces: `/webshell/private/ws?csrf=...` speaks the mux protocol; `/webshell/public/access/ws?token=...&epoch=E&offset=N` resumes viewers.

- [ ] **Step 1: Rewrite `ws_handler` and `WsQuery`**

Replace the `WsQuery` struct and `ws_handler` function with:

```rust
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

    let terminals = state.terminals.clone();
    let user = session.username;
    ws.on_upgrade(move |socket| pty::mux_bridge(socket, terminals, user))
}
```

(`session.username` is a `String` — the existing `attach(&session.username, ...)` call coerces it to `&str` — so `let user = session.username;` moves it into the closure cleanly.)

- [ ] **Step 2: access_ws resume params**

Find the access-ws query struct (the one deserialized in `access_ws`, near line 669) and add the two optional fields:

```rust
    #[serde(default)]
    epoch: Option<u64>,
    #[serde(default)]
    offset: Option<u64>,
```

In `access_ws`, build the resume pair and pass it to `attach_view` (currently `state.terminals.attach_view(&user, index, None)` after Task 1):

```rust
    let resume = match (q.epoch, q.offset) {
        (Some(e), Some(o)) => Some((e, o)),
        _ => None,
    };
    match state.terminals.attach_view(&user, index, resume) {
```

(`q` here is whatever binding the handler already uses for its query struct — keep its existing name.)

- [ ] **Step 3: Compile + tests**

Run: `cargo test`
Expected: compiles clean (the Task-2 dead-code warning for `mux_bridge` disappears); all tests pass.

- [ ] **Step 4: Commit**

```bash
git add src/main.rs
git commit -m "Wire mux bridge into /private/ws; access ws accepts resume params"
```

---

### Task 4: terminal.html — Conn manager + Session channels

**Files:**
- Modify: `static/terminal.html` (script block only)

**Interfaces:**
- Consumes: the wire protocol (Global Constraints), server behavior from Tasks 1–3.
- Produces: `Conn` singleton (`connect/reconnect/drop/sendJson/sendInput/isOpen`, fields `ws/generation/reconnectDelay/reconnectTimer/failures`); `Session` gains `epoch/offset/dead/opened`, methods `sendOpen/onHello/onOutput/onClosed`; loses `ws/generation/reconnectDelay/reconnectTimer/failures/connect/dropSocket/reconnect`.

All edits below are within the `<script>` block of `static/terminal.html`.

- [ ] **Step 1: Replace `wsUrl` and add `Conn`**

Replace the existing `wsUrl(index, mode, cols, rows)` function with:

```js
    function wsUrl() {
      const proto = location.protocol === "https:" ? "wss:" : "ws:";
      return `${proto}//${location.host}/webshell/private/ws?csrf=${encodeURIComponent(CSRF)}`;
    }

    // ---- single multiplexed connection: every opened slot rides this one
    // socket. Binary frames carry a 1-byte slot prefix; JSON text frames
    // carry control (open/resize/mode/close up, hello/closed down). The
    // reconnect loop, give-up state, logout probe and status ball all
    // describe this one socket now. ----
    const Conn = {
      ws: null,
      generation: 0,          // orphans superseded sockets' handlers
      reconnectDelay: 500,
      reconnectTimer: null,
      failures: 0,            // consecutive failed cycles; MAX_FAILURES = give up

      isOpen() { return !!this.ws && this.ws.readyState === WebSocket.OPEN; },

      connect() {
        clearTimeout(this.reconnectTimer);
        const myGen = ++this.generation;
        const sock = new WebSocket(wsUrl());
        this.ws = sock;
        sock.binaryType = "arraybuffer";
        refreshStatus();

        sock.onopen = () => {
          if (myGen !== this.generation) return;
          this.reconnectDelay = 500;
          this.failures = 0;
          // Restore every slot the user has opened; each resumes from its
          // own offset (delta) or replays in full — one round trip.
          sessions.forEach((s) => { if (s && s.opened) s.sendOpen(); });
          refreshSlots();
          refreshStatus();
          const a = sessions[active];
          if (a) a.term.focus();
        };
        sock.onmessage = (ev) => {
          if (myGen !== this.generation) return;
          if (typeof ev.data === "string") {
            let m;
            try { m = JSON.parse(ev.data); } catch (_) { return; }
            const s = sessions[m.term];
            if (!s) return;
            if (m.type === "hello") s.onHello(m);
            else if (m.type === "closed") s.onClosed(m);
            return;
          }
          const data = new Uint8Array(ev.data);
          if (!data.length) return;
          const s = sessions[data[0]];
          if (s) s.onOutput(data.subarray(1));
        };
        sock.onclose = () => {
          if (myGen !== this.generation) return;  // superseded socket: stay closed
          refreshSlots();                          // also probes auth: 401 -> login
          this.failures++;
          if (this.failures >= MAX_FAILURES) {
            // Give up: stop auto-retrying until the page is reloaded.
            refreshStatus();
            return;
          }
          refreshStatus();
          this.reconnectTimer = setTimeout(() => this.connect(), this.reconnectDelay);
          this.reconnectDelay = Math.min(this.reconnectDelay * 2, 5000);
        };
        sock.onerror = () => { try { sock.close(); } catch (_) {} };
      },

      sendJson(obj) { if (this.isOpen()) this.ws.send(JSON.stringify(obj)); },
      sendInput(index, text) {
        if (!this.isOpen()) return;
        const b = enc.encode(text);
        const f = new Uint8Array(b.length + 1);
        f[0] = index;
        f.set(b, 1);
        this.ws.send(f);
      },

      drop() {
        this.generation++;
        clearTimeout(this.reconnectTimer);
        if (this.ws) {
          this.ws.onmessage = null;   // no late frames into any term
          try { this.ws.close(); } catch (_) {}
          this.ws = null;
        }
      },
      reconnect() { this.failures = 0; this.reconnectDelay = 500; this.drop(); this.connect(); },
    };
```

- [ ] **Step 2: Replace `refreshStatus`**

```js
    function refreshStatus() {
      if (Conn.failures >= MAX_FAILURES) { setStatus("connection lost — reload", "down"); return; }
      if (!Conn.ws) { setStatus("connecting…", "wait"); return; }
      switch (Conn.ws.readyState) {
        case WebSocket.OPEN: {
          const s = sessions[active];
          setStatus(s && s.readOnly ? "read-only" : "connected");
          break;
        }
        case WebSocket.CONNECTING: setStatus("connecting…", "wait"); break;
        default: setStatus("reconnecting…", "wait");
      }
    }
```

- [ ] **Step 3: Rework `Session`**

3a. In the constructor, replace the per-socket fields

```js
        this.ws = null;
        this.opened = false;
        // Per-socket reconnect identity (see the double-socket fix).
        this.generation = 0;
        this.reconnectDelay = 500;
        this.reconnectTimer = null;
        // Consecutive failed connection cycles; MAX_FAILURES = give up (red status).
        this.failures = 0;
```

with the channel state

```js
        this.opened = false;      // user has visited this slot; re-open on reconnect
        this.dead = false;        // server closed the channel; re-open respawns
        this.epoch = null;        // shell-instance id from the last hello
        this.offset = 0;          // stream bytes received (the resume checkpoint)
        this.expectFirst = false; // next data frame is the replay/delta blob
        this.reopenTimer = null;
```

(keep `this.suppressReports = false;` as-is).

3b. Replace the three methods `connect()`, `dropSocket()`, `reconnect()` entirely with:

```js
      // Ask the server to (re)attach this slot over the mux connection,
      // resuming from our offset when the server still can.
      sendOpen() {
        clearTimeout(this.reopenTimer);
        this.dead = false;
        const msg = {
          type: "open", term: this.index,
          cols: this.term.cols, rows: this.term.rows,
          ro: this.readOnly,
        };
        if (this.epoch !== null) { msg.epoch = this.epoch; msg.offset = this.offset; }
        Conn.sendJson(msg);
      }

      onHello(m) {
        this.epoch = m.epoch;
        this.offset = m.offset;
        this.expectFirst = true;
        // resume: the stream continues exactly where we left off — keep the
        // screen, scroll position and all. replay: different shell or missed
        // window — redraw from scratch.
        if (m.mode === "replay") this.term.reset();
        if (this.isActive()) refreshStatus();
      }

      onOutput(data) {
        this.offset += data.length;
        if (this.expectFirst) {
          // Replay/delta blob (sent even when empty): suppress terminal
          // report replies so answers to historical color/status queries are
          // not injected into the live shell.
          this.expectFirst = false;
          this.suppressReports = true;
          const clear = () => { this.suppressReports = false; };
          this.term.write(data, clear);
          setTimeout(clear, 300);
        } else {
          this.term.write(data);
        }
      }

      onClosed(m) {
        // Shell exited / was reset ("exit") or attach failed ("error").
        // Either way our resume state is for a dead stream.
        this.dead = true;
        this.epoch = null;
        this.offset = 0;
        refreshSlots();
        if (!this.isActive()) return;   // background: re-opened on activation
        // Respawn the visible slot on a small delay so a crash-looping or
        // unspawnable shell cannot hot-loop open/closed cycles.
        clearTimeout(this.reopenTimer);
        this.reopenTimer = setTimeout(() => {
          if (this.isActive() && this.dead && Conn.isOpen()) this.sendOpen();
        }, m.reason === "error" ? 2000 : 500);
      }
```

3c. Replace `sendResize()` with:

```js
      sendResize() {
        if (!this.readOnly && this.opened) {
          Conn.sendJson({ type: "resize", term: this.index, cols: this.term.cols, rows: this.term.rows });
        }
      }
```

3d. In `input(d)`, replace the send guard

```js
        if (!this.readOnly && this.ws && this.ws.readyState === WebSocket.OPEN) {
          this.ws.send(enc.encode(d));
        }
```

with

```js
        if (!this.readOnly) Conn.sendInput(this.index, d);
```

- [ ] **Step 4: Rewire the call sites**

4a. `activate(i)`: replace `if (!s.opened) s.connect();` with

```js
      if (!s.opened) {
        s.opened = true;
        if (Conn.isOpen()) s.sendOpen();
      } else if (s.dead && Conn.isOpen()) {
        s.sendOpen();
      }
```

4b. Read-only toggle: replace the whole `roEl` change handler body after the guard with

```js
      s.readOnly = roEl.checked;
      s.term.options.disableStdin = s.readOnly;
      // Server-side enforcement flips instantly; no reconnect, no replay.
      Conn.sendJson({ type: "mode", term: s.index, ro: s.readOnly });
      refreshStatus();
```

(delete the `s.term.reset()` and `s.reconnect()` lines).

4c. Reset button handler: delete the two lines

```js
      s.term.reset();
      s.reconnect();     // respawns a fresh shell on attach
```

and in their place put

```js
      // The server kills the shell; the resulting closed frame drives the
      // respawn (Session.onClosed). Nothing else to do here.
```

4d. `visibilitychange` handler: replace the whole `sessions.forEach(...)` block with

```js
      if (Conn.failures >= MAX_FAILURES) { refreshSlots(); return; }  // given up: reload only
      if (!Conn.ws || Conn.ws.readyState === WebSocket.CLOSING || Conn.ws.readyState === WebSocket.CLOSED) {
        Conn.reconnect();
      }
```

(keep the trailing `refreshSlots();` that follows the block).

4e. Bottom of the script: replace the final `activate(0);` line with

```js
    Conn.connect();
    activate(0);
```

- [ ] **Step 5: Syntax gate**

Run the Global Constraints syntax check. Expected: `SYNTAX-OK`.

Then grep for stragglers:

```bash
grep -c "new WebSocket" static/terminal.html   # expect exactly 1 (inside Conn)
grep -n "dropSocket" static/terminal.html      # expect nothing
grep -n "wsUrl(this" static/terminal.html      # expect nothing
```

(Do NOT grep for `this.ws` or `.failures` — `Conn`'s own internals legitimately use those names.)

- [ ] **Step 6: Commit**

```bash
git add static/terminal.html
git commit -m "Client mux: one socket, per-slot channels with offset resume"
```

---

### Task 5: access.html — hello/offset resume for share viewers

**Files:**
- Modify: `static/access.html` (script block only)

**Interfaces:**
- Consumes: access-ws hello (`{"type":"hello","mode","epoch","offset"}`, no `term`), untagged binary frames, `&epoch=&offset=` query params (Task 3).

- [ ] **Step 1: Track resume state**

After the `let ws = null, generation = 0, ...` declarations add:

```js
    // Resume checkpoint: epoch identifies the shell instance, offset counts
    // stream bytes received. Passed on reconnect for a delta instead of a
    // full replay.
    let epoch = null, offset = 0;
```

- [ ] **Step 2: Send it and honor the hello**

Replace `wsUrl()` with:

```js
    function wsUrl() {
      const proto = location.protocol === "https:" ? "wss:" : "ws:";
      let u = `${proto}//${location.host}/webshell/public/access/ws?token=${encodeURIComponent(token)}`;
      if (epoch !== null) u += `&epoch=${epoch}&offset=${offset}`;
      return u;
    }
```

In `connect()`, delete the `let firstFrame = true;` line and replace `sock.onmessage` with:

```js
      sock.onmessage = (ev) => {
        if (myGen !== generation) return;
        if (typeof ev.data === "string") {
          let m;
          try { m = JSON.parse(ev.data); } catch (_) { return; }
          if (m.type === "hello") {
            epoch = m.epoch;
            offset = m.offset;
            // replay: different shell or missed window — redraw from scratch.
            // resume: stream continues seamlessly; keep the screen.
            if (m.mode === "replay") term.reset();
          }
          return;
        }
        const data = new Uint8Array(ev.data);
        offset += data.length;
        term.write(data);
      };
```

- [ ] **Step 3: Syntax gate + commit**

Run the Global Constraints syntax check. Expected: `SYNTAX-OK`.

```bash
git add static/access.html
git commit -m "Share viewer: offset resume via hello exchange"
```

---

### Task 6: Final review, build, deploy

**Files:** none new — verification and release only.

- [ ] **Step 1: Full-diff review**

Re-read the spec, then review `git diff <commit-before-task-1>..HEAD` against it. Confirm especially:
- hello + (possibly empty) replay frame precede live output on BOTH bridges;
- offset arithmetic matches on both sides (hello.offset = start of following data; client adds every data frame's length);
- no remaining references to the old per-slot socket in either HTML file;
- `Lagged` closes the channel/connection on both bridges.

- [ ] **Step 2: Gates**

Run: `cargo test` and the syntax check. Expected: all pass.

- [ ] **Step 3: Build + push**

```bash
git push
./build-x86_64.sh
```

Expected: `>> Built target/x86_64-unknown-linux-gnu/release/webshell`.

- [ ] **Step 4: Stage on server, ASK USER, then restart**

```bash
scp -o BatchMode=yes target/x86_64-unknown-linux-gnu/release/webshell \
  wushilin@gate.wushilin.net:/opt/processmaster/dropin/webshell/webshell.new
```

**STOP: ask the user for restart approval (kills live shell sessions).** Only after approval:

```bash
ssh -o BatchMode=yes wushilin@gate.wushilin.net \
  'pkill -x webshell; sleep 3; ps -o pid,lstart -C webshell; \
   curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:9193/webshell/login; \
   grep -c mux /opt/processmaster/dropin/webshell/webshell'
```

Expected: a fresh PID, `200`, grep count ≥ 1.

- [ ] **Step 5: Hand the user the on-device checklist**

- open several slots, switch: instant, no reconnect;
- airplane-mode 10 s during `yes` spam → reconnect shows only missed lines, no full redraw, scroll kept;
- background the tab 10 min (quiet shell) → foreground resumes instantly;
- heavy output past the ring while backgrounded → clean full replay;
- reset button → fresh shell (~0.5 s);
- read-only toggle → instant, typing blocked, no replay flash;
- share link viewer survives a network blip with a delta;
- logout in another tab → red ball, login redirect;
- status ball states: green / blinking yellow / red after ~30 failures.
