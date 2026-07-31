# Single-socket multiplexing + offset-based fast resume

Date: 2026-08-01
Scope: `src/` (main.rs, terminals.rs, pty.rs) and `static/terminal.html`,
`static/access.html`. Protocol change; client and server ship together in one
binary, so the cutover is atomic and rollback is redeploying the old binary.
Primary target: iPhone Chrome (WebKit). Desktop must not regress.

## Problems

1. Each of up to 9 slots opens its own WebSocket: 9 auth/CSRF/origin checks,
   9 reconnect loops, 9 status states collapsed into one ball, and a burst of
   connections on every foreground.
2. Every attach replays the entire scrollback ring (up to `scrollback_cap`
   bytes) even when the client was gone for two seconds and missed nothing.
   On mobile, background kill + foreground means a full redraw of every slot,
   losing the visual scroll position.

## Decisions (user-confirmed)

- **All opened slots stream live** over the single socket. Switching slots
  touches no network — every opened slot's xterm is continuously fed.
  (Chosen over pausing background slots; bandwidth traded for zero-delta
  switches.)
- **Delta resume applies at connect time** (page load, reconnect after
  background kill or network blip): each slot resumes from the client's byte
  offset when possible, with full replay as the fallback floor.
- **The share page gets resume too**, same mechanism, single implicit channel.
- **Resume window = scrollback window**, in bytes, per slot. The server keeps
  no per-client state: the existing ring plus two counters serve any number
  of viewers. If a slot produced more than `scrollback_cap` bytes while the
  client was away, resume degrades to full replay — today's behavior, never
  worse.

## Wire protocol

One WebSocket at `/webshell/private/ws?csrf=...` (query keeps only `csrf`).

**Binary frames = terminal data.** First byte is the slot index (0-based),
the rest is payload.

- Client → server: keystrokes for that slot. Dropped server-side if the
  channel is read-only or not open.
- Server → client: shell output. The client adds `payload.length` to that
  slot's offset counter.

**Text frames = JSON control messages.**

Client → server:

- `{"type":"open","term":i,"cols":c,"rows":r}` — attach slot `i`, spawning
  if needed. First-ever open (no stored epoch/offset).
- `{"type":"open","term":i,"cols":c,"rows":r,"epoch":E,"offset":N}` —
  re-attach with resume state from a previous connection.
- `{"type":"resize","term":i,"cols":c,"rows":r}` — resize (ignored for
  read-only channels).
- `{"type":"mode","term":i,"ro":true|false}` — set read-only. Server stops
  forwarding input for the channel; enforcement is server-side, the client
  `disableStdin` is cosmetic.
- `{"type":"close","term":i}` — detach the channel (shell keeps running).

Server → client:

- `{"type":"hello","term":i,"mode":"resume","epoch":E,"offset":N}` — the
  client's offset was inside the ring. Data frames that follow continue
  from byte `N`. No client-side reset.
- `{"type":"hello","term":i,"mode":"replay","epoch":E,"offset":S}` — full
  replay: the client must `term.reset()` and set its counter to `S`, the
  stream position where the replay data begins (`total_out − replay_len` at
  the cut). Sent on first open, epoch mismatch (shell respawned), or window
  overflow.
- `{"type":"closed","term":i,"reason":"exit"|"reset"|"error"}` — the shell
  died, was reset, or attach failed. The client marks the slot dead; the
  next `open` respawns it.

**Offset accounting.** `hello.offset` is the byte position at which the data
stream (that follows the hello) begins: for `resume` it equals the client's
requested `N`; for `replay` it is `total_out − replay_len` at the attach cut.
The client sets its counter to `hello.offset` and adds every subsequent data
frame's length. This makes the counter identical on both sides by
construction, with no ambiguity about whether replay bytes count (they do —
they are stream bytes like any other).

**Ordering guarantee.** Per channel, the server sends: hello, then replay or
delta bytes, then live output — all cut under the scrollback lock exactly as
`attach()` does today, so no byte is duplicated or lost at the seam.

## Server changes

`terminals.rs`:

- `Scrollback` gains `total_out: u64`, incremented in `push()` under the
  existing lock.
- `Terminal` gains `epoch: u64` — a fresh value per spawn (process-global
  `AtomicU64` counter; must never repeat within a server run, and a server
  restart invalidates cookies/sessions anyway).
- `attach()` takes `resume: Option<(u64 /*epoch*/, u64 /*offset*/)>` and the
  returned `Attachment` gains `epoch: u64`, `base_offset: u64` (stream
  position where `replay` begins) and `mode: AttachMode` (`Resume` — replay
  contains only the missed tail — or `Replay`). Decision logic, under the
  scrollback lock:
  - epoch mismatch or no resume state → `Replay`, full snapshot.
  - `offset > total_out` (bogus client) → `Replay`; use checked arithmetic —
    `total_out − offset` must never underflow.
  - `total_out − offset > ring.len()` → `Replay`, full snapshot.
  - else → `Resume`, snapshot of the last `total_out − offset` bytes (may
    be empty).
- `attach_view()` gets the same treatment for the share path.

`pty.rs`: the per-socket `bridge` is replaced by (or wrapped in) a mux
bridge:

- One task per WebSocket connection. It owns a `HashMap<usize, Channel>`
  where each `Channel` holds the attachment handles plus a per-channel
  `read_only: bool` and an abort handle for its forward task.
- Per channel, a forward task pumps `output_rx` → tagged binary frames into
  a shared `mpsc` that a single writer task drains to the socket (one writer
  serializes all frames; hello + replay are queued through the same path to
  preserve ordering).
- The connection task reads socket frames: binary → route to
  `channel.input_tx` (unless read-only); text → handle open/resize/mode/
  close.
- A channel's `shutdown_rx` firing sends `{"type":"closed",...}` and removes
  the channel; the connection stays up.
- Connection close aborts all forward tasks and drops attachments (receivers
  unsubscribe; shells keep running).
- Broadcast lag (`RecvError::Lagged`) on a channel: treat as a broken seam —
  send `closed` with `reason:"error"`; the client re-opens with its offset
  and the ring heals it (delta or replay as appropriate).

`main.rs`: `ws_handler` drops `term`/`mode`/`cols`/`rows` from the query
(auth + CSRF + origin only) and hands the socket to the mux bridge. The
share `access_ws` keeps its endpoint and token auth but speaks the same
hello/offset exchange for its single implicit channel (viewer attach:
`open` carries no cols/rows effect, `mode` fixed read-only, input dropped).

## Client changes

`terminal.html`:

- New `Connection` singleton owning: the WebSocket, the bounded reconnect
  loop (`MAX_FAILURES`, 5 s backoff cap), the logout probe (401 →
  login redirect), visibility fast-reconnect, and the status ball. All moved
  from per-`Session` code — the ball now describes the one socket.
- `Session` keeps its xterm, fit, touch/scroll, input path, plus new
  `epoch`/`offset` resume state. `Session.connect()` becomes
  `Connection.openChannel(session)`: sends `open` with stored epoch/offset.
- On socket open, the manager re-`open`s every slot the user has opened
  (`sessions[i]` exists), restoring all slots in one round trip.
- `hello` handling: `resume` → nothing (stream continues seamlessly);
  `replay` → existing reset-and-replay path with report-reply suppression,
  exactly like today's first frame.
- `closed` handling: if it's the active slot, re-open immediately (respawn —
  covers the reset button and shell exit, replacing today's
  socket-drop-triggered respawn). Background slots just mark the slot dot
  off; re-opened on activation.
- Data frames route by slot byte to the right `Session.term.write()` and
  bump the offset. Input path prepends the slot byte.
- Read-only toggle sends `mode` (no reconnect). Reset stays HTTP; the
  resulting `closed{reason:"reset"}` drives the respawn.
- Slot switching: no network. `refreshSlots` polling stays (running dots +
  logout probe).

`access.html`: same offset counting and hello handling for its one channel;
its reconnect loop stays as-is otherwise.

## Error handling

- Malformed control frames / out-of-range slot: server ignores the frame and
  logs; it does not kill the connection.
- `open` on an already-open channel: server closes the old channel first
  (last open wins) — covers client-side races on fast re-activation.
- Attach/spawn failure → `closed{reason:"error"}` for that slot only; other
  slots unaffected (today the whole socket got an HTTP error).
- Auth failure at upgrade: 401 exactly as today; the client's logout probe
  already handles it.
- The server never trusts client offsets beyond the window check — a bogus
  offset degrades to full replay, never leaks bytes outside the ring
  (delta length is clamped to `min(total_out − offset, ring.len())`; an
  offset *greater* than `total_out` is invalid and → `Replay`).

## Testing

- `cargo test` unit tests for the resume decision: fresh open, exact-fit
  delta, empty delta (offset == total_out), window overflow, epoch
  mismatch, offset > total_out, ring-wrapped delta content correctness.
- `node --check` on the extracted inline script (both pages).
- Desktop regression: multi-slot usage, ro toggle, reset, share view.
- On-device acceptance (the gate, as always):
  - airplane-mode toggle mid-`yes` spam → reconnect shows only missed
    output, no full redraw, scroll position kept;
  - background 10 min with a quiet shell → instant resume, zero bytes;
  - background during heavy output exceeding the ring → clean full replay;
  - reset button → fresh shell (epoch bump → replay);
  - share link on a second device resumes after a blip;
  - logout elsewhere → red ball + login redirect (unchanged).

## Out of scope

- QUIC / WebTransport / HTTP-2 ws: revisit when WebKit's WebTransport is
  dependable; the channel-tagged framing is transport-agnostic by design.
- Compression of replay/delta (ws permessage-deflate or app-level): measure
  first; the delta path mostly removes the need.
- Persisting resume state across page reloads (sessionStorage): possible
  later — offsets are plain numbers — but reload-replays are acceptable now.
