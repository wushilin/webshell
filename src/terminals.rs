//! Persistent, resumable terminal slots keyed per authenticated user.
//!
//! Each user owns a fixed pool of slots. A slot lazily spawns a login shell on
//! first attach and keeps it running across WebSocket disconnects, so the user
//! can resume it later. A per-slot scrollback buffer is replayed on reattach.
//! Multiple clients may attach to the same slot simultaneously (shared view).

use std::collections::HashMap;
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::util::lock;
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use tokio::sync::{broadcast, watch};

/// Commands to the blocking thread that owns the PTY master.
pub enum PtyCmd {
    Input(Vec<u8>),
    Resize { cols: u16, rows: u16 },
    Kill,
}

/// Identity of a shell spawn. Keep this within JavaScript's exact-integer
/// range because it crosses the wire as a JSON number. Randomness, rather
/// than a process-local counter, prevents an epoch from being reused after a
/// server restart and splicing a new shell onto a browser's old screen.
fn next_epoch() -> u64 {
    loop {
        let epoch = rand::random::<u64>() & ((1_u64 << 53) - 1);
        if epoch != 0 {
            return epoch;
        }
    }
}

/// How an attachment's `replay` bytes relate to what the client already has.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AttachMode {
    /// `replay` is exactly the bytes the client is missing; no reset needed.
    Resume,
    /// `replay` is the full ring; the client must reset and redraw.
    Replay,
}

/// Scanner position of a [`ModeTracker`] between feeds. Sequences routinely
/// straddle eviction boundaries, so the position must persist across calls.
enum Scan {
    Ground,
    Esc,
    Csi { buf: Vec<u8> },
}

/// Tracks the DECSET private modes a replay's oldest byte assumes. Fed
/// exactly the bytes evicted from the ring's front, it answers: which modes
/// did the trimmed-away prefix leave enabled? A full replay must reinstate
/// those (alt screen above all — a fullscreen app whose `?1049h` scrolled out
/// of the ring would otherwise redraw into the primary buffer, and its exit
/// would restore nothing).
struct ModeTracker {
    st: Scan,
    /// `?1`: application cursor keys.
    app_cursor: bool,
    /// `?25l`: cursor hidden (visible is the default).
    cursor_hidden: bool,
    /// `?47`/`?1047`/`?1049`: alt screen, remembering which variant enabled it.
    alt_screen: Option<u16>,
    /// `?2004`: bracketed paste.
    bracketed_paste: bool,
    /// `?9`/`?1000`-`?1003` mouse tracking and `?1005`/`?1006`/`?1015`/`?1016`
    /// encodings still enabled. The client swallows these (drag stays local
    /// selection) but remembers them to synthesize SGR wheel reports; without
    /// them in the replay a resumed fullscreen app falls back to arrow keys.
    mouse: std::collections::BTreeSet<u16>,
}

impl ModeTracker {
    fn new() -> Self {
        ModeTracker {
            st: Scan::Ground,
            app_cursor: false,
            cursor_hidden: false,
            alt_screen: None,
            bracketed_paste: false,
            mouse: std::collections::BTreeSet::new(),
        }
    }

    fn feed(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.st = match std::mem::replace(&mut self.st, Scan::Ground) {
                Scan::Ground if b == 0x1b => Scan::Esc,
                Scan::Ground => Scan::Ground,
                Scan::Esc if b == b'[' => Scan::Csi { buf: Vec::new() },
                Scan::Esc if b == 0x1b => Scan::Esc,
                Scan::Esc => Scan::Ground,
                Scan::Csi { mut buf } => match b {
                    // Parameter and intermediate bytes. The cap only guards
                    // against pathological streams; real DECSETs are short.
                    0x20..=0x3f => {
                        if buf.len() < 32 {
                            buf.push(b);
                        }
                        Scan::Csi { buf }
                    }
                    0x40..=0x7e => {
                        self.dispatch(&buf, b);
                        Scan::Ground
                    }
                    0x1b => Scan::Esc,
                    // C0 controls inside a CSI are executed by terminals
                    // without aborting the sequence; ignore them likewise.
                    _ => Scan::Csi { buf },
                },
            };
        }
    }

    fn dispatch(&mut self, buf: &[u8], final_byte: u8) {
        let set = match final_byte {
            b'h' => true,
            b'l' => false,
            _ => return,
        };
        let Some(params) = buf.strip_prefix(b"?") else {
            return;
        };
        for p in params.split(|&b| b == b';') {
            let Some(n) = std::str::from_utf8(p).ok().and_then(|s| s.parse::<u16>().ok()) else {
                continue;
            };
            match n {
                1 => self.app_cursor = set,
                25 => self.cursor_hidden = !set,
                47 | 1047 | 1049 => self.alt_screen = if set { Some(n) } else { None },
                2004 => self.bracketed_paste = set,
                9 | 1000..=1003 | 1005 | 1006 | 1015 | 1016 => {
                    if set {
                        self.mouse.insert(n);
                    } else {
                        self.mouse.remove(&n);
                    }
                }
                _ => {}
            }
        }
    }

    /// Sequences reinstating every non-default mode, for the head of a replay.
    /// Alt screen first: entering it clears the (just-reset) alt buffer before
    /// the replayed frames draw.
    fn synth(&self) -> Vec<u8> {
        let mut out = Vec::new();
        if let Some(n) = self.alt_screen {
            out.extend_from_slice(format!("\x1b[?{n}h").as_bytes());
        }
        if self.app_cursor {
            out.extend_from_slice(b"\x1b[?1h");
        }
        if self.bracketed_paste {
            out.extend_from_slice(b"\x1b[?2004h");
        }
        for n in &self.mouse {
            out.extend_from_slice(format!("\x1b[?{n}h").as_bytes());
        }
        if self.cursor_hidden {
            out.extend_from_slice(b"\x1b[?25l");
        }
        out
    }
}

/// Capped ring buffer of recent shell output, replayed to new clients.
struct Scrollback {
    buf: VecDeque<u8>,
    cap: usize,
    /// Total bytes ever pushed since spawn (monotonic, not capped). The
    /// client mirrors this count; resume = serving the difference.
    total: u64,
    /// Mode state at the ring's front — what the oldest surviving byte
    /// assumes the terminal looks like. See [`ModeTracker`].
    front_state: ModeTracker,
}

impl Scrollback {
    fn new(cap: usize) -> Self {
        Scrollback {
            buf: VecDeque::new(),
            cap,
            total: 0,
            front_state: ModeTracker::new(),
        }
    }
    fn push(&mut self, data: &[u8]) {
        self.total += data.len() as u64;
        self.buf.extend(data.iter().copied());
        let mut evicted = Vec::new();
        while self.buf.len() > self.cap {
            evicted.push(self.buf.pop_front().expect("len > cap > 0"));
        }
        self.front_state.feed(&evicted);
    }

    /// Escape sequences a full replay must be prefixed with so the ring's
    /// bytes render against the mode state they were emitted under. Sent to
    /// the client out-of-band (hello `init`), never counted in the stream
    /// offset. Empty whenever the enabling sequences still live in the ring.
    fn front_init(&self) -> Vec<u8> {
        self.front_state.synth()
    }
    fn snapshot(&self) -> Vec<u8> {
        self.buf.iter().copied().collect()
    }

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
}

/// A single live terminal (one running login shell).
struct Terminal {
    input_tx: std::sync::mpsc::SyncSender<PtyCmd>,
    output_tx: broadcast::Sender<Vec<u8>>,
    scrollback: Arc<Mutex<Scrollback>>,
    alive: Arc<AtomicBool>,
    /// Current PTY grid (cols, rows), updated on every resize. Read-only
    /// viewers mirror this so their rendering matches the owner's.
    size: Arc<Mutex<(u16, u16)>>,
    /// Flipped to `true` when this shell dies or is killed. Attached bridges
    /// watch it and disconnect, so their clients reconnect to the fresh shell.
    /// This is needed because `output_tx` living in this struct keeps the
    /// broadcast channel open, so `Closed` alone never reaches subscribers.
    shutdown_tx: watch::Sender<bool>,
    /// Signals the child directly, bypassing the input queue. Reset/delete
    /// exist to recover a *stuck* shell, which is exactly when that queue is
    /// unusable: the command thread blocks in `write_all` whenever the PTY
    /// buffer is full and the program is not reading, so a queued `Kill` is
    /// never reached — and once the bounded queue fills, it is not even
    /// accepted. Hanging the shell up is what unblocks that write.
    ///
    /// `None` once the command thread is about to reap the child. This is not
    /// bookkeeping: a `ChildKiller` is a bare pid, so signalling after `wait()`
    /// could hit an unrelated process that inherited the number. Both sides go
    /// through this mutex, so the child is either still unreaped when we
    /// signal it, or already cleared and we do nothing.
    killer: Arc<Mutex<Option<Box<dyn portable_pty::ChildKiller + Send + Sync>>>>,
    /// Identity of this spawn; see NEXT_EPOCH.
    epoch: u64,
}

impl Terminal {
    /// Kill the shell and notify every attached bridge to disconnect.
    fn stop(&self) {
        let _ = self.shutdown_tx.send(true);
        // SIGHUP, which is the right signal for a login shell going away: it
        // runs exit traps and terminates anything that does not handle it.
        // The command thread follows up with SIGKILL as it unwinds.
        if let Some(killer) = lock(&self.killer).as_mut() {
            let _ = killer.kill();
        }
        // Best-effort nudge so the command thread unwinds promptly when it is
        // idle rather than blocked; the hangup above is what reaches a shell
        // whose input queue is unusable.
        let _ = self.input_tx.try_send(PtyCmd::Kill);
    }
}

/// What a client needs to bridge a WebSocket to a terminal.
pub struct Attachment {
    pub input_tx: std::sync::mpsc::SyncSender<PtyCmd>,
    pub output_rx: broadcast::Receiver<Vec<u8>>,
    /// Fires when the terminal dies or is reset; the bridge should disconnect.
    pub shutdown_rx: watch::Receiver<bool>,
    /// Recent output to write before streaming live data (resume/replay).
    pub replay: Vec<u8>,
    /// How an attachment's `replay` bytes relate to what the client already has.
    pub mode: AttachMode,
    /// Identity of this shell spawn.
    pub epoch: u64,
    /// Stream position where `replay` begins.
    pub base_offset: u64,
    /// Mode-reinstating prefix for a full replay (see `Scrollback::front_init`).
    /// Delivered in the hello, outside the offset-counted stream. Empty on
    /// resume.
    pub init: Vec<u8>,
}

struct UserPool {
    slots: Vec<Mutex<Option<Terminal>>>,
}

impl UserPool {
    fn new(n: usize) -> Self {
        UserPool {
            slots: (0..n).map(|_| Mutex::new(None)).collect(),
        }
    }
}

pub struct Terminals {
    pools: Mutex<HashMap<String, Arc<UserPool>>>,
    slots_per_user: usize,
    /// Login command template; `{user}` is substituted per user.
    login_cmd: Vec<String>,
    /// Config-seeded extra environment for every spawn.
    envs: std::collections::BTreeMap<String, String>,
    /// The OS account every shell runs as (login identities all share it).
    owner: String,
    /// The owner's home directory, for the spawned shell's cwd/$HOME.
    owner_home: String,
    scrollback_cap: usize,
}

#[derive(serde::Serialize)]
pub struct SlotStatus {
    pub index: usize,
    pub running: bool,
}

impl Terminals {
    pub fn new(
        slots_per_user: usize,
        login_cmd: Vec<String>,
        envs: std::collections::BTreeMap<String, String>,
        owner: String,
        owner_home: String,
        scrollback_cap: usize,
    ) -> Self {
        Terminals {
            pools: Mutex::new(HashMap::new()),
            slots_per_user,
            login_cmd,
            envs,
            owner,
            owner_home,
            scrollback_cap,
        }
    }

    fn pool(&self, user: &str) -> Arc<UserPool> {
        lock(&self.pools)
            .entry(user.to_string())
            .or_insert_with(|| Arc::new(UserPool::new(self.slots_per_user)))
            .clone()
    }

    /// Current running state of every slot for `user`.
    pub fn list(&self, user: &str) -> Vec<SlotStatus> {
        let pool = self.pool(user);
        pool.slots
            .iter()
            .enumerate()
            .map(|(index, slot)| {
                let running = lock(slot)
                    .as_ref()
                    .map(|t| t.alive.load(Ordering::Relaxed))
                    .unwrap_or(false);
                SlotStatus { index, running }
            })
            .collect()
    }

    /// Attach to `user`'s slot `index`, spawning (or respawning a dead) shell as
    /// needed. Returns handles for bridging plus the replay buffer.
    pub fn attach(
        &self,
        user: &str,
        index: usize,
        cols: u16,
        rows: u16,
        resume: Option<(u64, u64)>,
    ) -> Result<Attachment, String> {
        if index >= self.slots_per_user {
            return Err("slot out of range".into());
        }
        let pool = self.pool(user);
        let slot = &pool.slots[index];
        let mut guard = lock(slot);

        let need_spawn = match guard.as_ref() {
            None => true,
            Some(t) => !t.alive.load(Ordering::Relaxed),
        };
        if need_spawn {
            if let Some(old) = guard.take() {
                old.stop();
            }
            let term = spawn_terminal(
                &self.login_cmd,
                user,
                &self.owner,
                &self.owner_home,
                &self.envs,
                cols,
                rows,
                self.scrollback_cap,
            )
            .map_err(|e| e.to_string())?;
            *guard = Some(term);
        }

        let term = guard.as_ref().unwrap();
        let _ = term.input_tx.try_send(PtyCmd::Resize { cols, rows });

        // Resume only against the same shell instance; a stale epoch means
        // the client's offset counts a different shell's stream.
        let client_offset = match resume {
            Some((e, off)) if e == term.epoch => Some(off),
            _ => None,
        };
        // Cut + subscribe under the same lock the reader thread uses, so
        // there is no gap/overlap at the cut point.
        let sb = lock(&term.scrollback);
        let (mode, base_offset, replay) = sb.cut(client_offset);
        let init = match mode {
            AttachMode::Replay => sb.front_init(),
            AttachMode::Resume => Vec::new(),
        };
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
            init,
        })
    }

    /// Attach a read-only *viewer* (e.g. a share link) to an already-running
    /// slot. Unlike `attach`, this never spawns a shell and never resizes the
    /// owner's PTY, so a viewer cannot affect the session. Errors if the slot
    /// is not currently running.
    pub fn attach_view(
        &self,
        user: &str,
        index: usize,
        resume: Option<(u64, u64)>,
    ) -> Result<Attachment, String> {
        if index >= self.slots_per_user {
            return Err("slot out of range".into());
        }
        let pool = self.pool(user);
        let guard = lock(&pool.slots[index]);
        let term = match guard.as_ref() {
            Some(t) if t.alive.load(Ordering::Relaxed) => t,
            _ => return Err("session not running".into()),
        };
        // Resume only against the same shell instance; a stale epoch means
        // the client's offset counts a different shell's stream.
        let client_offset = match resume {
            Some((e, off)) if e == term.epoch => Some(off),
            _ => None,
        };
        // Cut + subscribe under the same lock the reader thread uses, so
        // there is no gap/overlap at the cut point.
        let sb = lock(&term.scrollback);
        let (mode, base_offset, replay) = sb.cut(client_offset);
        let init = match mode {
            AttachMode::Replay => sb.front_init(),
            AttachMode::Resume => Vec::new(),
        };
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
            init,
        })
    }

    /// Current PTY grid `(cols, rows)` of a running slot, for viewers to mirror.
    pub fn current_size(&self, user: &str, index: usize) -> Option<(u16, u16)> {
        if index >= self.slots_per_user {
            return None;
        }
        let pool = self.pool(user);
        let guard = lock(&pool.slots[index]);
        match guard.as_ref() {
            Some(t) if t.alive.load(Ordering::Relaxed) => Some(*lock(&t.size)),
            _ => None,
        }
    }

    /// Kill a slot's shell (if any) and disconnect its attached clients. The
    /// next attach respawns a fresh one.
    pub fn reset(&self, user: &str, index: usize) {
        if index >= self.slots_per_user {
            return;
        }
        let pool = self.pool(user);
        let taken = lock(&pool.slots[index]).take();
        if let Some(term) = taken {
            term.stop();
        }
    }
}

/// Assemble the spawn command: resolved argv template plus environment.
/// Split from `spawn_terminal` so the env/argv logic is testable without
/// opening a PTY.
fn build_command(
    login_cmd: &[String],
    user: &str,
    owner: &str,
    owner_home: &str,
    envs: &std::collections::BTreeMap<String, String>,
) -> anyhow::Result<CommandBuilder> {
    // Resolve the command template. The current configuration contains no
    // user-controlled fields, but keeping substitution here makes Terminals
    // independent of how a command template is assembled.
    let resolved: Vec<String> = login_cmd
        .iter()
        .map(|part| part.replace("{user}", user))
        .collect();
    let (program, args) = resolved
        .split_first()
        .ok_or_else(|| anyhow::anyhow!("empty login command"))?;

    let mut cmd = CommandBuilder::new(program);
    cmd.args(args);
    cmd.env("TERM", "xterm-256color");
    // Do not trust the service manager's inherited identity environment. The
    // process is already running as the owner, and these values come from that
    // effective user's passwd entry.
    // These name the OS account the shell actually runs as. `user` is the
    // login identity (google:someone@example.com) and only keys the slot pool
    // — putting it in $USER would disagree with `whoami`, which reads the uid.
    cmd.env("HOME", owner_home);
    cmd.env("USER", owner);
    cmd.env("LOGNAME", owner);
    cmd.cwd(owner_home);
    // Config-seeded environment last, so it can override the built-ins.
    for (k, v) in envs {
        cmd.env(k, v);
    }
    Ok(cmd)
}

fn spawn_terminal(
    login_cmd: &[String],
    user: &str,
    owner: &str,
    owner_home: &str,
    envs: &std::collections::BTreeMap<String, String>,
    cols: u16,
    rows: u16,
    scrollback_cap: usize,
) -> anyhow::Result<Terminal> {
    let pty_system = native_pty_system();
    let pair = pty_system.openpty(PtySize {
        rows,
        cols,
        pixel_width: 0,
        pixel_height: 0,
    })?;

    let cmd = build_command(login_cmd, user, owner, owner_home, envs)?;
    let program = cmd.get_argv()[0].to_string_lossy().into_owned();

    let child = pair
        .slave
        .spawn_command(cmd)
        .map_err(|e| anyhow::anyhow!("spawn {program:?} (cwd {owner_home}): {e}"))?;
    drop(pair.slave); // so the master sees EOF when the shell exits

    // Taken before the child moves into the command thread: this is the only
    // handle `stop()` can use without going through that thread. The thread
    // clears it before reaping, so it never outlives the pid it names.
    let killer = Arc::new(Mutex::new(Some(child.clone_killer())));

    // From here the child is ours to clean up. Returning early with `?` would
    // drop it without killing or reaping it: `Child`'s drop does neither, and
    // the command thread that normally does the reaping is not spawned yet, so
    // the shell would survive as an orphan and stay a zombie of this process
    // for as long as it runs.
    let mut child = child;
    let (reader, writer) = match (pair.master.try_clone_reader(), pair.master.take_writer()) {
        (Ok(reader), Ok(writer)) => (reader, writer),
        (reader, writer) => {
            let _ = child.kill();
            let _ = child.wait();
            let err = reader
                .err()
                .or_else(|| writer.err())
                .unwrap_or_else(|| anyhow::anyhow!("pty handle setup failed"));
            return Err(err);
        }
    };
    let master = pair.master;

    // Tokio's broadcast is a ring of `capacity` slots and frees a value only
    // when it is OVERWRITTEN, not when every receiver has read it — so the
    // channel permanently retains capacity × chunk_size bytes per terminal
    // once output has flowed. At 8 KiB reads, 2048 slots meant ~16 MiB per
    // slot (128× the default 128 KiB scrollback) sitting resident forever.
    // 64 caps that at ~512 KiB, and overrunning it is harmless: a lagged
    // receiver just re-opens and the scrollback ring heals it with a delta
    // or a full replay.
    let (output_tx, _) = broadcast::channel::<Vec<u8>>(64);
    let scrollback = Arc::new(Mutex::new(Scrollback::new(scrollback_cap)));
    let alive = Arc::new(AtomicBool::new(true));
    let size = Arc::new(Mutex::new((cols, rows)));
    let (shutdown_tx, _) = watch::channel(false);

    // Bound queued terminal input. Combined with the 64 KiB WebSocket message
    // limit, this caps pending input near 8 MiB instead of allowing OOM growth.
    let (input_tx, input_rx) = std::sync::mpsc::sync_channel::<PtyCmd>(128);

    // Reader thread: shell output -> scrollback + live broadcast.
    {
        let output_tx = output_tx.clone();
        let scrollback = scrollback.clone();
        let alive = alive.clone();
        let shutdown_tx = shutdown_tx.clone();
        let reap_tx = input_tx.clone();
        std::thread::spawn(move || {
            let mut reader = reader;
            let mut buf = [0u8; 8192];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let chunk = buf[..n].to_vec();
                        // Append + broadcast under one lock for a clean attach cut.
                        let mut sb = lock(&scrollback);
                        sb.push(&chunk);
                        let _ = output_tx.send(chunk);
                    }
                }
            }
            // Shell exited on its own: mark dead and disconnect attached clients
            // so they reconnect and get a fresh shell.
            alive.store(false, Ordering::Relaxed);
            let _ = shutdown_tx.send(true);
            // Wake the command thread so it reaps the child NOW. Without this
            // it stays parked on recv() — senders live in the Terminal, so the
            // channel never closes — leaving a zombie and a blocked thread
            // until something re-attaches to this slot. For a background slot
            // the client deliberately does not re-open, so that could be days.
            // The command thread will also observe the PTY failure while
            // writing; avoid blocking this reader if the bounded queue is full.
            let _ = reap_tx.try_send(PtyCmd::Kill);
        });
    }

    // Command thread: owns master (input + resize) and reaps the child.
    {
        let size = size.clone();
        let killer = killer.clone();
        std::thread::spawn(move || {
            let mut writer = writer;
            let mut child = child;
            while let Ok(cmd) = input_rx.recv() {
                match cmd {
                    PtyCmd::Input(b) => {
                        if writer.write_all(&b).is_err() {
                            break;
                        }
                        let _ = writer.flush();
                    }
                    PtyCmd::Resize { cols, rows } => {
                        *lock(&size) = (cols, rows);
                        let _ = master.resize(PtySize {
                            rows,
                            cols,
                            pixel_width: 0,
                            pixel_height: 0,
                        });
                    }
                    PtyCmd::Kill => break,
                }
            }
            let _ = child.kill();
            // Retire the shared killer BEFORE reaping: once wait() collects the
            // child, its pid is free to be reused, and a stale killer would
            // signal whoever gets it next.
            lock(&killer).take();
            let _ = child.wait();
        });
    }

    Ok(Terminal {
        input_tx,
        output_tx,
        scrollback,
        alive,
        size,
        shutdown_tx,
        killer,
        epoch: next_epoch(),
    })
}

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
    fn replay_reinstates_alt_screen_trimmed_from_the_ring() {
        let mut s = Scrollback::new(16);
        s.push(b"\x1b[?1049h"); // fullscreen app enters the alt screen…
        s.push(&[b'x'; 64]); // …then its redraws trim the enable out
        let (mode, _, _) = s.cut(None);
        assert_eq!(mode, AttachMode::Replay);
        assert_eq!(s.front_init(), b"\x1b[?1049h");
    }

    #[test]
    fn no_init_while_the_enable_is_still_in_the_ring() {
        let mut s = Scrollback::new(1024);
        s.push(b"\x1b[?1049h");
        s.push(b"drawing");
        assert!(s.front_init().is_empty());
    }

    #[test]
    fn leaving_alt_screen_clears_the_init() {
        let mut s = Scrollback::new(8);
        s.push(b"\x1b[?1049h");
        s.push(&[b'x'; 32]);
        s.push(b"\x1b[?1049l"); // app exits the alt screen…
        s.push(&[b'y'; 32]); // …and the disable is trimmed out too
        assert!(s.front_init().is_empty());
    }

    #[test]
    fn tracker_survives_sequences_split_across_evictions() {
        let mut s = Scrollback::new(4);
        s.push(b"\x1b[?10");
        s.push(b"49h");
        s.push(&[b'x'; 16]);
        assert_eq!(s.front_init(), b"\x1b[?1049h");
    }

    #[test]
    fn init_reinstates_each_tracked_mode() {
        let mut s = Scrollback::new(4);
        s.push(b"\x1b[?1h\x1b[?2004h\x1b[?25l\x1b[?1003h\x1b[?1006h\x1b[?1049h");
        s.push(&[b'x'; 8]);
        assert_eq!(
            s.front_init(),
            b"\x1b[?1049h\x1b[?1h\x1b[?2004h\x1b[?1003h\x1b[?1006h\x1b[?25l".as_slice()
        );
    }

    #[test]
    fn init_reinstates_mouse_modes_and_disabling_clears_them() {
        // Claude Code's exact enable set, trimmed from the ring, must come
        // back in the init — the client synthesizes wheel reports only while
        // it knows the app wants SGR mouse tracking.
        let mut s = Scrollback::new(4);
        s.push(b"\x1b[?1000h\x1b[?1002h\x1b[?1003h\x1b[?1006h");
        s.push(&[b'x'; 8]);
        assert_eq!(
            s.front_init(),
            b"\x1b[?1000h\x1b[?1002h\x1b[?1003h\x1b[?1006h".as_slice()
        );

        let mut s = Scrollback::new(4);
        s.push(b"\x1b[?1000h\x1b[?1006h\x1b[?1006l\x1b[?1000l");
        s.push(&[b'x'; 8]);
        assert_eq!(s.front_init(), b"".as_slice());
    }

    #[test]
    fn combined_params_and_untracked_modes_are_handled() {
        let mut s = Scrollback::new(4);
        s.push(b"\x1b[?1049;2004h\x1b[?12h\x1b[31m");
        s.push(&[b'x'; 8]);
        assert_eq!(s.front_init(), b"\x1b[?1049h\x1b[?2004h".as_slice());
    }

    #[test]
    fn total_keeps_counting_past_the_cap() {
        let mut s = Scrollback::new(4);
        s.push(b"aaaa");
        s.push(b"bbbb");
        s.push(b"cc");
        let (mode, base, bytes) = s.cut(None);
        assert_eq!(mode, AttachMode::Replay);
        assert_eq!(base, 6); // total 10 − ring 4
        assert_eq!(bytes, b"bbcc");
    }

    #[test]
    fn build_command_seeds_and_overrides_env() {
        let envs = [
            ("EDITOR".to_string(), "vim".to_string()),
            ("TERM".to_string(), "screen-256color".to_string()),
        ]
        .into();
        let cmd = build_command(
            &["/bin/sh".to_string(), "-l".to_string()],
            "google:x@example.com",
            "alice",
            "/home/alice",
            &envs,
        )
        .unwrap();
        // Config wins over the built-in TERM; new keys are added.
        assert_eq!(
            cmd.get_env("TERM"),
            Some(std::ffi::OsStr::new("screen-256color"))
        );
        assert_eq!(cmd.get_env("EDITOR"), Some(std::ffi::OsStr::new("vim")));
        // Built-ins survive when not overridden.
        assert_eq!(
            cmd.get_env("HOME"),
            Some(std::ffi::OsStr::new("/home/alice"))
        );
        assert_eq!(cmd.get_env("USER"), Some(std::ffi::OsStr::new("alice")));
        assert_eq!(cmd.get_env("LOGNAME"), Some(std::ffi::OsStr::new("alice")));
    }

    #[test]
    fn build_command_rejects_an_empty_command() {
        assert!(build_command(&[], "u", "o", "/", &Default::default()).is_err());
    }
}
