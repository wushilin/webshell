//! Persistent, resumable terminal slots keyed per authenticated user.
//!
//! Each user owns a fixed pool of slots. A slot lazily spawns a login shell on
//! first attach and keeps it running across WebSocket disconnects, so the user
//! can resume it later. A per-slot scrollback buffer is replayed on reattach.
//! Multiple clients may attach to the same slot simultaneously (shared view).

use std::collections::HashMap;
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use crate::util::lock;
use tokio::sync::{broadcast, watch};

/// Commands to the blocking thread that owns the PTY master.
pub enum PtyCmd {
    Input(Vec<u8>),
    Resize { cols: u16, rows: u16 },
    Kill,
}

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

/// Capped ring buffer of recent shell output, replayed to new clients.
struct Scrollback {
    buf: VecDeque<u8>,
    cap: usize,
    /// Total bytes ever pushed since spawn (monotonic, not capped). The
    /// client mirrors this count; resume = serving the difference.
    total: u64,
}

impl Scrollback {
    fn new(cap: usize) -> Self {
        Scrollback {
            buf: VecDeque::new(),
            cap,
            total: 0,
        }
    }
    fn push(&mut self, data: &[u8]) {
        self.total += data.len() as u64;
        self.buf.extend(data.iter().copied());
        while self.buf.len() > self.cap {
            self.buf.pop_front();
        }
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
    /// Identity of this spawn; see NEXT_EPOCH.
    epoch: u64,
}

impl Terminal {
    /// Kill the shell and notify every attached bridge to disconnect.
    fn stop(&self) {
        let _ = self.shutdown_tx.send(true);
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
        owner_home: String,
        scrollback_cap: usize,
    ) -> Self {
        Terminals {
            pools: Mutex::new(HashMap::new()),
            slots_per_user,
            login_cmd,
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
                &self.owner_home,
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
    }

    /// Attach a read-only *viewer* (e.g. a share link) to an already-running
    /// slot. Unlike `attach`, this never spawns a shell and never resizes the
    /// owner's PTY, so a viewer cannot affect the session. Errors if the slot
    /// is not currently running.
    pub fn attach_view(&self, user: &str, index: usize, resume: Option<(u64, u64)>) -> Result<Attachment, String> {
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

fn spawn_terminal(
    login_cmd: &[String],
    user: &str,
    owner_home: &str,
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
    cmd.env("HOME", owner_home);
    cmd.env("USER", user);
    cmd.env("LOGNAME", user);
    cmd.cwd(owner_home);

    let child = pair
        .slave
        .spawn_command(cmd)
        .map_err(|e| anyhow::anyhow!("spawn {program:?} (cwd {owner_home}): {e}"))?;
    drop(pair.slave); // so the master sees EOF when the shell exits

    let reader = pair.master.try_clone_reader()?;
    let writer = pair.master.take_writer()?;
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
        epoch: NEXT_EPOCH.fetch_add(1, Ordering::Relaxed),
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
