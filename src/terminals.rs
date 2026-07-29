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

use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use tokio::sync::{broadcast, watch};

/// Commands to the blocking thread that owns the PTY master.
pub enum PtyCmd {
    Input(Vec<u8>),
    Resize { cols: u16, rows: u16 },
    Kill,
}

/// Capped ring buffer of recent shell output, replayed to new clients.
struct Scrollback {
    buf: VecDeque<u8>,
    cap: usize,
}

impl Scrollback {
    fn new(cap: usize) -> Self {
        Scrollback {
            buf: VecDeque::new(),
            cap,
        }
    }
    fn push(&mut self, data: &[u8]) {
        self.buf.extend(data.iter().copied());
        while self.buf.len() > self.cap {
            self.buf.pop_front();
        }
    }
    fn snapshot(&self) -> Vec<u8> {
        self.buf.iter().copied().collect()
    }
}

/// A single live terminal (one running login shell).
struct Terminal {
    input_tx: std::sync::mpsc::Sender<PtyCmd>,
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
}

impl Terminal {
    /// Kill the shell and notify every attached bridge to disconnect.
    fn stop(&self) {
        let _ = self.shutdown_tx.send(true);
        let _ = self.input_tx.send(PtyCmd::Kill);
    }
}

/// What a client needs to bridge a WebSocket to a terminal.
pub struct Attachment {
    pub input_tx: std::sync::mpsc::Sender<PtyCmd>,
    pub output_rx: broadcast::Receiver<Vec<u8>>,
    /// Fires when the terminal dies or is reset; the bridge should disconnect.
    pub shutdown_rx: watch::Receiver<bool>,
    /// Recent output to write before streaming live data (resume/replay).
    pub replay: Vec<u8>,
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
    scrollback_cap: usize,
}

#[derive(serde::Serialize)]
pub struct SlotStatus {
    pub index: usize,
    pub running: bool,
}

impl Terminals {
    pub fn new(slots_per_user: usize, login_cmd: Vec<String>, scrollback_cap: usize) -> Self {
        Terminals {
            pools: Mutex::new(HashMap::new()),
            slots_per_user,
            login_cmd,
            scrollback_cap,
        }
    }

    fn pool(&self, user: &str) -> Arc<UserPool> {
        self.pools
            .lock()
            .unwrap()
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
                let running = slot
                    .lock()
                    .unwrap()
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
    ) -> Result<Attachment, String> {
        if index >= self.slots_per_user {
            return Err("slot out of range".into());
        }
        let pool = self.pool(user);
        let slot = &pool.slots[index];
        let mut guard = slot.lock().unwrap();

        let need_spawn = match guard.as_ref() {
            None => true,
            Some(t) => !t.alive.load(Ordering::Relaxed),
        };
        if need_spawn {
            if let Some(old) = guard.take() {
                old.stop();
            }
            let term = spawn_terminal(&self.login_cmd, user, cols, rows, self.scrollback_cap)
                .map_err(|e| e.to_string())?;
            *guard = Some(term);
        }

        let term = guard.as_ref().unwrap();
        let _ = term.input_tx.send(PtyCmd::Resize { cols, rows });

        // Take a scrollback snapshot and subscribe under the same lock the
        // reader thread uses, so there is no gap/overlap at the cut point.
        let sb = term.scrollback.lock().unwrap();
        let replay = sb.snapshot();
        let output_rx = term.output_tx.subscribe();
        drop(sb);

        Ok(Attachment {
            input_tx: term.input_tx.clone(),
            output_rx,
            shutdown_rx: term.shutdown_tx.subscribe(),
            replay,
        })
    }

    /// Attach a read-only *viewer* (e.g. a share link) to an already-running
    /// slot. Unlike `attach`, this never spawns a shell and never resizes the
    /// owner's PTY, so a viewer cannot affect the session. Errors if the slot
    /// is not currently running.
    pub fn attach_view(&self, user: &str, index: usize) -> Result<Attachment, String> {
        if index >= self.slots_per_user {
            return Err("slot out of range".into());
        }
        let pool = self.pool(user);
        let guard = pool.slots[index].lock().unwrap();
        let term = match guard.as_ref() {
            Some(t) if t.alive.load(Ordering::Relaxed) => t,
            _ => return Err("session not running".into()),
        };
        let sb = term.scrollback.lock().unwrap();
        let replay = sb.snapshot();
        let output_rx = term.output_tx.subscribe();
        drop(sb);
        Ok(Attachment {
            input_tx: term.input_tx.clone(),
            output_rx,
            shutdown_rx: term.shutdown_tx.subscribe(),
            replay,
        })
    }

    /// Current PTY grid `(cols, rows)` of a running slot, for viewers to mirror.
    pub fn current_size(&self, user: &str, index: usize) -> Option<(u16, u16)> {
        if index >= self.slots_per_user {
            return None;
        }
        let pool = self.pool(user);
        let guard = pool.slots[index].lock().unwrap();
        match guard.as_ref() {
            Some(t) if t.alive.load(Ordering::Relaxed) => Some(*t.size.lock().unwrap()),
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
        let taken = pool.slots[index].lock().unwrap().take();
        if let Some(term) = taken {
            term.stop();
        }
    }
}

fn spawn_terminal(
    login_cmd: &[String],
    user: &str,
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

    // Substitute {user} in the command template.
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
    // For the dev fallback (shell as current user) start in HOME; `login`
    // sets the target user's HOME itself.
    if program.ends_with("sh") {
        if let Some(home) = std::env::var_os("HOME") {
            cmd.cwd(home);
        }
    }

    let child = pair.slave.spawn_command(cmd)?;
    drop(pair.slave); // so the master sees EOF when the shell exits

    let reader = pair.master.try_clone_reader()?;
    let writer = pair.master.take_writer()?;
    let master = pair.master;

    let (output_tx, _) = broadcast::channel::<Vec<u8>>(2048);
    let scrollback = Arc::new(Mutex::new(Scrollback::new(scrollback_cap)));
    let alive = Arc::new(AtomicBool::new(true));
    let size = Arc::new(Mutex::new((cols, rows)));
    let (shutdown_tx, _) = watch::channel(false);

    let (input_tx, input_rx) = std::sync::mpsc::channel::<PtyCmd>();

    // Reader thread: shell output -> scrollback + live broadcast.
    {
        let output_tx = output_tx.clone();
        let scrollback = scrollback.clone();
        let alive = alive.clone();
        let shutdown_tx = shutdown_tx.clone();
        std::thread::spawn(move || {
            let mut reader = reader;
            let mut buf = [0u8; 8192];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let chunk = buf[..n].to_vec();
                        // Append + broadcast under one lock for a clean attach cut.
                        let mut sb = scrollback.lock().unwrap();
                        sb.push(&chunk);
                        let _ = output_tx.send(chunk);
                    }
                }
            }
            // Shell exited on its own: mark dead and disconnect attached clients
            // so they reconnect and get a fresh shell.
            alive.store(false, Ordering::Relaxed);
            let _ = shutdown_tx.send(true);
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
                        *size.lock().unwrap() = (cols, rows);
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
    })
}
