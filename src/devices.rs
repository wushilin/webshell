//! Trusted devices: browsers that have already proved possession of an
//! identity's authenticator and may therefore skip the TOTP step for a bounded
//! window.
//!
//! What a trust record buys is *only* the second factor. The first — the local
//! password, or the Google sign-in — is verified on every login regardless. A
//! record is not a credential that logs anyone in; it is evidence that this
//! browser has already demonstrated possession of the authenticator for this
//! identity.
//!
//! This lives beside `enrollment.toml` rather than inside it. Enrollment holds
//! every user's TOTP secret and is rewritten rarely; trust is churny — a
//! `last_used_at` update on every login — and a bad write to the churny file
//! must not be able to take the secrets down with it.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::identity::Identity;
use crate::util::lock;

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Hash of the cookie value, which is what the store is keyed by. The file
/// therefore never holds a value that is itself a bearer token — the same
/// reasoning as `session::session_key`.
fn token_hash(token: &str) -> String {
    B64.encode(Sha256::digest(token.as_bytes()))
}

/// One trusted browser.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Device {
    /// Public handle, shown in the management UI and in logs. Distinct from
    /// the token: naming a device in a log line must not print a credential.
    pub id: String,
    pub identity: Identity,
    /// base64(sha256(cookie value)).
    pub token_hash: String,
    pub created_at: u64,
    /// Absolute, set once at mint and never extended. A sliding window would
    /// let a stolen cookie refresh its own lifetime forever.
    pub expires_at: u64,
    pub last_used_at: u64,
    /// The `enrolled_at` of the TOTP secret this trust was established
    /// against. Re-enrolling changes it, which strands every older record for
    /// that identity without any separate revocation step — including when an
    /// operator hand-edits `enrollment.toml` to recover a lost authenticator,
    /// where no code of ours runs at all.
    pub enrolled_at: u64,
    /// Display only, never compared: browsers auto-update their UA string and
    /// phones roam between networks, so matching on either would un-trust
    /// honest users at random. `authorize` does not even accept one, so there
    /// is no path by which it could become a condition. Refreshed on each use
    /// alongside `last_ip`, so the list describes the browser as it is now.
    #[serde(default)]
    pub user_agent: String,
    #[serde(default)]
    pub created_ip: String,
    #[serde(default)]
    pub last_ip: String,
}

impl Device {
    fn expired(&self, now: u64) -> bool {
        now >= self.expires_at
    }
}

/// The display-only facts about a browser. Grouped because they travel
/// together and neither is ever compared — they exist so a person can
/// recognise their own devices in the list.
pub struct Client<'a> {
    pub user_agent: &'a str,
    pub ip: &'a str,
}

#[derive(Default, Deserialize, Serialize)]
struct File {
    #[serde(default, rename = "device", skip_serializing_if = "Vec::is_empty")]
    devices: Vec<Device>,
}

/// Reads and writes the trusted-device file.
///
/// **Every mutation holds the lock across the write**, so the in-memory map and
/// the file move together as one step. Snapshotting under the lock and writing
/// after releasing it — the obvious shape, and the wrong one — lets two writers
/// interleave: the slower one lands a snapshot taken before the faster one's
/// change and silently reverts it on disk while memory still looks correct. For
/// a revocation that means a revoked device coming back after a restart, which
/// is exactly the failure this store must not have.
///
/// The cost is that a write serializes readers for the duration of one small
/// `fsync`. At the rate logins happen that is invisible, and it buys an
/// invariant worth far more than the contention it costs.
pub struct DeviceStore {
    path: PathBuf,
    /// Keyed by `token_hash`, so authorizing a cookie is one hash lookup.
    inner: Mutex<HashMap<String, Device>>,
}

impl DeviceStore {
    /// Load the file, or start empty if it does not exist — a fresh install
    /// trusts nobody, which is not an error. Expired records are dropped on
    /// the way in rather than carried around until the first sweep.
    pub fn load(path: &Path, now: u64) -> anyhow::Result<DeviceStore> {
        let devices = if path.exists() {
            let text = std::fs::read_to_string(path)
                .map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))?;
            let parsed: File = toml::from_str(&text)
                .map_err(|e| anyhow::anyhow!("parsing {}: {e}", path.display()))?;
            parsed
                .devices
                .into_iter()
                .filter(|d| !d.expired(now))
                .map(|d| (d.token_hash.clone(), d))
                .collect()
        } else {
            HashMap::new()
        };
        Ok(DeviceStore {
            path: path.to_path_buf(),
            inner: Mutex::new(devices),
        })
    }

    /// Trust a browser, returning `(cookie value, device id)`.
    ///
    /// The caller has already verified a TOTP code; this only records the
    /// consequence. `window_secs` is counted from now and never revisited.
    pub fn mint(
        &self,
        identity: &Identity,
        enrolled_at: u64,
        window_secs: u64,
        max_per_identity: usize,
        client: &Client<'_>,
        now: u64,
    ) -> anyhow::Result<(String, String)> {
        let token = crate::config::random_token(24);
        let id = crate::config::random_token(9);
        let device = Device {
            id: id.clone(),
            identity: identity.clone(),
            token_hash: token_hash(&token),
            created_at: now,
            expires_at: now.saturating_add(window_secs),
            last_used_at: now,
            enrolled_at,
            user_agent: display_text(client.user_agent),
            created_ip: display_text(client.ip),
            last_ip: display_text(client.ip),
        };

        let key = device.token_hash.clone();
        let mut guard = lock(&self.inner);
        guard.retain(|_, d| !d.expired(now));
        // Evict least-recently-used rather than refusing at the cap. A real
        // person has a handful of browsers; a refusal here would be
        // baffling where a silent recycle is not.
        let mut mine: Vec<(String, u64)> = guard
            .iter()
            .filter(|(_, d)| &d.identity == identity)
            .map(|(k, d)| (k.clone(), d.last_used_at))
            .collect();
        if mine.len() >= max_per_identity.max(1) {
            mine.sort_by_key(|(_, used)| *used);
            let excess = mine.len() + 1 - max_per_identity.max(1);
            for (key, _) in mine.into_iter().take(excess) {
                guard.remove(&key);
            }
        }
        guard.insert(key.clone(), device);
        // Roll back if it could not be persisted, so a failed mint leaves no
        // trace: the caller is told it failed and hands out no cookie, and a
        // record nobody holds the token for would only be confusing clutter.
        if let Err(e) = self.write(&guard) {
            guard.remove(&key);
            return Err(e);
        }
        Ok((token, id))
    }

    /// Authorize a presented cookie and record the use, returning the device
    /// id on success.
    ///
    /// Every condition is checked here rather than spread over the caller:
    /// the record must exist, belong to this identity, not have expired, and
    /// have been established against the identity's *current* TOTP secret.
    pub fn authorize(
        &self,
        token: &str,
        identity: &Identity,
        enrolled_at: u64,
        client: &Client<'_>,
        now: u64,
    ) -> Option<String> {
        let mut guard = lock(&self.inner);
        let device = guard.get_mut(&token_hash(token))?;
        if &device.identity != identity || device.expired(now) || device.enrolled_at != enrolled_at
        {
            return None;
        }
        device.last_used_at = now;
        // Refresh both display facts together. A browser that auto-updates
        // would otherwise be listed forever under the version string it
        // happened to have on the day it was trusted, while its address
        // stayed current — one stale field beside one fresh one.
        device.last_ip = display_text(client.ip);
        device.user_agent = display_text(client.user_agent);
        let id = device.id.clone();
        if let Err(e) = self.write(&guard) {
            // The trust is real even if recording the use failed; a read-only
            // disk should not lock the user out of their own device. Only the
            // bookkeeping is lost, and it is refreshed on the next login.
            tracing::error!("could not persist trusted-device use: {e}");
        }
        Some(id)
    }

    /// This identity's live devices, newest first. `enrolled_at` filters out
    /// records stranded by a re-enrollment, so the list never offers to revoke
    /// something that has already stopped working.
    pub fn list(&self, identity: &Identity, enrolled_at: u64, now: u64) -> Vec<Device> {
        let mut devices: Vec<Device> = lock(&self.inner)
            .values()
            .filter(|d| &d.identity == identity && !d.expired(now) && d.enrolled_at == enrolled_at)
            .cloned()
            .collect();
        devices.sort_by(|a, b| b.created_at.cmp(&a.created_at).then(a.id.cmp(&b.id)));
        devices
    }

    /// The device id a cookie maps to, without authorizing it — used only to
    /// mark "this browser" in the listing.
    pub fn id_for_token(&self, token: &str) -> Option<String> {
        lock(&self.inner)
            .get(&token_hash(token))
            .map(|d| d.id.clone())
    }

    /// Revoke one of `identity`'s devices. Scoped to the caller the same way
    /// `ShareStore::revoke` is: another identity's id is indistinguishable
    /// from one that does not exist.
    pub fn revoke(&self, identity: &Identity, id: &str) -> bool {
        let mut guard = lock(&self.inner);
        let Some(key) = guard
            .iter()
            .find(|(_, d)| d.id == id && &d.identity == identity)
            .map(|(k, _)| k.clone())
        else {
            return false;
        };
        guard.remove(&key);
        // Deliberately not rolled back if the write fails. The removal stands
        // in memory, so the device stops working immediately; re-inserting it
        // to match the disk would be the one outcome nobody asked for. The
        // error is logged loudly because it means the revocation will not
        // survive a restart.
        if let Err(e) = self.write(&guard) {
            tracing::error!("REVOCATION NOT PERSISTED for device {id}: {e}");
        }
        true
    }

    /// Revoke every device this identity holds. Also the hook for a
    /// re-enrollment, which strands them anyway — this removes the corpses.
    pub fn revoke_all(&self, identity: &Identity) -> usize {
        let mut guard = lock(&self.inner);
        let before = guard.len();
        guard.retain(|_, d| &d.identity != identity);
        let removed = before - guard.len();
        if removed > 0 {
            if let Err(e) = self.write(&guard) {
                tracing::error!("REVOCATION NOT PERSISTED for {identity}: {e}");
            }
        }
        removed
    }

    /// Forget the device a cookie names, whoever it belongs to. Backs "sign
    /// out and forget this device", where the cookie is the only handle the
    /// caller has.
    pub fn revoke_token(&self, token: &str) -> Option<String> {
        let mut guard = lock(&self.inner);
        let id = guard.remove(&token_hash(token))?.id;
        if let Err(e) = self.write(&guard) {
            tracing::error!("REVOCATION NOT PERSISTED for device {id}: {e}");
        }
        Some(id)
    }

    /// Forget the record a cookie names, but only if it belongs to `identity`.
    ///
    /// One critical section rather than a lookup followed by a removal: the
    /// caller's question is "is this dead weight of mine?", and answering it
    /// in two steps leaves a window where the answer stops being true.
    pub fn forget_if_owned(&self, token: &str, identity: &Identity) -> Option<String> {
        let mut guard = lock(&self.inner);
        let key = token_hash(token);
        guard.get(&key).filter(|d| &d.identity == identity)?;
        let id = guard.remove(&key)?.id;
        if let Err(e) = self.write(&guard) {
            tracing::error!("REVOCATION NOT PERSISTED for device {id}: {e}");
        }
        Some(id)
    }

    /// Drop expired records. Runs on the same minute timer as the session and
    /// share sweeps, so a browser that is never used again does not hold a row
    /// forever.
    pub fn sweep(&self, now: u64) -> usize {
        let mut guard = lock(&self.inner);
        let before = guard.len();
        guard.retain(|_, d| !d.expired(now));
        let removed = before - guard.len();
        if removed > 0 {
            tracing::info!("device sweep: dropped {removed} expired trusted device(s)");
            if let Err(e) = self.write(&guard) {
                tracing::error!("could not persist device sweep: {e}");
            }
        }
        removed
    }

    /// Serialize the whole file atomically, mode 0600. A record is a
    /// second-factor bypass for as long as it lives, so it is never
    /// world-readable and never a half-written file another process could load.
    ///
    /// Atomic in the crash sense as well as the concurrent one: the content
    /// goes to a temporary file that is fsynced, then `rename`d into place —
    /// a reader sees either the whole old file or the whole new one, never a
    /// prefix. The parent directory is fsynced afterwards, because the rename
    /// itself is metadata: without that, a crash can lose the swap even though
    /// the data it points at was safely on disk.
    ///
    /// Callers must hold the map lock across this. It takes `&HashMap` rather
    /// than the guard so that stays a property of the call sites, but every
    /// one of them passes a live guard.
    fn write(&self, devices: &HashMap<String, Device>) -> anyhow::Result<()> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let mut list: Vec<Device> = devices.values().cloned().collect();
        // Stable order: a HashMap would reshuffle the file on every write and
        // make diffs unreadable.
        list.sort_by(|a, b| {
            a.identity
                .to_string()
                .cmp(&b.identity.to_string())
                .then(a.id.cmp(&b.id))
        });
        let text = toml::to_string_pretty(&File { devices: list })?;

        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(parent)?;
        let name = self
            .path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("devices.toml");
        let tmp = parent.join(format!(".{name}.{}.tmp", crate::config::random_token(8)));
        let result = (|| -> anyhow::Result<()> {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)?;
            file.write_all(text.as_bytes())?;
            file.sync_all()?;
            std::fs::rename(&tmp, &self.path)?;
            // Make the rename itself durable, not just the bytes it points at.
            // Best-effort: a filesystem that refuses to open a directory is not
            // a reason to fail a write that already landed.
            if let Ok(dir) = std::fs::File::open(parent) {
                let _ = dir.sync_all();
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        result
    }
}

/// User-Agent and address strings are attacker-influenced values that end up
/// in a page, so they get the same treatment share notes do: control
/// characters collapsed, whitespace normalized, length bounded. Escaping stays
/// the renderer's job — the modal writes them with `textContent`.
fn display_text(raw: &str) -> String {
    crate::share::sanitize_note(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: u64 = 24 * 3600;
    const WINDOW: u64 = 30 * DAY;

    fn tmpdir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("webshell-devices-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn store(dir: &Path, now: u64) -> DeviceStore {
        DeviceStore::load(&dir.join("devices.toml"), now).unwrap()
    }

    fn id(s: &str) -> Identity {
        s.parse().unwrap()
    }

    fn client<'a>(user_agent: &'a str, ip: &'a str) -> Client<'a> {
        Client { user_agent, ip }
    }

    fn mint(s: &DeviceStore, who: &Identity, enrolled_at: u64, now: u64) -> String {
        s.mint(
            who,
            enrolled_at,
            WINDOW,
            10,
            &client("Firefox/1.0", "10.0.0.1"),
            now,
        )
        .unwrap()
        .0
    }

    #[test]
    fn a_trusted_device_survives_a_reload() {
        let dir = tmpdir("reload");
        let who = id("google:a@gmail.com");
        let token = {
            let s = store(&dir, 1000);
            mint(&s, &who, 500, 1000)
        };
        let s = store(&dir, 2000);
        assert!(s
            .authorize(&token, &who, 500, &client("Firefox/1.0", "10.0.0.1"), 2000)
            .is_some());
    }

    #[test]
    fn the_file_is_not_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmpdir("perms");
        let s = store(&dir, 1000);
        mint(&s, &id("google:a@gmail.com"), 500, 1000);
        let mode = std::fs::metadata(dir.join("devices.toml"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "a record is a second-factor bypass");
    }

    #[test]
    fn an_expired_record_is_refused_and_pruned() {
        let dir = tmpdir("expiry");
        let who = id("google:a@gmail.com");
        let s = store(&dir, 1000);
        let token = mint(&s, &who, 500, 1000);
        let at_expiry = 1000 + WINDOW;
        assert!(
            s.authorize(
                &token,
                &who,
                500,
                &client("Firefox/1.0", "10.0.0.1"),
                at_expiry - 1
            )
            .is_some(),
            "still inside the window"
        );
        assert!(s
            .authorize(
                &token,
                &who,
                500,
                &client("Firefox/1.0", "10.0.0.1"),
                at_expiry
            )
            .is_none());
        assert_eq!(s.sweep(at_expiry), 1);
        assert!(s.list(&who, 500, at_expiry).is_empty());
    }

    #[test]
    fn using_a_device_never_extends_its_window() {
        // The whole point of an absolute expiry: a stolen cookie cannot
        // refresh its own lifetime by being used.
        let dir = tmpdir("absolute");
        let who = id("google:a@gmail.com");
        let s = store(&dir, 1000);
        let token = mint(&s, &who, 500, 1000);
        for day in 1..30 {
            assert!(s
                .authorize(
                    &token,
                    &who,
                    500,
                    &client("Firefox/1.0", "10.0.0.1"),
                    1000 + day * DAY
                )
                .is_some());
        }
        assert!(
            s.authorize(
                &token,
                &who,
                500,
                &client("Firefox/1.0", "10.0.0.1"),
                1000 + WINDOW
            )
            .is_none(),
            "30 days from the opt-in, however much it was used since"
        );
    }

    #[test]
    fn re_enrolling_strands_every_older_device() {
        // The operator-recovery path: enrollment.toml is edited by hand and
        // the identity enrolls a new authenticator. No code of ours ran, so
        // the enrolled_at comparison is the only thing standing here.
        let dir = tmpdir("reenroll");
        let who = id("google:a@gmail.com");
        let s = store(&dir, 1000);
        let token = mint(&s, &who, 500, 1000);
        assert!(s
            .authorize(&token, &who, 500, &client("Firefox/1.0", "10.0.0.1"), 1100)
            .is_some());
        assert!(
            s.authorize(&token, &who, 900, &client("Firefox/1.0", "10.0.0.1"), 1100)
                .is_none(),
            "a new TOTP secret invalidates trust established against the old one"
        );
        assert!(
            s.list(&who, 900, 1100).is_empty(),
            "and the listing does not offer to revoke a dead record"
        );
    }

    #[test]
    fn one_identitys_device_is_not_anothers() {
        let dir = tmpdir("cross");
        let a = id("google:a@gmail.com");
        let b = id("google:b@gmail.com");
        let s = store(&dir, 1000);
        let token = mint(&s, &a, 500, 1000);
        assert!(s
            .authorize(&token, &b, 500, &client("Firefox/1.0", "10.0.0.1"), 1100)
            .is_none());
        assert!(s
            .authorize(&token, &a, 500, &client("Firefox/1.0", "10.0.0.1"), 1100)
            .is_some());
    }

    #[test]
    fn the_cap_evicts_the_least_recently_used() {
        let dir = tmpdir("cap");
        let who = id("google:a@gmail.com");
        let s = store(&dir, 1000);
        let first = s
            .mint(&who, 500, WINDOW, 2, &client("A", "10.0.0.1"), 1000)
            .unwrap()
            .0;
        let second = s
            .mint(&who, 500, WINDOW, 2, &client("B", "10.0.0.2"), 1001)
            .unwrap()
            .0;
        // Touch the older one so the newer is now least-recently-used.
        assert!(s
            .authorize(&first, &who, 500, &client("Firefox/1.0", "10.0.0.1"), 1002)
            .is_some());
        let third = s
            .mint(&who, 500, WINDOW, 2, &client("C", "10.0.0.3"), 1003)
            .unwrap()
            .0;
        assert_eq!(s.list(&who, 500, 1003).len(), 2);
        assert!(s
            .authorize(&second, &who, 500, &client("Firefox/1.0", "10.0.0.2"), 1004)
            .is_none());
        assert!(s
            .authorize(&first, &who, 500, &client("Firefox/1.0", "10.0.0.1"), 1004)
            .is_some());
        assert!(s
            .authorize(&third, &who, 500, &client("Firefox/1.0", "10.0.0.3"), 1004)
            .is_some());
    }

    #[test]
    fn the_cap_counts_only_this_identitys_live_records() {
        let dir = tmpdir("cap-scope");
        let a = id("google:a@gmail.com");
        let b = id("google:b@gmail.com");
        let s = store(&dir, 1000);
        let a1 = s
            .mint(&a, 500, WINDOW, 1, &client("A", ""), 1000)
            .unwrap()
            .0;
        // b filling its own quota must not evict a's only device.
        s.mint(&b, 500, WINDOW, 1, &client("B", ""), 1001).unwrap();
        s.mint(&b, 500, WINDOW, 1, &client("B2", ""), 1002).unwrap();
        assert!(s
            .authorize(&a1, &a, 500, &client("Firefox/1.0", ""), 1003)
            .is_some());
    }

    #[test]
    fn revoke_is_scoped_to_the_owner() {
        let dir = tmpdir("revoke");
        let a = id("google:a@gmail.com");
        let b = id("google:b@gmail.com");
        let s = store(&dir, 1000);
        let (token, device_id) = s.mint(&a, 500, WINDOW, 10, &client("A", ""), 1000).unwrap();
        assert!(!s.revoke(&b, &device_id), "not b's to revoke");
        assert!(s
            .authorize(&token, &a, 500, &client("Firefox/1.0", ""), 1100)
            .is_some());
        assert!(s.revoke(&a, &device_id));
        assert!(s
            .authorize(&token, &a, 500, &client("Firefox/1.0", ""), 1100)
            .is_none());
    }

    #[test]
    fn revoke_all_leaves_other_identities_alone() {
        let dir = tmpdir("revoke-all");
        let a = id("google:a@gmail.com");
        let b = id("google:b@gmail.com");
        let s = store(&dir, 1000);
        mint(&s, &a, 500, 1000);
        mint(&s, &a, 500, 1001);
        let btoken = mint(&s, &b, 500, 1002);
        assert_eq!(s.revoke_all(&a), 2);
        assert!(s.list(&a, 500, 1100).is_empty());
        assert!(s
            .authorize(&btoken, &b, 500, &client("Firefox/1.0", ""), 1100)
            .is_some());
    }

    #[test]
    fn a_cookie_can_forget_its_own_device() {
        let dir = tmpdir("forget");
        let who = id("google:a@gmail.com");
        let s = store(&dir, 1000);
        let (token, device_id) = s
            .mint(&who, 500, WINDOW, 10, &client("A", ""), 1000)
            .unwrap();
        assert_eq!(s.id_for_token(&token).as_deref(), Some(device_id.as_str()));
        assert_eq!(s.revoke_token(&token).as_deref(), Some(device_id.as_str()));
        assert!(s
            .authorize(&token, &who, 500, &client("Firefox/1.0", ""), 1100)
            .is_none());
        assert!(s.revoke_token(&token).is_none());
    }

    #[test]
    fn a_garbage_cookie_authorizes_nothing() {
        let dir = tmpdir("garbage");
        let who = id("google:a@gmail.com");
        let s = store(&dir, 1000);
        mint(&s, &who, 500, 1000);
        let nobody = client("Firefox/1.0", "");
        assert!(s
            .authorize("not-a-real-token", &who, 500, &nobody, 1100)
            .is_none());
        assert!(s.authorize("", &who, 500, &nobody, 1100).is_none());
    }

    #[test]
    fn concurrent_writers_do_not_lose_each_others_records() {
        // The store is shared by every request thread. If a mutation snapshots
        // under the lock but writes after releasing it, two writers interleave
        // and the slower one lands a snapshot taken before the faster one's
        // change — silently reverting it on disk. In-memory state looks right,
        // so it only surfaces after a restart: a revoked device coming back.
        use std::sync::Arc;

        let dir = tmpdir("concurrent");
        let store = Arc::new(store(&dir, 1000));
        let threads: Vec<_> = (0..16)
            .map(|i| {
                let s = Arc::clone(&store);
                std::thread::spawn(move || {
                    let who = id(&format!("google:u{i}@gmail.com"));
                    s.mint(&who, 500, WINDOW, 10, &client("Firefox/1.0", ""), 1000)
                        .unwrap();
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }

        // Memory is fine either way — the lock protects it. Disk is the test.
        let reloaded = DeviceStore::load(&dir.join("devices.toml"), 1000).unwrap();
        for i in 0..16 {
            let who = id(&format!("google:u{i}@gmail.com"));
            assert_eq!(
                reloaded.list(&who, 500, 1000).len(),
                1,
                "u{i} was written and then lost by a racing writer"
            );
        }
    }

    #[test]
    fn concurrent_revokes_and_mints_leave_disk_matching_memory() {
        use std::sync::Arc;

        let dir = tmpdir("concurrent-mixed");
        let store = Arc::new(store(&dir, 1000));
        let keep = id("google:keep@gmail.com");
        let doomed = id("google:doomed@gmail.com");
        let (_, doomed_id) = store
            .mint(&doomed, 500, WINDOW, 10, &client("Firefox/1.0", ""), 1000)
            .unwrap();

        let a = {
            let s = Arc::clone(&store);
            let doomed = doomed.clone();
            std::thread::spawn(move || {
                s.revoke(&doomed, &doomed_id);
            })
        };
        let b = {
            let s = Arc::clone(&store);
            let keep = keep.clone();
            std::thread::spawn(move || {
                s.mint(&keep, 500, WINDOW, 10, &client("Firefox/1.0", ""), 1001)
                    .unwrap();
            })
        };
        a.join().unwrap();
        b.join().unwrap();

        let reloaded = DeviceStore::load(&dir.join("devices.toml"), 1001).unwrap();
        assert_eq!(
            reloaded.list(&keep, 500, 1001).len(),
            1,
            "the mint was lost"
        );
        assert!(
            reloaded.list(&doomed, 500, 1001).is_empty(),
            "the revocation was lost — a revoked device returns after a restart"
        );
    }

    #[test]
    fn a_browser_upgrade_neither_breaks_trust_nor_leaves_a_stale_label() {
        // The User-Agent is display-only. `authorize` cannot even see one as a
        // condition — it takes the whole Client and writes it — so a browser
        // that auto-updates keeps working, and the list follows it.
        let dir = tmpdir("ua-upgrade");
        let who = id("google:a@gmail.com");
        let s = store(&dir, 1000);
        let (token, _) = s
            .mint(
                &who,
                500,
                WINDOW,
                10,
                &client("Mozilla/5.0 Firefox/130.0", "10.0.0.1"),
                1000,
            )
            .unwrap();

        // Same browser, a minor version later, from a new address.
        assert!(
            s.authorize(
                &token,
                &who,
                500,
                &client("Mozilla/5.0 Firefox/131.0", "10.0.0.9"),
                1100,
            )
            .is_some(),
            "an upgraded browser is still the trusted device"
        );

        let listed = &s.list(&who, 500, 1100)[0];
        assert_eq!(listed.user_agent, "Mozilla/5.0 Firefox/131.0");
        assert_eq!(listed.last_ip, "10.0.0.9");
        // What it was trusted from is still on record; only the "last seen"
        // fields move.
        assert_eq!(listed.created_ip, "10.0.0.1");
    }

    #[test]
    fn a_hostile_user_agent_is_defanged_before_it_is_stored() {
        let dir = tmpdir("ua");
        let who = id("google:a@gmail.com");
        let s = store(&dir, 1000);
        s.mint(
            &who,
            500,
            WINDOW,
            10,
            &client("Mozilla\n\r\t<script>alert(1)</script>", ""),
            1000,
        )
        .unwrap();
        let ua = &s.list(&who, 500, 1000)[0].user_agent;
        assert!(!ua.contains('\n') && !ua.contains('\r') && !ua.contains('\t'));
        assert!(ua.len() <= 120);
    }

    #[test]
    fn the_file_never_holds_the_cookie_value() {
        let dir = tmpdir("nosecret");
        let s = store(&dir, 1000);
        let token = mint(&s, &id("google:a@gmail.com"), 500, 1000);
        let text = std::fs::read_to_string(dir.join("devices.toml")).unwrap();
        assert!(
            !text.contains(&token),
            "the store keys on a hash, so a leaked file is not a set of bypasses"
        );
    }
}
