//! Per-identity state webshell maintains itself: the issuer subject pinned on
//! first login, and the TOTP secret once enrolled.
//!
//! This lives in its own file rather than in `config.toml` for three reasons.
//! Serializing TOML drops comments and reorders keys, so rewriting the
//! operator's config on every enrollment would quietly eat their annotations;
//! a bad write here cannot take the listen address and cookie key with it; and
//! it keeps the boundary legible — one file is policy you edit, this one is
//! state the program owns.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::identity::Identity;
use crate::util::lock;

/// What we remember about one identity.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Record {
    /// The issuer's stable subject claim, pinned the first time this identity
    /// logs in. Email is mutable and, off gmail.com, re-assignable; `sub` is
    /// not. A mismatch afterwards means the address now belongs to a different
    /// account, and access is refused rather than silently transferred.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    /// base32 TOTP secret. Absent means "not enrolled yet", which is what
    /// drives the enrollment screen on next login.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mfa_secret: Option<String>,
    /// Unix seconds when the TOTP secret was accepted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enrolled_at: Option<u64>,
}

impl Record {
    pub fn enrolled(&self) -> bool {
        self.mfa_secret.is_some()
    }
}

/// One entry as it appears on disk. Flattened into a map in memory.
#[derive(Deserialize, Serialize)]
struct Entry {
    id: Identity,
    #[serde(flatten)]
    record: Record,
}

#[derive(Default, Deserialize, Serialize)]
struct File {
    #[serde(default, rename = "enrollment", skip_serializing_if = "Vec::is_empty")]
    entries: Vec<Entry>,
}

/// Reads and writes the enrollment file.
///
/// Every mutation takes the same lock and writes the whole file while holding
/// it: enrollment is read-modify-write, and two people enrolling at once would
/// otherwise lose one of them.
pub struct EnrollmentStore {
    path: PathBuf,
    inner: Mutex<HashMap<Identity, Record>>,
}

impl EnrollmentStore {
    /// Load the file, or start empty if it does not exist yet — a fresh
    /// install has nobody enrolled, which is not an error.
    pub fn load(path: &Path) -> anyhow::Result<EnrollmentStore> {
        let entries = if path.exists() {
            let text = std::fs::read_to_string(path)
                .map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))?;
            let parsed: File = toml::from_str(&text)
                .map_err(|e| anyhow::anyhow!("parsing {}: {e}", path.display()))?;
            parsed
                .entries
                .into_iter()
                .map(|e| (e.id, e.record))
                .collect()
        } else {
            HashMap::new()
        };
        Ok(EnrollmentStore {
            path: path.to_path_buf(),
            inner: Mutex::new(entries),
        })
    }

    pub fn get(&self, id: &Identity) -> Option<Record> {
        lock(&self.inner).get(id).cloned()
    }

    /// Pin the issuer subject the first time we see this identity, and check it
    /// every time after. `Ok(false)` means the pin did not match — same
    /// address, different account.
    pub fn pin_subject(&self, id: &Identity, sub: &str) -> anyhow::Result<bool> {
        let mut guard = lock(&self.inner);
        let record = guard.entry(id.clone()).or_default();
        match record.sub.as_deref() {
            Some(known) if known != sub => return Ok(false),
            Some(_) => return Ok(true),
            None => record.sub = Some(sub.to_string()),
        }
        let snapshot = guard.clone();
        drop(guard);
        self.write(&snapshot)?;
        Ok(true)
    }

    /// Record a verified TOTP secret, completing enrollment.
    pub fn enroll(&self, id: &Identity, secret: &str, now: u64) -> anyhow::Result<()> {
        let snapshot = {
            let mut guard = lock(&self.inner);
            let record = guard.entry(id.clone()).or_default();
            record.mfa_secret = Some(secret.to_string());
            record.enrolled_at = Some(now);
            guard.clone()
        };
        self.write(&snapshot)
    }

    /// Serialize the whole file atomically, mode 0600. It holds every user's
    /// TOTP secret, so it is never world-readable and never a half-written
    /// file another process could load.
    fn write(&self, entries: &HashMap<Identity, Record>) -> anyhow::Result<()> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let mut list: Vec<Entry> = entries
            .iter()
            .map(|(id, record)| Entry {
                id: id.clone(),
                record: record.clone(),
            })
            .collect();
        // Stable order: a HashMap would reshuffle the file on every write and
        // make diffs unreadable.
        list.sort_by_key(|e| e.id.to_string());
        let text = toml::to_string_pretty(&File { entries: list })?;

        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        let name = self
            .path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("enrollment.toml");
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
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(dir: &Path) -> EnrollmentStore {
        EnrollmentStore::load(&dir.join("enrollment.toml")).unwrap()
    }

    fn tmpdir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("webshell-enroll-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn missing_file_is_an_empty_store() {
        let s = store(&tmpdir("missing"));
        assert!(s.get(&"google:a@gmail.com".parse().unwrap()).is_none());
    }

    #[test]
    fn enrollment_survives_a_reload() {
        let dir = tmpdir("reload");
        let id: Identity = "google:a@gmail.com".parse().unwrap();
        {
            let s = store(&dir);
            s.pin_subject(&id, "sub-123").unwrap();
            s.enroll(&id, "JBSWY3DP", 1000).unwrap();
        }
        let s = store(&dir);
        let r = s.get(&id).unwrap();
        assert_eq!(r.sub.as_deref(), Some("sub-123"));
        assert_eq!(r.mfa_secret.as_deref(), Some("JBSWY3DP"));
        assert_eq!(r.enrolled_at, Some(1000));
        assert!(r.enrolled());
    }

    #[test]
    fn a_pinned_subject_refuses_a_different_account() {
        let dir = tmpdir("pin");
        let s = store(&dir);
        let id: Identity = "google:a@gmail.com".parse().unwrap();
        assert!(s.pin_subject(&id, "sub-123").unwrap());
        assert!(s.pin_subject(&id, "sub-123").unwrap(), "same account again");
        // Same address, different Google account: refuse rather than transfer.
        assert!(!s.pin_subject(&id, "sub-999").unwrap());
    }

    #[test]
    fn the_file_is_not_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmpdir("perms");
        let s = store(&dir);
        s.enroll(&"google:a@gmail.com".parse().unwrap(), "SEED", 1)
            .unwrap();
        let mode = std::fs::metadata(dir.join("enrollment.toml"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "enrollment holds TOTP secrets");
    }
}
