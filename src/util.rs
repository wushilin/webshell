//! Small shared helpers.

use std::sync::{Mutex, MutexGuard};

/// Lock a mutex, tolerating poisoning.
///
/// `lock().unwrap()` is the usual reflex, but it is the wrong default for a
/// process that holds a user's shells for weeks: a single panic anywhere under
/// a lock would poison it permanently, and every later access would panic too
/// — one unlucky unwind and that user's terminals are bricked until restart.
///
/// Nothing behind these locks has an invariant that a panic could leave
/// half-applied: they hold a scrollback ring, a session map, a `(cols, rows)`
/// pair, font prefs. Recovering the data is strictly better than propagating
/// the poison.
pub fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}
