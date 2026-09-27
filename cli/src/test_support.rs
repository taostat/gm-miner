//! Shared test-only helpers for the `gmcli` binary crate.
//!
//! `GMCLI_CONFIG_DIR` is a process-global environment variable, so every
//! test in this binary that points it at a private tempdir must serialise
//! against every *other* such test in the same test binary — not just the
//! ones in its own module. `commands::wizard` and `commands::persist` each
//! used to hold an independent local mutex for the same env var; since
//! `cargo test` runs a module's tests on separate threads within one
//! process by default, those two locks did not serialise against each
//! other, and a test in one module could silently overwrite the override a
//! test in the other module was relying on — observed in practice as a
//! `persist` test's fixture tokens ending up written into the real
//! `~/.gmcli/config.json`. [`ConfigDirGuard`] is the one lock every such
//! test uses.

#![expect(
    clippy::expect_used,
    reason = "test-only helper; a tempdir that can't be created should panic the test"
)]

use std::sync::{Mutex, MutexGuard};

static CONFIG_DIR_ENV: Mutex<()> = Mutex::new(());

/// Points `GMCLI_CONFIG_DIR` at a fresh tempdir for the guard's scope,
/// holding the shared lock for this whole binary crate's test suite so no
/// other test's env mutation can interleave. Clears the override on drop,
/// even if the test panics.
pub(crate) struct ConfigDirGuard {
    /// Held to serialise env mutation across every test module; never read.
    _lock: MutexGuard<'static, ()>,
    /// Owns the tempdir so it outlives the guard; never read.
    _dir: tempfile::TempDir,
}

impl ConfigDirGuard {
    pub(crate) fn new() -> Self {
        let lock = CONFIG_DIR_ENV
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = tempfile::tempdir().expect("tempdir");
        // The held lock serialises this against every other env mutation in
        // this test binary. No `unsafe` block: the bin crate is
        // `#![forbid(unsafe_code)]`, and on edition 2021 `set_var` is still
        // callable directly.
        std::env::set_var("GMCLI_CONFIG_DIR", dir.path());
        Self {
            _lock: lock,
            _dir: dir,
        }
    }
}

impl Drop for ConfigDirGuard {
    fn drop(&mut self) {
        // Still holding the lock until after this returns.
        std::env::remove_var("GMCLI_CONFIG_DIR");
    }
}
