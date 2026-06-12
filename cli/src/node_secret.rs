//! Node-secret generation for the miner.
//!
//! Mechanism 1 of `docs/plans/attestation-and-identity.md`: the miner
//! sets a secret for its node, hands it to the registry at registration,
//! and bakes it into the container's env where envoy enforces it as the
//! `x-gm-node-key` header. The secret is generated once on the first
//! `gm-miner deploy` and persisted in the CLI config so re-deploys reuse
//! the same value.

use std::fmt::Write as _;

use anyhow::{Context, Result};

use crate::config;

/// Length in bytes of the random material behind a node secret. 32 bytes
/// (256 bits) is well past any brute-force concern for a pre-shared
/// credential; hex-encoded it is a 64-character string.
const SECRET_BYTES: usize = 32;

/// Generate a fresh node secret: 32 random bytes, lowercase hex-encoded.
///
/// Reads the operating system CSPRNG directly (`/dev/urandom` on Unix) so
/// the CLI needs no extra crypto dependency. The 64-char hex string sits
/// inside the registry's `node_secret` length bounds (16–128).
///
/// # Errors
/// Returns an error if the OS random source cannot be read.
pub fn generate() -> Result<String> {
    let bytes = os_random_bytes()?;
    let mut hex = String::with_capacity(SECRET_BYTES * 2);
    for byte in bytes {
        // `write!` to a String never fails, so the result is discarded.
        let _ = write!(hex, "{byte:02x}");
    }
    Ok(hex)
}

#[cfg(unix)]
fn os_random_bytes() -> Result<[u8; SECRET_BYTES]> {
    use std::io::Read as _;

    let mut buf = [0u8; SECRET_BYTES];
    let mut urandom = std::fs::File::open("/dev/urandom").context("open /dev/urandom")?;
    urandom
        .read_exact(&mut buf)
        .context("read random bytes from /dev/urandom")?;
    Ok(buf)
}

#[cfg(not(unix))]
fn os_random_bytes() -> Result<[u8; SECRET_BYTES]> {
    anyhow::bail!("node-secret generation requires a Unix host (/dev/urandom)")
}

/// Resolve the `x-gm-node-key` secret for the worker named `app_name`.
///
/// Each worker (Phala CVM) carries its own secret — never shared with a
/// sibling, so a leaked secret burns only one worker. A re-deploy of an
/// existing worker must reuse the exact same value (what envoy enforces,
/// what the registry stores, and what the gateway presents all have to
/// agree), so the secret stored in that worker's [`WorkerRecord`] is
/// returned verbatim. A worker with no record yet (a first deploy or
/// `worker add`) gets a freshly generated secret.
///
/// `entry` is the active network's config entry; the secret is matched on
/// `app_name`, the stable local handle for a worker before the registry
/// assigns its `worker_id`. Returns `(secret, freshly_generated)` so the
/// caller can report which path ran and persist a fresh secret into a new
/// [`WorkerRecord`] alongside the `worker_id`/`app_id` the registry and
/// Phala return.
///
/// `allow_legacy` enables the pre-multi-worker fallback: when set and no
/// `WorkerRecord` matches, the network-level [`legacy_node_secret`] is
/// reused. Only `gm-miner deploy` (worker #1) sets it — that legacy secret
/// belongs to worker #1, so a `worker add` must never inherit it.
///
/// [`legacy_node_secret`]: config::NetworkEntry::legacy_node_secret
///
/// # Errors
/// Returns an error if a fresh secret is needed but the OS random source
/// cannot be read.
pub fn for_worker(
    entry: Option<&config::NetworkEntry>,
    app_name: &str,
    allow_legacy: bool,
) -> Result<(String, bool)> {
    if let Some(existing) = entry
        .and_then(|e| e.worker_by_app_name(app_name))
        .map(|w| w.node_secret.as_str())
    {
        if !existing.trim().is_empty() {
            return Ok((existing.to_owned(), false));
        }
    }
    // A pre-multi-worker config stored its single secret at the network
    // level with no `WorkerRecord`. Re-deploying that worker #1 must reuse
    // it so the registry's stored secret stays in lockstep with what the
    // running envoy enforces — but a `worker add` must never inherit it.
    if allow_legacy {
        if let Some(legacy) = entry.and_then(config::NetworkEntry::legacy_node_secret) {
            return Ok((legacy.to_owned(), false));
        }
    }
    let secret = generate().context("generate node secret")?;
    Ok((secret, true))
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test assertions intentionally panic on unexpected values"
)]
mod tests {
    use super::*;
    use crate::config::{NetworkEntry, WorkerRecord};

    #[test]
    fn generate_produces_64_hex_chars() {
        let secret = generate().expect("generate node secret");
        assert_eq!(secret.len(), SECRET_BYTES * 2);
        assert!(secret.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(secret.chars().all(|c| !c.is_ascii_uppercase()));
    }

    #[test]
    fn generate_is_not_constant() {
        // Two consecutive draws must differ — a constant secret would be
        // a catastrophic failure of the CSPRNG read.
        let a = generate().expect("first secret");
        let b = generate().expect("second secret");
        assert_ne!(a, b);
    }

    fn entry_with(workers: Vec<WorkerRecord>) -> NetworkEntry {
        NetworkEntry {
            workers,
            ..Default::default()
        }
    }

    fn worker(app_name: &str, secret: &str) -> WorkerRecord {
        WorkerRecord {
            worker_id: format!("id-{app_name}"),
            app_id: format!("app-{app_name}"),
            app_name: app_name.to_owned(),
            node_secret: secret.to_owned(),
        }
    }

    #[test]
    fn for_worker_reuses_an_existing_workers_secret() {
        let entry = entry_with(vec![worker("gm-miner-1", "stable-secret")]);
        let (secret, fresh) =
            for_worker(Some(&entry), "gm-miner-1", false).expect("resolve existing worker secret");
        assert_eq!(secret, "stable-secret");
        assert!(!fresh, "an existing worker must not be re-keyed");
    }

    #[test]
    fn for_worker_generates_a_fresh_secret_for_a_new_worker() {
        let entry = entry_with(vec![worker("gm-miner-1", "secret-1")]);
        let (secret, fresh) =
            for_worker(Some(&entry), "gm-miner-2", false).expect("generate fresh worker secret");
        assert!(fresh, "a brand-new worker must get a fresh secret");
        assert_eq!(secret.len(), SECRET_BYTES * 2);
        assert_ne!(
            secret, "secret-1",
            "a new worker's secret must not be shared with a sibling"
        );
    }

    #[test]
    fn for_worker_yields_distinct_secrets_per_worker() {
        // Two new workers (no record yet) must get independent secrets —
        // a per-worker secret is never shared across workers.
        let entry = entry_with(Vec::new());
        let (a, _) = for_worker(Some(&entry), "gm-miner-1", false).expect("first new worker");
        let (b, _) = for_worker(Some(&entry), "gm-miner-2", false).expect("second new worker");
        assert_ne!(a, b);
    }

    #[test]
    fn for_worker_with_no_entry_generates_fresh() {
        let (secret, fresh) = for_worker(None, "gm-miner-1", true).expect("no config entry yet");
        assert!(fresh);
        assert_eq!(secret.len(), SECRET_BYTES * 2);
    }

    #[test]
    fn for_worker_reuses_a_legacy_network_secret_for_worker_one() {
        // A pre-multi-worker config with no WorkerRecord must reuse the
        // legacy network-level secret on a worker #1 re-deploy
        // (`allow_legacy`), keeping the registry and envoy in lockstep.
        let entry = NetworkEntry {
            legacy_node_secret: Some("legacy-key".to_owned()),
            ..Default::default()
        };
        let (secret, fresh) =
            for_worker(Some(&entry), "gm-miner-1", true).expect("reuse legacy secret");
        assert_eq!(secret, "legacy-key");
        assert!(!fresh, "a legacy worker #1 must not be re-keyed");
    }

    #[test]
    fn for_worker_never_inherits_legacy_secret_on_worker_add() {
        // A `worker add` (allow_legacy = false) must mint its own secret —
        // inheriting worker #1's legacy secret would share a credential.
        let entry = NetworkEntry {
            legacy_node_secret: Some("legacy-key".to_owned()),
            ..Default::default()
        };
        let (secret, fresh) =
            for_worker(Some(&entry), "gm-miner-2", false).expect("fresh secret for added worker");
        assert!(fresh);
        assert_ne!(secret, "legacy-key");
    }

    #[test]
    fn for_worker_ignores_legacy_secret_once_a_record_exists() {
        // Once a WorkerRecord exists the legacy value is dead — a new worker
        // must get its own fresh secret, never the legacy one.
        let entry = NetworkEntry {
            workers: vec![worker("gm-miner-1", "record-secret")],
            legacy_node_secret: Some("legacy-key".to_owned()),
            ..Default::default()
        };
        let (secret, fresh) =
            for_worker(Some(&entry), "gm-miner-2", true).expect("fresh secret for new worker");
        assert!(fresh);
        assert_ne!(secret, "legacy-key");
        assert_ne!(secret, "record-secret");
    }
}
