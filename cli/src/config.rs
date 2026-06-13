//! CLI configuration persisted to `~/.gm-miner/config.json`.
//!
//! Pattern mirrors blockmachine's `auth_config.py`, adapted for Rust.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Default config directory.
fn config_dir() -> PathBuf {
    std::env::var("GM_MINER_CONFIG_DIR").map_or_else(
        |_| {
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".gm-miner")
        },
        PathBuf::from,
    )
}

/// Path to the config file.
#[must_use]
pub fn config_path() -> PathBuf {
    config_dir().join("config.json")
}

/// Per-network token set.
///
/// `refresh_token` is captured from the device-code flow and used to mint a
/// fresh access token silently when the stored one expires, avoiding a full
/// browser re-login. Absent for a config written before refresh support
/// existed — the operator simply re-runs `gm-miner login` in that case.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct TokenEntry {
    pub access_token: Option<String>,
    pub token_expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
}

/// Margin treated as "about to expire": a token within this window of its
/// stated expiry is rejected up front. A `gm-miner deploy` does many
/// minutes of CVM work before its trailing `register-image` call, so a
/// token that is merely "still valid right now" is not good enough.
pub const TOKEN_EXPIRY_MARGIN_SECS: i64 = 300;

impl TokenEntry {
    /// Returns true if `token_expires_at` is set and is in the past, or
    /// within [`TOKEN_EXPIRY_MARGIN_SECS`] of now.
    ///
    /// A token with no `token_expires_at` is treated as not-expired here:
    /// the registry's 401 handling remains the backstop for that case.
    #[must_use]
    pub fn is_expired_or_near(&self) -> bool {
        let Some(raw) = self.token_expires_at.as_deref() else {
            return false;
        };
        let Ok(expiry) = chrono::DateTime::parse_from_rfc3339(raw) else {
            // An unparseable timestamp is treated as expired — better to
            // force a re-login than to trust a corrupt value.
            return true;
        };
        let cutoff = chrono::Utc::now() + chrono::Duration::seconds(TOKEN_EXPIRY_MARGIN_SECS);
        expiry.with_timezone(&chrono::Utc) <= cutoff
    }
}

/// One deployed data-plane worker (Phala CVM) under the active hotkey.
///
/// The CLI tracks the operator's deployed CVMs so `worker list` can map
/// the registry's worker rows back to Phala `app_id`s and so a re-deploy
/// or `register-image` of an existing worker reuses the exact same
/// `node_secret` — what envoy enforces, what the registry stores, and
/// what the gateway presents all have to agree.
///
/// `node_secret` is per-worker (never shared between workers): a leaked
/// or rotated secret burns only the one worker.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerRecord {
    /// The registry's worker id (ULID), assigned by the registry on
    /// `POST /miners/register` (worker #1) or `POST /miners/{hotkey}/workers`.
    pub worker_id: String,
    /// The Phala Cloud `app_id` of the deployed CVM. Stored so `worker
    /// remove` can remind the operator which CVM to `phala cvms delete`.
    pub app_id: String,
    /// The operator-chosen CVM name passed to `phala deploy --name`. The
    /// stable local handle for the worker — a re-deploy reuses the
    /// record matched on this name.
    pub app_name: String,
    /// The worker's `x-gm-node-key` pre-shared credential (Mechanism 1 of
    /// `docs/plans/attestation-and-identity.md`).
    pub node_secret: String,
    /// Set on a *provisional* record (empty `worker_id`) that a `worker add`
    /// wrote before its registry POST — i.e. an in-flight or failed secondary
    /// worker. It keeps that stub off the worker-#1 registration paths
    /// (`deploy` / `register-image`), which would otherwise overwrite worker
    /// #1, while still distinguishing it from a primary-redeploy stub. Cleared
    /// once the registry assigns a `worker_id` (the record's role is then read
    /// from its position), so it never appears on a registered record.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub provisional_secondary: bool,
}

/// Per-network configuration.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct NetworkEntry {
    pub api_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tokens: Option<TokenEntry>,
    /// The miner's deployed workers for this network. Scoped per network
    /// so a mainnet and a testnet deployment from the same config get
    /// distinct workers (and distinct per-worker `x-gm-node-key` values).
    /// Populated as the operator runs `gm-miner deploy` (worker #1) and
    /// `gm-miner worker add` (further capacity).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub workers: Vec<WorkerRecord>,
    /// Secret persisted by a pre-multi-worker CLI under the network-level
    /// `node_secret` key. It lets an upgraded CLI recover the `x-gm-node-key`
    /// the operator's already-deployed worker #1 enforces. It is round-tripped
    /// through saves (`login`, token refresh, `set-api-keys`) so an upgrade
    /// followed by a login does not drop it before the migrating deploy or
    /// `register-image` runs; [`upsert_worker`] clears it the moment the first
    /// [`WorkerRecord`] lands, since the secret then lives in that record.
    ///
    /// [`upsert_worker`]: NetworkEntry::upsert_worker
    #[serde(
        default,
        rename = "node_secret",
        skip_serializing_if = "Option::is_none"
    )]
    pub legacy_node_secret: Option<String>,
}

impl NetworkEntry {
    /// The worker record whose `app_name` matches, if any.
    #[must_use]
    pub fn worker_by_app_name(&self, app_name: &str) -> Option<&WorkerRecord> {
        self.workers.iter().find(|w| w.app_name == app_name)
    }

    /// The worker record whose registry `worker_id` matches, if any.
    #[must_use]
    pub fn worker_by_id(&self, worker_id: &str) -> Option<&WorkerRecord> {
        self.workers.iter().find(|w| w.worker_id == worker_id)
    }

    /// The worker record whose Phala `app_id` matches, if any.
    #[must_use]
    pub fn worker_by_app_id(&self, app_id: &str) -> Option<&WorkerRecord> {
        self.workers.iter().find(|w| w.app_id == app_id)
    }

    /// The pre-multi-worker `node_secret` to fall back on, if this network
    /// has no tracked workers yet. A network with `WorkerRecord`s has
    /// migrated past the legacy single-secret model, so the legacy value is
    /// ignored to avoid leaking a stale secret onto a fresh worker.
    #[must_use]
    pub fn legacy_node_secret(&self) -> Option<&str> {
        if !self.workers.is_empty() {
            return None;
        }
        self.legacy_node_secret
            .as_deref()
            .filter(|s| !s.trim().is_empty())
    }

    /// Whether `app_id` names a secondary worker. `register-image` rejects
    /// only this case: it re-registers worker #1, and routing a secondary
    /// through `/miners/register` would overwrite worker #1. See
    /// [`is_secondary`](Self::is_secondary) for what counts as secondary.
    #[must_use]
    pub fn is_secondary_by_app_id(&self, app_id: &str) -> bool {
        self.worker_by_app_id(app_id)
            .is_some_and(|tracked| self.is_secondary(tracked))
    }

    /// Whether `app_name` names a secondary worker — `deploy` gates on this.
    /// See [`is_secondary`](Self::is_secondary).
    #[must_use]
    pub fn is_secondary_by_app_name(&self, app_name: &str) -> bool {
        self.worker_by_app_name(app_name)
            .is_some_and(|tracked| self.is_secondary(tracked))
    }

    /// A `tracked` record is secondary iff either:
    /// - it is registered (real `worker_id`) and that id differs from the
    ///   first record's — a `worker add` worker; or
    /// - it is a provisional `worker add` stub (`provisional_secondary`),
    ///   an in-flight or failed secondary that must stay off the worker-#1
    ///   paths even though it has no `worker_id` yet.
    ///
    /// A provisional *primary* stub (empty `worker_id`, flag unset — a first
    /// deploy or a worker #1 redeploy) is not secondary, so a retry/recovery
    /// through `deploy`/`register-image` is allowed.
    fn is_secondary(&self, tracked: &WorkerRecord) -> bool {
        if tracked.worker_id.is_empty() {
            return tracked.provisional_secondary;
        }
        self.workers
            .first()
            .is_some_and(|first| first.worker_id != tracked.worker_id)
    }

    /// Insert a worker record, dropping any prior record for the same worker
    /// so a re-deploy updates in place rather than accumulating duplicates.
    ///
    /// "Same worker" is the registry `worker_id` (stable across re-deploys)
    /// when the incoming record carries one — this catches a re-deploy that
    /// changed its `--app-name`, which an app-name-only match would miss,
    /// leaving a stale record that the primary/secondary checks could later
    /// mis-read. The `app_name` is always also matched so the empty-
    /// `worker_id` pre-registration stub a fresh deploy writes is superseded
    /// (rather than orphaned) when the registry's `worker_id` lands.
    ///
    /// Worker order is preserved: the record lands at the position of the
    /// first match (or the end when new), so the first record stays worker #1
    /// across re-deploys and `is_primary_worker*` keeps reading correctly.
    pub fn upsert_worker(&mut self, record: WorkerRecord) {
        let matches = |w: &WorkerRecord| {
            let same_worker = !record.worker_id.is_empty() && w.worker_id == record.worker_id;
            same_worker || w.app_name == record.app_name
        };
        match self.workers.iter().position(matches) {
            Some(idx) => {
                self.workers.retain(|w| !matches(w));
                self.workers.insert(idx.min(self.workers.len()), record);
            }
            None => self.workers.push(record),
        }
        // The migration is complete once a worker record exists: the secret
        // now lives in the record, so the legacy network-level copy is dead
        // and must not linger to be re-read or re-serialized.
        self.legacy_node_secret = None;
    }

    /// Drop the worker record whose registry `worker_id` matches. Returns
    /// the removed record so the caller can report the freed `app_id`.
    pub fn remove_worker_by_id(&mut self, worker_id: &str) -> Option<WorkerRecord> {
        let idx = self.workers.iter().position(|w| w.worker_id == worker_id)?;
        Some(self.workers.remove(idx))
    }

    /// Drop a *provisional* worker record (empty `worker_id`) matched by its
    /// `app_id` or `app_name`. Used by `worker remove` to clear the local
    /// dead-end a deploy that launched a CVM but never registered leaves
    /// behind. Returns the removed record, or `None` if nothing matched.
    pub fn remove_provisional_worker(&mut self, id: &str) -> Option<WorkerRecord> {
        let idx = self
            .workers
            .iter()
            .position(|w| w.worker_id.is_empty() && (w.app_id == id || w.app_name == id))?;
        Some(self.workers.remove(idx))
    }
}

/// Provider API keys persisted by `gm-miner set-api-keys`.
///
/// Values are stored in `~/.gm-miner/config.json` (mode 0600).
/// Missing fields mean "not configured" — the deploy command treats
/// a completely absent `provider_keys` section the same as all-None.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ProviderKeys {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anthropic: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub openai: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub google: Option<String>,
}

impl ProviderKeys {
    /// Returns true if at least one key is set to a non-empty, non-whitespace value.
    ///
    /// `Some("")` and `Some("  ")` are treated as not set so that accidental
    /// empty-string assignments (e.g. from an unset shell variable) don't
    /// silently pass the deploy preflight check.
    #[must_use]
    pub fn any_set(&self) -> bool {
        let non_empty = |v: &Option<String>| v.as_deref().is_some_and(|s| !s.trim().is_empty());
        non_empty(&self.anthropic) || non_empty(&self.openai) || non_empty(&self.google)
    }
}

/// Root config structure.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub networks: std::collections::HashMap<String, NetworkEntry>,
    /// Which network is currently active.
    pub active_network: Option<String>,
    /// Provider API keys set by `gm-miner set-api-keys`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_keys: Option<ProviderKeys>,
}

impl Config {
    /// Active network name, defaulting to `"mainnet"`.
    #[must_use]
    pub fn active_network(&self) -> &str {
        self.active_network.as_deref().unwrap_or("mainnet")
    }

    /// Mutable reference to the active network entry (creating it if absent).
    pub fn active_entry_mut(&mut self) -> &mut NetworkEntry {
        let key = self.active_network().to_owned();
        self.networks.entry(key).or_default()
    }

    /// Current tokens for the active network.
    #[must_use]
    pub fn active_tokens(&self) -> Option<&TokenEntry> {
        self.networks
            .get(self.active_network())
            .and_then(|n| n.tokens.as_ref())
    }

    /// The active network's entry, if one has been created.
    #[must_use]
    pub fn active_network_entry(&self) -> Option<&NetworkEntry> {
        self.networks.get(self.active_network())
    }

    /// Registry API URL for the active network.
    #[must_use]
    pub fn api_url(&self) -> String {
        self.networks
            .get(self.active_network())
            .and_then(|n| n.api_url.clone())
            .unwrap_or_else(|| {
                if self.active_network() == "testnet" {
                    "https://test-gm-registry.taostats.io".to_string()
                } else {
                    "https://gm-registry.taostats.io".to_string()
                }
            })
    }
}

/// Load config from disk, returning a default if the file doesn't exist.
///
/// # Errors
/// Returns an error if the file exists but cannot be read or parsed.
pub fn load() -> Result<Config> {
    let path = config_path();
    if !path.exists() {
        return Ok(Config::default());
    }
    let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))
}

/// Persist config to disk, creating the directory if needed.
///
/// # Errors
/// Returns an error if the directory cannot be created, the file cannot be
/// written, or (on Unix) the permissions cannot be set.
pub fn save(cfg: &Config) -> Result<()> {
    let dir = config_dir();
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("create config dir {}", dir.display()))?;

    let path = config_path();
    let bytes = serde_json::to_vec_pretty(cfg).context("serialize config")?;
    std::fs::write(&path, &bytes).with_context(|| format!("write {}", path.display()))?;

    // Restrict permissions on Unix so the file is not world-readable.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&path, perms)
            .with_context(|| format!("chmod 600 {}", path.display()))?;
    }

    Ok(())
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test assertions intentionally panic on unexpected values"
)]
mod tests {
    use super::{Config, NetworkEntry, WorkerRecord};
    use std::collections::HashMap;

    fn worker(worker_id: &str, app_name: &str, secret: &str) -> WorkerRecord {
        WorkerRecord {
            worker_id: worker_id.to_owned(),
            app_id: format!("app_{worker_id}"),
            app_name: app_name.to_owned(),
            node_secret: secret.to_owned(),
            ..Default::default()
        }
    }

    fn config_with_workers(network: &str, workers: Vec<WorkerRecord>) -> Config {
        let mut networks = HashMap::new();
        networks.insert(
            network.to_owned(),
            NetworkEntry {
                workers,
                ..Default::default()
            },
        );
        Config {
            networks,
            active_network: Some(network.to_owned()),
            provider_keys: None,
        }
    }

    #[test]
    fn workers_vec_round_trips_through_json() {
        let cfg = config_with_workers(
            "testnet",
            vec![
                worker("01J0A", "gm-miner-1", "secret-a"),
                worker("01J0B", "gm-miner-2", "secret-b"),
            ],
        );

        let bytes = serde_json::to_vec(&cfg).expect("serialize config");
        let back: Config = serde_json::from_slice(&bytes).expect("deserialize config");

        let entry = back.networks.get("testnet").expect("testnet entry");
        assert_eq!(entry.workers.len(), 2);
        assert_eq!(entry.workers[0].worker_id, "01J0A");
        assert_eq!(entry.workers[0].app_id, "app_01J0A");
        assert_eq!(entry.workers[0].app_name, "gm-miner-1");
        assert_eq!(entry.workers[0].node_secret, "secret-a");
        assert_eq!(entry.workers[1].worker_id, "01J0B");
        assert_eq!(entry.workers[1].node_secret, "secret-b");
    }

    #[test]
    fn empty_workers_vec_is_omitted_from_json() {
        // A network that never deployed must not bloat config.json with an
        // empty `workers` array, matching the skip-if-empty contract.
        let cfg = config_with_workers("mainnet", Vec::new());
        let json = serde_json::to_string(&cfg).expect("serialize config");
        assert!(
            !json.contains("workers"),
            "empty workers vec must be skipped: {json}"
        );
    }

    #[test]
    fn config_without_workers_field_defaults_to_empty() {
        // A config.json written before the workers field existed must
        // still parse — `#[serde(default)]` fills an empty vec.
        let json = r#"{"networks":{"testnet":{"api_url":"https://x"}},"active_network":"testnet"}"#;
        let cfg: Config = serde_json::from_str(json).expect("parse legacy config");
        let entry = cfg.networks.get("testnet").expect("testnet entry");
        assert!(entry.workers.is_empty());
    }

    #[test]
    fn legacy_node_secret_is_read_and_round_trips_until_migrated() {
        // A pre-multi-worker config stored its single secret under the
        // network-level `node_secret` key. It must be readable (so an
        // upgraded CLI can recover it) AND survive an interim save such as
        // `login` or a token refresh — otherwise the secret is lost before
        // the migrating deploy/register-image ever runs.
        let json = r#"{"networks":{"testnet":{"api_url":"https://x","node_secret":"legacy-key"}},"active_network":"testnet"}"#;
        let cfg: Config = serde_json::from_str(json).expect("parse legacy config");
        let entry = cfg.networks.get("testnet").expect("testnet entry");
        assert_eq!(entry.legacy_node_secret(), Some("legacy-key"));

        let resaved = serde_json::to_string(&cfg).expect("serialize config");
        assert!(
            resaved.contains(r#""node_secret":"legacy-key""#),
            "legacy node_secret must round-trip until migrated: {resaved}"
        );
    }

    #[test]
    fn upsert_worker_clears_the_legacy_secret() {
        // Once the first worker record lands the migration is done; the
        // legacy network-level secret must be dropped so it can't be
        // re-read or re-serialized.
        let mut entry = NetworkEntry {
            legacy_node_secret: Some("legacy-key".to_owned()),
            ..Default::default()
        };
        entry.upsert_worker(worker("01J0A", "gm-miner-1", "legacy-key"));
        assert_eq!(entry.legacy_node_secret, None);

        let json = serde_json::to_string(&entry).expect("serialize entry");
        assert!(
            !json.contains("legacy-key") || json.matches("legacy-key").count() == 1,
            "the only legacy-key left must be inside the worker record: {json}"
        );
    }

    #[test]
    fn legacy_node_secret_ignored_once_workers_exist() {
        // A network that has migrated to per-worker records must not leak the
        // stale legacy secret onto a fresh worker.
        let entry = NetworkEntry {
            workers: vec![worker("01J0A", "gm-miner-1", "fresh")],
            legacy_node_secret: Some("legacy-key".to_owned()),
            ..Default::default()
        };
        assert_eq!(entry.legacy_node_secret(), None);
    }

    #[test]
    fn legacy_node_secret_rejects_blank() {
        let entry = NetworkEntry {
            legacy_node_secret: Some("   ".to_owned()),
            ..Default::default()
        };
        assert_eq!(entry.legacy_node_secret(), None);
    }

    #[test]
    fn is_secondary_classifies_registered_and_provisional_records() {
        let entry = NetworkEntry {
            workers: vec![
                worker("01J0A", "gm-miner-1", "a"),
                worker("01J0B", "gm-miner-2", "b"),
                // A provisional worker #1 redeploy under a new name: appended
                // after the primary but not yet registered, flag unset.
                WorkerRecord {
                    worker_id: String::new(),
                    app_id: "app_x".to_owned(),
                    app_name: "gm-miner-1b".to_owned(),
                    node_secret: "s".to_owned(),
                    ..Default::default()
                },
                // A provisional `worker add` stub: empty worker_id but the
                // secondary flag is set, so it must classify as secondary.
                WorkerRecord {
                    worker_id: String::new(),
                    app_id: "app_y".to_owned(),
                    app_name: "gm-miner-3".to_owned(),
                    node_secret: "s".to_owned(),
                    provisional_secondary: true,
                },
            ],
            ..Default::default()
        };
        // Registered first record — not secondary.
        assert!(!entry.is_secondary_by_app_name("gm-miner-1"));
        // Registered non-first record — secondary.
        assert!(entry.is_secondary_by_app_name("gm-miner-2"));
        // Provisional primary redeploy stub — not secondary, so a deploy
        // retry against it is allowed to recover.
        assert!(!entry.is_secondary_by_app_name("gm-miner-1b"));
        assert!(!entry.is_secondary_by_app_id("app_x"));
        // Provisional worker-add stub — secondary, kept off the worker-#1
        // paths even without a worker_id.
        assert!(entry.is_secondary_by_app_name("gm-miner-3"));
        assert!(entry.is_secondary_by_app_id("app_y"));
        // Untracked name — not secondary.
        assert!(!entry.is_secondary_by_app_name("gm-miner-9"));
    }

    #[test]
    fn upsert_worker_replaces_on_matching_app_name() {
        let mut entry = NetworkEntry {
            workers: vec![worker("01J0A", "gm-miner-1", "old")],
            ..Default::default()
        };
        // A re-deploy of the same CVM keeps one record, with the new
        // worker_id/secret — never a duplicate.
        entry.upsert_worker(worker("01J0C", "gm-miner-1", "new"));
        assert_eq!(entry.workers.len(), 1);
        assert_eq!(entry.workers[0].worker_id, "01J0C");
        assert_eq!(entry.workers[0].node_secret, "new");
    }

    #[test]
    fn upsert_worker_appends_distinct_app_name() {
        let mut entry = NetworkEntry {
            workers: vec![worker("01J0A", "gm-miner-1", "a")],
            ..Default::default()
        };
        entry.upsert_worker(worker("01J0B", "gm-miner-2", "b"));
        assert_eq!(entry.workers.len(), 2);
    }

    #[test]
    fn upsert_worker_matches_renamed_worker_by_id() {
        // Worker #1 redeployed under a new --app-name keeps the same registry
        // worker_id. The upsert must update it in place (no stale duplicate,
        // position preserved) rather than appending a second primary record.
        let mut entry = NetworkEntry {
            workers: vec![
                worker("01J0A", "gm-miner-1", "a"),
                worker("01J0B", "gm-miner-2", "b"),
            ],
            ..Default::default()
        };
        entry.upsert_worker(worker("01J0A", "gm-miner-renamed", "a2"));
        assert_eq!(entry.workers.len(), 2, "no stale duplicate");
        assert_eq!(entry.workers[0].worker_id, "01J0A", "position preserved");
        assert_eq!(entry.workers[0].app_name, "gm-miner-renamed");
        assert_eq!(entry.workers[0].node_secret, "a2");
        assert_eq!(entry.workers[1].app_name, "gm-miner-2");
        // worker #1 stays primary after the rename — never seen as secondary.
        assert!(!entry.is_secondary_by_app_name("gm-miner-renamed"));
        assert!(entry.is_secondary_by_app_name("gm-miner-2"));
    }

    #[test]
    fn upsert_worker_supersedes_a_preregistration_stub() {
        // A fresh deploy first writes a stub with an empty worker_id (matched
        // on app_name); when the registry's worker_id lands, the final upsert
        // must replace that stub in place, not append alongside it.
        let mut entry = NetworkEntry {
            workers: vec![worker("", "gm-miner-1", "secret")],
            ..Default::default()
        };
        entry.upsert_worker(worker("01J0A", "gm-miner-1", "secret"));
        assert_eq!(entry.workers.len(), 1);
        assert_eq!(entry.workers[0].worker_id, "01J0A");
    }

    #[test]
    fn remove_worker_by_id_returns_and_drops_the_record() {
        let mut entry = NetworkEntry {
            workers: vec![
                worker("01J0A", "gm-miner-1", "a"),
                worker("01J0B", "gm-miner-2", "b"),
            ],
            ..Default::default()
        };
        let removed = entry
            .remove_worker_by_id("01J0A")
            .expect("worker present to remove");
        assert_eq!(removed.app_id, "app_01J0A");
        assert_eq!(entry.workers.len(), 1);
        assert_eq!(entry.workers[0].worker_id, "01J0B");
        assert!(entry.remove_worker_by_id("nope").is_none());
    }

    #[test]
    fn remove_provisional_worker_matches_app_id_or_name_only() {
        let mut entry = NetworkEntry {
            workers: vec![
                worker("01J0A", "gm-miner-1", "a"),
                WorkerRecord {
                    worker_id: String::new(),
                    app_id: "app_prov".to_owned(),
                    app_name: "gm-miner-2".to_owned(),
                    node_secret: "s".to_owned(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        // A registered worker's app_id must not match (worker_id is non-empty).
        assert!(entry.remove_provisional_worker("app_01J0A").is_none());
        // The provisional record matches by app_id.
        let removed = entry
            .remove_provisional_worker("app_prov")
            .expect("provisional record present");
        assert_eq!(removed.app_name, "gm-miner-2");
        assert_eq!(entry.workers.len(), 1);
        // And by app_name (set up a second provisional to check that path).
        entry.workers.push(WorkerRecord {
            worker_id: String::new(),
            app_id: "app_prov2".to_owned(),
            app_name: "gm-miner-3".to_owned(),
            node_secret: "s".to_owned(),
            ..Default::default()
        });
        assert!(entry.remove_provisional_worker("gm-miner-3").is_some());
    }

    #[test]
    fn is_secondary_by_app_id_distinguishes_first_from_added() {
        // The deploy-created worker (first record) is primary; a registered
        // worker-add worker (later record) is secondary. register-image gates
        // on this.
        let entry = NetworkEntry {
            workers: vec![
                worker("01J0A", "gm-miner-1", "a"),
                worker("01J0B", "gm-miner-2", "b"),
                // A provisional worker-#1 redeploy stub appended after the
                // primary: never secondary, so register-image can recover it.
                WorkerRecord {
                    worker_id: String::new(),
                    app_id: "app_prov".to_owned(),
                    app_name: "gm-miner-1b".to_owned(),
                    node_secret: "s".to_owned(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        assert!(!entry.is_secondary_by_app_id("app_01J0A"));
        assert!(entry.is_secondary_by_app_id("app_01J0B"));
        assert!(!entry.is_secondary_by_app_id("app_prov"));
        // An untracked app_id is not secondary either.
        assert!(!entry.is_secondary_by_app_id("app_unknown"));
    }

    #[test]
    fn lookups_match_by_app_name_and_worker_id() {
        let entry = NetworkEntry {
            workers: vec![worker("01J0A", "gm-miner-1", "a")],
            ..Default::default()
        };
        assert_eq!(
            entry
                .worker_by_app_name("gm-miner-1")
                .expect("by app_name")
                .worker_id,
            "01J0A"
        );
        assert_eq!(
            entry.worker_by_id("01J0A").expect("by worker_id").app_name,
            "gm-miner-1"
        );
        assert!(entry.worker_by_app_name("absent").is_none());
        assert!(entry.worker_by_id("absent").is_none());
    }
}
