//! CLI configuration persisted to `~/.gmcli/config.json`.

use anyhow::{Context, Result};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::network::Network;

/// The `sub` claim of a JWT, read without verifying the signature — the gm
/// registry verifies the token; the CLI only needs the identity it asserts.
fn jwt_sub(token: &str) -> Option<String> {
    let payload = token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    claims.get("sub")?.as_str().map(str::to_owned)
}

/// Default config directory.
fn config_dir() -> PathBuf {
    std::env::var("GMCLI_CONFIG_DIR").map_or_else(
        |_| {
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".gmcli")
        },
        PathBuf::from,
    )
}

/// Path to the config file.
#[must_use]
pub fn config_path() -> PathBuf {
    config_dir().join("config.json")
}

/// Path to the advisory lockfile guarding read-modify-write sequences.
fn lock_path() -> PathBuf {
    config_dir().join(".lock")
}

/// Per-network token set.
///
/// `refresh_token` is captured from the device-code flow and used to mint a
/// fresh access token silently when the stored one expires, avoiding a full
/// browser re-login. Absent for a config written before refresh support
/// existed — the operator simply re-runs `gmcli login` in that case.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct TokenEntry {
    pub access_token: Option<String>,
    pub token_expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
}

/// Margin treated as "about to expire": a token within this window of its
/// stated expiry is rejected up front. A `gmcli deploy` does many
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

/// The hotkey the miner registers and serves under, recorded by
/// `gmcli register-hotkey`.
///
/// `ss58` is the on-chain account address — the stable identity every later
/// command (login, deploy, doctor, earnings) references. `name` is the
/// btcli `--wallet.hotkey` name, present only when the hotkey was registered
/// (or named) through the assisted btcli flow; a bring-your-own ss58 has no
/// local wallet name. `verified` records whether registration on the subnet
/// metagraph was confirmed locally — a bring-your-own ss58 entered without
/// btcli present is recorded unverified and confirmed later by the
/// registry/gateway on first deploy.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HotkeyRecord {
    pub ss58: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default)]
    pub verified: bool,
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
    /// Registry worker provenance derived from the provider upstream selectors
    /// active when this worker was deployed. Stored per worker so
    /// `register-image` recovery preserves the deployed backend instead of
    /// relabeling from whatever global config is current later.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
    /// The provider slot ids advertised at deploy time, derived from the
    /// keys baked into this CVM. Stored per worker so `register-image`
    /// recovery re-sends what the worker actually holds instead of
    /// re-deriving from whatever local keys are current later.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_slots: Option<std::collections::BTreeMap<String, Vec<String>>>,
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
    /// Populated as the operator runs `gmcli deploy` (worker #1) and
    /// `gmcli worker add` (further capacity).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub workers: Vec<WorkerRecord>,
    /// The hotkey this miner registers and serves under, recorded by
    /// `gmcli register-hotkey`. Scoped per network so a testnet and a
    /// mainnet hotkey from the same config stay distinct.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registered_hotkey: Option<HotkeyRecord>,
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
    /// Record the registered hotkey, replacing any prior one. `register-hotkey`
    /// routes through here rather than poking the field so the persistence
    /// shape stays in one place.
    pub fn set_registered_hotkey(&mut self, record: HotkeyRecord) {
        self.registered_hotkey = Some(record);
    }

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

/// Provider API keys persisted by `gmcli set-api-keys`.
///
/// Values are stored in `~/.gmcli/config.json` (mode 0600).
/// Missing fields mean "not configured" — the deploy command treats
/// a completely absent `provider_keys` section the same as all-None.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ProviderKeys {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anthropic: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anthropic_upstream: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bedrock_region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bedrock_api_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub openai: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub openai_upstream: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub azure_openai_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub azure_openai_api_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub google: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chutes: Option<String>,
}

/// True when `v` holds a non-empty, non-whitespace value. `Some("")` and
/// `Some("  ")` count as unset so an accidental empty-string assignment (e.g.
/// from an unset shell variable) doesn't silently pass the deploy preflight.
fn non_empty(v: Option<&str>) -> bool {
    v.is_some_and(|s| !s.trim().is_empty())
}

/// Bail naming every flag in `fields` whose value is unset, for a selected
/// cloud upstream that `start.sh` would otherwise reject at boot.
fn require_present(label: &str, fields: &[(&str, Option<&str>)]) -> Result<()> {
    let missing: Vec<&str> = fields
        .iter()
        .filter_map(|(flag, v)| (!non_empty(*v)).then_some(*flag))
        .collect();
    if !missing.is_empty() {
        anyhow::bail!(
            "{label} requires {} — set via `gmcli set-api-keys`",
            missing.join(", ")
        );
    }
    Ok(())
}

const AZURE_OPENAI_ALLOWED_SUFFIXES: [&str; 3] = [
    "openai.azure.com",
    "services.ai.azure.com",
    "cognitiveservices.azure.com",
];

fn validate_bedrock_region(region: &str) -> Result<()> {
    if region
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        Ok(())
    } else {
        anyhow::bail!("--bedrock-region must contain only letters, numbers, and hyphens")
    }
}

fn validate_dns_host(label: &str, host: &str) -> Result<()> {
    let valid = !host.is_empty()
        && !host.starts_with('.')
        && !host.ends_with('.')
        && !host.contains("..")
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
    if valid {
        Ok(())
    } else {
        anyhow::bail!("{label} must be a DNS host (got '{host}')")
    }
}

fn host_allowed_by_suffix(host: &str, suffix: &str) -> bool {
    host.len() > suffix.len()
        && host.ends_with(suffix)
        && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
}

fn validate_azure_openai_endpoint(endpoint: &str) -> Result<()> {
    let mut rest = endpoint;
    if let Some(stripped) = endpoint.strip_prefix("https://") {
        rest = stripped;
    } else if endpoint.starts_with("http://") {
        anyhow::bail!("--azure-openai-endpoint must use https when a scheme is provided");
    } else if endpoint.contains("://") {
        anyhow::bail!("--azure-openai-endpoint has unsupported URL scheme");
    }

    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.contains('@') {
        anyhow::bail!("--azure-openai-endpoint must not contain userinfo");
    }
    let host = authority
        .split_once(':')
        .map_or(authority, |(host, _)| host)
        .to_ascii_lowercase();
    validate_dns_host("--azure-openai-endpoint host", &host)?;

    if AZURE_OPENAI_ALLOWED_SUFFIXES
        .iter()
        .any(|suffix| host_allowed_by_suffix(&host, suffix))
    {
        Ok(())
    } else {
        anyhow::bail!(
            "--azure-openai-endpoint host '{host}' is not in the allowed suffix set: {}",
            AZURE_OPENAI_ALLOWED_SUFFIXES.join(", ")
        )
    }
}

impl ProviderKeys {
    /// Returns true if at least one key is set to a non-empty, non-whitespace value.
    #[must_use]
    pub fn any_set(&self) -> bool {
        let anthropic_upstream = self.anthropic_upstream.as_deref().unwrap_or("direct");
        let openai_upstream = self.openai_upstream.as_deref().unwrap_or("direct");
        ((anthropic_upstream == "direct" && non_empty(self.anthropic.as_deref()))
            || (anthropic_upstream == "bedrock" && non_empty(self.bedrock_api_key.as_deref())))
            || ((openai_upstream == "direct" && non_empty(self.openai.as_deref()))
                || (openai_upstream == "azure" && non_empty(self.azure_openai_api_key.as_deref())))
            || non_empty(self.google.as_deref())
            || non_empty(self.chutes.as_deref())
    }

    /// Reject a selected cloud upstream that is missing fields `start.sh`
    /// requires at boot. Without this, `gmcli deploy` would launch a CVM that
    /// crash-loops because `start.sh` exits — fail fast at deploy instead.
    ///
    /// # Errors
    /// Returns an error when `anthropic_upstream`/`openai_upstream` is an
    /// unknown value, or when a selected `bedrock`/`azure` upstream is missing
    /// a required field.
    pub fn validate_upstreams(&self) -> Result<()> {
        crate::slots::validate_cloud_backend_single_keys(self)?;
        match self.anthropic_upstream.as_deref().unwrap_or("direct") {
            "direct" => {}
            "bedrock" => {
                require_present(
                    "anthropic-upstream=bedrock",
                    &[
                        ("--bedrock-region", self.bedrock_region.as_deref()),
                        ("--bedrock-api-key", self.bedrock_api_key.as_deref()),
                    ],
                )?;
                validate_bedrock_region(self.bedrock_region.as_deref().unwrap_or_default())?;
            }
            other => {
                anyhow::bail!("anthropic-upstream must be 'direct' or 'bedrock' (got '{other}')")
            }
        }
        match self.openai_upstream.as_deref().unwrap_or("direct") {
            "direct" => {}
            "azure" => {
                require_present(
                    "openai-upstream=azure",
                    &[
                        (
                            "--azure-openai-endpoint",
                            self.azure_openai_endpoint.as_deref(),
                        ),
                        (
                            "--azure-openai-api-key",
                            self.azure_openai_api_key.as_deref(),
                        ),
                    ],
                )?;
                validate_azure_openai_endpoint(
                    self.azure_openai_endpoint.as_deref().unwrap_or_default(),
                )?;
            }
            other => anyhow::bail!("openai-upstream must be 'direct' or 'azure' (got '{other}')"),
        }
        Ok(())
    }

    /// Registry worker provenance is a single optional backend marker. If both
    /// cloud upstreams are configured, Bedrock takes precedence; the registry
    /// only needs "cloud-backed, use the inference probe" here, while each
    /// offer's `upstream_model` carries the per-model translation detail.
    #[must_use]
    pub fn worker_backend(&self) -> Option<&'static str> {
        if self.anthropic_upstream.as_deref() == Some("bedrock") {
            Some("bedrock")
        } else if self.openai_upstream.as_deref() == Some("azure") {
            Some("azure")
        } else {
            None
        }
    }
}

/// Record of the operator's one-time acceptance of the gm miner terms.
///
/// Written by the `gmcli deploy` terms gate to suppress re-prompts. The
/// authoritative, tamper-resistant copy lives on the registry's miner record
/// (keyed to hotkey); this local copy is convenience only — a `version` that
/// no longer matches the CLI's current terms re-prompts.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptedTerms {
    /// The terms version the operator accepted (`crate::terms::CURRENT_TERMS_VERSION`).
    pub version: String,
    /// RFC 3339 timestamp the acceptance was recorded.
    pub timestamp: String,
}

/// Root config structure.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub networks: std::collections::HashMap<String, NetworkEntry>,
    /// Which network is currently active.
    pub active_network: Option<String>,
    /// The operator's one-time terms acceptance, recorded at first deploy.
    /// Account-wide (not per-network): the representation is about the
    /// operator's provider accounts, not a single subnet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_terms: Option<AcceptedTerms>,
    /// Provider API keys set by `gmcli set-api-keys`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_keys: Option<ProviderKeys>,
    /// Phala Cloud API key, persisted the first time a deploy resolves it
    /// (interactive paste) so later deploys never re-ask. Network-independent:
    /// one Phala account funds every network's CVMs. A `--phala-api-key` flag
    /// or the `PHALA_API_KEY` / `PHALA_CLOUD_API_KEY` env var overrides it for
    /// a single run without persisting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phala_api_key: Option<String>,
    /// This-run-only registry URL from `--api-url` / `GM_REGISTRY_URL`. Never
    /// serialized (`#[serde(skip)]`), so a [`save`] triggered mid-run — e.g. a
    /// token refresh — can't leak the throwaway URL into the persisted
    /// per-network `api_url`. [`Self::api_url`] consults it ahead of the stored
    /// value; everything else reads through that one accessor.
    #[serde(skip)]
    pub api_url_override: Option<String>,
}

impl Config {
    /// Active network name, defaulting to `"mainnet"`.
    #[must_use]
    pub fn active_network(&self) -> &str {
        self.active_network.as_deref().unwrap_or("mainnet")
    }

    /// The active network as a typed [`Network`] profile, carrying its
    /// `netuid`, chain websocket, and default registry URL. An unrecognised
    /// stored value (a hand-edited config) falls back to the default network
    /// rather than panicking.
    #[must_use]
    pub fn resolved_network(&self) -> Network {
        self.active_network
            .as_deref()
            .and_then(|s| s.parse().ok())
            .unwrap_or_default()
    }

    /// Set `network` as the active selection in memory. Callers persist it
    /// with [`save`] when the choice should stick across later commands.
    pub fn set_network(&mut self, network: Network) {
        self.active_network = Some(network.as_str().to_owned());
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

    /// The hotkey recorded for the active network by `register-hotkey`, if any.
    /// The stable identity login/deploy/doctor/earnings reference.
    #[must_use]
    pub fn registered_hotkey(&self) -> Option<&HotkeyRecord> {
        self.active_network_entry()
            .and_then(|n| n.registered_hotkey.as_ref())
    }

    /// The miner's hotkey ss58, derived from the active login token's `sub`
    /// claim — the identity the registry keys miners on. Preferred over
    /// [`Self::registered_hotkey`]: once logged in the token *is* the hotkey,
    /// so no command needs to ask for it.
    #[must_use]
    pub fn token_hotkey(&self) -> Option<String> {
        jwt_sub(self.active_tokens()?.access_token.as_deref()?)
    }

    /// Registry API URL for the active network.
    ///
    /// A this-run-only [`api_url_override`](Self::api_url_override) wins (so a
    /// `--api-url` / `GM_REGISTRY_URL` override takes effect without being
    /// persisted); then a stored per-network `api_url` (set by `login`);
    /// otherwise the active [`Network`]'s default registry URL.
    #[must_use]
    pub fn api_url(&self) -> String {
        if let Some(url) = self.api_url_override.as_ref() {
            return url.clone();
        }
        self.networks
            .get(self.active_network())
            .and_then(|n| n.api_url.clone())
            .unwrap_or_else(|| self.resolved_network().default_registry_url().to_owned())
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
/// Writes a sibling temp file at mode 0600, fsyncs it, then atomically renames
/// it over `config.json`, so a crash, SIGINT, or full disk mid-write can never
/// leave the file empty or partial — it holds the only on-disk copy of each
/// worker's `node_secret`. The 0600 mode is set on the temp before the rename,
/// so there is no window where the final file is world-readable.
///
/// # Errors
/// Returns an error if the directory cannot be created, the temp file cannot be
/// written, or the rename fails.
pub fn save(cfg: &Config) -> Result<()> {
    let dir = config_dir();
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("create config dir {}", dir.display()))?;

    let path = config_path();
    let tmp_path = dir.join("config.json.tmp");
    let bytes = serde_json::to_vec_pretty(cfg).context("serialize config")?;

    if let Err(e) = write_tmp_then_rename(&tmp_path, &path, &bytes) {
        // Never leave a partial temp behind to be mistaken for valid state.
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e);
    }
    Ok(())
}

/// Write `bytes` to `tmp_path` at mode 0600, fsync, then atomically rename it
/// over `final_path`. Split out so [`save`] can clean up the temp on any error.
fn write_tmp_then_rename(
    tmp_path: &std::path::Path,
    final_path: &std::path::Path,
    bytes: &[u8],
) -> Result<()> {
    use std::io::Write as _;

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    let mut file = opts
        .open(tmp_path)
        .with_context(|| format!("open {}", tmp_path.display()))?;
    // Set 0600 on the open fd (not just OpenOptions::mode, which is ignored when
    // a looser-permissioned temp already exists) so the renamed-over config can
    // never inherit world/group-readable bits for the only on-disk secret copy.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod 0600 {}", tmp_path.display()))?;
    }
    file.write_all(bytes)
        .with_context(|| format!("write {}", tmp_path.display()))?;
    // sync_all (not flush) forces bytes to storage and surfaces a deferred
    // ENOSPC before the rename, so a full disk can't publish a truncated config.
    file.sync_all()
        .with_context(|| format!("sync {}", tmp_path.display()))?;
    drop(file);

    std::fs::rename(tmp_path, final_path)
        .with_context(|| format!("rename {} -> {}", tmp_path.display(), final_path.display()))?;

    // The rename's durability is a directory-entry change, which sync_all on the
    // file does not cover — fsync the parent so a power loss right after a
    // success return can't roll back a freshly written node_secret.
    #[cfg(unix)]
    if let Some(parent) = final_path.parent() {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

/// Run a load-modify-save sequence while holding an exclusive advisory file
/// lock, so two concurrent `gmcli` runs can't interleave reads and writes and
/// silently drop one side's change. `deploy` persists the worker record three
/// times over several minutes; any other command running in that window would
/// otherwise race it.
///
/// The lock is held only for the brief `f` body (load → mutate → save) and is
/// released when this returns. Callers must never await a network call inside
/// `f`.
///
/// # Errors
/// Returns an error if the lockfile cannot be created or locked, or if `f`
/// itself fails.
pub fn with_config_lock<T>(f: impl FnOnce() -> Result<T>) -> Result<T> {
    let dir = config_dir();
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("create config dir {}", dir.display()))?;

    let path = lock_path();
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .with_context(|| format!("open lockfile {}", path.display()))?;
    let mut guard = fd_lock::RwLock::new(file);
    let _write = guard
        .write()
        .with_context(|| format!("acquire lock on {}", path.display()))?;
    f()
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test assertions intentionally panic on unexpected values"
)]
mod tests {
    use super::{Config, HotkeyRecord, NetworkEntry, TokenEntry, WorkerRecord};
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
            phala_api_key: None,
            api_url_override: None,
            accepted_terms: None,
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
    fn worker_backend_defaults_and_omits_when_absent() {
        let json = r#"{"worker_id":"01J0A","app_id":"app_01J0A","app_name":"gm-miner-1","node_secret":"secret"}"#;
        let worker: WorkerRecord = serde_json::from_str(json).expect("parse legacy worker record");
        assert_eq!(worker.backend, None);

        let resaved = serde_json::to_string(&worker).expect("serialize worker record");
        assert!(
            !resaved.contains("backend"),
            "absent worker backend must stay omitted: {resaved}"
        );

        let mut cloud = worker;
        cloud.backend = Some("bedrock".to_owned());
        let cloud_json = serde_json::to_value(&cloud).expect("serialize cloud worker");
        assert_eq!(cloud_json["backend"], "bedrock");
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
                    ..Default::default()
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
    fn api_url_falls_back_to_network_default() {
        use crate::network::Network;

        // Testnet with no stored api_url resolves the saygm.com default.
        let cfg = Config {
            networks: HashMap::new(),
            active_network: Some("testnet".to_owned()),
            provider_keys: None,
            phala_api_key: None,
            api_url_override: None,
            accepted_terms: None,
        };
        assert_eq!(cfg.resolved_network(), Network::Testnet);
        assert_eq!(cfg.api_url(), "https://test-registry.saygm.com");

        // Default (no active_network) is mainnet.
        let cfg = Config::default();
        assert_eq!(cfg.resolved_network(), Network::Mainnet);
        assert_eq!(cfg.api_url(), "https://registry.saygm.com");
    }

    #[test]
    fn set_network_is_sticky_and_typed() {
        use crate::network::Network;

        let mut cfg = Config::default();
        cfg.set_network(Network::Testnet);
        assert_eq!(cfg.active_network(), "testnet");
        assert_eq!(cfg.resolved_network(), Network::Testnet);
    }

    #[test]
    fn registered_hotkey_round_trips_and_is_network_scoped() {
        let mut cfg = config_with_workers("testnet", Vec::new());
        cfg.active_entry_mut().set_registered_hotkey(HotkeyRecord {
            ss58: "5Test".to_owned(),
            name: Some("miner".to_owned()),
            verified: true,
        });

        let bytes = serde_json::to_vec(&cfg).expect("serialize config");
        let back: Config = serde_json::from_slice(&bytes).expect("deserialize config");
        let record = back.registered_hotkey().expect("hotkey recorded");
        assert_eq!(record.ss58, "5Test");
        assert_eq!(record.name.as_deref(), Some("miner"));
        assert!(record.verified);
        // A different active network sees no hotkey.
        let mut other = back;
        other.set_network(crate::network::Network::Mainnet);
        assert!(other.registered_hotkey().is_none());
    }

    #[test]
    fn absent_registered_hotkey_is_omitted_from_json() {
        let cfg = config_with_workers("mainnet", Vec::new());
        let json = serde_json::to_string(&cfg).expect("serialize config");
        assert!(
            !json.contains("registered_hotkey"),
            "absent hotkey must be skipped: {json}"
        );
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

    // ── On-disk save/load round-trips ────────────────────────────────────────
    //
    // These drive the real [`save`]/[`load`] against a tempdir via
    // `GMCLI_CONFIG_DIR`. That env var is process-global, so a single mutex
    // serialises every test that points the config dir at its own tempdir —
    // otherwise parallel tests would clobber each other's `GMCLI_CONFIG_DIR`.

    use std::sync::{Mutex, MutexGuard};

    static CONFIG_DIR_ENV: Mutex<()> = Mutex::new(());

    /// Point `GMCLI_CONFIG_DIR` at a fresh tempdir for the duration of the
    /// returned guard's scope. Holds the env mutex so concurrent on-disk tests
    /// don't fight over the variable.
    fn with_temp_config_dir() -> (tempfile::TempDir, MutexGuard<'static, ()>) {
        let guard = CONFIG_DIR_ENV
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = tempfile::tempdir().expect("create tempdir");
        // SAFETY: writes are serialised by `guard`; no other thread reads the
        // var concurrently while a test holds it.
        unsafe { std::env::set_var("GMCLI_CONFIG_DIR", dir.path()) };
        (dir, guard)
    }

    fn sample_config() -> Config {
        let mut entry = NetworkEntry::default();
        entry.upsert_worker(worker("01J0A", "gm-miner-1", "node-secret-xyz"));
        let mut networks = HashMap::new();
        networks.insert("testnet".to_owned(), entry);
        Config {
            networks,
            active_network: Some("testnet".to_owned()),
            provider_keys: None,
            phala_api_key: None,
            api_url_override: None,
            accepted_terms: None,
        }
    }

    #[test]
    fn save_then_load_round_trips_on_disk() {
        let (dir, _guard) = with_temp_config_dir();
        super::save(&sample_config()).expect("save config");

        let back = super::load().expect("load config");
        let secret = &back.networks.get("testnet").expect("testnet entry").workers[0].node_secret;
        assert_eq!(secret, "node-secret-xyz");
        // The atomic rename must leave no temp sibling behind.
        assert!(
            !dir.path().join("config.json.tmp").exists(),
            "temp file must not survive a successful save"
        );
    }

    #[cfg(unix)]
    #[test]
    fn saved_config_is_mode_0600_even_over_a_loose_stale_temp() {
        use std::os::unix::fs::PermissionsExt as _;

        let (dir, _guard) = with_temp_config_dir();
        std::fs::create_dir_all(dir.path()).expect("mkdir");
        // A leftover world-readable temp from a crashed prior run must not let
        // the renamed-over config inherit loose bits.
        let stale = dir.path().join("config.json.tmp");
        std::fs::write(&stale, b"stale").expect("seed stale temp");
        std::fs::set_permissions(&stale, std::fs::Permissions::from_mode(0o644))
            .expect("loosen stale temp");

        super::save(&sample_config()).expect("save config");

        let mode = std::fs::metadata(super::config_path())
            .expect("stat config")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o600,
            "node_secret file must never be group/world readable"
        );
    }

    #[test]
    fn refresh_save_does_not_persist_the_api_url_override() {
        // FIX 2: a this-run-only --api-url override lives in `api_url_override`
        // (`#[serde(skip)]`), so a save triggered by a token refresh writes the
        // stored per-network api_url, never the throwaway override.
        let (_dir, _guard) = with_temp_config_dir();
        let mut cfg = sample_config();
        cfg.active_entry_mut().api_url = Some("https://stored.example.com".to_owned());
        super::save(&cfg).expect("seed config");

        // Simulate `load_config` injecting an override, then a refresh save.
        let mut loaded = super::load().expect("reload config");
        loaded.api_url_override = Some("https://throwaway.example.com".to_owned());
        assert_eq!(loaded.api_url(), "https://throwaway.example.com");
        super::save(&loaded).expect("save after refresh");

        let back = super::load().expect("reload after refresh");
        assert_eq!(back.api_url_override, None, "override is never serialized");
        assert_eq!(
            back.networks
                .get("testnet")
                .expect("entry")
                .api_url
                .as_deref(),
            Some("https://stored.example.com"),
            "the stored api_url must be untouched by the override"
        );
        assert_eq!(back.api_url(), "https://stored.example.com");
    }

    #[test]
    fn locked_save_round_trips_without_corruption() {
        // FIX 3: a load → mutate → save under `with_config_lock` is a no-deadlock
        // path (the lock and `save` use independent file handles) and leaves a
        // well-formed config that reloads cleanly.
        let (_dir, _guard) = with_temp_config_dir();
        super::save(&sample_config()).expect("seed config");

        super::with_config_lock(|| {
            let mut cfg = super::load()?;
            cfg.active_entry_mut()
                .upsert_worker(worker("01J0B", "gm-miner-2", "second-secret"));
            super::save(&cfg)
        })
        .expect("locked load-modify-save");

        let back = super::load().expect("reload after locked save");
        let workers = &back.networks.get("testnet").expect("entry").workers;
        assert_eq!(workers.len(), 2);
        assert_eq!(workers[1].node_secret, "second-secret");
    }

    #[test]
    fn refresh_token_only_merge_preserves_access_token() {
        // The override-run refresh path persists only the rotated refresh token,
        // leaving the stored access token and api_url untouched. Exercise the
        // same load → field-merge → save primitive on disk.
        let (_dir, _guard) = with_temp_config_dir();
        let mut cfg = sample_config();
        cfg.active_entry_mut().tokens = Some(TokenEntry {
            access_token: Some("stored-access".to_owned()),
            token_expires_at: Some("2099-01-01T00:00:00Z".to_owned()),
            refresh_token: Some("old-refresh".to_owned()),
        });
        super::save(&cfg).expect("seed config");

        super::with_config_lock(|| {
            let mut on_disk = super::load()?;
            on_disk
                .networks
                .entry("testnet".to_owned())
                .or_default()
                .tokens
                .get_or_insert_with(Default::default)
                .refresh_token = Some("rotated-refresh".to_owned());
            super::save(&on_disk)
        })
        .expect("merge rotated refresh");

        let tokens = super::load()
            .expect("reload")
            .networks
            .get("testnet")
            .expect("entry")
            .tokens
            .clone()
            .expect("tokens present");
        assert_eq!(tokens.access_token.as_deref(), Some("stored-access"));
        assert_eq!(tokens.refresh_token.as_deref(), Some("rotated-refresh"));
    }
}
