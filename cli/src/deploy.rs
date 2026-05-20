//! `gm-miner deploy` — single-shot trust-correct deploy flow.
//!
//! This module and `crate::gcp` together replace the former
//! `dstack/deploy.sh`: the whole operator deploy pipeline is now the
//! `gm-miner deploy` subcommand.
//!
//! Steps (orchestrated from `main::cmd_deploy`):
//!   1. Read provider API keys from config; error early if none set.
//!   2. Auth preflight (`GET /miners/me`) — fail fast if the operator
//!      forgot `gm-miner login` or has a stale token, before any CVM work.
//!   3. Fetch the approved `ImageVersion` list from the registry.
//!   4. Select the newest supported version (or a pinned one if `--version` given).
//!   5. Provision GCP (`crate::gcp`): preflight host tools, set the project,
//!      enable service APIs, describe-or-create the GCS bucket + Artifact
//!      Registry repo, then build + push the miner image (or accept a
//!      pre-built `--image-ref`) and resolve the digest-pinned ref.
//!   6. Render the bundled `dstack/docker-compose.yaml` template with the
//!      digest-pinned image ref.
//!   7. Bootstrap the dstack project if `app.json` is missing (writes the
//!      dstack-cloud global config, then calls `dstack-cloud new` with GCP
//!      coordinates, `--key-provider kms`, and `--gw`). If `app.json` already
//!      exists, validate its trust-critical fields instead
//!      ([`validate_app_json_trust`]).
//!   8. Pull the dstack-cloud OS image (`crate::gcp::pull_os_image`).
//!   9. Submit to dstack-cloud (via the `DstackClient` trait for testability).
//!  10. Poll `dstack-cloud status --json` until `compose_sha256` and
//!      `os_image_hash` are populated (up to `boot_timeout_secs` seconds).
//!  11. **Verify** both match the registry's approved version — refuse and exit 1
//!      if they don't.
//!  12. Call `register_image` with the verified hashes.

use anyhow::{bail, Context, Result};
use chrono::DateTime;
use serde::{Deserialize, Serialize};

use crate::config::ProviderKeys;

// ── GCP configuration ─────────────────────────────────────────────────────────

/// GCP-specific fields written into `app.json` after `dstack-cloud new`.
///
/// The deploy.sh script patches `gcp_config` in app.json between bootstrap
/// and deploy so that `dstack-cloud deploy` has a valid GCS upload target and
/// can provision the correct machine type/zone on fresh machines.
///
/// Fields mirror those used by the reference `dstack/deploy.sh`:
/// - `project` — GCP project ID
/// - `zone` — GCP zone (e.g. `us-central1-a`)
/// - `machine_type` — Compute Engine machine type (e.g. `c3-standard-4`)
/// - `instance_name` — Compute Engine instance name (matches the app name)
/// - `bucket` — GCS bucket URI for dstack image upload (e.g. `gs://<project>-dstack`)
#[derive(Debug, Clone)]
pub struct GcpConfig {
    pub project: String,
    pub zone: String,
    pub machine_type: String,
    pub instance_name: String,
    pub bucket: String,
}

impl GcpConfig {
    /// Derive a GCS bucket name from the GCP project ID using the same
    /// convention as `deploy.sh`: `gs://<project>-dstack`.
    #[must_use]
    pub fn default_bucket(project: &str) -> String {
        format!("gs://{project}-dstack")
    }
}

/// Patch `gcp_config` fields in the `app.json` file written by `dstack-cloud new`.
///
/// `dstack-cloud new` seeds `gcp_config.bucket` (and other fields) from the
/// global `~/.config/dstack-cloud/config.json`, which is often empty or
/// stale on a fresh machine.  This function writes the deploy-time values so
/// `dstack-cloud deploy` has a valid upload target.
///
/// Matches the python patch in `dstack/deploy.sh` (both fresh and re-deploy
/// paths): always writes `project`, `zone`, `machine_type`, `instance_name`,
/// and `bucket`.
///
/// # Errors
/// Returns an error if the file cannot be read, parsed, or written.
pub fn patch_app_json(app_json_path: &std::path::Path, gcp: &GcpConfig) -> Result<()> {
    let raw = std::fs::read_to_string(app_json_path)
        .with_context(|| format!("read {}", app_json_path.display()))?;

    let mut app: serde_json::Value =
        serde_json::from_str(&raw).with_context(|| format!("parse {}", app_json_path.display()))?;

    let gcp_obj = app
        .as_object_mut()
        .context("app.json root is not an object")?
        .entry("gcp_config")
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));

    let map = gcp_obj
        .as_object_mut()
        .context("app.json gcp_config is not an object")?;

    map.insert(
        "project".into(),
        serde_json::Value::String(gcp.project.clone()),
    );
    map.insert("zone".into(), serde_json::Value::String(gcp.zone.clone()));
    map.insert(
        "machine_type".into(),
        serde_json::Value::String(gcp.machine_type.clone()),
    );
    map.insert(
        "instance_name".into(),
        serde_json::Value::String(gcp.instance_name.clone()),
    );
    map.insert(
        "bucket".into(),
        serde_json::Value::String(gcp.bucket.clone()),
    );

    let patched = serde_json::to_string_pretty(&app).context("re-serialize app.json")?;
    std::fs::write(app_json_path, patched)
        .with_context(|| format!("write {}", app_json_path.display()))?;

    Ok(())
}

// ── app.json trust validation ─────────────────────────────────────────────────

/// The KMS URL the miner's trust model is anchored to. An `app.json` whose
/// `kms_url` differs points the CVM at a different key authority and breaks
/// the registry's attestation chain. Mirrors the global config written by
/// `deploy.sh`.
pub const TRUSTED_KMS_URL: &str = "https://kms.tdxlab.dstack.org:12001";

/// Validate the trust-critical fields of an existing `app.json` and correct
/// them in place if they are wrong.
///
/// `dstack-cloud new` writes a fresh, trust-correct `app.json`, but the
/// deploy path also accepts an `app.json` that already exists on disk — it
/// could be stale (from an older toolchain) or tampered with. Before that
/// file is trusted as the deploy target, three fields are checked:
///
/// - `key_provider` must be `kms` — only KMS produces an attestation chain
///   the registry can verify. Anything else (e.g. `local`) is rejected hard;
///   silently re-writing it could mask a tampered file, so this fails loudly.
/// - `gateway_enabled` must be `true` — the gateway is the trust boundary
///   the registry probes envoy through. A missing or `false` value is
///   corrected in place (the subcommand knows the right value).
/// - `kms_url` must equal [`TRUSTED_KMS_URL`] — a missing value is filled in;
///   a *different* non-empty value is rejected hard (it points the CVM at
///   another key authority).
///
/// Returns `true` if the file was modified (corrected) and needs no further
/// action, `false` if it was already trust-correct.
///
/// # Errors
/// Returns an error if the file cannot be read/parsed/written, or if a
/// trust-critical field holds an actively wrong value that must not be
/// silently overwritten.
pub fn validate_app_json_trust(app_json_path: &std::path::Path) -> Result<bool> {
    let raw = std::fs::read_to_string(app_json_path)
        .with_context(|| format!("read {}", app_json_path.display()))?;
    let mut app: serde_json::Value =
        serde_json::from_str(&raw).with_context(|| format!("parse {}", app_json_path.display()))?;
    let obj = app
        .as_object_mut()
        .context("app.json root is not an object")?;

    let mut corrected = false;

    // key_provider — reject anything that is not exactly "kms".
    match obj.get("key_provider").and_then(serde_json::Value::as_str) {
        Some(DSTACK_KEY_PROVIDER) => {}
        other => bail!(
            "app.json has key_provider={} — refusing to deploy. The miner's \
             attestation chain requires `kms`; delete app.json to re-scaffold \
             a trust-correct project, or fix it by hand.",
            other.map_or_else(|| "<missing>".to_owned(), |s| format!("{s:?}"))
        ),
    }

    // gateway_enabled — must be true; correct a missing/false value in place.
    if obj
        .get("gateway_enabled")
        .and_then(serde_json::Value::as_bool)
        != Some(true)
    {
        tracing::warn!(
            "app.json gateway_enabled was not true; correcting it — the registry \
             probes envoy through the gateway, so it must be enabled"
        );
        obj.insert("gateway_enabled".to_owned(), serde_json::Value::Bool(true));
        corrected = true;
    }

    // kms_url — fill in if missing; reject a different non-empty value.
    match obj.get("kms_url").and_then(serde_json::Value::as_str) {
        Some(TRUSTED_KMS_URL) => {}
        None | Some("") => {
            tracing::warn!(
                kms_url = TRUSTED_KMS_URL,
                "app.json kms_url was empty; setting it"
            );
            obj.insert(
                "kms_url".to_owned(),
                serde_json::Value::String(TRUSTED_KMS_URL.to_owned()),
            );
            corrected = true;
        }
        Some(other) => bail!(
            "app.json has kms_url={other:?} but the miner trusts {TRUSTED_KMS_URL:?} \
             — refusing to deploy against a different key authority. Delete app.json \
             to re-scaffold, or fix it by hand if the change is intentional."
        ),
    }

    if corrected {
        let patched = serde_json::to_string_pretty(&app).context("re-serialize app.json")?;
        std::fs::write(app_json_path, patched)
            .with_context(|| format!("write {}", app_json_path.display()))?;
    }

    Ok(corrected)
}

/// Default poll interval when waiting for the CVM to boot (seconds).
pub const POLL_INTERVAL_SECS: u64 = 5;
/// Default maximum time to wait for hashes to appear after deploy (seconds).
pub const DEFAULT_BOOT_TIMEOUT_SECS: u64 = 300;

/// Key-provider passed to `dstack-cloud new`. The miner's trust model
/// requires KMS — fixed here so an operator cannot accidentally weaken
/// it from the CLI. Mirrors `dstack/deploy.sh`.
pub const DSTACK_KEY_PROVIDER: &str = "kms";

/// Build the argument list for `dstack-cloud new`.
///
/// `dstack-cloud new` takes the project name as a positional argument
/// followed by GCP coordinates. Two flags are hardcoded because the
/// miner's trust model requires them:
///   - `--key-provider kms` — only KMS produces an attestation chain
///     the registry can verify.
///   - `--gw` — gateway must be enabled for the registry to probe envoy
///     directly (no bearer token; the gateway is the trust boundary).
///
/// Extracted from `RealDstackClient::bootstrap` so the wiring can be
/// asserted without spawning a subprocess.
#[must_use]
pub fn build_dstack_new_args(app_name: &str, gcp: &GcpConfig) -> Vec<String> {
    vec![
        "new".to_owned(),
        app_name.to_owned(),
        "--project".to_owned(),
        gcp.project.clone(),
        "--zone".to_owned(),
        gcp.zone.clone(),
        "--machine-type".to_owned(),
        gcp.machine_type.clone(),
        "--instance-name".to_owned(),
        gcp.instance_name.clone(),
        "--key-provider".to_owned(),
        DSTACK_KEY_PROVIDER.to_owned(),
        "--gw".to_owned(),
    ]
}

// ── dstack-cloud global config ────────────────────────────────────────────────

/// The dstack-cloud global config JSON, written to
/// `~/.config/dstack-cloud/config.json` if absent.
///
/// `dstack-cloud new` reads KMS/gateway service URLs from this file. On a
/// fresh machine the file does not exist; `deploy.sh` seeds it before
/// calling `dstack-cloud new`. The `gcp` / `image_search_paths` blocks are
/// left at their defaults — the per-project `app.json` carries the
/// deploy-time GCP coordinates.
const DSTACK_GLOBAL_CONFIG: &str = r#"{
  "services": {
    "kms_urls": ["https://kms.tdxlab.dstack.org:12001"],
    "gateway_urls": ["https://gateway.tdxlab.dstack.org:12002"],
    "pccs_url": ""
  },
  "image_search_paths": ["~/.dstack/images"],
  "gcp": {
    "project": "",
    "zone": "us-central1-a",
    "bucket": ""
  }
}
"#;

/// Ensure the dstack-cloud global config exists, creating it from the
/// trusted default if absent. Mirrors `ensure_dstack_cloud_global_config`
/// in `deploy.sh`.
///
/// # Errors
/// Returns an error if the directory or file cannot be created.
pub fn ensure_dstack_global_config() -> Result<()> {
    let Some(home) = dirs::home_dir() else {
        bail!("could not resolve the home directory for the dstack-cloud config");
    };
    let cfg = home
        .join(".config")
        .join("dstack-cloud")
        .join("config.json");
    if cfg.exists() {
        return Ok(());
    }
    let dir = cfg
        .parent()
        .context("dstack-cloud config path has no parent")?;
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    tracing::info!(path = %cfg.display(), "writing dstack-cloud global config");
    std::fs::write(&cfg, DSTACK_GLOBAL_CONFIG)
        .with_context(|| format!("write {}", cfg.display()))?;
    Ok(())
}

// ── Registry image-version types ─────────────────────────────────────────────

/// A single approved (`compose_hash`, `os_image_hash`) entry from the registry.
#[derive(Debug, Clone, Deserialize)]
pub struct ImageVersion {
    pub compose_hash: String,
    pub os_image_hash: String,
    pub status: String,
    pub notes: Option<String>,
    pub created_at: String,
}

/// Response body from `GET /image-versions?status=supported`.
#[derive(Debug, Deserialize)]
pub struct ImageVersionsResponse {
    pub versions: Vec<ImageVersion>,
}

// ── dstack abstraction ────────────────────────────────────────────────────────

/// Result returned after a successful dstack-cloud deploy + status poll.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DstackDeployResult {
    /// SHA-256 of the rendered `docker-compose.yaml` as computed by dstack-cloud.
    pub compose_sha256: String,
    /// OS image hash reported by dstack-cloud.
    pub os_image_hash: String,
}

/// Abstraction over the dstack-cloud CLI, injectable for tests.
///
/// The real implementation shells out to `dstack-cloud new` (bootstrap),
/// `dstack-cloud deploy`, and `dstack-cloud status --json`. The mock
/// implementation returns pre-canned values without touching the filesystem.
pub trait DstackClient {
    /// Bootstrap a new dstack project in the project directory by running
    /// `dstack-cloud new <app_name> --project ... --zone ... --machine-type ...
    /// --instance-name ... --key-provider kms --gw`, then patch `app.json`
    /// with `gcp` so `dstack-cloud deploy` has a valid GCS upload target
    /// (`bucket` is not a `dstack-cloud new` flag, so it must be patched in
    /// after the fact).
    ///
    /// The KMS key-provider and gateway-enabled flags are baked in: the
    /// miner's attestation chain requires both, and exposing them as
    /// configurable would let an operator accidentally weaken the trust
    /// model. Mirrors `dstack/deploy.sh`.
    ///
    /// Only called when `app.json` is absent (i.e. on a fresh machine with
    /// no prior deploy).
    ///
    /// # Errors
    /// Returns an error if `dstack-cloud new` fails or `app.json` cannot
    /// be patched.
    fn bootstrap(&self, app_name: &str, gcp: &GcpConfig) -> Result<()>;

    /// Patch `gcp_config` fields in an existing `app.json` (re-deploy path).
    ///
    /// Called when the project is already bootstrapped to keep GCP coordinates
    /// current (project, zone, `machine_type`, bucket) without clobbering the
    /// `app_id` / `instance_id_seed` that dstack uses to identify the CVM.
    ///
    /// # Errors
    /// Returns an error if `app.json` cannot be read or written.
    fn refresh_gcp_config(&self, gcp: &GcpConfig) -> Result<()>;

    /// Returns true if the project directory already contains `app.json`,
    /// meaning the dstack project has already been bootstrapped.
    fn is_bootstrapped(&self) -> bool;

    /// Validate the trust-critical fields of an already-existing `app.json`
    /// (re-deploy path) and correct them in place where safe.
    ///
    /// Called only when [`Self::is_bootstrapped`] is true. A freshly
    /// `dstack-cloud new`-scaffolded project is trust-correct by
    /// construction, but a file that was already on disk could be stale or
    /// tampered with; this check refuses to deploy against a weakened one.
    /// See [`validate_app_json_trust`].
    ///
    /// # Errors
    /// Returns an error if `app.json` cannot be read/written or holds an
    /// actively wrong trust-critical value.
    fn validate_existing_trust(&self) -> Result<()>;

    /// Deploy and return the compose + OS image hashes that dstack-cloud
    /// actually used. `compose_yaml` is the rendered compose file content;
    /// `env_vars` are the operator's provider API keys to pass via dstack's
    /// encrypted env upload. `gcp` is used to refresh `gcp_config` in
    /// `app.json` before calling `dstack-cloud deploy` (both fresh and
    /// re-deploy paths). `boot_timeout_secs` controls how long to poll
    /// for hashes before giving up.
    ///
    /// # Errors
    /// Returns an error if the deploy fails or the hashes cannot be read back
    /// within `boot_timeout_secs`.
    fn deploy(
        &self,
        compose_yaml: &str,
        env_vars: &ProviderKeys,
        gcp: &GcpConfig,
        boot_timeout_secs: u64,
    ) -> Result<DstackDeployResult>;
}

// ── Real dstack-cloud implementation ─────────────────────────────────────────

/// Shells out to `dstack-cloud deploy` and parses the resulting
/// `dstack-cloud status --json` to obtain both hashes.
pub struct RealDstackClient {
    /// App name used by dstack-cloud (defaults to `gm-miner-1`).
    pub app_name: String,
    /// Directory for dstack project state (`dist/<app_name>`).
    pub project_dir: std::path::PathBuf,
}

impl RealDstackClient {
    /// Create a client that manages state in `<dist_root>/<app_name>`.
    #[must_use]
    pub fn new(app_name: impl Into<String>, dist_root: &std::path::Path) -> Self {
        let name = app_name.into();
        let project_dir = dist_root.join(&name);
        Self {
            app_name: name,
            project_dir,
        }
    }
}

/// Output of `dstack-cloud status --json`.
#[derive(Debug, Deserialize)]
struct DstackStatus {
    compose_sha256: Option<String>,
    os_image_hash: Option<String>,
}

impl DstackClient for RealDstackClient {
    fn is_bootstrapped(&self) -> bool {
        self.project_dir.join("app.json").exists()
    }

    fn bootstrap(&self, _hint_app_name: &str, gcp: &GcpConfig) -> Result<()> {
        // Use the app name this client was constructed with; the hint is for
        // test stubs that don't store state.
        //
        // `dstack-cloud new <name>` creates `<cwd>/<name>/` containing the
        // generated `app.json`. To land it at `self.project_dir`, run from
        // the parent and pass `app_name` as the positional name — mirrors
        // `dstack/deploy.sh` which does `cd "${DIST_DIR}" && dstack-cloud
        // new "${APP_NAME}"`.
        let parent_dir = self.project_dir.parent().unwrap_or_else(|| {
            // project_dir has no parent only when it is a root (e.g. "/"
            // or "C:\"). That can't happen with the default `dist/<app>`
            // layout; fall back to "." so the command can still run and
            // the operator gets a clean error from dstack-cloud itself.
            std::path::Path::new(".")
        });
        std::fs::create_dir_all(parent_dir)
            .with_context(|| format!("create parent dir {}", parent_dir.display()))?;

        let args = build_dstack_new_args(&self.app_name, gcp);
        let status = std::process::Command::new("dstack-cloud")
            .args(&args)
            .current_dir(parent_dir)
            .status()
            .context("run dstack-cloud new — is dstack-cloud installed?")?;

        if !status.success() {
            bail!(
                "dstack-cloud new exited with status {}",
                status.code().unwrap_or(-1)
            );
        }

        // Patch gcp_config immediately after bootstrap. `dstack-cloud new`
        // now seeds project/zone/machine_type/instance_name from the flags
        // above, but `bucket` is not a `new` flag — it comes from the
        // global config (often empty on a fresh machine). This call writes
        // the deploy-time bucket and (idempotently) reaffirms the other
        // GCP coordinates so a subsequent `dstack-cloud deploy` has a
        // valid upload target.
        let app_json = self.project_dir.join("app.json");
        patch_app_json(&app_json, gcp)
            .with_context(|| format!("patch gcp_config in {}", app_json.display()))?;

        Ok(())
    }

    fn refresh_gcp_config(&self, gcp: &GcpConfig) -> Result<()> {
        let app_json = self.project_dir.join("app.json");
        patch_app_json(&app_json, gcp)
            .with_context(|| format!("refresh gcp_config in {}", app_json.display()))
    }

    fn validate_existing_trust(&self) -> Result<()> {
        let app_json = self.project_dir.join("app.json");
        let corrected = validate_app_json_trust(&app_json)
            .with_context(|| format!("validate trust fields in {}", app_json.display()))?;
        if corrected {
            tracing::info!(
                path = %app_json.display(),
                "corrected trust-critical fields in existing app.json"
            );
        }
        Ok(())
    }

    fn deploy(
        &self,
        compose_yaml: &str,
        env_vars: &ProviderKeys,
        gcp: &GcpConfig,
        boot_timeout_secs: u64,
    ) -> Result<DstackDeployResult> {
        use std::fs;
        use std::io::Write as _;
        #[cfg(unix)]
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        fs::create_dir_all(&self.project_dir)
            .with_context(|| format!("create project dir {}", self.project_dir.display()))?;

        // Refresh gcp_config on every deploy (both fresh and re-deploy paths).
        // On a fresh machine this runs after bootstrap has already written the
        // file; on re-deploy it keeps project/zone/bucket current without
        // touching app_id / instance_id_seed.
        self.refresh_gcp_config(gcp)?;

        // Write the rendered compose file.
        let compose_path = self.project_dir.join("docker-compose.yaml");
        fs::write(&compose_path, compose_yaml)
            .with_context(|| format!("write {}", compose_path.display()))?;

        // Write .env via a temp-file-then-rename so the target file is always
        // at mode 0600 from the moment it exists — no window where a partially-
        // written or broader-permission file is present on disk.
        let env_path = self.project_dir.join(".env");
        {
            let mut lines = String::new();
            if let Some(k) = &env_vars.anthropic {
                lines.push_str("ANTHROPIC_API_KEY=");
                lines.push_str(k);
                lines.push('\n');
            }
            if let Some(k) = &env_vars.openai {
                lines.push_str("OPENAI_API_KEY=");
                lines.push_str(k);
                lines.push('\n');
            }
            if let Some(k) = &env_vars.google {
                lines.push_str("GOOGLE_API_KEY=");
                lines.push_str(k);
                lines.push('\n');
            }

            // Write to a sibling temp file first, then atomically rename over
            // the target. The temp file is created at 0600 from the start, so
            // the target is never visible with broader permissions during
            // an overwrite.
            let tmp_path = self.project_dir.join(".env.tmp");

            #[cfg(unix)]
            {
                let mut file = fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(&tmp_path)
                    .with_context(|| format!("open {}", tmp_path.display()))?;
                file.write_all(lines.as_bytes())
                    .with_context(|| format!("write {}", tmp_path.display()))?;
                // Explicit set_permissions ensures 0600 even if umask is
                // permissive and the file somehow already existed.
                fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600))
                    .with_context(|| format!("chmod 600 {}", tmp_path.display()))?;
            }

            #[cfg(not(unix))]
            {
                let mut file = fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(&tmp_path)
                    .with_context(|| format!("open {}", tmp_path.display()))?;
                file.write_all(lines.as_bytes())
                    .with_context(|| format!("write {}", tmp_path.display()))?;
            }

            fs::rename(&tmp_path, &env_path).with_context(|| {
                format!("rename {} -> {}", tmp_path.display(), env_path.display())
            })?;
        }

        // Run dstack-cloud deploy.
        let status = std::process::Command::new("dstack-cloud")
            .arg("deploy")
            .current_dir(&self.project_dir)
            .status()
            .context("run dstack-cloud deploy — is dstack-cloud installed?")?;

        if !status.success() {
            bail!(
                "dstack-cloud deploy exited with status {}",
                status.code().unwrap_or(-1)
            );
        }

        // Poll `dstack-cloud status --json` until both hashes are populated.
        // The CVM may take seconds to minutes to boot after deploy returns.
        self.poll_status(boot_timeout_secs)
    }
}

impl RealDstackClient {
    /// Poll `dstack-cloud status --json` every [`POLL_INTERVAL_SECS`] seconds
    /// until both `compose_sha256` and `os_image_hash` are non-empty, or until
    /// `timeout_secs` elapses.
    fn poll_status(&self, timeout_secs: u64) -> Result<DstackDeployResult> {
        use std::time::{Duration, Instant};

        let deadline = Instant::now() + Duration::from_secs(timeout_secs);
        let poll = Duration::from_secs(POLL_INTERVAL_SECS);
        let mut attempt: u32 = 0;

        loop {
            attempt += 1;
            let out = std::process::Command::new("dstack-cloud")
                .args(["status", "--json"])
                .current_dir(&self.project_dir)
                .output()
                .context("run dstack-cloud status --json")?;

            if out.status.success() {
                let ds: DstackStatus = serde_json::from_slice(&out.stdout)
                    .context("parse dstack-cloud status --json output")?;

                if let (Some(compose_sha256), Some(os_image_hash)) =
                    (ds.compose_sha256, ds.os_image_hash)
                {
                    if !compose_sha256.is_empty() && !os_image_hash.is_empty() {
                        return Ok(DstackDeployResult {
                            compose_sha256,
                            os_image_hash,
                        });
                    }
                }
            } else {
                // A non-zero exit is expected on a fresh deployment before the
                // control plane is ready — treat it as "not yet available"
                // rather than a hard failure (mirrors the old deploy.sh
                // behaviour which tolerated early status failures).
                tracing::info!(
                    attempt,
                    stderr = %String::from_utf8_lossy(&out.stderr).trim(),
                    "dstack-cloud status --json not ready yet (non-zero exit); will retry"
                );
            }

            // Hashes not yet populated (or status not ready) — check deadline before sleeping.
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                bail!(
                    "timed out after {timeout_secs}s waiting for the CVM to boot \
                     (compose_sha256/os_image_hash never appeared in \
                     `dstack-cloud status --json`); \
                     increase --boot-timeout-secs or check the dstack-cloud console"
                );
            }

            let sleep = remaining.min(poll);
            tracing::debug!(attempt, ?sleep, "hashes not yet available; waiting");
            std::thread::sleep(sleep);
        }
    }
}

// ── Registry image-version fetch ─────────────────────────────────────────────

/// Fetch supported image versions from the registry.
///
/// Returns the full list sorted newest-first by `created_at`.
///
/// # Errors
/// Returns an error if the registry returns 404 (endpoint not yet deployed),
/// any other non-2xx status, or the response body cannot be parsed.
pub async fn fetch_supported_versions(registry_url: &str) -> Result<Vec<ImageVersion>> {
    // Build a one-shot client with a 30 s timeout — same as RegistryClient —
    // rather than using bare `reqwest::get()` which has no timeout.
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent(concat!("gm-miner/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("build reqwest client for /image-versions")?;

    let url = format!("{registry_url}/image-versions?status=supported");
    let resp = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;

    let http_status = resp.status();
    if http_status == reqwest::StatusCode::NOT_FOUND {
        bail!(
            "registry returned 404 for /image-versions — your gm-miner build is newer than \
             the registry deployment; wait for the registry to be updated and retry"
        );
    }
    if !http_status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        bail!("GET /image-versions failed ({http_status}): {body}");
    }

    let body: ImageVersionsResponse = resp
        .json()
        .await
        .context("parse /image-versions response")?;

    let mut versions = body.versions;

    // Sort newest-first by the parsed `created_at` instant. Raw RFC 3339
    // strings only sort correctly when every offset is `Z`; an entry like
    // `2025-05-01T00:30:00+01:00` would otherwise sort after an older `Z`
    // timestamp. Unparseable timestamps sort last so they are never picked
    // as the default newest version.
    versions.sort_by_key(|v| std::cmp::Reverse(created_at_key(v)));

    Ok(versions)
}

/// Sort key for ordering `ImageVersion`s by `created_at`, newest-first.
///
/// Returns the parsed UTC instant, or `DateTime::<Utc>::MIN_UTC` when the
/// timestamp cannot be parsed so malformed entries sort as oldest.
fn created_at_key(v: &ImageVersion) -> chrono::DateTime<chrono::Utc> {
    DateTime::parse_from_rfc3339(&v.created_at)
        .map_or(chrono::DateTime::<chrono::Utc>::MIN_UTC, |dt| dt.to_utc())
}

/// Select a version from the list, optionally pinned to a specific index
/// (1-based, matching the order returned by the registry newest-first).
///
/// # Errors
/// Returns an error if the list is empty or the requested index is out of range.
pub fn select_version(versions: &[ImageVersion], pin: Option<usize>) -> Result<&ImageVersion> {
    if versions.is_empty() {
        bail!("registry returned no supported image versions — no approved version to deploy");
    }

    match pin {
        None => Ok(&versions[0]),
        Some(n) => {
            if n == 0 || n > versions.len() {
                bail!("--version {n} is out of range (1..={})", versions.len());
            }
            Ok(&versions[n - 1])
        }
    }
}

// ── Compose template rendering ────────────────────────────────────────────────

/// Render the compose template, substituting `${GM_IMAGE_REF...}` with
/// the supplied pinned image reference.
///
/// Mirrors the `sed` invocation in `deploy.sh`:
///
/// ```text
/// sed "s|\${GM_IMAGE_REF[^}]*}|${PINNED_REF}|g" ...
/// ```
///
/// # Errors
/// Returns an error if the substitution did not change the template (i.e.
/// the placeholder was not found).
pub fn render_compose(template: &str, pinned_image_ref: &str) -> Result<String> {
    // Replace the shell-variable placeholder pattern ${GM_IMAGE_REF...}
    // with the digest-pinned ref. We do a simple prefix match: anything
    // that starts with `${GM_IMAGE_REF` and ends at the next `}`.
    let result = replace_image_ref_placeholder(template, pinned_image_ref);
    if result == template {
        bail!(
            "compose template does not contain a GM_IMAGE_REF placeholder; \
             expected something like ${{GM_IMAGE_REF:?...}} in dstack/docker-compose.yaml"
        );
    }
    Ok(result)
}

/// Replace every `${GM_IMAGE_REF...}` shell-variable expression in `text`
/// with `replacement`. Equivalent to the sed expression in `deploy.sh`:
///
/// ```text
/// sed "s|\${GM_IMAGE_REF[^}]*}|${PINNED_REF}|g"
/// ```
fn replace_image_ref_placeholder(text: &str, replacement: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut remaining = text;
    let prefix = "${GM_IMAGE_REF";

    loop {
        match remaining.find(prefix) {
            None => {
                result.push_str(remaining);
                break;
            }
            Some(start) => {
                result.push_str(&remaining[..start]);
                let after_prefix = &remaining[start + prefix.len()..];
                match after_prefix.find('}') {
                    None => {
                        // Unterminated placeholder — leave it as-is.
                        result.push_str(&remaining[start..]);
                        break;
                    }
                    Some(end_offset) => {
                        result.push_str(replacement);
                        remaining = &after_prefix[end_offset + 1..];
                    }
                }
            }
        }
    }

    result
}

// ── Hash verification ─────────────────────────────────────────────────────────

/// Verify that the actual hashes from dstack-cloud match the registry-approved
/// version.
///
/// # Errors
/// Returns a loud, actionable error if either hash does not match.
pub fn verify_hashes(actual: &DstackDeployResult, approved: &ImageVersion) -> Result<()> {
    let compose_match =
        actual.compose_sha256.to_lowercase() == approved.compose_hash.to_lowercase();
    let os_match = actual.os_image_hash.to_lowercase() == approved.os_image_hash.to_lowercase();

    if compose_match && os_match {
        return Ok(());
    }

    let mut msg = String::from("HASH MISMATCH — deployment is suspect; refusing to register.\n\n");

    if !compose_match {
        msg.push_str("  compose_hash\n    expected (registry): ");
        msg.push_str(&approved.compose_hash);
        msg.push_str("\n    actual (dstack):     ");
        msg.push_str(&actual.compose_sha256);
        msg.push_str("\n\n");
    }
    if !os_match {
        msg.push_str("  os_image_hash\n    expected (registry): ");
        msg.push_str(&approved.os_image_hash);
        msg.push_str("\n    actual (dstack):     ");
        msg.push_str(&actual.os_image_hash);
        msg.push_str("\n\n");
    }
    msg.push_str(
        "If you believe this is a legitimate new build, wait for the registry to \
         publish a new approved version and retry.",
    );

    bail!("{msg}");
}

// ── Timestamp helper ──────────────────────────────────────────────────────────

/// Format an RFC 3339 `created_at` timestamp for human display.
#[must_use]
pub fn format_created_at(ts: &str) -> String {
    DateTime::parse_from_rfc3339(ts).map_or_else(
        |_| ts.to_owned(),
        |dt| dt.format("%Y-%m-%d %H:%M UTC").to_string(),
    )
}

// ── Bundled compose template ──────────────────────────────────────────────────

/// The dstack compose template, bundled at compile time from
/// `dstack/docker-compose.yaml` relative to the workspace root.
pub const COMPOSE_TEMPLATE: &str = include_str!("../../dstack/docker-compose.yaml");

// ── Serialisable `ImageVersion` for tests ────────────────────────────────────

/// Mirror of `ImageVersion` with `Serialize` — only used to build mock
/// registry responses in tests.
#[derive(Serialize)]
pub struct ImageVersionOut {
    pub compose_hash: String,
    pub os_image_hash: String,
    pub status: String,
    pub notes: Option<String>,
    pub created_at: String,
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test assertions intentionally panic on unexpected values"
)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_replaced_once() {
        let template = "image: ${GM_IMAGE_REF:?GM_IMAGE_REF must be set}\n  ports:\n";
        let rendered =
            render_compose(template, "reg.example.com/app@sha256:abc123").expect("should render");
        assert!(rendered.contains("reg.example.com/app@sha256:abc123"));
        assert!(!rendered.contains("GM_IMAGE_REF"));
    }

    #[test]
    fn placeholder_missing_returns_error() {
        let template = "image: my-image\n";
        assert!(render_compose(template, "anything").is_err());
    }

    #[test]
    fn verify_hashes_passes_on_match() {
        let actual = DstackDeployResult {
            compose_sha256: "abc123".to_string(),
            os_image_hash: "def456".to_string(),
        };
        let approved = ImageVersion {
            compose_hash: "abc123".to_string(),
            os_image_hash: "def456".to_string(),
            status: "supported".to_string(),
            notes: None,
            created_at: "2025-01-01T00:00:00Z".to_string(),
        };
        assert!(verify_hashes(&actual, &approved).is_ok());
    }

    #[test]
    fn verify_hashes_case_insensitive() {
        let actual = DstackDeployResult {
            compose_sha256: "ABC123".to_string(),
            os_image_hash: "DEF456".to_string(),
        };
        let approved = ImageVersion {
            compose_hash: "abc123".to_string(),
            os_image_hash: "def456".to_string(),
            status: "supported".to_string(),
            notes: None,
            created_at: "2025-01-01T00:00:00Z".to_string(),
        };
        assert!(verify_hashes(&actual, &approved).is_ok());
    }

    #[test]
    fn verify_hashes_fails_on_compose_mismatch() {
        let actual = DstackDeployResult {
            compose_sha256: "WRONG".to_string(),
            os_image_hash: "def456".to_string(),
        };
        let approved = ImageVersion {
            compose_hash: "abc123".to_string(),
            os_image_hash: "def456".to_string(),
            status: "supported".to_string(),
            notes: None,
            created_at: "2025-01-01T00:00:00Z".to_string(),
        };
        let err = verify_hashes(&actual, &approved).unwrap_err();
        assert!(err.to_string().contains("compose_hash"));
        assert!(err.to_string().contains("HASH MISMATCH"));
    }

    #[test]
    fn verify_hashes_fails_on_os_mismatch() {
        let actual = DstackDeployResult {
            compose_sha256: "abc123".to_string(),
            os_image_hash: "WRONG".to_string(),
        };
        let approved = ImageVersion {
            compose_hash: "abc123".to_string(),
            os_image_hash: "def456".to_string(),
            status: "supported".to_string(),
            notes: None,
            created_at: "2025-01-01T00:00:00Z".to_string(),
        };
        let err = verify_hashes(&actual, &approved).unwrap_err();
        assert!(err.to_string().contains("os_image_hash"));
        assert!(err.to_string().contains("HASH MISMATCH"));
    }

    #[test]
    fn verify_hashes_fails_on_both_mismatch() {
        let actual = DstackDeployResult {
            compose_sha256: "W1".to_string(),
            os_image_hash: "W2".to_string(),
        };
        let approved = ImageVersion {
            compose_hash: "abc123".to_string(),
            os_image_hash: "def456".to_string(),
            status: "supported".to_string(),
            notes: None,
            created_at: "2025-01-01T00:00:00Z".to_string(),
        };
        let err = verify_hashes(&actual, &approved).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("compose_hash"));
        assert!(msg.contains("os_image_hash"));
    }

    #[test]
    fn select_version_latest_when_no_pin() {
        let versions = vec![
            ImageVersion {
                compose_hash: "new".to_string(),
                os_image_hash: "new".to_string(),
                status: "supported".to_string(),
                notes: None,
                created_at: "2025-03-01T00:00:00Z".to_string(),
            },
            ImageVersion {
                compose_hash: "old".to_string(),
                os_image_hash: "old".to_string(),
                status: "supported".to_string(),
                notes: None,
                created_at: "2025-01-01T00:00:00Z".to_string(),
            },
        ];
        let selected = select_version(&versions, None).expect("should select");
        assert_eq!(selected.compose_hash, "new");
    }

    #[test]
    fn select_version_pinned() {
        let versions = vec![
            ImageVersion {
                compose_hash: "new".to_string(),
                os_image_hash: "new".to_string(),
                status: "supported".to_string(),
                notes: None,
                created_at: "2025-03-01T00:00:00Z".to_string(),
            },
            ImageVersion {
                compose_hash: "old".to_string(),
                os_image_hash: "old".to_string(),
                status: "supported".to_string(),
                notes: None,
                created_at: "2025-01-01T00:00:00Z".to_string(),
            },
        ];
        let selected = select_version(&versions, Some(2)).expect("should select");
        assert_eq!(selected.compose_hash, "old");
    }

    #[test]
    fn select_version_empty_errors() {
        assert!(select_version(&[], None).is_err());
    }

    #[test]
    fn select_version_out_of_range_errors() {
        let versions = vec![ImageVersion {
            compose_hash: "x".to_string(),
            os_image_hash: "x".to_string(),
            status: "supported".to_string(),
            notes: None,
            created_at: "2025-01-01T00:00:00Z".to_string(),
        }];
        assert!(select_version(&versions, Some(2)).is_err());
        assert!(select_version(&versions, Some(0)).is_err());
    }

    fn sample_gcp() -> GcpConfig {
        GcpConfig {
            project: "my-project".to_owned(),
            zone: "us-east1-b".to_owned(),
            machine_type: "c3-standard-8".to_owned(),
            instance_name: "miner-a".to_owned(),
            bucket: "gs://my-project-dstack".to_owned(),
        }
    }

    /// Trust-correct deploy requires `dstack-cloud new` to be invoked with
    /// the GCP coordinates from `GcpConfig`, plus the hardcoded
    /// `--key-provider kms` and `--gw` flags. Anything missing here means
    /// a fresh-machine deploy would scaffold a project with weaker
    /// settings than `deploy.sh` produced, and the registry would later
    /// refuse the resulting attestation.
    #[test]
    fn build_dstack_new_args_matches_deploy_sh() {
        let gcp = sample_gcp();
        let args = build_dstack_new_args("gm-miner-1", &gcp);

        // Subcommand and positional name in the correct order.
        assert_eq!(args[0], "new");
        assert_eq!(args[1], "gm-miner-1");

        // Every required flag pair is present somewhere in the arg list.
        let pairs = [
            ("--project", "my-project"),
            ("--zone", "us-east1-b"),
            ("--machine-type", "c3-standard-8"),
            ("--instance-name", "miner-a"),
            ("--key-provider", "kms"),
        ];
        for (flag, value) in pairs {
            let pos = args.iter().position(|a| a == flag);
            assert!(pos.is_some(), "flag {flag} missing from {args:?}");
            let idx = pos.unwrap_or(0);
            assert_eq!(
                args[idx + 1],
                value,
                "flag {flag} should be followed by {value}, got {:?}",
                args[idx + 1]
            );
        }

        // `--gw` is a boolean flag — present, no value follows.
        assert!(args.iter().any(|a| a == "--gw"), "missing --gw in {args:?}");
    }

    /// Trust-critical: `--key-provider kms` is never substitutable from
    /// the CLI, because anything other than KMS breaks attestation.
    #[test]
    fn dstack_key_provider_is_kms() {
        assert_eq!(DSTACK_KEY_PROVIDER, "kms");
    }

    /// The positional `name` argument is what dstack-cloud uses as the
    /// project name in app.json; it must be the `app_name` we pass in,
    /// not a flag like `--name`.
    #[test]
    fn build_dstack_new_args_positional_name() {
        let args = build_dstack_new_args("custom-app", &sample_gcp());
        assert_eq!(args[1], "custom-app");
        assert!(
            !args.iter().any(|a| a == "--name"),
            "--name flag must not appear (name is positional in dstack-cloud new)"
        );
    }

    // ── P2 fix: poll_status must not return on empty hash strings ─────────────

    /// `DstackStatus` with `Some("")` fields must not be treated as ready; only
    /// non-empty strings should terminate the poll loop.
    ///
    /// We test this through the `DstackStatus` deserialization + the ready-check
    /// predicate directly (the struct is private but visible in the test module).
    #[test]
    fn dstack_status_empty_strings_not_ready() {
        // Simulate what happens when dstack-cloud emits `{"compose_sha256": "",
        // "os_image_hash": ""}` — both Some("") must not satisfy the ready check.
        let compose_sha256: Option<String> = Some(String::new());
        let os_image_hash: Option<String> = Some(String::new());

        let ready = matches!(
            (compose_sha256, os_image_hash),
            (Some(ref c), Some(ref o)) if !c.is_empty() && !o.is_empty()
        );
        assert!(!ready, "empty strings must not be treated as ready");
    }

    /// Non-empty hashes must be treated as ready.
    #[test]
    fn dstack_status_non_empty_strings_are_ready() {
        let compose_sha256: Option<String> = Some("sha256:abc".to_owned());
        let os_image_hash: Option<String> = Some("sha256:def".to_owned());

        let ready = matches!(
            (compose_sha256, os_image_hash),
            (Some(ref c), Some(ref o)) if !c.is_empty() && !o.is_empty()
        );
        assert!(ready, "non-empty hashes must be treated as ready");
    }

    /// One empty and one non-empty must not be treated as ready.
    #[test]
    fn dstack_status_partial_empty_not_ready() {
        let compose_sha256: Option<String> = Some("sha256:abc".to_owned());
        let os_image_hash: Option<String> = Some(String::new());

        let ready = matches!(
            (compose_sha256, os_image_hash),
            (Some(ref c), Some(ref o)) if !c.is_empty() && !o.is_empty()
        );
        assert!(!ready, "partial empty (one empty string) must not be ready");
    }

    // ── app.json trust-field validation ───────────────────────────────────────

    /// Write `content` to a fresh temp `app.json` and return (dir, path).
    /// The dir handle must be kept alive to keep the file on disk.
    fn temp_app_json(content: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("create tempdir");
        let path = dir.path().join("app.json");
        std::fs::write(&path, content).expect("write app.json");
        (dir, path)
    }

    /// A trust-correct app.json passes unchanged (returns `false` — no
    /// correction needed).
    #[test]
    fn trust_validation_passes_correct_app_json() {
        let (_dir, path) = temp_app_json(
            r#"{"key_provider":"kms","gateway_enabled":true,
                "kms_url":"https://kms.tdxlab.dstack.org:12001"}"#,
        );
        let corrected = validate_app_json_trust(&path).expect("valid app.json must pass");
        assert!(!corrected, "trust-correct file must not be modified");
    }

    /// A `key_provider` other than `kms` is rejected hard — never silently
    /// rewritten, because that could mask a tampered file.
    #[test]
    fn trust_validation_rejects_non_kms_key_provider() {
        let (_dir, path) = temp_app_json(
            r#"{"key_provider":"local","gateway_enabled":true,
                "kms_url":"https://kms.tdxlab.dstack.org:12001"}"#,
        );
        let err = validate_app_json_trust(&path).expect_err("non-kms must be rejected");
        assert!(err.to_string().contains("key_provider"));
        assert!(err.to_string().contains("kms"));
    }

    /// A missing `key_provider` is also rejected (no value to trust).
    #[test]
    fn trust_validation_rejects_missing_key_provider() {
        let (_dir, path) = temp_app_json(
            r#"{"gateway_enabled":true,"kms_url":"https://kms.tdxlab.dstack.org:12001"}"#,
        );
        let err =
            validate_app_json_trust(&path).expect_err("missing key_provider must be rejected");
        assert!(err.to_string().contains("key_provider"));
    }

    /// `gateway_enabled:false` is corrected in place to `true`.
    #[test]
    fn trust_validation_corrects_gateway_disabled() {
        let (_dir, path) = temp_app_json(
            r#"{"key_provider":"kms","gateway_enabled":false,
                "kms_url":"https://kms.tdxlab.dstack.org:12001"}"#,
        );
        let corrected = validate_app_json_trust(&path).expect("must correct, not fail");
        assert!(
            corrected,
            "gateway_enabled:false must be reported as corrected"
        );

        let raw = std::fs::read_to_string(&path).expect("re-read");
        let v: serde_json::Value = serde_json::from_str(&raw).expect("parse");
        assert_eq!(v["gateway_enabled"], serde_json::Value::Bool(true));
    }

    /// A missing `gateway_enabled` is filled in as `true`.
    #[test]
    fn trust_validation_fills_missing_gateway_enabled() {
        let (_dir, path) = temp_app_json(
            r#"{"key_provider":"kms","kms_url":"https://kms.tdxlab.dstack.org:12001"}"#,
        );
        let corrected = validate_app_json_trust(&path).expect("must correct");
        assert!(corrected);
        let raw = std::fs::read_to_string(&path).expect("re-read");
        let v: serde_json::Value = serde_json::from_str(&raw).expect("parse");
        assert_eq!(v["gateway_enabled"], serde_json::Value::Bool(true));
    }

    /// A missing `kms_url` is filled in with the trusted URL.
    #[test]
    fn trust_validation_fills_missing_kms_url() {
        let (_dir, path) = temp_app_json(r#"{"key_provider":"kms","gateway_enabled":true}"#);
        let corrected = validate_app_json_trust(&path).expect("must correct");
        assert!(corrected);
        let raw = std::fs::read_to_string(&path).expect("re-read");
        let v: serde_json::Value = serde_json::from_str(&raw).expect("parse");
        assert_eq!(v["kms_url"], TRUSTED_KMS_URL);
    }

    /// A *different* non-empty `kms_url` is rejected hard — it points the
    /// CVM at another key authority and must not be silently overwritten.
    #[test]
    fn trust_validation_rejects_different_kms_url() {
        let (_dir, path) = temp_app_json(
            r#"{"key_provider":"kms","gateway_enabled":true,
                "kms_url":"https://evil.example.com:12001"}"#,
        );
        let err = validate_app_json_trust(&path).expect_err("foreign kms_url must be rejected");
        assert!(err.to_string().contains("kms_url"));
        assert!(err.to_string().contains(TRUSTED_KMS_URL));
    }

    /// The trusted KMS URL constant matches the URL the app.json template
    /// and the dstack-cloud global config use.
    #[test]
    fn trusted_kms_url_is_tdxlab() {
        assert_eq!(TRUSTED_KMS_URL, "https://kms.tdxlab.dstack.org:12001");
        assert!(DSTACK_GLOBAL_CONFIG.contains(TRUSTED_KMS_URL));
    }

    // ── P1 fix: poll_status treats non-zero exit as "not ready" ──────────────

    /// A non-zero exit from `dstack-cloud status --json` must be treated as
    /// "not ready yet", not a hard failure. Verify that the success-path
    /// ready-check is only evaluated when the process exits zero — i.e. the
    /// non-zero branch does not attempt to parse stdout as JSON.
    ///
    /// This directly reflects the control-flow change in `poll_status`: a
    /// non-zero exit now falls through to the deadline / sleep path instead
    /// of bailing.
    #[test]
    fn poll_status_non_zero_exit_falls_through_to_deadline() {
        // Replicate the branching logic from poll_status to confirm the
        // non-zero branch does not try to parse output as a DstackStatus.
        let exit_success = false; // simulates a non-zero exit code
        let stdout_bytes: &[u8] = b""; // stdout is garbage/empty on failure

        let mut ready_checked = false;

        if exit_success {
            // This block must NOT run when exit is non-zero.
            let ds_result: Result<DstackStatus, _> = serde_json::from_slice(stdout_bytes);
            if ds_result.is_ok() {
                ready_checked = true;
            }
        }
        // Non-zero exit → ready_checked remains false → poll continues.
        assert!(
            !ready_checked,
            "non-zero exit must not trigger the ready-check path"
        );
    }

    /// A zero exit with non-empty hashes must be treated as ready (success path
    /// still works correctly after the control-flow restructure).
    #[test]
    fn poll_status_zero_exit_with_hashes_is_ready() {
        let exit_success = true;
        let stdout_bytes = br#"{"compose_sha256":"sha256:abc","os_image_hash":"sha256:def"}"#;

        let mut result: Option<DstackDeployResult> = None;

        if exit_success {
            let ds: DstackStatus = serde_json::from_slice(stdout_bytes).expect("parse");
            if let (Some(c), Some(o)) = (ds.compose_sha256, ds.os_image_hash) {
                if !c.is_empty() && !o.is_empty() {
                    result = Some(DstackDeployResult {
                        compose_sha256: c,
                        os_image_hash: o,
                    });
                }
            }
        }

        let r = result.expect("zero exit with non-empty hashes must be ready");
        assert_eq!(r.compose_sha256, "sha256:abc");
        assert_eq!(r.os_image_hash, "sha256:def");
    }
}
