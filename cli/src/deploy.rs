//! `gm-miner deploy` — single-shot trust-correct deploy flow.
//!
//! This module and `crate::image` together are the whole operator deploy
//! pipeline: the `gm-miner deploy` subcommand builds the miner image,
//! submits the compose stack to Phala Cloud, verifies the resulting CVM's
//! measured hashes against the registry allow-list, and registers the
//! image.
//!
//! Phala Cloud owns the confidential VM, the KMS, and `app_id`
//! authorization. The trust check therefore rests entirely on verifying
//! the deployed CVM's compose hash and OS image hash against the
//! registry's approved `ImageVersion` list — there is no client-side KMS
//! trust-pinning to do.
//!
//! Steps (orchestrated from `main::cmd_deploy`):
//!   1. Read provider API keys from config; error early if none set.
//!   2. Auth preflight (`GET /miners/me`) — fail fast if the operator
//!      forgot `gm-miner login` or has a stale token, before any CVM work.
//!   3. Fetch the approved `ImageVersion` list from the registry.
//!   4. Select the newest supported version (or a pinned one if `--version`
//!      given).
//!   5. Prepare the deploy target ([`prepare_deploy_target`]): build and
//!      push the miner image to a public registry (or accept a pre-built
//!      `--image-ref`), then render the bundled `dstack/docker-compose.yaml`
//!      template with the digest-pinned ref.
//!   6. Submit the compose stack to Phala Cloud (via the [`PhalaClient`]
//!      trait for testability), wait for the CVM to boot, and read back
//!      the measured `compose_hash` + `os_image_hash`.
//!   7. **Verify** both match the registry's approved version — refuse and
//!      exit 1 if they don't.
//!   8. Call `register_image` with the verified hashes.

use anyhow::{bail, Context, Result};
use chrono::DateTime;
use serde::{Deserialize, Serialize};

use crate::config::ProviderKeys;

/// Default poll interval when waiting for the CVM to boot (seconds).
pub const POLL_INTERVAL_SECS: u64 = 5;
/// Default maximum time to wait for hashes to appear after deploy (seconds).
pub const DEFAULT_BOOT_TIMEOUT_SECS: u64 = 300;

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

// ── Phala Cloud deploy abstraction ────────────────────────────────────────────

/// Result returned after a successful Phala Cloud deploy + status poll.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DstackDeployResult {
    /// Canonical compose hash measured by the CVM (RTMR3-derived). Read
    /// from `phala cvms get <app-id> --json`.
    pub compose_sha256: String,
    /// OS image hash reported for the CVM.
    pub os_image_hash: String,
}

/// Abstraction over the `phala` CLI, injectable for tests.
///
/// The real implementation ([`RealPhalaClient`]) shells out to
/// `phala deploy` and `phala cvms get`. Tests inject a stub that returns
/// pre-canned values without touching the filesystem or a subprocess.
pub trait PhalaClient {
    /// Deploy the compose stack to Phala Cloud and return the compose + OS
    /// image hashes the platform measured for the resulting CVM.
    ///
    /// `compose_yaml` is the rendered compose file content; `env_vars` are
    /// the operator's provider API keys, encrypted client-side to the CVM
    /// key by `phala deploy`. `node_secret` is the miner's node secret
    /// (Mechanism 1 of `docs/plans/attestation-and-identity.md`), passed in
    /// the same encrypted env as `GM_NODE_SECRET`. `boot_timeout_secs`
    /// controls how long to poll for the measured hashes before giving up.
    ///
    /// # Errors
    /// Returns an error if the deploy fails or the hashes cannot be read
    /// back within `boot_timeout_secs`.
    fn deploy(
        &self,
        compose_yaml: &str,
        env_vars: &ProviderKeys,
        node_secret: &str,
        boot_timeout_secs: u64,
    ) -> Result<DstackDeployResult>;
}

// ── Image provisioning abstraction ────────────────────────────────────────────

/// Abstraction over the image-build step, injectable so the deploy
/// orchestration can be exercised without a real `docker` toolchain.
///
/// The real implementation (in `crate::image`, wired by `main`) either
/// builds and pushes the miner image to a public registry, or — when the
/// operator supplied `--image-ref` — skips the build and returns the
/// pre-built ref.
pub trait ImageProvisioner {
    /// Build the miner image and return the digest-pinned image ref to
    /// embed in the compose template.
    ///
    /// # Errors
    /// Returns an error if the image build/push fails.
    fn provision(&self) -> Result<String>;
}

/// Prepare the deploy target: provision the miner image, then render the
/// compose file with the digest-pinned ref.
///
/// This is the network-free core of the deploy orchestration, extracted so
/// it can be integration-tested against real code rather than a
/// re-implemented copy of the branch logic.
///
/// Returns the rendered `docker-compose.yaml` content (image ref pinned).
///
/// # Errors
/// Returns an error if image provisioning or compose rendering fails.
pub fn prepare_deploy_target(provisioner: &dyn ImageProvisioner) -> Result<String> {
    // Build/push the image (or accept a pre-built ref). The
    // build-vs-prebuilt branch lives entirely inside the `ImageProvisioner`.
    let image_ref = provisioner.provision()?;

    // Render the compose template with the digest-pinned ref.
    render_compose(COMPOSE_TEMPLATE, &image_ref)
}

// ── Real `phala` CLI implementation ───────────────────────────────────────────

/// Shells out to `phala deploy` and parses the resulting
/// `phala cvms get <app-id> --json` to obtain both hashes.
pub struct RealPhalaClient {
    /// CVM name passed to `phala deploy --name`.
    pub app_name: String,
    /// Directory used to stage the rendered compose file and env file.
    pub project_dir: std::path::PathBuf,
    /// Instance type for the CVM (`phala deploy --instance-type`).
    pub instance_type: String,
    /// Disk size for the CVM (`phala deploy --disk-size`).
    pub disk_size: String,
}

impl RealPhalaClient {
    /// Create a client that stages compose/env files in `project_dir`.
    #[must_use]
    pub fn new(
        app_name: impl Into<String>,
        project_dir: std::path::PathBuf,
        instance_type: impl Into<String>,
        disk_size: impl Into<String>,
    ) -> Self {
        Self {
            app_name: app_name.into(),
            project_dir,
            instance_type: instance_type.into(),
            disk_size: disk_size.into(),
        }
    }
}

/// JSON emitted by `phala deploy --json` on a successful new-CVM deploy.
#[derive(Debug, Deserialize)]
struct PhalaDeployOutput {
    success: bool,
    app_id: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

/// The CVM detail document returned by `phala cvms get <app-id> --json`.
///
/// Field path is the verified shape of the Phala Cloud CVM-detail schema:
/// the canonical compose hash is the top-level `compose_hash`, and the OS
/// image hash is nested under `os.os_image_hash`. Both are read here; the
/// registry allow-list is keyed on exactly these two values.
#[derive(Debug, Deserialize)]
struct PhalaCvmDetail {
    compose_hash: Option<String>,
    os: Option<PhalaCvmOs>,
}

/// The `os` sub-object of [`PhalaCvmDetail`].
#[derive(Debug, Deserialize)]
struct PhalaCvmOs {
    os_image_hash: Option<String>,
}

/// JSON-path documentation for the measured hashes, kept as a constant so
/// the dependency on the Phala Cloud CVM-detail schema is greppable and
/// easy to update if the API changes.
///
/// Verified against the `phala` CLI source (`@phala/phala-cli`, the
/// `cvms get` response schema for API version `2026-01-21`): the CVM
/// detail document carries the canonical compose hash at the top-level
/// `compose_hash` field and the OS image hash at `os.os_image_hash`.
pub const PHALA_COMPOSE_HASH_FIELD: &str = "compose_hash";
/// See [`PHALA_COMPOSE_HASH_FIELD`]; the OS image hash field path.
pub const PHALA_OS_IMAGE_HASH_FIELD: &str = "os.os_image_hash";

/// Parse the measured hashes out of `phala cvms get <app-id> --json` output.
///
/// `succeeded` is the command's exit status; `stdout` is its raw stdout.
///
/// Returns `Ok(Some(..))` only when the command succeeded and both hashes
/// are present and non-empty; `Ok(None)` when the command exited non-zero
/// (the CVM is not ready yet) or when either hash is still absent/empty.
///
/// # Errors
/// Returns an error if `succeeded` is true but `stdout` is not valid
/// `cvms get --json` JSON.
pub fn parse_phala_cvm_detail(
    succeeded: bool,
    stdout: &[u8],
) -> Result<Option<DstackDeployResult>> {
    if !succeeded {
        return Ok(None);
    }

    let detail: PhalaCvmDetail =
        serde_json::from_slice(stdout).context("parse phala cvms get --json output")?;

    let compose = detail.compose_hash;
    let os_image = detail.os.and_then(|o| o.os_image_hash);

    match (compose, os_image) {
        (Some(compose_sha256), Some(os_image_hash))
            if !compose_sha256.is_empty() && !os_image_hash.is_empty() =>
        {
            Ok(Some(DstackDeployResult {
                compose_sha256,
                os_image_hash,
            }))
        }
        _ => Ok(None),
    }
}

/// Build the argument list for `phala deploy`.
///
/// `phala deploy` submits a Docker Compose stack to Phala Cloud, which
/// provisions the `TEEPod`, runs the KMS, encrypts the env file client-side
/// to the CVM key, and assigns the `app_id`. The flags pin the CVM name,
/// instance type, disk size, compose file, and env file, and request JSON
/// output plus `--wait` so the call returns only once the CVM is up.
///
/// Extracted from [`RealPhalaClient::deploy`] so the wiring can be asserted
/// without spawning a subprocess.
#[must_use]
pub fn build_phala_deploy_args(
    app_name: &str,
    instance_type: &str,
    disk_size: &str,
    compose_path: &str,
    env_path: &str,
) -> Vec<String> {
    vec![
        "deploy".to_owned(),
        "--name".to_owned(),
        app_name.to_owned(),
        "--instance-type".to_owned(),
        instance_type.to_owned(),
        "--disk-size".to_owned(),
        disk_size.to_owned(),
        "--compose".to_owned(),
        compose_path.to_owned(),
        "--env".to_owned(),
        env_path.to_owned(),
        "--wait".to_owned(),
        "--json".to_owned(),
    ]
}

/// Run `phala cvms get <app-id> --json` once and parse the measured
/// `compose_hash` + `os.os_image_hash` via [`parse_phala_cvm_detail`].
///
/// Returns `Ok(None)` when the command exited non-zero (the CVM is not
/// ready) or when either hash is still absent/empty.
///
/// # Errors
/// Returns an error only if `phala` cannot be spawned, or it exits
/// successfully but emits output that is not valid `cvms get --json` JSON.
fn read_phala_cvm_detail(app_id: &str) -> Result<Option<DstackDeployResult>> {
    let out = std::process::Command::new("phala")
        .args(["cvms", "get", app_id, "--json"])
        .output()
        .context("run phala cvms get — is the phala CLI installed? (npm i -g phala)")?;

    if !out.status.success() {
        tracing::info!(
            stderr = %String::from_utf8_lossy(&out.stderr).trim(),
            "phala cvms get --json not ready yet (non-zero exit)"
        );
    }

    parse_phala_cvm_detail(out.status.success(), &out.stdout)
}

impl PhalaClient for RealPhalaClient {
    fn deploy(
        &self,
        compose_yaml: &str,
        env_vars: &ProviderKeys,
        node_secret: &str,
        boot_timeout_secs: u64,
    ) -> Result<DstackDeployResult> {
        use std::fs;

        fs::create_dir_all(&self.project_dir)
            .with_context(|| format!("create project dir {}", self.project_dir.display()))?;

        // Write the rendered compose file.
        let compose_path = self.project_dir.join("docker-compose.yaml");
        fs::write(&compose_path, compose_yaml)
            .with_context(|| format!("write {}", compose_path.display()))?;

        // Write the env file at mode 0600 so the secrets are never visible
        // with broader permissions. `phala deploy` reads this file and
        // encrypts its contents client-side to the CVM key.
        let env_path = self.project_dir.join(".env");
        write_env_file(&env_path, env_vars, node_secret)?;

        let compose_arg = compose_path.to_string_lossy().into_owned();
        let env_arg = env_path.to_string_lossy().into_owned();
        let args = build_phala_deploy_args(
            &self.app_name,
            &self.instance_type,
            &self.disk_size,
            &compose_arg,
            &env_arg,
        );

        let out = std::process::Command::new("phala")
            .args(&args)
            .output()
            .context("run phala deploy — is the phala CLI installed? (npm i -g phala)")?;
        if !out.status.success() {
            bail!(
                "phala deploy exited with status {}: {}",
                out.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }

        let app_id = parse_phala_deploy_output(&out.stdout)?;
        println!("Phala Cloud assigned app_id {app_id}; waiting for the CVM to report hashes ...");

        // Poll `phala cvms get` until both measured hashes are populated.
        // `phala deploy --wait` returns once the CVM is up, but the
        // platform may take a few more seconds to publish the measured
        // hashes in the CVM detail document.
        poll_phala_cvm_detail(&app_id, boot_timeout_secs)
    }
}

/// Poll `phala cvms get <app-id> --json` every [`POLL_INTERVAL_SECS`]
/// seconds until both `compose_hash` and `os.os_image_hash` are non-empty,
/// or until `timeout_secs` elapses.
///
/// # Errors
/// Returns an error if `phala` cannot be spawned, emits unparseable JSON,
/// or the hashes never appear before `timeout_secs` elapses.
fn poll_phala_cvm_detail(app_id: &str, timeout_secs: u64) -> Result<DstackDeployResult> {
    use std::time::{Duration, Instant};

    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let poll = Duration::from_secs(POLL_INTERVAL_SECS);
    let mut attempt: u32 = 0;

    loop {
        attempt += 1;
        if let Some(result) = read_phala_cvm_detail(app_id)? {
            return Ok(result);
        }

        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            bail!(
                "timed out after {timeout_secs}s waiting for the CVM to report \
                 hashes (compose_hash/os_image_hash never appeared in \
                 `phala cvms get {app_id} --json`); \
                 increase --boot-timeout-secs or check the Phala Cloud dashboard"
            );
        }

        let sleep = remaining.min(poll);
        tracing::debug!(attempt, ?sleep, "hashes not yet available; waiting");
        std::thread::sleep(sleep);
    }
}

/// Parse `phala deploy --json` output into the assigned `app_id`.
///
/// # Errors
/// Returns an error if the output is not valid JSON, reports a failed
/// deploy, or carries no `app_id`.
fn parse_phala_deploy_output(stdout: &[u8]) -> Result<String> {
    let parsed: PhalaDeployOutput =
        serde_json::from_slice(stdout).context("parse phala deploy --json output")?;
    if !parsed.success {
        bail!(
            "phala deploy reported failure: {}",
            parsed.error.as_deref().unwrap_or("<no error detail>")
        );
    }
    parsed
        .app_id
        .filter(|id| !id.is_empty())
        .context("phala deploy succeeded but returned no app_id")
}

/// Write the provider keys + node secret to `env_path` at mode 0600.
///
/// Uses a temp-file-then-rename so the target file is always at mode 0600
/// from the moment it exists — no window where a partially-written or
/// broader-permission file is present on disk.
fn write_env_file(
    env_path: &std::path::Path,
    env_vars: &ProviderKeys,
    node_secret: &str,
) -> Result<()> {
    use std::fs;
    use std::io::Write as _;
    #[cfg(unix)]
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

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
    // The node secret envoy enforces as the x-gm-node-key header. Always
    // written: `cmd_deploy` resolves it before this call.
    lines.push_str("GM_NODE_SECRET=");
    lines.push_str(node_secret);
    lines.push('\n');

    let parent = env_path
        .parent()
        .context("env file path has no parent directory")?;
    let tmp_path = parent.join(".env.tmp");

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

    fs::rename(&tmp_path, env_path)
        .with_context(|| format!("rename {} -> {}", tmp_path.display(), env_path.display()))
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
/// with `replacement`.
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

/// Normalize a hash to the registry's canonical form: lowercase, with any
/// `sha256:` prefix stripped. Phala Cloud may report a hash uppercased or
/// `sha256:`-prefixed; the registry's `POST /miners/register` only accepts
/// `^[0-9a-f]{64}$`, so the hash must be normalized before it is both
/// verified and sent onward.
#[must_use]
pub fn normalize_hash(hash: &str) -> String {
    let lowered = hash.to_lowercase();
    match lowered.strip_prefix("sha256:") {
        Some(stripped) => stripped.to_owned(),
        None => lowered,
    }
}

/// Verify that the actual hashes from Phala Cloud match the
/// registry-approved version, returning the normalized actual hashes.
///
/// Both sides are normalized (lowercased, `sha256:` prefix stripped) before
/// comparison. The returned [`DstackDeployResult`] holds the normalized
/// values so the loud verification check and the subsequent registration
/// operate on the exact same hash.
///
/// # Errors
/// Returns a loud, actionable error if either hash does not match.
pub fn verify_hashes(
    actual: &DstackDeployResult,
    approved: &ImageVersion,
) -> Result<DstackDeployResult> {
    let normalized = DstackDeployResult {
        compose_sha256: normalize_hash(&actual.compose_sha256),
        os_image_hash: normalize_hash(&actual.os_image_hash),
    };
    let compose_match = normalized.compose_sha256 == normalize_hash(&approved.compose_hash);
    let os_match = normalized.os_image_hash == normalize_hash(&approved.os_image_hash);

    if compose_match && os_match {
        return Ok(normalized);
    }

    let mut msg = String::from("HASH MISMATCH — deployment is suspect; refusing to register.\n\n");

    if !compose_match {
        msg.push_str("  compose_hash\n    expected (registry): ");
        msg.push_str(&approved.compose_hash);
        msg.push_str("\n    actual (phala):      ");
        msg.push_str(&actual.compose_sha256);
        msg.push_str("\n\n");
    }
    if !os_match {
        msg.push_str("  os_image_hash\n    expected (registry): ");
        msg.push_str(&approved.os_image_hash);
        msg.push_str("\n    actual (phala):      ");
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

// ── `phala` CLI preflight ─────────────────────────────────────────────────────

/// Preflight that the `phala` CLI is on `PATH`.
///
/// `phala` is the runtime dependency of `gm-miner deploy`: it submits the
/// compose stack to Phala Cloud and reports the measured CVM hashes. A
/// missing CLI is caught here with an actionable install hint before any
/// image build runs.
///
/// # Errors
/// Returns an error if `phala` is not on `PATH`.
pub fn preflight_phala_cli() -> Result<()> {
    let on_path = std::process::Command::new("phala")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if !on_path {
        bail!(
            "the `phala` CLI is required for `gm-miner deploy` but was not found on PATH.\n  \
             install it with: npm i -g phala"
        );
    }
    Ok(())
}

// ── Bundled compose template ──────────────────────────────────────────────────

/// The compose template, bundled at compile time from
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

    fn approved(compose: &str, os: &str) -> ImageVersion {
        ImageVersion {
            compose_hash: compose.to_owned(),
            os_image_hash: os.to_owned(),
            status: "supported".to_owned(),
            notes: None,
            created_at: "2025-01-01T00:00:00Z".to_owned(),
        }
    }

    #[test]
    fn placeholder_replaced_once() {
        let template = "image: ${GM_IMAGE_REF:?GM_IMAGE_REF must be set}\n  ports:\n";
        let rendered =
            render_compose(template, "ghcr.io/o/app@sha256:abc123").expect("should render");
        assert!(rendered.contains("ghcr.io/o/app@sha256:abc123"));
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
        let verified =
            verify_hashes(&actual, &approved("abc123", "def456")).expect("hashes should match");
        assert_eq!(verified.compose_sha256, "abc123");
        assert_eq!(verified.os_image_hash, "def456");
    }

    #[test]
    fn verify_hashes_case_insensitive() {
        let actual = DstackDeployResult {
            compose_sha256: "ABC123".to_string(),
            os_image_hash: "DEF456".to_string(),
        };
        let verified =
            verify_hashes(&actual, &approved("abc123", "def456")).expect("hashes should match");
        assert_eq!(verified.compose_sha256, "abc123");
        assert_eq!(verified.os_image_hash, "def456");
    }

    #[test]
    fn verify_hashes_strips_sha256_prefix() {
        // Phala Cloud may report a `sha256:`-prefixed or uppercased hash;
        // the registry only accepts bare lowercase hex. The returned hashes
        // must be normalized so registration uses the value that was
        // actually verified.
        let actual = DstackDeployResult {
            compose_sha256: "sha256:ABC123".to_string(),
            os_image_hash: "SHA256:DEF456".to_string(),
        };
        let verified =
            verify_hashes(&actual, &approved("abc123", "def456")).expect("hashes should match");
        assert_eq!(verified.compose_sha256, "abc123");
        assert_eq!(verified.os_image_hash, "def456");
    }

    #[test]
    fn normalize_hash_lowercases_and_strips_prefix() {
        assert_eq!(normalize_hash("ABCDEF"), "abcdef");
        assert_eq!(normalize_hash("sha256:ABCDEF"), "abcdef");
        assert_eq!(normalize_hash("SHA256:abcdef"), "abcdef");
        assert_eq!(normalize_hash("abcdef"), "abcdef");
    }

    #[test]
    fn verify_hashes_fails_on_compose_mismatch() {
        let actual = DstackDeployResult {
            compose_sha256: "WRONG".to_string(),
            os_image_hash: "def456".to_string(),
        };
        let err = verify_hashes(&actual, &approved("abc123", "def456")).unwrap_err();
        assert!(err.to_string().contains("compose_hash"));
        assert!(err.to_string().contains("HASH MISMATCH"));
    }

    #[test]
    fn verify_hashes_fails_on_os_mismatch() {
        let actual = DstackDeployResult {
            compose_sha256: "abc123".to_string(),
            os_image_hash: "WRONG".to_string(),
        };
        let err = verify_hashes(&actual, &approved("abc123", "def456")).unwrap_err();
        assert!(err.to_string().contains("os_image_hash"));
        assert!(err.to_string().contains("HASH MISMATCH"));
    }

    #[test]
    fn verify_hashes_fails_on_both_mismatch() {
        let actual = DstackDeployResult {
            compose_sha256: "W1".to_string(),
            os_image_hash: "W2".to_string(),
        };
        let err = verify_hashes(&actual, &approved("abc123", "def456")).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("compose_hash"));
        assert!(msg.contains("os_image_hash"));
    }

    #[test]
    fn select_version_latest_when_no_pin() {
        let versions = vec![
            ImageVersion {
                created_at: "2025-03-01T00:00:00Z".to_string(),
                ..approved("new", "new")
            },
            ImageVersion {
                created_at: "2025-01-01T00:00:00Z".to_string(),
                ..approved("old", "old")
            },
        ];
        let selected = select_version(&versions, None).expect("should select");
        assert_eq!(selected.compose_hash, "new");
    }

    #[test]
    fn select_version_pinned() {
        let versions = vec![
            ImageVersion {
                created_at: "2025-03-01T00:00:00Z".to_string(),
                ..approved("new", "new")
            },
            ImageVersion {
                created_at: "2025-01-01T00:00:00Z".to_string(),
                ..approved("old", "old")
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
        let versions = vec![approved("x", "x")];
        assert!(select_version(&versions, Some(2)).is_err());
        assert!(select_version(&versions, Some(0)).is_err());
    }

    // ── phala deploy argument wiring ──────────────────────────────────────────

    /// `phala deploy` must be invoked with the compose file, env file,
    /// instance type, disk size, `--wait`, and `--json` — the env file is
    /// what carries the (client-side-encrypted) provider keys, and `--json`
    /// is required so the deploy output can be parsed for `app_id`.
    #[test]
    fn build_phala_deploy_args_wires_every_flag() {
        let args = build_phala_deploy_args(
            "gm-miner-1",
            "tdx.medium",
            "40G",
            "/tmp/dist/docker-compose.yaml",
            "/tmp/dist/.env",
        );
        assert_eq!(args[0], "deploy");
        let pairs = [
            ("--name", "gm-miner-1"),
            ("--instance-type", "tdx.medium"),
            ("--disk-size", "40G"),
            ("--compose", "/tmp/dist/docker-compose.yaml"),
            ("--env", "/tmp/dist/.env"),
        ];
        for (flag, value) in pairs {
            let pos = args.iter().position(|a| a == flag);
            assert!(pos.is_some(), "flag {flag} missing from {args:?}");
            let idx = pos.unwrap_or(0);
            assert_eq!(
                args[idx + 1],
                value,
                "flag {flag} should be followed by {value}"
            );
        }
        assert!(
            args.iter().any(|a| a == "--wait"),
            "missing --wait in {args:?}"
        );
        assert!(
            args.iter().any(|a| a == "--json"),
            "missing --json in {args:?}"
        );
    }

    // ── phala deploy output parsing ───────────────────────────────────────────

    #[test]
    fn parse_phala_deploy_output_extracts_app_id() {
        let stdout = br#"{"success":true,"vm_uuid":"u","name":"n","app_id":"app_abc123"}"#;
        let app_id = parse_phala_deploy_output(stdout).expect("must parse");
        assert_eq!(app_id, "app_abc123");
    }

    #[test]
    fn parse_phala_deploy_output_rejects_failure() {
        let stdout = br#"{"success":false,"error":"quota exceeded"}"#;
        let err = parse_phala_deploy_output(stdout).expect_err("failure must error");
        assert!(err.to_string().contains("quota exceeded"));
    }

    #[test]
    fn parse_phala_deploy_output_rejects_missing_app_id() {
        let stdout = br#"{"success":true}"#;
        let err = parse_phala_deploy_output(stdout).expect_err("missing app_id must error");
        assert!(err.to_string().contains("app_id"));
    }

    // ── phala cvms get detail parsing ─────────────────────────────────────────

    /// The verified field path: top-level `compose_hash` and nested
    /// `os.os_image_hash` in the `phala cvms get --json` document.
    #[test]
    fn parse_phala_cvm_detail_reads_compose_and_os_hash() {
        let stdout = br#"{
            "app_id":"app_abc",
            "compose_hash":"sha256:aaa",
            "os":{"name":"dstack-0.5.3","os_image_hash":"sha256:bbb"}
        }"#;
        let result = parse_phala_cvm_detail(true, stdout)
            .expect("must parse")
            .expect("both hashes present");
        assert_eq!(result.compose_sha256, "sha256:aaa");
        assert_eq!(result.os_image_hash, "sha256:bbb");
    }

    /// A non-zero `phala cvms get` exit means the CVM is not ready yet —
    /// the parser must return `Ok(None)`, never an error.
    #[test]
    fn parse_phala_cvm_detail_non_zero_exit_is_none() {
        let result =
            parse_phala_cvm_detail(false, b"garbage").expect("non-zero exit must not error");
        assert!(result.is_none(), "non-zero exit must yield None");
    }

    /// A detail document with the hashes still absent must yield `None` so
    /// the poll loop keeps waiting.
    #[test]
    fn parse_phala_cvm_detail_missing_hashes_is_none() {
        let stdout = br#"{"app_id":"app_abc","status":"starting"}"#;
        let result = parse_phala_cvm_detail(true, stdout).expect("must parse");
        assert!(result.is_none(), "missing hashes must yield None");
    }

    /// Empty-string hashes must not be treated as ready.
    #[test]
    fn parse_phala_cvm_detail_empty_hashes_is_none() {
        let stdout = br#"{"compose_hash":"","os":{"os_image_hash":""}}"#;
        let result = parse_phala_cvm_detail(true, stdout).expect("must parse");
        assert!(result.is_none(), "empty hashes must yield None");
    }

    /// A `compose_hash` present but `os` block absent must yield `None`.
    #[test]
    fn parse_phala_cvm_detail_partial_is_none() {
        let stdout = br#"{"compose_hash":"sha256:aaa"}"#;
        let result = parse_phala_cvm_detail(true, stdout).expect("must parse");
        assert!(result.is_none(), "partial detail must yield None");
    }

    #[test]
    fn parse_phala_cvm_detail_invalid_json_errors() {
        assert!(parse_phala_cvm_detail(true, b"not json").is_err());
    }

    /// The documented field-path constants must match the `phala cvms get`
    /// CVM-detail schema this module parses.
    #[test]
    fn hash_field_path_constants_are_documented() {
        assert_eq!(PHALA_COMPOSE_HASH_FIELD, "compose_hash");
        assert_eq!(PHALA_OS_IMAGE_HASH_FIELD, "os.os_image_hash");
    }

    // ── prepare_deploy_target ─────────────────────────────────────────────────

    /// `prepare_deploy_target` provisions the image and pins the returned
    /// ref into the rendered compose file.
    #[test]
    fn prepare_deploy_target_embeds_provisioner_ref() {
        struct StubProvisioner;
        impl ImageProvisioner for StubProvisioner {
            fn provision(&self) -> Result<String> {
                Ok("ghcr.io/taostat/gm-miner@sha256:deadbeef".to_owned())
            }
        }
        let rendered = prepare_deploy_target(&StubProvisioner).expect("orchestration must succeed");
        assert!(
            rendered.contains("sha256:deadbeef"),
            "the provisioner's ref must be pinned into the compose file"
        );
        assert!(
            !rendered.contains("${GM_IMAGE_REF"),
            "the ${{GM_IMAGE_REF}} placeholder must be substituted"
        );
    }

    /// An image-build failure must propagate out of `prepare_deploy_target`.
    #[test]
    fn prepare_deploy_target_propagates_build_failure() {
        struct FailingProvisioner;
        impl ImageProvisioner for FailingProvisioner {
            fn provision(&self) -> Result<String> {
                bail!("image build+push failed")
            }
        }
        let err = prepare_deploy_target(&FailingProvisioner).expect_err("build failure must abort");
        assert!(err.to_string().contains("image build+push failed"));
    }
}
