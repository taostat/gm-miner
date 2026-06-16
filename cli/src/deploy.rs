//! `gmcli deploy` — single-shot trust-correct deploy flow.
//!
//! This module and `crate::image` together are the whole operator deploy
//! pipeline: the `gmcli deploy` subcommand builds the miner image,
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
//!      forgot `gmcli login` or has a stale token, before any CVM work.
//!   3. Fetch the approved `ImageVersion` list from the registry.
//!   4. Select the newest supported version (or a pinned one if `--version`
//!      given).
//!   5. Prepare the deploy target ([`prepare_deploy_target`]): build and
//!      push the miner image to a registry (or accept a pre-built
//!      `--image-ref`), then render the bundled `dstack/docker-compose.yaml`
//!      template with the digest-pinned ref. Resolve private-registry pull
//!      credentials from the image ref's host plus the operator-set
//!      `GHCR_PULL_USERNAME` / `GHCR_PULL_TOKEN` env vars.
//!   6. Submit the compose stack to Phala Cloud (via the [`PhalaClient`]
//!      trait for testability) — with a production OS image (`--image` +
//!      `--no-dev-os`), the corrected digest-aware pre-launch script, and
//!      the registry pull credentials in the encrypted env — wait for the
//!      CVM to boot, and read back the measured `compose_hash` +
//!      `os_image_hash` and the CVM's public endpoint.
//!   7. **Verify** both hashes match the registry's approved version —
//!      refuse and exit 1 if they don't.
//!   8. Call `register_image` with the verified hashes and the endpoint.

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
    /// Digest-pinned, directly-pullable reference of the gm-published miner
    /// image whose compose renders to `compose_hash`, e.g.
    /// `ghcr.io/taostat/gm-miner@sha256:...`. `gmcli deploy` defaults to this
    /// so a normal miner deploys the gm-supported image rather than building
    /// one. Optional because the field post-dates the earliest rows; an entry
    /// without it cannot be deployed by digest, so the default path fails with
    /// guidance toward `--image-ref` / `--image-repo`.
    #[serde(default)]
    pub image_ref: Option<String>,
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

/// Everything `gmcli deploy` needs back from a Phala Cloud deploy: the
/// CVM's measured hashes (verified against the registry allow-list) and
/// the CVM's public endpoint (sent to the registry on registration).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeployOutcome {
    /// Measured `compose_hash` + `os_image_hash` for the CVM.
    pub hashes: DstackDeployResult,
    /// The CVM's public RA-TLS data-plane endpoint — the dstack
    /// TLS-passthrough (`s`-suffix) form of `endpoints[0].app`, e.g.
    /// `https://<app-id>-8080s.dstack-<node>.phala.network`. Registered
    /// with the registry so the gateway connects to the URL on which
    /// the miner's RA-TLS certificate is actually presented.
    pub endpoint: String,
    /// The Phala Cloud `app_id` of the deployed CVM, read from the
    /// CVM-detail document. Persisted in the worker's `WorkerRecord` so
    /// `worker remove` can tell the operator which CVM to `phala cvms
    /// delete`.
    pub app_id: String,
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
    /// the same encrypted env as `GM_NODE_SECRET`. `registry_creds`, when
    /// present, are private-registry pull credentials written into the
    /// same encrypted env so the CVM's pre-launch script can `docker login`
    /// and pull the (private) miner image. `boot_timeout_secs` controls
    /// how long to poll for the measured hashes before giving up.
    ///
    /// # Errors
    /// Returns an error if the deploy fails or the hashes/endpoint cannot
    /// be read back within `boot_timeout_secs`.
    fn deploy(
        &self,
        compose_yaml: &str,
        env_vars: &ProviderKeys,
        node_secret: &str,
        registry_creds: Option<&RegistryCredentials>,
        boot_timeout_secs: u64,
    ) -> Result<DeployOutcome>;
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

/// A prepared deploy target: the digest-pinned miner image ref and the
/// compose file rendered to embed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeployTarget {
    /// Digest-pinned miner image reference, e.g.
    /// `ghcr.io/owner/gm-miner@sha256:...`.
    pub image_ref: String,
    /// `docker-compose.yaml` content with `${GM_IMAGE_REF}` substituted.
    pub rendered_compose: String,
}

/// Prepare the deploy target: provision the miner image, then render the
/// compose file with the digest-pinned ref and the active network.
///
/// Returns the digest-pinned image ref (needed to derive the registry
/// pull credentials) and the rendered `docker-compose.yaml` content.
///
/// # Errors
/// Returns an error if image provisioning or compose rendering fails.
pub fn prepare_deploy_target(
    provisioner: &dyn ImageProvisioner,
    network: &str,
) -> Result<DeployTarget> {
    // Build/push the image (or accept a pre-built ref). The
    // build-vs-prebuilt branch lives entirely inside the `ImageProvisioner`.
    let image_ref = provisioner.provision()?;

    // Render the compose template with the digest-pinned ref and the
    // active network — both end up as literals in the rendered compose
    // and contribute to the attestation-measured compose_hash.
    let rendered_compose = render_compose(COMPOSE_TEMPLATE, &image_ref, network)?;

    Ok(DeployTarget {
        image_ref,
        rendered_compose,
    })
}

// ── Private-registry pull credentials ─────────────────────────────────────────

/// Default OS image passed to `phala deploy --image`.
///
/// The OS image version must match the dstack version of the Phala node
/// the CVM lands on. The current prod nodes (prod5/prod9) run dstack
/// v0.5.7, so `dstack-0.5.7` is the working default; `dstack-0.5.10`
/// returns "no available resources".
pub const DEFAULT_OS_IMAGE: &str = "dstack-0.5.7";

/// Environment variable carrying the GHCR pull username.
pub const GHCR_PULL_USERNAME_VAR: &str = "GHCR_PULL_USERNAME";
/// Environment variable carrying the GHCR pull token (`read:packages`).
pub const GHCR_PULL_TOKEN_VAR: &str = "GHCR_PULL_TOKEN";

/// Pull credentials for a private container registry, written into the
/// `phala deploy` env file so the CVM's pre-launch script can `docker
/// login` and pull the miner image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryCredentials {
    /// Registry host the credentials authenticate against, e.g. `ghcr.io`.
    pub registry: String,
    /// Registry username.
    pub username: String,
    /// Registry password / token.
    pub password: String,
}

/// Extract the registry host from a container image reference.
///
/// A registry host is the first `/`-separated component, but only when it
/// looks like a host (contains a `.` or `:`, or is the literal
/// `localhost`). A ref with no such component — e.g. `library/alpine` —
/// resolves to Docker Hub (`docker.io`), which is public.
#[must_use]
pub fn registry_host(image_ref: &str) -> String {
    let first = image_ref.split('/').next().unwrap_or(image_ref);
    if first == "localhost" || first.contains('.') || first.contains(':') {
        first.to_owned()
    } else {
        "docker.io".to_owned()
    }
}

/// Resolve private-registry pull credentials for `image_ref`.
///
/// Returns `Ok(None)` when no credentials are needed — the image is on Docker
/// Hub (`docker.io`, public), or `public_pull` is set (the gm-published
/// supported image, which is published for anonymous pull). For any other
/// registry host with `public_pull == false` the miner image is assumed
/// private, so the operator-set `GHCR_PULL_USERNAME` / `GHCR_PULL_TOKEN`
/// environment variables are required.
///
/// `public_pull` is true only for the flag-less default deploy of the
/// gm-published image; an operator's own `--image-ref` keeps the
/// credentials-required behaviour since it may point at a private repo.
///
/// # Errors
/// Returns an actionable error if the image is on a private registry,
/// `public_pull` is false, and either credential environment variable is
/// unset or empty.
pub fn resolve_registry_credentials(
    image_ref: &str,
    public_pull: bool,
) -> Result<Option<RegistryCredentials>> {
    let registry = registry_host(image_ref);
    if registry == "docker.io" || public_pull {
        return Ok(None);
    }

    let username = non_empty_env(GHCR_PULL_USERNAME_VAR);
    let password = non_empty_env(GHCR_PULL_TOKEN_VAR);

    match (username, password) {
        (Some(username), Some(password)) => Ok(Some(RegistryCredentials {
            registry,
            username,
            password,
        })),
        _ => bail!(
            "the miner image is on the private registry `{registry}` but the pull \
             credentials are not set.\n  \
             set {GHCR_PULL_USERNAME_VAR} and {GHCR_PULL_TOKEN_VAR} (a `read:packages` \
             token) so the CVM can authenticate and pull the image"
        ),
    }
}

/// Read an environment variable, returning `None` when it is unset or
/// whitespace-only.
#[must_use]
pub fn non_empty_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
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
    /// Production OS image for the CVM (`phala deploy --image`). Must match
    /// the dstack version of the Phala node the CVM lands on.
    pub os_image: String,
    /// The Phala Cloud API key, applied as `PHALA_CLOUD_API_KEY` on the
    /// `phala` subprocesses only — never the global process environment — so
    /// the secret never leaks to the `git`/`docker` children of the image
    /// build. `None` when the operator authenticates via `phala` CLI login,
    /// which the subprocess inherits anyway.
    pub api_key: Option<String>,
}

impl RealPhalaClient {
    /// Create a client that stages compose/env files in `project_dir`.
    #[must_use]
    pub fn new(
        app_name: impl Into<String>,
        project_dir: std::path::PathBuf,
        instance_type: impl Into<String>,
        disk_size: impl Into<String>,
        os_image: impl Into<String>,
    ) -> Self {
        Self {
            app_name: app_name.into(),
            project_dir,
            instance_type: instance_type.into(),
            disk_size: disk_size.into(),
            os_image: os_image.into(),
            api_key: None,
        }
    }

    /// Set the Phala Cloud API key to scope onto the `phala` subprocesses.
    #[must_use]
    pub fn with_api_key(mut self, api_key: Option<String>) -> Self {
        self.api_key = api_key;
        self
    }
}

/// Build a `phala` command with the API key scoped onto it (via `.env`),
/// never the global process environment — so the secret reaches only the
/// `phala` CLI, not the `git`/`docker` subprocesses of the image build.
fn phala_command(api_key: Option<&str>) -> std::process::Command {
    let mut cmd = std::process::Command::new("phala");
    if let Some(key) = api_key {
        cmd.env("PHALA_CLOUD_API_KEY", key);
    }
    cmd
}

/// The CVM detail document returned by `phala cvms get <cvm-id> --json`.
///
/// Field path is the verified shape of the Phala Cloud CVM-detail schema:
/// the canonical compose hash is the top-level `compose_hash`, the OS
/// image hash is nested under `os.os_image_hash`, and the CVM's public
/// endpoint is `endpoints[0].app`. All three are read here.
#[derive(Debug, Deserialize)]
struct PhalaCvmDetail {
    app_id: Option<String>,
    name: Option<String>,
    compose_hash: Option<String>,
    os: Option<PhalaCvmOs>,
    #[serde(default)]
    endpoints: Vec<PhalaCvmEndpoint>,
}

/// The `os` sub-object of [`PhalaCvmDetail`].
#[derive(Debug, Deserialize)]
struct PhalaCvmOs {
    os_image_hash: Option<String>,
}

/// An entry of the `endpoints` array of [`PhalaCvmDetail`]. `app` is the
/// public URL of the miner's envoy data plane (the `:8080` mapped port).
#[derive(Debug, Deserialize)]
struct PhalaCvmEndpoint {
    app: Option<String>,
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
/// See [`PHALA_COMPOSE_HASH_FIELD`]; the miner endpoint field path.
pub const PHALA_ENDPOINT_FIELD: &str = "endpoints[0].app";
/// See [`PHALA_COMPOSE_HASH_FIELD`]; the Phala Cloud `app_id` field path.
pub const PHALA_APP_ID_FIELD: &str = "app_id";

/// Parse the CVM's Phala Cloud `app_id` out of `phala cvms get <app-id>
/// --json` output.
///
/// `succeeded` is the command's exit status; `stdout` is its raw stdout.
/// Returns `Ok(Some(..))` only when the command succeeded and `app_id` is
/// present and non-empty; `Ok(None)` otherwise.
///
/// # Errors
/// Returns an error if `succeeded` is true but `stdout` is not valid
/// `cvms get --json` JSON.
pub fn parse_phala_cvm_app_id(succeeded: bool, stdout: &[u8]) -> Result<Option<String>> {
    if !succeeded {
        return Ok(None);
    }

    let detail: PhalaCvmDetail =
        serde_json::from_slice(stdout).context("parse phala cvms get --json output")?;

    Ok(detail.app_id.filter(|id| !id.is_empty()))
}

/// Parse the CVM's operator-chosen `name` (the `phala deploy --name` value)
/// out of `phala cvms get <app-id> --json` output.
///
/// `succeeded` is the command's exit status; `stdout` is its raw stdout.
/// Returns `Ok(Some(..))` only when the command succeeded and `name` is
/// present and non-empty; `Ok(None)` otherwise. `register-image` uses this
/// to record the worker under the same `app_name` a later `deploy` would
/// pass, so the records reconcile instead of duplicating.
///
/// # Errors
/// Returns an error if `succeeded` is true but `stdout` is not valid
/// `cvms get --json` JSON.
pub fn parse_phala_cvm_name(succeeded: bool, stdout: &[u8]) -> Result<Option<String>> {
    if !succeeded {
        return Ok(None);
    }

    let detail: PhalaCvmDetail =
        serde_json::from_slice(stdout).context("parse phala cvms get --json output")?;

    Ok(detail.name.filter(|name| !name.is_empty()))
}

/// Parse the miner's public endpoint out of `phala cvms get <app-id>
/// --json` output.
///
/// `succeeded` is the command's exit status; `stdout` is its raw stdout.
/// The endpoint is `endpoints[0].app` — the public URL of the CVM's envoy
/// data plane, e.g. `https://<app-id>-8080.dstack-<node>.phala.network`.
///
/// Returns `Ok(Some(..))` only when the command succeeded and the
/// endpoint is present and non-empty; `Ok(None)` when the command exited
/// non-zero or the endpoint is still absent/empty.
///
/// # Errors
/// Returns an error if `succeeded` is true but `stdout` is not valid
/// `cvms get --json` JSON.
pub fn parse_phala_cvm_endpoint(succeeded: bool, stdout: &[u8]) -> Result<Option<String>> {
    if !succeeded {
        return Ok(None);
    }

    let detail: PhalaCvmDetail =
        serde_json::from_slice(stdout).context("parse phala cvms get --json output")?;

    Ok(detail
        .endpoints
        .into_iter()
        .next()
        .and_then(|e| e.app)
        .filter(|app| !app.is_empty()))
}

/// Rewrite a dstack `:8080` endpoint URL into its TLS-passthrough form.
///
/// `phala cvms get` reports the default port-mapped URL
/// (`https://<app-id>-8080.dstack-<node>.phala.network`), which the
/// dstack gateway serves with **TLS termination at the edge** — the
/// caller sees the gateway's ACME certificate, not the miner's. The
/// miner's RA-TLS data plane needs the dstack **`s`-suffix** form
/// (`https://<app-id>-8080s.dstack-<node>.phala.network`): in that mode
/// the gateway does TLS passthrough, so the TLS connection terminates
/// on the miner's Envoy and the caller receives the dstack-minted
/// RA-TLS certificate carrying the TDX quote. The registered endpoint
/// must be this passthrough URL or the gateway can never verify
/// Mechanism 2.
///
/// The transform appends `s` to the first DNS label, which dstack's
/// ingress scheme (`<id>-<port>[s|g]`) defines as the port suffix. An
/// endpoint already in `s`-suffix form is returned unchanged.
///
/// # Errors
///
/// Returns an error when `endpoint` is not a URL whose host's first
/// label ends in `-<port-digits>` — i.e. not the dstack port-mapped
/// shape this transform understands. Failing here is deliberate: a
/// deploy must not register an endpoint that cannot present the RA-TLS
/// cert.
pub fn to_ratls_passthrough_endpoint(endpoint: &str) -> Result<String> {
    let (scheme, rest) = endpoint
        .split_once("://")
        .with_context(|| format!("endpoint is not an absolute URL: {endpoint}"))?;
    // The authority runs up to the first `/`, `?`, or `#`.
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(authority_end);
    let (first_label, host_rest) = authority.split_once('.').with_context(|| {
        format!("endpoint host has no dotted domain to derive a passthrough URL from: {endpoint}")
    })?;

    // The port suffix is the run of trailing digits after the last `-`.
    let (label_head, port) = first_label.rsplit_once('-').with_context(|| {
        format!("endpoint host label {first_label:?} is not the dstack <id>-<port> shape")
    })?;
    if let Some(port_digits) = port.strip_suffix('s') {
        // Already a passthrough URL — leave it untouched, but only if
        // what precedes the `s` really is the port.
        if !port_digits.is_empty() && port_digits.chars().all(|c| c.is_ascii_digit()) {
            return Ok(endpoint.to_owned());
        }
    }
    if port.is_empty() || !port.chars().all(|c| c.is_ascii_digit()) {
        anyhow::bail!(
            "endpoint host label {first_label:?} does not end in a numeric port; \
             cannot derive the dstack TLS-passthrough form of {endpoint}"
        );
    }
    Ok(format!("{scheme}://{label_head}-{port}s.{host_rest}{tail}"))
}

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

/// Inputs for [`build_phala_deploy_args`], grouped so the call site does
/// not need a long positional list.
#[derive(Debug, Clone, Copy)]
pub struct PhalaDeployArgs<'a> {
    /// CVM name (`--name`).
    pub app_name: &'a str,
    /// Instance type (`--instance-type`).
    pub instance_type: &'a str,
    /// Disk size (`--disk-size`).
    pub disk_size: &'a str,
    /// Production OS image (`--image`).
    pub os_image: &'a str,
    /// Rendered compose file path (`--compose`).
    pub compose_path: &'a str,
    /// Env file path (`--env`).
    pub env_path: &'a str,
    /// Pre-launch script path (`--pre-launch-script`).
    pub prelaunch_path: &'a str,
}

/// Build the argument list for `phala deploy`.
///
/// `phala deploy` submits a Docker Compose stack to Phala Cloud, which
/// provisions the `TEEPod`, runs the KMS, encrypts the env file client-side
/// to the CVM key, and assigns the `app_id`. The flags pin the CVM name,
/// instance type, disk size, compose file, env file, and the corrected
/// pre-launch script, request a production OS image (`--image` plus
/// `--no-dev-os` — never a `dstack-dev-*` image for an attested miner),
/// and request JSON output plus `--wait` so the call returns only once the
/// CVM is up. The deployed CVM's identity is *not* scraped from
/// `phala deploy`'s stdout (its success output mixes a human-readable
/// `Provisioning CVM ...` line with the JSON); it is resolved afterwards
/// via `phala cvms get <name>`, keyed on the `--name` set here.
///
/// Extracted from [`RealPhalaClient::deploy`] so the wiring can be asserted
/// without spawning a subprocess.
#[must_use]
pub fn build_phala_deploy_args(args: &PhalaDeployArgs<'_>) -> Vec<String> {
    vec![
        "deploy".to_owned(),
        "--name".to_owned(),
        args.app_name.to_owned(),
        "--instance-type".to_owned(),
        args.instance_type.to_owned(),
        "--disk-size".to_owned(),
        args.disk_size.to_owned(),
        "--image".to_owned(),
        args.os_image.to_owned(),
        "--no-dev-os".to_owned(),
        "--compose".to_owned(),
        args.compose_path.to_owned(),
        "--env".to_owned(),
        args.env_path.to_owned(),
        "--pre-launch-script".to_owned(),
        args.prelaunch_path.to_owned(),
        "--wait".to_owned(),
        "--json".to_owned(),
    ]
}

/// Run `phala cvms get <cvm-id> --json` once and parse the full deploy
/// outcome — measured `compose_hash` + `os.os_image_hash` + the public
/// endpoint — from the single CVM-detail document.
///
/// `cvm_id` is any identifier `phala cvms get` accepts: an `app_id`, a
/// UUID, or the CVM *name*. `gmcli deploy` passes the name it set with
/// `phala deploy --name`.
///
/// Returns `Ok(None)` when the command exited non-zero (the CVM is not
/// ready) or when either hash or the endpoint is still absent/empty.
///
/// # Errors
/// Returns an error only if `phala` cannot be spawned, or it exits
/// successfully but emits output that is not valid `cvms get --json` JSON.
fn read_phala_cvm_outcome(cvm_id: &str, api_key: Option<&str>) -> Result<Option<DeployOutcome>> {
    let out = phala_command(api_key)
        .args(["cvms", "get", cvm_id, "--json"])
        .output()
        .context("run phala cvms get — is the phala CLI installed? (npm i -g phala)")?;

    if !out.status.success() {
        tracing::info!(
            stderr = %String::from_utf8_lossy(&out.stderr).trim(),
            "phala cvms get --json not ready yet (non-zero exit)"
        );
    }

    let succeeded = out.status.success();
    let Some(hashes) = parse_phala_cvm_detail(succeeded, &out.stdout)? else {
        return Ok(None);
    };
    let Some(endpoint) = parse_phala_cvm_endpoint(succeeded, &out.stdout)? else {
        return Ok(None);
    };
    let Some(app_id) = parse_phala_cvm_app_id(succeeded, &out.stdout)? else {
        return Ok(None);
    };
    // Register the TLS-passthrough form: the miner's RA-TLS cert is only
    // presented to callers on the dstack `s`-suffix URL (see
    // `to_ratls_passthrough_endpoint`).
    let endpoint = to_ratls_passthrough_endpoint(&endpoint)?;
    Ok(Some(DeployOutcome {
        hashes,
        endpoint,
        app_id,
    }))
}

impl PhalaClient for RealPhalaClient {
    fn deploy(
        &self,
        compose_yaml: &str,
        env_vars: &ProviderKeys,
        node_secret: &str,
        registry_creds: Option<&RegistryCredentials>,
        boot_timeout_secs: u64,
    ) -> Result<DeployOutcome> {
        use std::fs;

        fs::create_dir_all(&self.project_dir)
            .with_context(|| format!("create project dir {}", self.project_dir.display()))?;

        // Write the rendered compose file.
        let compose_path = self.project_dir.join("docker-compose.yaml");
        fs::write(&compose_path, compose_yaml)
            .with_context(|| format!("write {}", compose_path.display()))?;

        // Write the corrected, digest-aware pre-launch script. Phala
        // Cloud's auto-injected v0.0.14 script mis-parses digest-pinned
        // image refs; this bundled copy fixes that.
        let prelaunch_path = self.project_dir.join("prelaunch.sh");
        fs::write(&prelaunch_path, PRELAUNCH_SCRIPT)
            .with_context(|| format!("write {}", prelaunch_path.display()))?;

        // Write the env file at mode 0600 so the secrets are never visible
        // with broader permissions. `phala deploy` reads this file and
        // encrypts its contents client-side to the CVM key.
        let env_path = self.project_dir.join(".env");
        write_env_file(&env_path, env_vars, node_secret, registry_creds)?;

        let compose_arg = compose_path.to_string_lossy().into_owned();
        let env_arg = env_path.to_string_lossy().into_owned();
        let prelaunch_arg = prelaunch_path.to_string_lossy().into_owned();
        let args = build_phala_deploy_args(&PhalaDeployArgs {
            app_name: &self.app_name,
            instance_type: &self.instance_type,
            disk_size: &self.disk_size,
            os_image: &self.os_image,
            compose_path: &compose_arg,
            env_path: &env_arg,
            prelaunch_path: &prelaunch_arg,
        });

        let out = phala_command(self.api_key.as_deref())
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

        // `phala deploy --json` succeeded. Its success-path stdout is not
        // a clean JSON object (see `build_phala_deploy_args`), so the
        // deployed CVM is resolved by name via the poll loop below rather
        // than by scraping this output.
        println!(
            "phala deploy succeeded for CVM {}; waiting for the CVM to report hashes ...",
            self.app_name
        );

        poll_phala_cvm_outcome(&self.app_name, self.api_key.as_deref(), boot_timeout_secs)
    }
}

/// Poll `phala cvms get <cvm-id> --json` every [`POLL_INTERVAL_SECS`]
/// seconds until the measured hashes and the public endpoint are all
/// non-empty, or until `timeout_secs` elapses.
///
/// `cvm_id` is any identifier `phala cvms get` accepts — `gmcli deploy`
/// passes the CVM name it set with `phala deploy --name`.
///
/// # Errors
/// Returns an error if `phala` cannot be spawned, emits unparseable JSON,
/// or the outcome never appears before `timeout_secs` elapses.
fn poll_phala_cvm_outcome(
    cvm_id: &str,
    api_key: Option<&str>,
    timeout_secs: u64,
) -> Result<DeployOutcome> {
    use std::time::{Duration, Instant};

    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let poll = Duration::from_secs(POLL_INTERVAL_SECS);
    let mut attempt: u32 = 0;

    loop {
        attempt += 1;
        if let Some(outcome) = read_phala_cvm_outcome(cvm_id, api_key)? {
            return Ok(outcome);
        }

        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            bail!(
                "timed out after {timeout_secs}s waiting for the CVM to report \
                 its hashes and endpoint (compose_hash/os_image_hash/endpoint \
                 never appeared in `phala cvms get {cvm_id} --json`); \
                 increase --boot-timeout-secs or check the Phala Cloud dashboard"
            );
        }

        let sleep = remaining.min(poll);
        tracing::debug!(attempt, ?sleep, "deploy outcome not yet available; waiting");
        std::thread::sleep(sleep);
    }
}

/// Render the `phala deploy` env file body from the provider keys, node
/// secret, and (optional) private-registry pull credentials.
///
/// Extracted as a pure function so the exact env-file contents can be
/// asserted in tests without touching the filesystem.
#[must_use]
pub fn render_env_file(
    env_vars: &ProviderKeys,
    node_secret: &str,
    registry_creds: Option<&RegistryCredentials>,
) -> String {
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

    // Private-registry pull credentials, consumed by the CVM's pre-launch
    // script (`docker login` before pulling the private miner image).
    if let Some(creds) = registry_creds {
        lines.push_str("DSTACK_DOCKER_REGISTRY=");
        lines.push_str(&creds.registry);
        lines.push('\n');
        lines.push_str("DSTACK_DOCKER_USERNAME=");
        lines.push_str(&creds.username);
        lines.push('\n');
        lines.push_str("DSTACK_DOCKER_PASSWORD=");
        lines.push_str(&creds.password);
        lines.push('\n');
    }

    lines
}

/// Write the provider keys + node secret + registry credentials to
/// `env_path` at mode 0600.
///
/// Uses a temp-file-then-rename so the target file is always at mode 0600
/// from the moment it exists — no window where a partially-written or
/// broader-permission file is present on disk.
fn write_env_file(
    env_path: &std::path::Path,
    env_vars: &ProviderKeys,
    node_secret: &str,
    registry_creds: Option<&RegistryCredentials>,
) -> Result<()> {
    use std::fs;
    use std::io::Write as _;
    #[cfg(unix)]
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

    let lines = render_env_file(env_vars, node_secret, registry_creds);

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
    // A one-shot client (30 s timeout, gmcli user-agent) — same shape as
    // RegistryClient — rather than bare `reqwest::get()` which has no timeout.
    let client = crate::client::build_http_client()?;

    let url = format!("{registry_url}/image-versions?status=supported");
    let resp = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;

    let http_status = resp.status();
    if http_status == reqwest::StatusCode::NOT_FOUND {
        bail!(
            "registry returned 404 for /image-versions — your gmcli build is newer than \
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

// ── Default image-ref resolution ──────────────────────────────────────────────

/// How `gmcli deploy` resolves the miner image to deploy, in priority order.
///
/// A normal miner deploys the gm-published, registry-supported image — they
/// never build. The two non-default arms exist only as explicit opt-ins:
/// `--image-ref` pins a specific pre-built digest, and `--image-repo` requests
/// a local build+push (the legacy path).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageSource {
    /// Use this digest-pinned ref verbatim — no build.
    Prebuilt {
        /// The digest-pinned ref to embed in the compose file.
        image_ref: String,
        /// True when this is the registry-supported, gm-published image (the
        /// flag-less default). That image is published for public pull, so a
        /// deploy of it must not demand operator GHCR pull credentials. False
        /// for an operator's own `--image-ref`, which may be on a private repo.
        gm_published: bool,
    },
    /// Build the miner image locally and push it to this public repo, then
    /// pin the pushed digest. Requested explicitly via `--image-repo`.
    Build,
}

/// Resolve which image a deploy should use from the operator's flags and the
/// registry-selected supported version.
///
/// Precedence:
///   1. `--image-ref` (explicit pre-built digest) — always wins.
///   2. `--image-repo` (explicit local build opt-in) — build + push.
///   3. The registry-supported version's `image_ref` — the default, so a
///      normal miner deploys the gm-published image without building.
///
/// # Errors
/// Returns an error when neither flag is set and the supported version carries
/// no `image_ref` — there is then no image to deploy, and the message points
/// at `--image-ref` / `--image-repo`.
pub fn resolve_image_source(
    image_ref_flag: Option<&str>,
    image_repo_flag: Option<&str>,
    supported_image_ref: Option<&str>,
) -> Result<ImageSource> {
    if let Some(explicit) = image_ref_flag {
        return Ok(ImageSource::Prebuilt {
            image_ref: explicit.to_owned(),
            gm_published: false,
        });
    }
    if image_repo_flag.is_some() {
        return Ok(ImageSource::Build);
    }
    if let Some(supported) = supported_image_ref {
        return Ok(ImageSource::Prebuilt {
            image_ref: supported.to_owned(),
            gm_published: true,
        });
    }
    bail!(
        "the registry's supported image version has no pullable image_ref, so \
         there is no gm-published image to deploy by default.\n  \
         pass --image-ref <registry/repo@sha256:...> to deploy a specific \
         pre-built image, or --image-repo <registry/owner/gm-miner> to build \
         and push one yourself"
    )
}

// ── Compose template rendering ────────────────────────────────────────────────

/// Placeholder substituted with the active network name (`testnet` /
/// `mainnet`) at compose render time. A literal in the rendered compose,
/// so its value is part of the attestation-measured `compose_hash`.
const GM_NETWORK_PLACEHOLDER: &str = "__GM_NETWORK__";

/// Render the compose template, substituting `${GM_IMAGE_REF...}` with
/// the supplied pinned image reference and `__GM_NETWORK__` with the
/// active network name.
///
/// # Errors
/// Returns an error if either placeholder is missing.
pub fn render_compose(template: &str, pinned_image_ref: &str, network: &str) -> Result<String> {
    // Replace the shell-variable placeholder pattern ${GM_IMAGE_REF...}
    // with the digest-pinned ref. We do a simple prefix match: anything
    // that starts with `${GM_IMAGE_REF` and ends at the next `}`.
    let with_image = replace_image_ref_placeholder(template, pinned_image_ref);
    if with_image == template {
        bail!(
            "compose template does not contain a GM_IMAGE_REF placeholder; \
             expected something like ${{GM_IMAGE_REF:?...}} in dstack/docker-compose.yaml"
        );
    }
    if !with_image.contains(GM_NETWORK_PLACEHOLDER) {
        bail!(
            "compose template does not contain a {GM_NETWORK_PLACEHOLDER} placeholder; \
             expected GM_NETWORK={GM_NETWORK_PLACEHOLDER} in dstack/docker-compose.yaml"
        );
    }
    Ok(with_image.replace(GM_NETWORK_PLACEHOLDER, network))
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
/// `phala` is the runtime dependency of `gmcli deploy`: it submits the
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
            "the `phala` CLI is required for `gmcli deploy` but was not found on PATH.\n  \
             install it with: npm i -g phala"
        );
    }
    Ok(())
}

// ── Bundled compose template ──────────────────────────────────────────────────

/// The compose template, bundled at compile time from
/// `dstack/docker-compose.yaml` relative to the workspace root.
pub const COMPOSE_TEMPLATE: &str = include_str!("../../dstack/docker-compose.yaml");

/// The corrected Phala Cloud pre-launch script, bundled at compile time
/// from `dstack/prelaunch.sh`.
///
/// Phala Cloud auto-injects a pre-launch script (v0.0.14) whose GHCR
/// pull-verification block mis-parses digest-pinned image refs and aborts
/// the boot with a 404. `gmcli deploy` always pins images by digest, so
/// it always passes this corrected, digest-aware script via
/// `phala deploy --pre-launch-script`.
pub const PRELAUNCH_SCRIPT: &str = include_str!("../../dstack/prelaunch.sh");

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_ref: Option<String>,
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
            image_ref: None,
        }
    }

    // ── default image-ref resolution ──────────────────────────────────────────

    /// With no flags, the registry-supported version's `image_ref` is the
    /// default — a normal miner deploys the gm-published image, never building.
    #[test]
    fn resolve_image_source_defaults_to_supported_ref() {
        let source = resolve_image_source(None, None, Some("ghcr.io/taostat/gm-miner@sha256:abc"))
            .expect("supported ref must resolve");
        assert_eq!(
            source,
            ImageSource::Prebuilt {
                image_ref: "ghcr.io/taostat/gm-miner@sha256:abc".to_owned(),
                gm_published: true,
            },
            "the supported default is marked gm_published (public pull)"
        );
    }

    /// `--image-ref` wins over both the supported default and `--image-repo`.
    #[test]
    fn resolve_image_source_image_ref_flag_overrides() {
        let source = resolve_image_source(
            Some("ghcr.io/me/gm-miner@sha256:def"),
            Some("ghcr.io/me/gm-miner"),
            Some("ghcr.io/taostat/gm-miner@sha256:abc"),
        )
        .expect("explicit ref must resolve");
        assert_eq!(
            source,
            ImageSource::Prebuilt {
                image_ref: "ghcr.io/me/gm-miner@sha256:def".to_owned(),
                gm_published: false,
            },
            "an explicit --image-ref is not the gm-published default"
        );
    }

    /// `--image-repo` (without `--image-ref`) opts into a local build even when
    /// a supported ref exists.
    #[test]
    fn resolve_image_source_image_repo_opts_into_build() {
        let source = resolve_image_source(
            None,
            Some("ghcr.io/me/gm-miner"),
            Some("ghcr.io/taostat/gm-miner@sha256:abc"),
        )
        .expect("build opt-in must resolve");
        assert_eq!(source, ImageSource::Build);
    }

    /// No flags and no supported `image_ref` is an error — there is nothing to
    /// deploy — and the message points at both escape hatches.
    #[test]
    fn resolve_image_source_errors_when_no_ref_available() {
        let err = resolve_image_source(None, None, None)
            .expect_err("missing image must abort the default path");
        let msg = err.to_string();
        assert!(msg.contains("--image-ref"), "got: {msg}");
        assert!(msg.contains("--image-repo"), "got: {msg}");
    }

    #[test]
    fn placeholder_replaced_once() {
        let template = "image: ${GM_IMAGE_REF:?GM_IMAGE_REF must be set}\n  \
                        env: GM_NETWORK=__GM_NETWORK__\n  ports:\n";
        let rendered = render_compose(template, "ghcr.io/o/app@sha256:abc123", "testnet")
            .expect("should render");
        assert!(rendered.contains("ghcr.io/o/app@sha256:abc123"));
        assert!(!rendered.contains("GM_IMAGE_REF"));
    }

    #[test]
    fn placeholder_missing_returns_error() {
        let template = "image: my-image\n";
        assert!(render_compose(template, "anything", "testnet").is_err());
    }

    /// The active network must appear as a rendered literal so it is
    /// part of the attestation-measured `compose_hash`.
    #[test]
    fn network_placeholder_replaced() {
        let template = "image: ${GM_IMAGE_REF:?}\n  env:\n    - GM_NETWORK=__GM_NETWORK__\n";
        let rendered =
            render_compose(template, "anything", "testnet").expect("should render testnet");
        assert!(rendered.contains("GM_NETWORK=testnet"));
        assert!(!rendered.contains("__GM_NETWORK__"));

        let rendered =
            render_compose(template, "anything", "mainnet").expect("should render mainnet");
        assert!(rendered.contains("GM_NETWORK=mainnet"));
    }

    /// A template missing the network placeholder is a compose-file bug —
    /// surface it as a clear error rather than silently rendering an
    /// image without the network selector.
    #[test]
    fn network_placeholder_missing_returns_error() {
        let template = "image: ${GM_IMAGE_REF:?}\n";
        assert!(render_compose(template, "anything", "testnet").is_err());
    }

    /// The bundled compose template must carry both placeholders so a
    /// real deploy renders correctly.
    #[test]
    fn bundled_compose_template_renders() {
        let rendered = render_compose(COMPOSE_TEMPLATE, "ghcr.io/o/m@sha256:deadbeef", "testnet")
            .expect("bundled compose template must render");
        assert!(rendered.contains("ghcr.io/o/m@sha256:deadbeef"));
        assert!(rendered.contains("GM_NETWORK=testnet"));
        assert!(!rendered.contains("__GM_NETWORK__"));
        assert!(
            !rendered.contains("GM_BENCHMARK_UPSTREAM_URL"),
            "GM_BENCHMARK_UPSTREAM_URL must no longer appear in the compose"
        );
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

    // ── phala API-key scoping ─────────────────────────────────────────────────

    /// The key must be scoped onto the `phala` subprocess via `.env` (so it
    /// never leaks to the `git`/`docker` children of the image build), and
    /// omitted entirely when there is none (CLI-session auth).
    #[test]
    fn phala_command_scopes_the_api_key_onto_the_subprocess() {
        let cmd = phala_command(Some("secret-key"));
        let scoped: Vec<_> = cmd
            .get_envs()
            .filter(|(k, _)| *k == std::ffi::OsStr::new("PHALA_CLOUD_API_KEY"))
            .collect();
        assert_eq!(scoped.len(), 1, "the key must be set on the command env");
        assert_eq!(
            scoped[0].1,
            Some(std::ffi::OsStr::new("secret-key")),
            "the scoped value must be the resolved key"
        );

        let no_key = phala_command(None);
        assert!(
            no_key
                .get_envs()
                .all(|(k, _)| k != std::ffi::OsStr::new("PHALA_CLOUD_API_KEY")),
            "no key means nothing is added to the command env"
        );
    }

    /// `with_api_key` records the key the client scopes onto its subprocesses.
    #[test]
    fn with_api_key_sets_the_field() {
        let client = RealPhalaClient::new("gm-miner-1", "/tmp/d".into(), "t", "40G", "os")
            .with_api_key(Some("k".to_owned()));
        assert_eq!(client.api_key.as_deref(), Some("k"));
    }

    // ── phala deploy argument wiring ──────────────────────────────────────────

    fn deploy_args() -> PhalaDeployArgs<'static> {
        PhalaDeployArgs {
            app_name: "gm-miner-1",
            instance_type: "tdx.medium",
            disk_size: "40G",
            os_image: "dstack-0.5.7",
            compose_path: "/tmp/dist/docker-compose.yaml",
            env_path: "/tmp/dist/.env",
            prelaunch_path: "/tmp/dist/prelaunch.sh",
        }
    }

    /// `phala deploy` must be invoked with the compose file, env file,
    /// pre-launch script, instance type, disk size, OS image, `--wait`, and
    /// `--json` — the env file is what carries the (client-side-encrypted)
    /// provider keys, `--wait` blocks until the CVM is up, and `--json`
    /// keeps the deploy's diagnostics machine-readable.
    #[test]
    fn build_phala_deploy_args_wires_every_flag() {
        let args = build_phala_deploy_args(&deploy_args());
        assert_eq!(args[0], "deploy");
        let pairs = [
            ("--name", "gm-miner-1"),
            ("--instance-type", "tdx.medium"),
            ("--disk-size", "40G"),
            ("--image", "dstack-0.5.7"),
            ("--compose", "/tmp/dist/docker-compose.yaml"),
            ("--env", "/tmp/dist/.env"),
            ("--pre-launch-script", "/tmp/dist/prelaunch.sh"),
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

    /// An attested miner must never boot a dev OS image: `phala deploy`
    /// must always carry `--no-dev-os`.
    #[test]
    fn build_phala_deploy_args_always_requests_production_os() {
        let args = build_phala_deploy_args(&deploy_args());
        assert!(
            args.iter().any(|a| a == "--no-dev-os"),
            "missing --no-dev-os in {args:?}"
        );
    }

    // ── registry-host derivation ──────────────────────────────────────────────

    #[test]
    fn registry_host_extracts_ghcr() {
        assert_eq!(
            registry_host("ghcr.io/taostat/gm-miner@sha256:abc"),
            "ghcr.io"
        );
    }

    #[test]
    fn registry_host_extracts_host_with_port() {
        assert_eq!(
            registry_host("localhost:5000/gm-miner@sha256:abc"),
            "localhost:5000"
        );
    }

    /// A ref with no host-looking first component is Docker Hub.
    #[test]
    fn registry_host_defaults_to_docker_hub() {
        assert_eq!(registry_host("library/alpine:3"), "docker.io");
        assert_eq!(registry_host("alpine"), "docker.io");
    }

    // ── private-registry credential resolution ────────────────────────────────

    /// `resolve_registry_credentials` treats Docker Hub as public — no
    /// credentials are required or returned.
    #[test]
    fn resolve_registry_credentials_skips_docker_hub() {
        let creds = resolve_registry_credentials("library/alpine:3", false)
            .expect("docker hub must not require creds");
        assert!(creds.is_none(), "docker hub is public — no creds");
    }

    /// The gm-published default image (`public_pull = true`) must not require
    /// operator GHCR pull credentials even on a private-looking host.
    #[test]
    fn resolve_registry_credentials_skips_public_pull_default() {
        let creds = resolve_registry_credentials("ghcr.io/taostat/gm-miner@sha256:abc", true)
            .expect("the gm-published default must not require creds");
        assert!(
            creds.is_none(),
            "public_pull must skip the private-registry credential requirement"
        );
    }

    /// A private (non-default) GHCR image with `public_pull = false` and no
    /// credential env vars must fail with an actionable error.
    #[test]
    fn resolve_registry_credentials_requires_creds_for_private_ref() {
        // Ensure the env vars are unset for this assertion.
        std::env::remove_var(GHCR_PULL_USERNAME_VAR);
        std::env::remove_var(GHCR_PULL_TOKEN_VAR);
        let err = resolve_registry_credentials("ghcr.io/me/private-miner@sha256:abc", false)
            .expect_err("a private image without creds must fail");
        assert!(
            err.to_string().contains("pull credentials are not set"),
            "got: {err}"
        );
    }

    // ── env-file rendering ────────────────────────────────────────────────────

    #[test]
    fn render_env_file_writes_node_secret_and_keys() {
        let keys = ProviderKeys {
            anthropic: Some("sk-ant".to_owned()),
            openai: None,
            google: None,
        };
        let body = render_env_file(&keys, "node-secret-xyz", None);
        assert!(body.contains("ANTHROPIC_API_KEY=sk-ant\n"));
        assert!(body.contains("GM_NODE_SECRET=node-secret-xyz\n"));
        assert!(
            !body.contains("DSTACK_DOCKER_"),
            "no registry creds must be written when none are supplied"
        );
        assert!(
            !body.contains("GM_BENCHMARK_UPSTREAM_URL"),
            "GM_BENCHMARK_UPSTREAM_URL must no longer be written to the env file"
        );
    }

    /// When private-registry credentials are supplied, all three
    /// `DSTACK_DOCKER_*` variables the pre-launch script needs must appear.
    #[test]
    fn render_env_file_writes_registry_credentials() {
        let keys = ProviderKeys::default();
        let creds = RegistryCredentials {
            registry: "ghcr.io".to_owned(),
            username: "miner-bot".to_owned(),
            password: "ghp_token".to_owned(),
        };
        let body = render_env_file(&keys, "node-secret", Some(&creds));
        assert!(body.contains("DSTACK_DOCKER_REGISTRY=ghcr.io\n"));
        assert!(body.contains("DSTACK_DOCKER_USERNAME=miner-bot\n"));
        assert!(body.contains("DSTACK_DOCKER_PASSWORD=ghp_token\n"));
    }

    // ── phala cvms get endpoint parsing ───────────────────────────────────────

    /// The miner endpoint is `endpoints[0].app` in the CVM-detail document.
    #[test]
    fn parse_phala_cvm_endpoint_reads_first_app_url() {
        let stdout = br#"{
            "app_id":"app_abc",
            "endpoints":[
                {"app":"https://app_abc-8080.dstack-prod5.phala.network"},
                {"app":"https://other"}
            ]
        }"#;
        let endpoint = parse_phala_cvm_endpoint(true, stdout)
            .expect("must parse")
            .expect("endpoint present");
        assert_eq!(endpoint, "https://app_abc-8080.dstack-prod5.phala.network");
    }

    #[test]
    fn parse_phala_cvm_endpoint_non_zero_exit_is_none() {
        let endpoint =
            parse_phala_cvm_endpoint(false, b"garbage").expect("non-zero exit must not error");
        assert!(endpoint.is_none());
    }

    #[test]
    fn ratls_passthrough_appends_s_after_the_port() {
        let got = to_ratls_passthrough_endpoint("https://app_abc-8080.dstack-prod5.phala.network")
            .expect("port-mapped URL transforms");
        assert_eq!(got, "https://app_abc-8080s.dstack-prod5.phala.network");
    }

    #[test]
    fn ratls_passthrough_preserves_path_and_query() {
        let got = to_ratls_passthrough_endpoint(
            "https://app_abc-8080.dstack-prod5.phala.network/attestation/info?nonce=x",
        )
        .expect("URL with path transforms");
        assert_eq!(
            got,
            "https://app_abc-8080s.dstack-prod5.phala.network/attestation/info?nonce=x"
        );
    }

    #[test]
    fn ratls_passthrough_is_idempotent_on_s_suffix_urls() {
        let already = "https://app_abc-8080s.dstack-prod5.phala.network";
        assert_eq!(
            to_ratls_passthrough_endpoint(already).expect("s-suffix URL is left as-is"),
            already
        );
    }

    #[test]
    fn ratls_passthrough_rejects_non_port_mapped_host() {
        // A plain `<app-id>.dstack...` host (default port 80/443) has no
        // `-<port>` label, so no passthrough form can be derived.
        assert!(
            to_ratls_passthrough_endpoint("https://app_abc.dstack-prod5.phala.network").is_err()
        );
    }

    #[test]
    fn ratls_passthrough_rejects_non_numeric_port_label() {
        assert!(
            to_ratls_passthrough_endpoint("https://app_abc-envoy.dstack-prod5.phala.network")
                .is_err()
        );
    }

    #[test]
    fn ratls_passthrough_rejects_non_url() {
        assert!(to_ratls_passthrough_endpoint("app_abc-8080.dstack-prod5.phala.network").is_err());
    }

    #[test]
    fn parse_phala_cvm_endpoint_missing_endpoints_is_none() {
        let stdout = br#"{"app_id":"app_abc","status":"starting"}"#;
        let endpoint = parse_phala_cvm_endpoint(true, stdout).expect("must parse");
        assert!(endpoint.is_none(), "absent endpoints must yield None");
    }

    #[test]
    fn parse_phala_cvm_endpoint_empty_app_is_none() {
        let stdout = br#"{"endpoints":[{"app":""}]}"#;
        let endpoint = parse_phala_cvm_endpoint(true, stdout).expect("must parse");
        assert!(endpoint.is_none(), "empty endpoint must yield None");
    }

    #[test]
    fn parse_phala_cvm_endpoint_invalid_json_errors() {
        assert!(parse_phala_cvm_endpoint(true, b"not json").is_err());
    }

    // ── phala cvms get app_id parsing ─────────────────────────────────────────

    #[test]
    fn parse_phala_cvm_app_id_reads_top_level_field() {
        let stdout = br#"{"app_id":"app_abc","compose_hash":"sha256:aaa"}"#;
        let app_id = parse_phala_cvm_app_id(true, stdout)
            .expect("must parse")
            .expect("app_id present");
        assert_eq!(app_id, "app_abc");
    }

    #[test]
    fn parse_phala_cvm_app_id_non_zero_exit_is_none() {
        let app_id =
            parse_phala_cvm_app_id(false, b"garbage").expect("non-zero exit must not error");
        assert!(app_id.is_none());
    }

    #[test]
    fn parse_phala_cvm_app_id_missing_is_none() {
        let stdout = br#"{"compose_hash":"sha256:aaa"}"#;
        let app_id = parse_phala_cvm_app_id(true, stdout).expect("must parse");
        assert!(app_id.is_none(), "absent app_id must yield None");
    }

    #[test]
    fn parse_phala_cvm_app_id_empty_is_none() {
        let stdout = br#"{"app_id":""}"#;
        let app_id = parse_phala_cvm_app_id(true, stdout).expect("must parse");
        assert!(app_id.is_none(), "empty app_id must yield None");
    }

    #[test]
    fn parse_phala_cvm_name_reads_top_level_field() {
        let stdout = br#"{"app_id":"app_abc","name":"gm-miner-1"}"#;
        let name = parse_phala_cvm_name(true, stdout)
            .expect("must parse")
            .expect("name present");
        assert_eq!(name, "gm-miner-1");
    }

    #[test]
    fn parse_phala_cvm_name_missing_or_empty_is_none() {
        assert!(parse_phala_cvm_name(true, br#"{"app_id":"app_abc"}"#)
            .expect("must parse")
            .is_none());
        assert!(parse_phala_cvm_name(true, br#"{"name":""}"#)
            .expect("must parse")
            .is_none());
    }

    #[test]
    fn parse_phala_cvm_name_non_zero_exit_is_none() {
        let name = parse_phala_cvm_name(false, b"garbage").expect("non-zero exit must not error");
        assert!(name.is_none());
    }

    // ── phala cvms get detail parsing ─────────────────────────────────────────

    /// Regression: the deployed CVM's identity is resolved via
    /// `phala cvms get --json`, never by scraping `phala deploy`'s stdout.
    ///
    /// `phala deploy --json` mixes a human-readable `Provisioning CVM
    /// <name>...` line into its success-path stdout before the JSON
    /// object, so a whole-buffer `serde_json` parse fails at line 1.
    /// `phala cvms get <name> --json` instead emits a single object: the
    /// CVM detail spread under a top-level `success: true` wrapper (the
    /// `phala` CLI's `context.success` shape). The CVM-detail parser must
    /// read `compose_hash` / `os.os_image_hash` / `endpoints[0].app`
    /// straight out of that wrapped object, tolerating the extra
    /// `success` field.
    #[test]
    fn cvm_outcome_parses_from_cvms_get_success_envelope() {
        let stdout = br#"{
            "success":true,
            "app_id":"app_abc",
            "name":"gm-miner-1",
            "compose_hash":"sha256:aaa",
            "os":{"name":"dstack-0.5.7","os_image_hash":"sha256:bbb"},
            "endpoints":[
                {"app":"https://app_abc-8080.dstack-prod5.phala.network"}
            ]
        }"#;
        let hashes = parse_phala_cvm_detail(true, stdout)
            .expect("cvms get success envelope must parse")
            .expect("both hashes present");
        assert_eq!(hashes.compose_sha256, "sha256:aaa");
        assert_eq!(hashes.os_image_hash, "sha256:bbb");

        let endpoint = parse_phala_cvm_endpoint(true, stdout)
            .expect("cvms get success envelope must parse")
            .expect("endpoint present");
        assert_eq!(endpoint, "https://app_abc-8080.dstack-prod5.phala.network");
    }

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
        assert_eq!(PHALA_ENDPOINT_FIELD, "endpoints[0].app");
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
        let target =
            prepare_deploy_target(&StubProvisioner, "testnet").expect("orchestration must succeed");
        assert_eq!(target.image_ref, "ghcr.io/taostat/gm-miner@sha256:deadbeef");
        assert!(
            target.rendered_compose.contains("sha256:deadbeef"),
            "the provisioner's ref must be pinned into the compose file"
        );
        assert!(
            !target.rendered_compose.contains("${GM_IMAGE_REF"),
            "the ${{GM_IMAGE_REF}} placeholder must be substituted"
        );
        assert!(
            target.rendered_compose.contains("GM_NETWORK=testnet"),
            "the active network must be substituted into the compose"
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
        let err = prepare_deploy_target(&FailingProvisioner, "testnet")
            .expect_err("build failure must abort");
        assert!(err.to_string().contains("image build+push failed"));
    }
}
