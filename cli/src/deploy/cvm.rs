//! Phala Cloud CVM orchestration: `phala deploy` + `phala cvms get` wiring.

use anyhow::{bail, Context, Result};
use serde::Deserialize;

use crate::config::ProviderKeys;
use crate::deploy::compose::{write_env_file, PRELAUNCH_SCRIPT};
use crate::deploy::hashes::{DeployOutcome, DstackDeployResult};
use crate::deploy::registry_auth::RegistryCredentials;

/// Default poll interval when waiting for the CVM to boot (seconds).
pub const POLL_INTERVAL_SECS: u64 = 5;

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

    /// The Phala Cloud `app_id` of a CVM already deployed under this client's
    /// `--name`, or `None` when the workspace has no such CVM.
    ///
    /// `phala deploy` refuses to reuse a CVM name ("A CVM with name '<name>'
    /// already exists in this workspace"), so `deploy` / `worker add` probe
    /// this *before* the image build and stop with the exact teardown command
    /// rather than failing minutes later inside `phala deploy`.
    ///
    /// # Errors
    /// Returns an error if `phala` cannot be spawned, or it exits successfully
    /// but emits output that is not valid `cvms get --json` JSON.
    fn existing_cvm_app_id(&self) -> Result<Option<String>>;
}

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
#[must_use]
pub fn phala_command(api_key: Option<&str>) -> std::process::Command {
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

/// The name lookup result and pagination metadata from one successful list
/// response. The metadata is required by the collision preflight: without it,
/// an empty first page cannot prove that no later page contains the name.
#[derive(Debug, PartialEq, Eq)]
struct PhalaCvmListPage {
    page: usize,
    total_pages: usize,
    app_id: Option<String>,
}

/// Parse one complete, paginated `phala cvms list --json` response.
fn parse_phala_cvm_list_page(stdout: &[u8], app_name: &str) -> Result<PhalaCvmListPage> {
    let listed: PhalaCvmList =
        serde_json::from_slice(stdout).context("parse phala cvms list --json output")?;
    if listed.success == Some(false) {
        bail!("phala cvms list --json reported failure");
    }
    let page = listed
        .page
        .context("phala cvms list --json output is missing `page`")?;
    let total_pages = listed
        .total_pages
        .context("phala cvms list --json output is missing `totalPages`")?;
    let items = listed
        .items
        .context("phala cvms list --json output is missing `items`")?;
    if page == 0
        || (total_pages > 0 && page > total_pages)
        || (total_pages == 0 && (page != 1 || !items.is_empty()))
    {
        bail!(
            "phala cvms list --json returned invalid pagination (page {page}, totalPages {total_pages})"
        );
    }

    let mut app_id = None;
    for row in items {
        if row.name.as_deref() != Some(app_name) {
            continue;
        }

        let usable_id = row
            .app_id
            .map(|id| id.trim().to_owned())
            .filter(|id| !id.is_empty())
            .with_context(|| {
                format!(
                    "phala cvms list --json has matching CVM `{app_name}` without a usable `app_id`"
                )
            })?;
        if app_id.is_none() {
            app_id = Some(usable_id);
        }
    }

    Ok(PhalaCvmListPage {
        page,
        total_pages,
        app_id,
    })
}

/// Walk every page of a CVM list until `app_name` is found or the server's
/// pagination envelope proves that the last page was read. Any fetch or parse
/// error is returned, never interpreted as an available name.
fn find_phala_cvm_app_id_by_name(
    mut fetch_page: impl FnMut(usize) -> Result<PhalaCvmListPage>,
) -> Result<Option<String>> {
    let mut requested_page = 1;
    loop {
        let listed = fetch_page(requested_page)?;
        if listed.page != requested_page {
            bail!(
                "phala cvms list --json returned page {} when page {} was requested",
                listed.page,
                requested_page
            );
        }
        if let Some(app_id) = listed.app_id {
            return Ok(Some(app_id));
        }
        if listed.total_pages == 0 || listed.page >= listed.total_pages {
            return Ok(None);
        }
        requested_page = listed
            .page
            .checked_add(1)
            .context("phala cvms pagination overflow")?;
    }
}

/// Build the arguments for one page of `phala cvms list --json`.
#[must_use]
fn build_phala_cvm_list_args(page: usize) -> Vec<String> {
    vec![
        "cvms".to_owned(),
        "list".to_owned(),
        "--json".to_owned(),
        "--page".to_owned(),
        page.to_string(),
    ]
}

/// One row of `phala cvms list --json`. Only the two fields the collision
/// preflight needs are modelled; everything else on the row is ignored.
#[derive(Debug, serde::Deserialize)]
struct PhalaCvmListRow {
    #[serde(alias = "app_id", alias = "appId")]
    app_id: Option<String>,
    #[serde(alias = "name", alias = "cvm", alias = "cvmName")]
    name: Option<String>,
}

/// `phala cvms list --json` wraps the rows in a paginated envelope
/// (`{ success, page, pageSize, total, totalPages, items: [...] }`), not a bare
/// array. `total`/`totalPages` are carried so a caller can tell when the name it
/// is looking for could sit on a page it has not fetched.
#[derive(Debug, serde::Deserialize)]
struct PhalaCvmList {
    #[serde(default)]
    success: Option<bool>,
    items: Option<Vec<PhalaCvmListRow>>,
    #[serde(default)]
    page: Option<usize>,
    #[serde(default, rename = "totalPages", alias = "total_pages")]
    total_pages: Option<usize>,
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

/// Run one paginated `phala cvms list --json` request and parse its collision
/// lookup result. A non-zero exit is an error because an unreadable page cannot
/// establish that the requested CVM name is free.
fn read_phala_cvm_list_page(
    page: usize,
    app_name: &str,
    api_key: Option<&str>,
) -> Result<PhalaCvmListPage> {
    let args = build_phala_cvm_list_args(page);
    let out = phala_command(api_key)
        .args(&args)
        .output()
        .context("run phala cvms list — is the phala CLI installed? (npm i -g phala)")?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        bail!(
            "could not read Phala CVM list page {page}, so `{app_name}` cannot be checked for a name collision: {}",
            stderr.trim()
        );
    }

    parse_phala_cvm_list_page(&out.stdout, app_name)
        .with_context(|| format!("parse Phala CVM list page {page}"))
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

    fn existing_cvm_app_id(&self) -> Result<Option<String>> {
        find_phala_cvm_app_id_by_name(|page| {
            read_phala_cvm_list_page(page, &self.app_name, self.api_key.as_deref())
        })
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

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test assertions intentionally panic on unexpected values"
)]
mod tests {
    use super::*;

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

    // ── phala cvms list parsing ──────────────────────────────────────────────

    #[test]
    fn a_listed_cvm_is_found_by_its_operator_chosen_name() {
        let stdout = br#"{"success":true,"page":1,"pageSize":10,"total":2,"totalPages":1,"items":[
            {"app_id":"app_other","name":"gm-testnet-other"},
            {"app_id":"app_mine","name":"gm-testnet-zai-a"}
        ]}"#;

        let found = parse_phala_cvm_list_page(stdout, "gm-testnet-zai-a")
            .expect("a readable list must parse")
            .app_id;

        assert_eq!(found.as_deref(), Some("app_mine"));
    }

    #[test]
    fn current_phala_cli_field_names_are_accepted() {
        let stdout = br#"{"success":true,"page":1,"pageSize":50,"total":1,"totalPages":1,"items":[
            {"appId":"app_mine","cvmName":"gm-miner-near-1"}
        ]}"#;

        let found = parse_phala_cvm_list_page(stdout, "gm-miner-near-1")
            .expect("current phala CLI list output must parse")
            .app_id;

        assert_eq!(found.as_deref(), Some("app_mine"));
    }

    #[test]
    fn a_name_absent_from_a_readable_list_is_free() {
        let stdout = br#"{"success":true,"page":1,"pageSize":50,"total":1,"totalPages":1,"items":[{"app_id":"app_other","name":"gm-testnet-other"}]}"#;

        let found = parse_phala_cvm_list_page(stdout, "gm-testnet-zai-a")
            .expect("list must parse")
            .app_id;

        assert_eq!(found, None, "a name nobody holds is free");
    }

    #[test]
    fn an_empty_workspace_leaves_every_name_free() {
        let found = parse_phala_cvm_list_page(
            br#"{"success":true,"page":1,"pageSize":50,"total":0,"totalPages":0,"items":[]}"#,
            "gm-testnet-zai-a",
        )
        .expect("an empty list must parse")
        .app_id;

        assert_eq!(found, None);
    }

    #[test]
    fn zero_total_pages_are_only_valid_for_an_empty_first_page() {
        let contradictory_pages = [
            br#"{"success":true,"page":2,"totalPages":0,"items":[]}"# as &[u8],
            br#"{"success":true,"page":1,"totalPages":0,"items":[{"app_id":"app_other","name":"gm-testnet-other"}]}"#,
        ];

        for stdout in contradictory_pages {
            assert!(
                parse_phala_cvm_list_page(stdout, "gm-testnet-zai-a").is_err(),
                "contradictory zero-page metadata must fail closed"
            );
        }
    }

    #[test]
    fn a_name_on_a_later_phala_page_is_checked_before_it_is_declared_free() {
        // `phala cvms list` returns a paginated envelope. The lookup must ask
        // for page two after page one omits the requested name.
        let page_one = br#"{
            "success":true,"page":1,"pageSize":50,"total":51,"totalPages":2,
            "items":[{"app_id":"app_other","name":"gm-testnet-other"}]
        }"#;
        let page_two = br#"{
            "success":true,"page":2,"pageSize":50,"total":51,"totalPages":2,
            "items":[{"app_id":"app_collision","name":"gm-testnet-colliding"}]
        }"#;
        let pages: [&[u8]; 2] = [page_one, page_two];
        let mut requested_pages = Vec::new();
        let found = find_phala_cvm_app_id_by_name(|page| {
            requested_pages.push(page);
            parse_phala_cvm_list_page(pages[page - 1], "gm-testnet-colliding")
        })
        .expect("all pages must parse");

        assert_eq!(requested_pages, vec![1, 2]);
        assert_eq!(
            found.as_deref(),
            Some("app_collision"),
            "every result page must be checked before a name is declared free"
        );
    }

    #[test]
    fn a_failed_later_phala_page_is_not_treated_as_a_free_name() {
        let page_one = br#"{
            "success":true,"page":1,"pageSize":50,"total":51,"totalPages":2,
            "items":[{"app_id":"app_other","name":"gm-testnet-other"}]
        }"#;
        let result = find_phala_cvm_app_id_by_name(|page| {
            if page == 1 {
                parse_phala_cvm_list_page(page_one, "gm-testnet-colliding")
            } else {
                Err(anyhow::anyhow!("page {page} unavailable"))
            }
        });

        assert!(result.is_err(), "a failed page must fail closed");
    }

    #[test]
    fn a_contradictory_zero_page_from_the_walker_is_not_treated_as_free() {
        let page_one = br#"{
            "success":true,"page":1,"pageSize":50,"total":51,"totalPages":2,
            "items":[{"app_id":"app_other","name":"gm-testnet-other"}]
        }"#;
        let page_two = br#"{
            "success":true,"page":2,"pageSize":50,"total":51,"totalPages":0,
            "items":[]
        }"#;
        let result = find_phala_cvm_app_id_by_name(|page| {
            parse_phala_cvm_list_page(
                if page == 1 { page_one } else { page_two },
                "gm-testnet-colliding",
            )
        });

        assert!(
            result.is_err(),
            "the walker must propagate contradictory zero-page metadata"
        );
    }

    #[test]
    fn a_page_without_items_is_not_treated_as_a_free_name() {
        let result = parse_phala_cvm_list_page(
            br#"{"success":true,"page":1,"totalPages":1}"#,
            "gm-testnet-colliding",
        );

        assert!(result.is_err(), "missing items must fail closed");
    }

    #[test]
    fn an_explicitly_failed_phala_page_is_not_treated_as_a_free_name() {
        let result = parse_phala_cvm_list_page(
            br#"{"success":false,"page":1,"totalPages":1,"items":[]}"#,
            "gm-testnet-colliding",
        );

        assert!(result.is_err(), "success=false must fail closed");
    }

    #[test]
    fn a_matching_phala_row_without_a_usable_app_id_is_not_free() {
        for app_id in ["null", "\"\""] {
            let stdout = format!(
                "{{\"success\":true,\"page\":1,\"totalPages\":1,\"items\":[{{\"name\":\"gm-testnet-colliding\",\"app_id\":{app_id}}}]}}"
            );
            let result = parse_phala_cvm_list_page(stdout.as_bytes(), "gm-testnet-colliding");

            assert!(result.is_err(), "app_id {app_id} must fail closed");
        }
    }

    #[test]
    fn paginated_phala_list_requests_carry_the_page_number() {
        assert_eq!(
            build_phala_cvm_list_args(2),
            vec!["cvms", "list", "--json", "--page", "2"]
        );
    }

    #[test]
    fn an_unreadable_list_is_an_error_not_an_empty_one() {
        // The whole point: "could not ask" must never read as "name is free",
        // or the collision preflight skips itself exactly when it is needed.
        let err = parse_phala_cvm_list_page(b"not json", "gm-testnet-zai-a")
            .expect_err("an unparseable list must not read as an absent CVM");

        assert!(err.to_string().contains("phala cvms list"), "{err}");
    }

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
}
