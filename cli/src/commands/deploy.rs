//! The deploy / worker / image-registration command flow.
//!
//! `gmcli deploy` (worker #1) and `gmcli worker add` (further capacity) share
//! the same Phala-CVM plumbing; they differ only in which registry endpoint
//! records the resulting worker. `register-image` re-registers worker #1 off a
//! deployed CVM, and `publish-image-version` computes an `ImageVersion` offline.

use anyhow::{bail, Context as _, Result};
use chrono::Utc;
use clap::Parser as _;

use gm_miner_cli::{
    client::{RegistryClient, UPSTREAM_MODEL_ECHO_CAPABILITY},
    cloud_policy::{cloud_fence_required_for_image_recovery, cloud_fence_required_for_worker},
    config::{self, Config, WorkerRecord},
    dependency::{ensure_dependency, PHALA},
    deploy::{
        fetch_supported_versions, format_created_at, normalize_hash, parse_phala_cvm_detail,
        parse_phala_cvm_endpoint, parse_phala_cvm_name, preflight_phala_cli, prepare_deploy_target,
        resolve_image_source, resolve_registry_credentials, select_version,
        to_ratls_passthrough_endpoint, verify_hashes, ImageProvisioner, ImageSource, ImageVersion,
        PhalaClient, PHALA_ENDPOINT_FIELD,
    },
    node_secret, slots, terms,
    types::{
        MinerStatus, WorkerCreateRequest, WorkerCreateResponse, WorkerEntry, WorkerListResponse,
    },
    workers::{is_secondary_live, worker_health_lines},
};

use crate::commands::persist::{
    persist_accepted_terms, persist_worker_record, remove_provisional_worker,
};
use crate::commands::status_error;
use crate::commands::streaming_check::deploy_streaming_advisory;
use crate::{DeployFlags, PublishImageVersionFlags};

/// Parsed `gmcli deploy` arguments, grouped so the dispatch match arm
/// and the subcommand entry point do not need a long positional list.
pub(crate) struct DeployArgs {
    pub(crate) app_name: String,
    pub(crate) image_ref: Option<String>,
    /// The resolved staging directory used verbatim by every deploy step.
    /// Set once in `cmd_deploy_subcommand` from `--dist-dir` or the
    /// `dist/<app_name>` default, so no later step recomputes — and
    /// diverges from — it.
    pub(crate) project_dir: std::path::PathBuf,
    pub(crate) image_repo: Option<String>,
    pub(crate) image_tag: String,
    pub(crate) instance_type: String,
    pub(crate) disk_size: String,
    pub(crate) os_image: String,
    pub(crate) repo_root: Option<std::path::PathBuf>,
    pub(crate) version: Option<usize>,
    pub(crate) boot_timeout_secs: u64,
    /// Phala Cloud API key override (`--phala-api-key`), not persisted.
    pub(crate) phala_api_key: Option<String>,
    /// Suppress interactive prompts (`--yes`): the Phala key paste and the
    /// `phala` install offer.
    pub(crate) assume_yes: bool,
    /// Record terms acceptance non-interactively (`--accept-terms`).
    pub(crate) accept_terms: bool,
}

/// Which registry endpoint records the worker a deploy produces.
///
/// `First` is `gmcli deploy`: `POST /miners/register` creates the
/// hotkey identity and worker #1. `Add` is `gmcli worker add`:
/// `POST /miners/{hotkey}/workers` attaches further capacity to the named
/// hotkey, which `worker add` resolves and validates *before* any CVM work
/// so an unregistered hotkey fails fast.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WorkerRegistration {
    First,
    Add { hotkey: String },
}

/// A throwaway [`Parser`] used to materialise [`DeployFlags`] with all its
/// clap defaults applied — the wizard's `deploy` step reuses the exact same
/// defaults a bare `gmcli deploy` would, with no flags passed.
///
/// [`Parser`]: clap::Parser
/// [`DeployFlags`]: crate::DeployFlags
#[derive(clap::Parser)]
struct DeployFlagsDefaults {
    #[command(flatten)]
    flags: DeployFlags,
}

/// Build a [`DeployFlags`] carrying clap's defaults, for the `init` wizard's
/// `deploy` step (equivalent to a bare `gmcli deploy`).
///
/// [`DeployFlags`]: crate::DeployFlags
pub(crate) fn default_deploy_flags() -> DeployFlags {
    DeployFlagsDefaults::parse_from(["gmcli deploy"]).flags
}

/// Resolve a [`DeployArgs`] from parsed CLI flags, computing the staging
/// directory once (`--dist-dir` or `dist/<app_name>`).
pub(crate) fn deploy_args_from_flags(flags: DeployFlags) -> DeployArgs {
    let project_dir = flags
        .dist_dir
        .unwrap_or_else(|| std::path::PathBuf::from("dist").join(&flags.app_name));
    DeployArgs {
        app_name: flags.app_name,
        image_ref: flags.image_ref,
        project_dir,
        image_repo: flags.image_repo,
        image_tag: flags.image_tag,
        instance_type: flags.instance_type,
        disk_size: flags.disk_size,
        os_image: flags.os_image,
        repo_root: flags.repo_root,
        version: flags.version,
        boot_timeout_secs: flags.boot_timeout_secs,
        phala_api_key: flags.phala_api_key,
        assume_yes: flags.yes,
        accept_terms: flags.accept_terms,
    }
}

/// Build and run the deploy subcommand from parsed CLI arguments.
///
/// Separated from `dispatch` to keep the match arm small.
pub(crate) async fn cmd_deploy_subcommand(
    cfg: Config,
    args: DeployArgs,
    registration: WorkerRegistration,
) -> Result<()> {
    // Phala gate: ensure the CLI is installed and resolve+validate the API key
    // before building the client. The key is scoped onto the `phala`
    // subprocesses via the client (never the global env), so it never reaches
    // the `git`/`docker` children of the image build.
    let phala_api_key = phala_preflight(&args).await?;
    let phala = gm_miner_cli::deploy::RealPhalaClient::new(
        args.app_name.clone(),
        args.project_dir.clone(),
        args.instance_type.clone(),
        args.disk_size.clone(),
        args.os_image.clone(),
    )
    .with_api_key(phala_api_key);
    let mut client = RegistryClient::new(cfg.clone());
    cmd_deploy(&cfg, &mut client, &phala, &args, &registration).await
}

/// `gmcli worker add` — attach a new CVM to the existing hotkey.
///
/// Three checks run *before* any CVM work so a misuse fails fast rather than
/// after a multi-minute deploy:
///   1. Worker #1 must already be tracked locally. If this network has no
///      tracked workers (a fresh machine, or a legacy `node_secret` config not
///      yet migrated by a `deploy`), `worker add` would attach a secondary
///      worker to a hotkey whose worker #1 the CLI cannot even name; the
///      provisional upsert would also clear the legacy secret before worker #1
///      was ever migrated. Require a `deploy` first.
///   2. The `--app-name` must not already name a *registered* worker.
///      Reusing the default `gm-miner-1` (or any registered name) would make
///      [`node_secret::for_worker`] reuse that worker's secret and the
///      config upsert overwrite its record — two workers sharing a secret
///      and the original left untracked. A provisional record (one whose
///      registration never completed, so its `worker_id` is empty) is *not*
///      a duplicate: re-running `worker add` with that name retries it.
///   3. The hotkey is resolved from `/miners/me` up front; `worker add`
///      requires an already-registered hotkey, so a 404 here fails before
///      the CVM is created (unlike `deploy`, which registers the hotkey).
///
/// [`node_secret::for_worker`]: gm_miner_cli::node_secret::for_worker
pub(crate) async fn cmd_worker_add(cfg: Config, args: DeployArgs) -> Result<()> {
    if cfg
        .active_network_entry()
        .is_none_or(|e| e.workers.is_empty())
    {
        bail!(
            "no worker #1 is tracked on this network yet; run `gmcli deploy` \
             first to register (or migrate) worker #1, then `gmcli worker \
             add` for further capacity"
        );
    }
    if let Some(existing) = cfg
        .active_network_entry()
        .and_then(|e| e.worker_by_app_name(&args.app_name))
    {
        if !existing.worker_id.is_empty() {
            bail!(
                "a worker named '{}' is already registered on this network; \
                 pass a distinct --app-name (e.g. --app-name gm-miner-2) so the \
                 new worker gets its own CVM and node secret",
                args.app_name
            );
        }
        // A provisional record with a real app_id is a CVM that launched but
        // whose registry POST never landed. Re-running `worker add` would
        // deploy a *second* CVM and orphan the first. Point the operator at
        // `worker remove`, which clears the local record (and names the CVM to
        // tear down), so the retry starts clean.
        if !existing.app_id.is_empty() {
            bail!(
                "worker '{}' has a CVM ({}) that was deployed but never \
                 registered. `worker add` would launch a second CVM and orphan \
                 it. Clear the stale record first:\n  gmcli worker remove {}\n\
                 (it prints the `phala cvms delete` to run), then re-run \
                 `gmcli worker add --app-name {}`.",
                args.app_name,
                existing.app_id,
                existing.app_id,
                args.app_name
            );
        }
        // An empty-app_id provisional stub that belongs to `deploy` (a primary
        // attempt, flag unset) must not be retried through `worker add` — that
        // would reuse worker #1's in-flight secret as a secondary. Send it back
        // to `deploy`. Only a provisional *secondary* stub retries here.
        if !existing.provisional_secondary {
            bail!(
                "'{}' is an in-flight worker #1 deploy, not a secondary worker; \
                 retry it with `gmcli deploy --app-name {}`, or \
                 `gmcli worker remove {}` to discard the stub",
                args.app_name,
                args.app_name,
                args.app_name
            );
        }
    }

    let mut client = RegistryClient::new(cfg.clone());
    client.preflight_auth().await?;
    let hotkey = fetch_hotkey(&mut client).await?;

    cmd_deploy_subcommand(cfg, args, WorkerRegistration::Add { hotkey }).await
}

/// Real [`ImageProvisioner`]: resolves the digest-pinned image ref a deploy
/// renders into its compose file.
///
/// The default (`source` = [`ImageSource::Prebuilt`]) returns the gm-published,
/// registry-supported ref as-is — a normal miner never builds. The build arm
/// (`source` = [`ImageSource::Build`]) is the explicit `--image-repo` opt-in:
/// the image is built with `docker buildx --push` to that public repo (Phala
/// Cloud pulls from there) and the pushed digest is pinned.
struct PublicRegistryProvisioner<'a> {
    args: &'a DeployArgs,
    source: ImageSource,
}

impl ImageProvisioner for PublicRegistryProvisioner<'_> {
    fn provision(&self) -> Result<String> {
        use gm_miner_cli::image;

        let args = self.args;

        if let ImageSource::Prebuilt { image_ref, .. } = &self.source {
            println!("Using pre-built image ref (skipping local build): {image_ref}");
            return Ok(image_ref.clone());
        }

        let repo = args.image_repo.as_deref().ok_or_else(|| {
            anyhow::anyhow!(
                "no image repo set; pass --image-repo <registry/owner/gm-miner> \
                 (or set GM_IMAGE_REPO) so the miner image can be pushed to a \
                 public registry, or pass --image-ref to use a pre-built image"
            )
        })?;

        image::preflight_tools()?;

        let repo_root = args
            .repo_root
            .clone()
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        let coords = image::ImageCoordinates::new(repo, &args.image_tag);

        let image_version = git_short_sha(&repo_root);
        println!("Building and pushing the miner image to {repo} ...");
        image::build_and_push_image(&coords, &image_version, &repo_root)
    }
}

/// Resolve the short git commit SHA of `repo_root` for the image version
/// (`GM_IMAGE_VERSION` build arg), falling back to `"unknown"`.
fn git_short_sha(repo_root: &std::path::Path) -> String {
    std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .current_dir(repo_root)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_owned())
}

/// Reject a plain `gmcli deploy` aimed at a registered *secondary* worker.
///
/// `deploy` registers worker #1 via `/miners/register`, which refreshes the
/// miner's oldest *live* worker. Pointed at the `--app-name` of a live
/// secondary worker it would overwrite worker #1 in the registry and corrupt
/// the mapping. A re-deploy of worker #1 (or a brand-new, untracked
/// `--app-name`, or a provisional record from an in-flight/failed deploy being
/// retried) is fine.
///
/// Which worker is #1 is read from the registry (`GET /miners/{hotkey}/workers`
/// via [`fetch_live_workers`]), never from a local record's position: local
/// records are never pruned when the registry deregisters a worker, so a dead
/// CVM can sit at local position 1 indefinitely while the registry's worker #1
/// is a later record. A positional guard called that live worker "secondary"
/// and refused to redeploy the operator's only serving worker.
pub(crate) async fn reject_secondary_worker_deploy(
    cfg: &Config,
    client: &mut RegistryClient,
    registration: &WorkerRegistration,
    app_name: &str,
) -> Result<()> {
    if *registration != WorkerRegistration::First {
        return Ok(());
    }
    // An untracked `--app-name` is a fresh worker #1 (or a replacement for it):
    // nothing to overwrite, and no reason to call the registry.
    let Some(tracked) = cfg
        .active_network_entry()
        .and_then(|e| e.worker_by_app_name(app_name))
    else {
        return Ok(());
    };
    // A record the registry has never seen (no `worker_id`) is classified by
    // its local flag alone — no round-trip can say anything about it.
    let live = if tracked.worker_id.is_empty() {
        Vec::new()
    } else {
        fetch_live_workers(client).await?
    };

    if is_secondary_live(tracked, &live) {
        bail!(
            "'{app_name}' is a secondary worker; `deploy` and `register-image` \
             only (re-)register worker #1. To replace this worker, \
             `gmcli worker remove <worker_id>` then `gmcli worker add \
             --app-name {app_name}`."
        );
    }
    Ok(())
}

/// The hotkey's live workers, as the registry sees them.
///
/// The source of truth for which workers exist: the registry deregisters
/// workers (and the operator removes them) without the local `workers` list
/// ever being pruned, so only this list can say which worker is #1.
///
/// An operator with no miner row yet (404 on `/miners/me`) — or a hotkey the
/// registry lists no workers for — has no live workers, which is an empty list,
/// not an error. Any other failure is propagated: `deploy` cannot proceed
/// without the registry anyway, and guessing here is what corrupts worker #1.
async fn fetch_live_workers(client: &mut RegistryClient) -> Result<Vec<WorkerEntry>> {
    let resp = client
        .get(gm_miner_cli::client::ME_PATH)
        .await
        .context("GET /miners/me")?;
    let status = resp.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(Vec::new());
    }
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        bail!(
            "could not read your miner record from {} ({status}): {body}",
            gm_miner_cli::client::ME_PATH
        );
    }
    let miner: MinerStatus = resp.json().await.context("parse /miners/me response")?;

    let path = format!("/miners/{}/workers", miner.hotkey);
    let resp = client
        .get(&path)
        .await
        .with_context(|| format!("GET {path}"))?;
    let status = resp.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(Vec::new());
    }
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        bail!("could not list your registered workers ({status}): {body}");
    }
    let list: WorkerListResponse = resp.json().await.context("parse worker list response")?;
    Ok(list.workers)
}

/// Reject a deploy whose `--app-name` already names a CVM in the operator's
/// Phala Cloud workspace.
///
/// `phala deploy --name` refuses to reuse a name (`A CVM with name '<name>'
/// already exists in this workspace`), so such a deploy dies *after* the image
/// build and the provider keys have been staged. Catching it up front turns
/// that into one actionable instruction.
///
/// gmcli never deletes the CVM itself: the delete destroys a running worker and
/// its encrypted env, so it stays the operator's explicit act.
pub(crate) fn reject_existing_cvm(app_name: &str, existing_app_id: Option<&str>) -> Result<()> {
    let Some(app_id) = existing_app_id else {
        return Ok(());
    };
    bail!(
        "a Phala CVM named '{app_name}' already exists (app_id {app_id}), and \
         `phala deploy` cannot reuse a CVM name — this deploy would fail.\n  \
         Tear the old CVM down first (this destroys that CVM and its encrypted \
         env, and it stops serving until the redeploy finishes; gmcli re-uploads \
         your provider keys and reuses the worker's node secret):\n    \
         phala cvms delete {app_id}\n  \
         then re-run this command."
    );
}

/// Probe Phala Cloud for a CVM already using this deploy's `--app-name` and
/// reject the deploy if there is one. Runs before any image build or terms
/// prompt, so the failure costs nothing.
fn preflight_cvm_name(phala: &dyn PhalaClient, app_name: &str) -> Result<()> {
    let existing = phala
        .existing_cvm_app_id()
        .with_context(|| format!("check whether a Phala CVM named '{app_name}' already exists"))?;
    reject_existing_cvm(app_name, existing.as_deref())
}

/// The registry `worker_id` of the record already tracked under `app_name`,
/// or empty if none. A redeploy carries this through its provisional stubs so
/// a mid-deploy failure can't erase a still-registered worker's id.
pub(crate) fn existing_worker_id_for(cfg: &Config, app_name: &str) -> String {
    cfg.active_network_entry()
        .and_then(|e| e.worker_by_app_name(app_name))
        .map(|w| w.worker_id.clone())
        .unwrap_or_default()
}

/// The Phala prerequisite gate, run at the start of every deploy.
///
/// Ensures the `phala` CLI is installed (offering to install it), then resolves
/// the Phala Cloud API key (flag → env → config → interactive paste, persisted)
/// and validates it — including a credit-balance check — against the Phala
/// Cloud API. Both run before any irreversible CVM work so a missing CLI, a
/// bad key, or an empty balance fails fast.
///
/// Returns the validated key so the caller can scope it onto the `phala`
/// subprocesses only (never the global process env, which the `git`/`docker`
/// children of the image build would inherit). `None` means the operator is
/// already authenticated via `phala` CLI login — that session is reused and
/// there is no key to pass.
async fn phala_preflight(args: &DeployArgs) -> Result<Option<String>> {
    ensure_dependency(&PHALA, args.assume_yes)?;
    gm_miner_cli::phala::resolve_key(args.phala_api_key.as_deref(), args.assume_yes).await
}

/// Whether the deploy target is a slot-capable image.
///
/// Capability comes from the registry rows' publish-time feature stamps:
/// the selected approved row on the default path, or — when the operator
/// passes an explicit `--image-ref` — whichever approved row published
/// that exact digest. An image the registry cannot vouch for (an unknown
/// ref, or any `--image-repo` build) is treated as legacy: slots are
/// never advertised for an entrypoint without a stamped row, which also
/// keeps a multi-key env from ever reaching a CVM that cannot parse it.
fn image_is_slot_capable(
    args: &DeployArgs,
    approved: &ImageVersion,
    versions: &[ImageVersion],
) -> bool {
    // Mirrors `resolve_image_source` precedence exactly: an explicit
    // --image-ref wins over --image-repo, which wins over the approved
    // row's default ref. The capability verdict must describe the image
    // that actually deploys.
    if let Some(explicit) = args.image_ref.as_deref() {
        return versions
            .iter()
            .any(|v| v.image_ref.as_deref() == Some(explicit) && v.slot_capable());
    }
    if args.image_repo.is_some() {
        return false;
    }
    approved.slot_capable()
}

/// Whether the image that will actually deploy contains the measured cloud
/// model binding. Cloud upstreams are refused unless the registry-approved image
/// row carries this feature, so an old gateway/image combination cannot accept
/// a cloud slot as if it were a direct worker.
fn image_is_cloud_binding_capable(
    args: &DeployArgs,
    approved: &ImageVersion,
    versions: &[ImageVersion],
) -> bool {
    if let Some(explicit) = args.image_ref.as_deref() {
        return versions
            .iter()
            .any(|v| v.image_ref.as_deref() == Some(explicit) && v.cloud_binding_capable());
    }
    if args.image_repo.is_some() {
        return false;
    }
    approved.cloud_binding_capable()
}

/// Keep every worker registration path behind the registry's authoritative
/// model-echo admission fence. The image feature is checked separately after
/// the approved image version is selected; this check protects the registry
/// call itself from an older registry that would treat cloud provenance as an
/// ordinary offer.
async fn require_cloud_registration_capability(
    client: &mut RegistryClient,
    backends: &std::collections::BTreeMap<String, String>,
    operation: &str,
) -> Result<()> {
    if backends.is_empty() {
        return Ok(());
    }
    require_registry_model_echo_capability(client, operation).await
}

/// Apply the registration fence using both the worker being (re-)registered's
/// recorded provenance and the current selector-derived map. An empty current
/// map is not enough to bypass a cloud or unknown historical record.
async fn require_cloud_registration_capability_for_worker(
    client: &mut RegistryClient,
    config: &Config,
    app_name: &str,
    backends: &std::collections::BTreeMap<String, String>,
    operation: &str,
) -> Result<()> {
    if !cloud_fence_required_for_worker(config, app_name, backends) {
        return Ok(());
    }
    if backends.is_empty() {
        require_registry_model_echo_capability(client, operation).await
    } else {
        require_cloud_registration_capability(client, backends, operation).await
    }
}

async fn require_registry_model_echo_capability(
    client: &mut RegistryClient,
    operation: &str,
) -> Result<()> {
    client
        .require_capability(UPSTREAM_MODEL_ECHO_CAPABILITY)
        .await
        .with_context(|| {
            format!("cloud worker {operation} requires registry capability upstream-model-echo")
        })
}

/// Resolve the image source (default = the gm-published `supported_image_ref`,
/// overridden by `--image-ref`, built locally for `--image-repo`), provision
/// it, and render the compose template around the resulting digest-pinned ref.
///
/// Whether the image needs pull credentials is decided later by an anonymous
/// registry probe ([`resolve_registry_credentials`]), not from any flag here.
fn resolve_and_render_target(
    cfg: &Config,
    args: &DeployArgs,
    supported_image_ref: Option<&str>,
) -> Result<gm_miner_cli::deploy::DeployTarget> {
    let source = resolve_image_source(
        args.image_ref.as_deref(),
        args.image_repo.as_deref(),
        supported_image_ref,
    )?;
    // The flag-less default deploys the registry-supported image; surface it
    // so the operator sees which image a bare `deploy` is using.
    if args.image_ref.is_none() && args.image_repo.is_none() {
        if let ImageSource::Prebuilt { image_ref } = &source {
            println!("Deploying the registry-supported image: {image_ref}");
        }
    }
    prepare_deploy_target(
        &PublicRegistryProvisioner { args, source },
        cfg.active_network(),
    )
}

pub(crate) async fn cmd_deploy(
    cfg: &Config,
    client: &mut RegistryClient,
    phala: &dyn PhalaClient,
    args: &DeployArgs,
    registration: &WorkerRegistration,
) -> Result<()> {
    let keys = deploy_preflight(cfg, client, phala, args, registration).await?;
    let worker_backends = keys.worker_backends();
    require_cloud_registration_capability_for_worker(
        client,
        cfg,
        &args.app_name,
        &worker_backends,
        "registration",
    )
    .await?;
    let registry_url = cfg.api_url();
    println!("Fetching approved image versions from {registry_url} ...");
    let versions = fetch_supported_versions(&registry_url).await?;
    let approved = select_version(&versions, args.version)?;
    println!(
        "Selected version {}  ({})",
        approved.notes.as_deref().unwrap_or("<no notes>"),
        format_created_at(&approved.created_at)
    );
    if !worker_backends.is_empty() && !image_is_cloud_binding_capable(args, approved, &versions) {
        anyhow::bail!(
            "cloud upstreams require a registry-approved image with the `upstream-model-hop` \
             feature; select an image with cloud model binding or wait for this image to be admitted"
        );
    }
    let mut record = prepare_worker_record(
        cfg,
        args,
        registration,
        WorkerRecordInput {
            keys,
            slot_capable: image_is_slot_capable(args, approved, &versions),
            backends: worker_backends,
        },
    )?;
    let target = resolve_and_render_target(cfg, args, approved.image_ref.as_deref())?;
    println!("Resolved miner image: {}", target.image_ref);
    let registry_creds = resolve_registry_credentials(&target.image_ref).await?;
    println!(
        "Deploying to Phala Cloud (boot timeout: {}s) ...",
        args.boot_timeout_secs
    );
    let actual = phala.deploy(
        &target.rendered_compose,
        keys,
        &record.node_secret,
        registry_creds.as_ref(),
        args.boot_timeout_secs,
    )?;
    // Persist the app id before fallible hash checks so failed deploys remain recoverable.
    record.app_id.clone_from(&actual.app_id);
    persist_worker_record(cfg.active_network(), record.clone())?;
    println!("Verifying hashes against registry approval ...");
    let verified = verify_hashes(&actual.hashes, approved)?;
    println!("  compose_hash  : OK ({})", verified.compose_sha256);
    println!("  os_image_hash : OK ({})", verified.os_image_hash);
    println!("Registering worker with the registry ...");
    record.worker_id = register_worker(
        client,
        registration,
        &WorkerImageArgs {
            compose_hash: &verified.compose_sha256,
            os_image_hash: &verified.os_image_hash,
            endpoint: &actual.endpoint,
            node_secret: Some(&record.node_secret),
            backends: record.backends.as_ref(),
            provider_slots: record.provider_slots.as_ref(),
            accepted_terms_version: Some(terms::CURRENT_TERMS_VERSION),
        },
    )
    .await?;
    record.provisional_secondary = false;
    persist_worker_record(cfg.active_network(), record.clone())?;
    print_deploy_summary(&record.worker_id, &actual.app_id, registration);
    deploy_streaming_advisory(cfg, &actual.endpoint, &record.node_secret).await;
    Ok(())
}

async fn deploy_preflight<'a>(
    cfg: &'a Config,
    client: &mut RegistryClient,
    phala: &dyn PhalaClient,
    args: &DeployArgs,
    registration: &WorkerRegistration,
) -> Result<&'a gm_miner_cli::config::ProviderKeys> {
    // Refuse unusable registry auth before any irreversible CVM work.
    client.preflight_auth().await?;
    reject_secondary_worker_deploy(cfg, client, registration, &args.app_name).await?;
    // Phala cannot reuse a CVM name; detect collisions before paying for an image build.
    preflight_cvm_name(phala, &args.app_name)?;
    // Only first-worker registration accepts terms, before any provider key is read.
    if *registration == WorkerRegistration::First {
        ensure_terms_accepted(cfg, args)?;
    }
    let keys = cfg.provider_keys.as_ref().filter(|keys| keys.any_set()).ok_or_else(|| {
        anyhow::anyhow!(
            "no provider keys; run `gmcli set-api-keys \
             --anthropic <key>` (and/or --openai / --google / --chutes / --zai / --moonshot / --deepinfra / --kubetee / --engy / --moonmath, \
             or configure --anthropic-upstream bedrock / --openai-upstream azure) first"
        )
    })?;
    keys.validate_upstreams()?;
    Ok(keys)
}

struct WorkerRecordInput<'a> {
    keys: &'a gm_miner_cli::config::ProviderKeys,
    slot_capable: bool,
    backends: std::collections::BTreeMap<String, String>,
}

fn prepare_worker_record(
    cfg: &Config,
    args: &DeployArgs,
    registration: &WorkerRegistration,
    input: WorkerRecordInput<'_>,
) -> Result<WorkerRecord> {
    let is_first = *registration == WorkerRegistration::First;
    let (node_secret, freshly_generated) =
        node_secret::for_worker(cfg.active_network_entry(), &args.app_name, is_first)?;
    let provider_slots = if input.slot_capable {
        slots::provider_slots_for_keys(input.keys, &node_secret)?
    } else {
        slots::reject_multikey_for_legacy_image(input.keys)?;
        std::collections::BTreeMap::new()
    };
    let record = WorkerRecord {
        worker_id: existing_worker_id_for(cfg, &args.app_name),
        app_id: String::new(),
        app_name: args.app_name.clone(),
        node_secret,
        backends: Some(input.backends),
        provider_slots: (!provider_slots.is_empty()).then_some(provider_slots),
        provisional_secondary: !is_first,
    };
    if freshly_generated {
        println!(
            "Generated a fresh node secret for worker '{}'.",
            args.app_name
        );
        // The running CVM must never depend on a secret lost by a later failed registry call.
        persist_worker_record(cfg.active_network(), record.clone())?;
    }
    Ok(record)
}

/// Print the deploy result and, for a first deploy, the next-step hint.
fn print_deploy_summary(worker_id: &str, app_id: &str, registration: &WorkerRegistration) {
    println!("  worker_id : {worker_id}");
    println!("  app_id    : {app_id}");
    if *registration == WorkerRegistration::First {
        println!("\nNext: gmcli declare-products --discount-pct <pct>  (then `gmcli status`)");
    }
}

/// Run the one-time terms-acceptance gate and persist a fresh acceptance.
///
/// A current acceptance already on record returns immediately. Otherwise the
/// operator accepts (interactively, or non-interactively via `--accept-terms`
/// / `GMCLI_ACCEPT_TERMS`) and the acceptance is written to the local config
/// so later deploys do not re-prompt. The registry-side record is sent
/// separately on the first-worker registration body.
fn ensure_terms_accepted(cfg: &Config, args: &DeployArgs) -> Result<()> {
    let stored = cfg.accepted_terms.as_ref().map(|a| a.version.as_str());
    match terms::gate(stored, args.accept_terms)? {
        terms::Gate::AlreadyAccepted => Ok(()),
        terms::Gate::AcceptedNow => persist_accepted_terms(),
    }
}

/// Register a freshly-deployed worker and return its registry `worker_id`.
///
/// `First` creates the hotkey identity + worker #1 via `/miners/register`;
/// `Add` looks up the caller's hotkey (`GET /miners/me`) and attaches the
/// worker via `POST /miners/{hotkey}/workers`.
async fn register_worker(
    client: &mut RegistryClient,
    registration: &WorkerRegistration,
    args: &WorkerImageArgs<'_>,
) -> Result<String> {
    match registration {
        WorkerRegistration::First => post_register_image(client, args).await,
        WorkerRegistration::Add { hotkey } => post_add_worker(client, hotkey, args).await,
    }
}

/// Fetch the calling miner's hotkey from `GET /miners/me`.
pub(crate) async fn fetch_hotkey(client: &mut RegistryClient) -> Result<String> {
    let resp = client
        .get(gm_miner_cli::client::ME_PATH)
        .await
        .context("GET /miners/me")?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        bail!(
            "could not determine your hotkey from {} ({status}): {body}; \
             run `gmcli deploy` first to register your hotkey",
            gm_miner_cli::client::ME_PATH
        );
    }
    let miner: MinerStatus = resp.json().await.context("parse /miners/me response")?;
    Ok(miner.hotkey)
}

/// `gmcli register-image` — re-register an already-deployed worker's
/// image with the registry without a full redeploy.
///
/// Reuses the per-worker node secret persisted under the matching
/// `app_id`, auto-discovers the deployed compose/os-image hashes and the
/// public endpoint via `phala cvms get <app-id> --json`, re-registers
/// worker #1 (`POST /miners/register`), then refreshes the worker record
/// with the returned `worker_id`.
pub(crate) async fn cmd_register_image_subcommand(cfg: Config, app_id: &str) -> Result<()> {
    // register-image re-registers worker #1 via `POST /miners/register`
    // (which refreshes the miner's oldest worker). The CLI's first worker
    // record is worker #1, so a tracked CVM that is *not* that record is a
    // worker-add worker; routing it through `/miners/register` would
    // overwrite worker #1's endpoint/secret and corrupt the local mapping.
    // Reject it and point the operator at `worker add` instead.
    //
    // Reuse the locally-tracked worker record for this CVM: its secret keeps
    // the registry's stored copy in sync with what the deployed envoy
    // enforces, and its `app_name` preserves the operator's original
    // `--app-name`. A worker not tracked locally has neither — the registry
    // then leaves any stored secret untouched.
    let network = cfg.active_network().to_owned();
    // Scope the same Phala key deploy would use (env or saved config key) onto
    // register-image's `phala cvms get`, so a recovery run works off the key
    // the deploy prompt persisted — not only a separate CLI login / env var.
    let phala_key = gm_miner_cli::phala::stored_key(cfg.phala_api_key.as_deref());
    let mut client = RegistryClient::new(cfg.clone());
    let RegisterImageContext {
        node_secret,
        existing_app_name,
        backends: register_backends,
        provider_slots,
        cloud_fence_required,
    } = register_image_context(&cfg, &mut client, app_id).await?;

    if cloud_fence_required {
        require_registry_model_echo_capability(&mut client, "recovery").await?;
    }

    // register-image is a hidden re-registration path (debug / registry
    // resync), not the guided deploy: a check-only preflight with an install
    // hint, never the interactive install offer `deploy` uses via
    // `ensure_dependency(&PHALA, ...)`.
    preflight_phala_cli()?;

    let out = gm_miner_cli::deploy::phala_command(phala_key.as_deref())
        .args(["cvms", "get", app_id, "--json"])
        .output()
        .context("run phala cvms get — is the phala CLI installed? (npm i -g phala)")?;
    if !out.status.success() {
        bail!(
            "phala cvms get {app_id} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }

    let hashes = parse_phala_cvm_detail(out.status.success(), &out.stdout)
        .context("read deployed worker hashes from phala cvms get")?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no measured hashes for CVM '{app_id}' \
                 (compose_hash/os_image_hash not present in \
                 `phala cvms get {app_id} --json`); \
                 deploy first with `gmcli deploy`"
            )
        })?;

    // The registry requires a non-empty `endpoint` on every registration —
    // read it from the same CVM-detail document already fetched above,
    // then rewrite it to the dstack TLS-passthrough (`s`-suffix) form so
    // the registered URL is the one on which the miner's RA-TLS
    // certificate is actually presented.
    let endpoint = parse_phala_cvm_endpoint(out.status.success(), &out.stdout)
        .context("read deployed worker endpoint from phala cvms get")?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no public endpoint for CVM '{app_id}' \
                 ({PHALA_ENDPOINT_FIELD} not present in \
                 `phala cvms get {app_id} --json`); \
                 the CVM may not have finished provisioning its gateway endpoint"
            )
        })?;
    let endpoint = to_ratls_passthrough_endpoint(&endpoint)
        .context("derive the RA-TLS passthrough endpoint for registration")?;

    // A register-image with no tracked secret re-registers worker #1 in
    // place and leaves the registry's stored secret untouched (omitted from
    // the body); a known secret is re-sent. The registry's
    // `/miners/register` only accepts bare lowercase hex hashes, so
    // normalize before POST.
    let compose_hash = normalize_hash(&hashes.compose_sha256);
    let os_image_hash = normalize_hash(&hashes.os_image_hash);
    let worker_id = post_register_image(
        &mut client,
        &WorkerImageArgs {
            compose_hash: &compose_hash,
            os_image_hash: &os_image_hash,
            endpoint: &endpoint,
            node_secret: node_secret.as_deref(),
            // register-image re-registers an already-existing worker. Reuse
            // the backends recorded at deploy time so a recovery or resync
            // preserves the worker's provenance instead of relabeling it from
            // whatever global config is current later. If no local record
            // exists, current config is only a best-effort fallback.
            backends: register_backends.as_ref(),
            provider_slots: provider_slots.as_ref(),
            // A register-image resync re-asserts the image, not the terms; the
            // registry keeps whatever acceptance the first deploy recorded.
            accepted_terms_version: None,
        },
    )
    .await?;

    // Refresh the worker record in place under the same `app_name` a later
    // `deploy` would pass, so the records reconcile instead of duplicating.
    // Prefer the locally-tracked name (the original `--app-name`); for a
    // legacy/untracked config fall back to the CVM's own `name` from `phala
    // cvms get`, and only as a last resort to the `app_id`.
    let cvm_name = parse_phala_cvm_name(out.status.success(), &out.stdout)
        .context("read deployed worker name from phala cvms get")?;
    let app_name = existing_app_name
        .or(cvm_name)
        .unwrap_or_else(|| app_id.to_owned());
    if let Some(secret) = node_secret {
        persist_worker_record(
            &network,
            WorkerRecord {
                worker_id: worker_id.clone(),
                app_id: app_id.to_owned(),
                app_name,
                node_secret: secret,
                backends: register_backends,
                provider_slots: provider_slots.clone(),
                provisional_secondary: false,
            },
        )?;
    }

    println!("  worker_id : {worker_id}");
    Ok(())
}

/// The backends `register-image` re-sends for a CVM: the recorded map for a
/// tracked worker, else the current config's map. `None` (omitted) for a
/// record written before the per-provider map. With no record, a direct-only
/// config is not enough to rewrite registry provenance, so the registry keeps
/// its authoritative stored value rather than the CLI re-asserting a lossy
/// guess that could narrow a mixed worker.
fn register_image_backends(
    record: Option<&WorkerRecord>,
    cfg: &Config,
) -> Option<std::collections::BTreeMap<String, String>> {
    if let Some(record) = record {
        record.backends.clone()
    } else {
        let backends = cfg.provider_keys.as_ref()?.worker_backends();
        (!backends.is_empty()).then_some(backends)
    }
}

struct RegisterImageContext {
    node_secret: Option<String>,
    existing_app_name: Option<String>,
    backends: Option<std::collections::BTreeMap<String, String>>,
    provider_slots: Option<std::collections::BTreeMap<String, Vec<String>>>,
    cloud_fence_required: bool,
}

/// Resolve what `register-image` re-sends for the CVM `app_id`, rejecting a
/// secondary worker.
///
/// Secondary is decided against the registry's live worker list, exactly as
/// `deploy`'s guard is (see [`reject_secondary_worker_deploy`]): a local
/// record's position says nothing once a sibling has been deregistered.
async fn register_image_context(
    cfg: &Config,
    client: &mut RegistryClient,
    app_id: &str,
) -> Result<RegisterImageContext> {
    let entry = cfg.active_network_entry();
    let tracked = entry.and_then(|n| n.worker_by_app_id(app_id));
    let live = match tracked {
        Some(tracked) if !tracked.worker_id.is_empty() => fetch_live_workers(client).await?,
        _ => Vec::new(),
    };
    if let Some(tracked) = tracked.filter(|tracked| is_secondary_live(tracked, &live)) {
        // A provisional secondary has no worker_id yet; point `worker remove`
        // at the app_id, which it also accepts, so the command is runnable in
        // every case.
        let remove_handle = if tracked.worker_id.is_empty() {
            app_id
        } else {
            &tracked.worker_id
        };
        bail!(
            "CVM '{app_id}' is a secondary worker (worker '{}'); \
             `register-image` only re-registers worker #1. To replace it, \
             `gmcli worker remove {}` then `gmcli worker add \
             --app-name {}`.",
            tracked.app_name,
            remove_handle,
            tracked.app_name
        );
    }
    // A tracked CVM re-sends its recorded secret. An untracked CVM on a
    // pre-multi-worker config falls back to the legacy network-level secret so
    // a resync still restores what envoy enforces; otherwise the registry
    // leaves its stored secret untouched.
    let node_secret = tracked.map(|w| w.node_secret.clone()).or_else(|| {
        entry
            .and_then(config::NetworkEntry::legacy_node_secret)
            .map(str::to_owned)
    });
    // Re-send the slot ids recorded at deploy time, never a re-derivation
    // from current config: local keys may have changed since this CVM was
    // deployed, and advertising slots the worker does not hold turns every
    // slot-routed request into a 421. An untracked CVM has no record, so it
    // re-registers unslotted until a proper deploy.
    let provider_slots = tracked.and_then(|w| w.provider_slots.clone());
    Ok(RegisterImageContext {
        node_secret,
        existing_app_name: tracked.map(|w| w.app_name.clone()),
        backends: register_image_backends(tracked, cfg),
        provider_slots,
        cloud_fence_required: cloud_fence_required_for_image_recovery(cfg, tracked),
    })
}

/// `gmcli publish-image-version` — compute a released image's `ImageVersion`
/// offline and publish it to the target network's registry allow-list.
///
/// Renders the compose for the network around the digest-pinned image ref,
/// computes `compose_hash` from the canonical `app_compose` serialization and
/// `os_image_hash` from the pinned OS image (no Phala Cloud deploy, no spend),
/// then POSTs the pair to the network's `/admin/image-versions` upsert
/// (idempotent). Authenticated by the registry admin key only.
pub(crate) async fn cmd_publish_image_version(
    cfg: &Config,
    flags: PublishImageVersionFlags,
) -> Result<()> {
    use gm_miner_cli::compose_hash::{compute_compose_hash, PINNED_OS_IMAGE_HASH};
    use gm_miner_cli::image_version::{
        build_admin_request, post_admin_image_version, registry_url_for, GitProvenance,
    };

    let network = cfg.resolved_network();
    let registry_url = registry_url_for(network, cfg.api_url_override.as_deref());

    println!(
        "Computing the {network} ImageVersion for {} offline ...",
        flags.image_ref
    );
    let compose_hash = compute_compose_hash(&flags.image_ref, network)?;
    let os_image_hash = PINNED_OS_IMAGE_HASH;
    println!("  compose_hash  : {compose_hash}");
    println!("  os_image_hash : {os_image_hash}");

    let provenance = GitProvenance {
        tag: flags.git_tag.clone(),
        commit: flags.git_commit.clone(),
        repo: Some(flags.git_repo.clone()),
    };
    let body = build_admin_request(
        &compose_hash,
        os_image_hash,
        &flags.image_ref,
        network,
        &provenance,
    );

    println!(
        "Publishing to {registry_url}{} ...",
        gm_miner_cli::image_version::ADMIN_IMAGE_VERSIONS_PATH
    );
    let action = post_admin_image_version(&registry_url, &flags.registry_admin_key, &body).await?;
    println!(
        "  {action}: compose_hash={} os_image_hash={}",
        body.compose_hash, body.os_image_hash
    );
    Ok(())
}

/// Fields the registry needs to register or attach a worker.
struct WorkerImageArgs<'a> {
    compose_hash: &'a str,
    os_image_hash: &'a str,
    /// The worker's public envoy endpoint. The registry requires this.
    endpoint: &'a str,
    /// The worker's `x-gm-node-key` secret, or `None` to omit it so the
    /// registry leaves any stored value untouched (a `register-image` for
    /// a worker whose secret the CLI does not track locally).
    node_secret: Option<&'a str>,
    /// Per-provider cloud backends (`provider -> adapter`) derived from the
    /// configured upstream selectors. `None` omits the field so the registry
    /// keeps its stored value (a `register-image` resync of an untracked
    /// direct worker); `deploy` always sends the map, even `{}`.
    backends: Option<&'a std::collections::BTreeMap<String, String>>,
    /// Direct-upstream provider slot ids advertised to the registry.
    provider_slots: Option<&'a std::collections::BTreeMap<String, Vec<String>>>,
    /// The gm-miner-terms version the operator accepted, sent on the
    /// first-worker registration so the registry records it on the miner row.
    /// `None` omits the field — the registry leaves any stored value untouched
    /// (a `worker add` or a `register-image` resync that does not re-accept).
    accepted_terms_version: Option<&'a str>,
}

/// POST verified compose + OS image hashes to `/miners/register` (worker #1)
/// and return the registry's `worker_id`.
async fn post_register_image(
    client: &mut RegistryClient,
    args: &WorkerImageArgs<'_>,
) -> Result<String> {
    // The registry requires both `endpoint` and `attestation_endpoint` as
    // non-empty strings. `attestation_endpoint` is reserved for future
    // attested-channel work and not yet consumed by the registry, so the
    // envoy endpoint is sent as a placeholder for both.
    let mut body = serde_json::to_value(WorkerCreateRequest {
        endpoint: args.endpoint,
        // `attestation_endpoint` is reserved for future attested-channel
        // work; send the envoy endpoint as a placeholder, matching worker add.
        attestation_endpoint: args.endpoint,
        compose_hash: args.compose_hash,
        os_image_hash: args.os_image_hash,
        node_secret: args.node_secret,
        backends: args.backends,
        provider_slots: args.provider_slots,
    })
    .context("serialize register body")?;
    // The accepted terms version, recorded on the miner row keyed to hotkey —
    // the tamper-resistant copy of the local config acceptance. `None` (a
    // register-image resync) leaves any stored value untouched.
    if let Some(version) = args.accepted_terms_version {
        body["accepted_terms_version"] = serde_json::Value::String(version.to_owned());
    }

    let resp = client
        .post("/miners/register", &body)
        .await
        .context("POST /miners/register")?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(status_error("register", status, &body));
    }

    let json: serde_json::Value = resp.json().await.context("parse register response")?;

    let worker_id = json
        .get("worker_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("register response missing worker_id: {json}"))?
        .to_owned();

    println!("Worker registered.");
    if let Some(s) = json.get("status").and_then(|v| v.as_str()) {
        println!("  status    : {s}");
    }
    println!("  compose   : {}", args.compose_hash);
    println!("  os image  : {}", args.os_image_hash);
    println!("  endpoint  : {}", args.endpoint);
    Ok(worker_id)
}

/// POST a worker to `POST /miners/{hotkey}/workers` and return its
/// registry `worker_id`. Used by `gmcli worker add`.
async fn post_add_worker(
    client: &mut RegistryClient,
    hotkey: &str,
    args: &WorkerImageArgs<'_>,
) -> Result<String> {
    let body = serde_json::to_value(WorkerCreateRequest {
        endpoint: args.endpoint,
        // `attestation_endpoint` is reserved for future attested-channel
        // work; send the envoy endpoint as a placeholder, matching the
        // first-worker registration.
        attestation_endpoint: args.endpoint,
        compose_hash: args.compose_hash,
        os_image_hash: args.os_image_hash,
        node_secret: args.node_secret,
        backends: args.backends,
        provider_slots: args.provider_slots,
    })
    .context("serialize worker-add body")?;

    let path = format!("/miners/{hotkey}/workers");
    let resp = client
        .post(&path, &body)
        .await
        .with_context(|| format!("POST {path}"))?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(status_error("worker add", status, &body));
    }

    let json: serde_json::Value = resp.json().await.context("parse worker-add response")?;

    let created: WorkerCreateResponse =
        serde_json::from_value(json).context("parse worker-add response shape")?;

    println!("Worker added.");
    println!("  status    : {}", created.status);
    println!("  hotkey    : {}", created.miner_hotkey);
    println!("  compose   : {}", args.compose_hash);
    println!("  os image  : {}", args.os_image_hash);
    println!("  endpoint  : {}", args.endpoint);
    Ok(created.worker_id)
}

/// `gmcli worker list` — pretty-print the hotkey's live workers.
pub(crate) async fn cmd_worker_list(client: &mut RegistryClient) -> Result<()> {
    let hotkey = fetch_hotkey(client).await?;
    let path = format!("/miners/{hotkey}/workers");
    let resp = client
        .get(&path)
        .await
        .with_context(|| format!("GET {path}"))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        bail!("worker list failed ({status}): {body}");
    }
    let list: WorkerListResponse = resp.json().await.context("parse worker list response")?;

    if list.workers.is_empty() {
        println!("No workers attached to {hotkey}.");
        return Ok(());
    }

    println!(
        "{:<28} {:<14} {:<24} ENDPOINT",
        "WORKER_ID", "STATUS", "LAST ATTESTATION"
    );
    println!("{}", "-".repeat(110));
    for w in &list.workers {
        println!(
            "{:<28} {:<14} {:<24} {}",
            w.worker_id,
            w.status,
            w.last_attestation_at.as_deref().unwrap_or("never"),
            w.endpoint,
        );
    }
    println!("\n{} worker(s) total.", list.workers.len());

    let now = Utc::now();
    for w in &list.workers {
        for line in worker_health_lines(w, list.consecutive_ok_required, now) {
            println!("{line}");
        }
    }
    Ok(())
}

/// `gmcli worker remove <id>` — deregister a worker and remind the
/// operator to tear down its Phala CVM separately.
///
/// `id` is the registry `worker_id` for a registered worker. It also accepts
/// the local `app_id` or `app_name` of a *provisional* record — a deploy that
/// launched a CVM but never registered, which has no `worker_id` to pass. A
/// provisional record is only local state, so it is dropped without a registry
/// DELETE; this clears the dead-end that otherwise blocks re-running `worker
/// add` for that name.
pub(crate) async fn cmd_worker_remove(cfg: Config, id: &str) -> Result<()> {
    let network = cfg.active_network().to_owned();
    let tracked = cfg.active_network_entry().and_then(|n| {
        n.worker_by_id(id)
            .or_else(|| n.worker_by_app_id(id))
            .or_else(|| n.worker_by_app_name(id))
    });

    if tracked.is_some_and(|w| w.worker_id.is_empty()) {
        return remove_provisional_worker(&network, id);
    }

    let app_id = tracked.map(|w| w.app_id.clone());
    let worker_id = tracked.map_or_else(|| id.to_owned(), |w| w.worker_id.clone());

    let mut client = RegistryClient::new(cfg);
    let hotkey = fetch_hotkey(&mut client).await?;
    let path = format!("/miners/{hotkey}/workers/{worker_id}");
    let resp = client
        .delete(&path)
        .await
        .with_context(|| format!("DELETE {path}"))?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        bail!("worker remove failed ({status}): {body}");
    }

    // Drop the local record so `worker list`/re-deploy don't reference a
    // deregistered worker. Locked so a concurrent deploy save can't resurrect it.
    config::with_config_lock(|| {
        let mut cfg = config::load().context("load gmcli config")?;
        cfg.active_network = Some(network);
        cfg.active_entry_mut().remove_worker_by_id(&worker_id);
        config::save(&cfg).context("persist worker removal to gmcli config")
    })?;

    println!("Worker {worker_id} deregistered from the registry.");
    let reminder = match app_id {
        Some(app_id) => {
            format!("Now tear down the Phala CVM separately:\n  phala cvms delete {app_id}")
        }
        None => "Now tear down the corresponding Phala CVM separately with \
             `phala cvms delete <app_id>` (its app_id was not tracked locally)."
            .to_owned(),
    };
    println!("{reminder}");
    Ok(())
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test assertions intentionally panic on unexpected values"
)]
mod tests {
    use super::*;
    use gm_miner_cli::config::{NetworkEntry, ProviderKeys};
    use std::collections::HashMap;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn cfg_with_keys(keys: ProviderKeys) -> Config {
        Config {
            active_network: Some("testnet".to_owned()),
            provider_keys: Some(keys),
            networks: HashMap::from([("testnet".to_owned(), NetworkEntry::default())]),
            ..Default::default()
        }
    }

    fn registry_cfg(server: &MockServer) -> Config {
        Config {
            active_network: Some("testnet".to_owned()),
            networks: HashMap::from([(
                "testnet".to_owned(),
                NetworkEntry {
                    api_url: Some(server.uri()),
                    tokens: Some(gm_miner_cli::config::TokenEntry {
                        access_token: Some("test-token".to_owned()),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )]),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn cloud_worker_registration_requires_registry_model_echo_capability() {
        let server = MockServer::start().await;
        let mut client = RegistryClient::new(registry_cfg(&server));
        let backends =
            std::collections::BTreeMap::from([("openai".to_owned(), "azure".to_owned())]);

        let error = require_cloud_registration_capability(&mut client, &backends, "registration")
            .await
            .expect_err("legacy registry must reject cloud worker registration");
        assert!(error.to_string().contains("upstream-model-echo"));
    }

    #[tokio::test]
    async fn cloud_worker_recovery_requires_registry_model_echo_capability() {
        let server = MockServer::start().await;
        let mut client = RegistryClient::new(registry_cfg(&server));
        let backends =
            std::collections::BTreeMap::from([("anthropic".to_owned(), "foundry".to_owned())]);

        let error = require_cloud_registration_capability(&mut client, &backends, "recovery")
            .await
            .expect_err("legacy registry must reject cloud worker recovery");
        assert!(error.to_string().contains("upstream-model-echo"));
    }

    #[tokio::test]
    async fn cloud_worker_recovery_proceeds_after_registry_model_echo_capability() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(gm_miner_cli::client::CAPABILITIES_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "capabilities": [gm_miner_cli::client::UPSTREAM_MODEL_ECHO_CAPABILITY],
            })))
            .mount(&server)
            .await;
        let mut client = RegistryClient::new(registry_cfg(&server));
        let backends =
            std::collections::BTreeMap::from([("anthropic".to_owned(), "foundry".to_owned())]);

        require_cloud_registration_capability(&mut client, &backends, "recovery")
            .await
            .expect("capability-admitted cloud worker recovery");
    }

    #[tokio::test]
    async fn worker_registration_fence_unions_selector_recorded_and_unknown_sources() {
        let server = MockServer::start().await;
        let mut config = registry_cfg(&server);
        config.provider_keys = Some(ProviderKeys {
            openai_upstream: Some("direct".to_owned()),
            ..Default::default()
        });
        config.active_entry_mut().workers.extend([
            WorkerRecord {
                app_name: "recorded-cloud".to_owned(),
                backends: Some(std::collections::BTreeMap::from([(
                    "openai".to_owned(),
                    "azure".to_owned(),
                )])),
                ..Default::default()
            },
            WorkerRecord {
                app_name: "unknown-provenance".to_owned(),
                ..Default::default()
            },
        ]);
        let mut client = RegistryClient::new(config.clone());

        for app_name in ["recorded-cloud", "unknown-provenance"] {
            let error = require_cloud_registration_capability_for_worker(
                &mut client,
                &config,
                app_name,
                &std::collections::BTreeMap::new(),
                "registration",
            )
            .await
            .expect_err("historical cloud or unknown provenance must stay fenced");
            assert!(error.to_string().contains("upstream-model-echo"));
        }

        let error = require_cloud_registration_capability_for_worker(
            &mut client,
            &config,
            "new-cloud",
            &std::collections::BTreeMap::from([("anthropic".to_owned(), "foundry".to_owned())]),
            "registration",
        )
        .await
        .expect_err("current cloud selectors must fence a new worker");
        assert!(error.to_string().contains("upstream-model-echo"));
    }

    #[tokio::test]
    async fn register_image_recovery_fence_does_not_trust_missing_backends() {
        let server = MockServer::start().await;
        let mut config = registry_cfg(&server);
        config.active_entry_mut().workers.extend([
            WorkerRecord {
                app_id: "recorded-cloud".to_owned(),
                backends: Some(std::collections::BTreeMap::from([(
                    "openai".to_owned(),
                    "azure".to_owned(),
                )])),
                ..Default::default()
            },
            WorkerRecord {
                app_id: "known-direct".to_owned(),
                backends: Some(std::collections::BTreeMap::new()),
                ..Default::default()
            },
        ]);
        let mut client = RegistryClient::new(config.clone());

        let cloud = register_image_context(&config, &mut client, "recorded-cloud")
            .await
            .expect("recorded cloud context");
        assert!(cloud.cloud_fence_required);
        let direct = register_image_context(&config, &mut client, "known-direct")
            .await
            .expect("known direct context");
        assert!(!direct.cloud_fence_required);
        let unknown = register_image_context(&config, &mut client, "untracked")
            .await
            .expect("unknown context");
        assert!(unknown.cloud_fence_required);
    }

    #[test]
    fn register_image_backends_use_recorded_backends_over_current_config() {
        let cfg = cfg_with_keys(ProviderKeys {
            openai_upstream: Some("azure".to_owned()),
            azure_openai_api_key: Some("azure-key".to_owned()),
            ..ProviderKeys::default()
        });
        let record = WorkerRecord {
            worker_id: "01J0A".to_owned(),
            app_id: "app_01J0A".to_owned(),
            app_name: "gm-miner-1".to_owned(),
            node_secret: "secret".to_owned(),
            backends: Some(std::collections::BTreeMap::from([(
                "anthropic".to_owned(),
                "bedrock".to_owned(),
            )])),
            ..Default::default()
        };

        let backends = register_image_backends(Some(&record), &cfg);
        assert_eq!(
            backends,
            Some(std::collections::BTreeMap::from([(
                "anthropic".to_owned(),
                "bedrock".to_owned()
            )]))
        );

        let body = serde_json::to_value(WorkerCreateRequest {
            endpoint: "https://app_01J0A-8080s.dstack-prod5.phala.network",
            attestation_endpoint: "https://app_01J0A-8080s.dstack-prod5.phala.network",
            compose_hash: "a".repeat(64).as_str(),
            os_image_hash: "b".repeat(64).as_str(),
            node_secret: Some("secret"),
            backends: backends.as_ref(),
            provider_slots: None,
        })
        .expect("serialize register-image request");
        assert_eq!(body["backends"]["anthropic"], "bedrock");
    }

    #[test]
    fn register_image_backends_fall_back_to_current_config_without_record() {
        let cfg = cfg_with_keys(ProviderKeys {
            anthropic_upstream: Some("foundry".to_owned()),
            azure_foundry_api_key: Some("foundry-key".to_owned()),
            openai_upstream: Some("azure".to_owned()),
            azure_openai_api_key: Some("azure-key".to_owned()),
            ..ProviderKeys::default()
        });

        // A mixed worker with no local record re-derives both providers.
        assert_eq!(
            register_image_backends(None, &cfg),
            Some(std::collections::BTreeMap::from([
                ("anthropic".to_owned(), "foundry".to_owned()),
                ("openai".to_owned(), "azure".to_owned()),
            ]))
        );

        // A fully-direct config sends nothing so the registry keeps its stored value.
        let direct = cfg_with_keys(ProviderKeys::default());
        assert_eq!(register_image_backends(None, &direct), None);
    }

    // ── CVM-name collision preflight ─────────────────────────────────────────

    /// A [`PhalaClient`] whose workspace already holds a CVM under the deploy's
    /// `--app-name`. `deploy` is never reached: no Phala Cloud, no docker.
    struct CollidingPhala;

    impl PhalaClient for CollidingPhala {
        fn deploy(
            &self,
            _compose_yaml: &str,
            _env_vars: &ProviderKeys,
            _node_secret: &str,
            _registry_creds: Option<&gm_miner_cli::deploy::RegistryCredentials>,
            _boot_timeout_secs: u64,
        ) -> Result<gm_miner_cli::deploy::DeployOutcome> {
            anyhow::bail!("the name-collision preflight must bail before `phala deploy`")
        }

        fn existing_cvm_app_id(&self) -> Result<Option<String>> {
            Ok(Some("app_0a1b2c".to_owned()))
        }
    }

    /// A workspace with no CVM under this name — the free-name case.
    struct FreeNamePhala;

    impl PhalaClient for FreeNamePhala {
        fn deploy(
            &self,
            _compose_yaml: &str,
            _env_vars: &ProviderKeys,
            _node_secret: &str,
            _registry_creds: Option<&gm_miner_cli::deploy::RegistryCredentials>,
            _boot_timeout_secs: u64,
        ) -> Result<gm_miner_cli::deploy::DeployOutcome> {
            anyhow::bail!("not exercised")
        }

        fn existing_cvm_app_id(&self) -> Result<Option<String>> {
            Ok(None)
        }
    }

    /// Regression (live testnet): `worker add --app-name <existing>` died inside
    /// `phala deploy` with `A CVM with name '<name>' already exists in this
    /// workspace` — after the image build, with no hint about what to do. The
    /// preflight must catch the collision and name the exact teardown command
    /// (gmcli never deletes the CVM itself: that destroys a running worker).
    #[test]
    fn an_existing_cvm_name_is_rejected_with_the_delete_command() {
        let err = preflight_cvm_name(&CollidingPhala, "gm-testnet-zai-a")
            .expect_err("a colliding CVM name must be rejected before the build");
        let msg = err.to_string();
        assert!(
            msg.contains("gm-testnet-zai-a") && msg.contains("already exists"),
            "must name the colliding CVM: {msg}"
        );
        assert!(
            msg.contains("phala cvms delete app_0a1b2c"),
            "must name the exact teardown command, with the app_id: {msg}"
        );
        assert!(
            msg.contains("destroys"),
            "must say what the delete destroys: {msg}"
        );
    }

    #[test]
    fn a_free_cvm_name_passes_the_preflight() {
        preflight_cvm_name(&FreeNamePhala, "gm-miner-1").expect("a free CVM name must deploy");
        reject_existing_cvm("gm-miner-1", None).expect("no existing CVM, nothing to reject");
    }
}
