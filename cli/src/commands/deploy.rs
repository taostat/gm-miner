//! The deploy / worker / image-registration command flow.
//!
//! `gmcli deploy` (worker #1) and `gmcli worker add` (further capacity) share
//! the same Phala-CVM plumbing; they differ only in which registry endpoint
//! records the resulting worker. `register-image` re-registers worker #1 off a
//! deployed CVM, and `publish-image-version` computes an `ImageVersion` offline.

use anyhow::{bail, Context as _, Result};
use clap::Parser as _;

use gm_miner_cli::{
    client::RegistryClient,
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
    types::{MinerStatus, WorkerCreateRequest, WorkerCreateResponse, WorkerListResponse},
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
///   1. Worker #1 must already be tracked locally. The first record in
///      `workers` *is* worker #1 — every `is_primary_worker*` decision rests
///      on that. If this network has no tracked workers (a fresh machine, or
///      a legacy `node_secret` config not yet migrated by a `deploy`), the
///      added worker would become `workers[0]` and be mistaken for worker #1;
///      the provisional upsert would also clear the legacy secret before
///      worker #1 was ever migrated. Require a `deploy` first.
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
/// miner's first worker. Pointed at the `--app-name` of a registered secondary
/// worker it would overwrite worker #1 in the registry and corrupt the local
/// mapping. A re-deploy of worker #1 (or a brand-new, untracked `--app-name`,
/// or a provisional record from an in-flight/failed deploy being retried) is
/// fine.
pub(crate) fn reject_secondary_worker_deploy(
    cfg: &Config,
    registration: &WorkerRegistration,
    app_name: &str,
) -> Result<()> {
    let is_secondary = *registration == WorkerRegistration::First
        && cfg
            .active_network_entry()
            .is_some_and(|e| e.is_secondary_by_app_name(app_name));
    if is_secondary {
        bail!(
            "'{app_name}' is a secondary worker; `deploy` and `register-image` \
             only (re-)register worker #1. To replace this worker, \
             `gmcli worker remove <worker_id>` then `gmcli worker add \
             --app-name {app_name}`."
        );
    }
    Ok(())
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
    if args.image_repo.is_some() {
        return false;
    }
    match args.image_ref.as_deref() {
        None => approved.slot_capable(),
        Some(explicit) => versions
            .iter()
            .any(|v| v.image_ref.as_deref() == Some(explicit) && v.slot_capable()),
    }
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

#[expect(
    clippy::too_many_lines,
    reason = "deploy orchestration is kept flat so the ordered operational steps stay visible"
)]
pub(crate) async fn cmd_deploy(
    cfg: &Config,
    client: &mut RegistryClient,
    phala: &dyn PhalaClient,
    args: &DeployArgs,
    registration: &WorkerRegistration,
) -> Result<()> {
    // Step 0: a plain `deploy` may only target worker #1 (see guard).
    reject_secondary_worker_deploy(cfg, registration, &args.app_name)?;

    // Step 0b: the one-time provider-ToS acceptable-use gate. Only the first
    // deploy gates — it is the registration that creates the hotkey identity
    // and carries the accepted version onto the registry's miner row. A
    // `worker add` runs only after a first deploy already accepted, so
    // re-gating it would persist a local acceptance the worker-add body never
    // sends to the registry, drifting the two records apart. The gate runs
    // before any provider key is read or baked into the CVM.
    if *registration == WorkerRegistration::First {
        ensure_terms_accepted(cfg, args)?;
    }

    // Step 1: ensure provider keys are configured.
    let keys = cfg
        .provider_keys
        .as_ref()
        .filter(|k| k.any_set())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no provider keys; run `gmcli set-api-keys \
                 --anthropic <key>` (and/or --openai / --google / --chutes, \
                 or configure --anthropic-upstream bedrock / --openai-upstream azure) first"
            )
        })?;
    keys.validate_upstreams()?;
    // Derive once so the registry worker-create body and the local
    // WorkerRecord persist exactly the same backend provenance.
    let worker_backend = keys.worker_backend().map(str::to_owned);

    // Step 1b: resolve the per-worker node secret. Each worker (CVM)
    // carries its own `x-gm-node-key` secret, never shared with a sibling
    // — a leaked secret burns only one worker. A re-deploy of an existing
    // worker (matched on `--app-name`) reuses the same value so what the
    // container bakes into env, what envoy enforces, and what the registry
    // stores all stay in lockstep (Mechanism 1 of attestation-and-identity.md).
    // Only worker #1 (`deploy`) may inherit a pre-multi-worker legacy
    // secret; a `worker add` must always mint its own.
    // The Phala CLI + API-key gate already ran in `cmd_deploy_subcommand`,
    // which scoped the validated key onto the `phala` client. The `phala`
    // client passed in here carries it.

    // Step 2: auth preflight. The Phala Cloud deploy is slow and
    // irreversible for the operator (CVM created), so we refuse to start
    // the deploy unless the registry will accept the eventual
    // registration. The preflight is a cheap `GET /miners/me` — a missing
    // token / 401 fails fast with an actionable message before any CVM work.
    client.preflight_auth().await?;

    // Step 3: fetch approved image versions from the registry.
    let registry_url = cfg.api_url();
    println!("Fetching approved image versions from {registry_url} ...");
    let versions = fetch_supported_versions(&registry_url).await?;

    // Step 4: select the target version.
    let approved = select_version(&versions, args.version)?;
    println!(
        "Selected version {}  ({})",
        approved.notes.as_deref().unwrap_or("<no notes>"),
        format_created_at(&approved.created_at),
    );

    let is_first = *registration == WorkerRegistration::First;
    // A provisional stub from a `worker add` must stay off the worker-#1
    // registration paths even before it has a worker_id; tag it so the
    // primary/secondary classifiers can tell it from a worker-#1 stub.
    let provisional_secondary = !is_first;
    // Redeploying a worker already registered under this `--app-name` keeps
    // its registry `worker_id`: the upcoming registration returns the same id.
    // Carrying it into the pre-registration stubs means a deploy that fails
    // after the CVM exists does not erase the worker_id — `worker remove` can
    // still issue the registry DELETE for the still-registered worker.
    let existing_worker_id = existing_worker_id_for(cfg, &args.app_name);
    let (node_secret, freshly_generated) =
        node_secret::for_worker(cfg.active_network_entry(), &args.app_name, is_first)?;
    let provider_slots = if image_is_slot_capable(args, approved, &versions) {
        slots::provider_slots_for_keys(keys, &node_secret)?
    } else {
        // The target image's entrypoint predates slots: it cannot fan out
        // multi-key values or honor x-gm-upstream-slot. Refuse multi-key
        // configs before any CVM launches, and advertise nothing so the
        // worker registers as legacy.
        slots::reject_multikey_for_legacy_image(keys)?;
        std::collections::BTreeMap::new()
    };
    if freshly_generated {
        println!(
            "Generated a fresh node secret for worker '{}'.",
            args.app_name
        );
        // Persist the secret before the CVM launches. If the deploy or the
        // registry call later fails, the running envoy enforces this secret
        // and a re-deploy with the same `--app-name` recovers it (matched on
        // app_name); without this, a fresh secret would exist only in memory
        // until step 9. The worker_id/app_id are filled in once Phala and the
        // registry return — step 9 upserts this same record in place.
        persist_worker_record(
            cfg.active_network(),
            WorkerRecord {
                worker_id: existing_worker_id.clone(),
                app_id: String::new(),
                app_name: args.app_name.clone(),
                node_secret: node_secret.clone(),
                backend: worker_backend.clone(),
                provider_slots: (!provider_slots.is_empty()).then(|| provider_slots.clone()),
                provisional_secondary,
            },
        )?;
    }

    // Step 5: resolve which image to deploy (default = the gm-published ref
    // on the selected version) and render the compose around it.
    let target = resolve_and_render_target(cfg, args, approved.image_ref.as_deref())?;
    println!("Resolved miner image: {}", target.image_ref);

    // Step 5b: resolve private-registry pull credentials. An anonymous OCI
    // manifest probe decides whether the image is genuinely private: a public
    // image renders a clean deploy with no `DSTACK_DOCKER_*` env, while a
    // private one requires the operator-set GHCR pull credentials so the
    // CVM's pre-launch script can `docker login` and pull.
    let registry_creds = resolve_registry_credentials(&target.image_ref).await?;

    // Step 6: submit the compose stack to Phala Cloud and poll until the
    // CVM reports its measured hashes. Phala Cloud provisions the TEEPod,
    // runs the KMS, encrypts the env vars client-side to the CVM key, and
    // assigns the `app_id`.
    println!(
        "Deploying to Phala Cloud (boot timeout: {}s) ...",
        args.boot_timeout_secs
    );
    let actual = phala.deploy(
        &target.rendered_compose,
        keys,
        &node_secret,
        registry_creds.as_ref(),
        args.boot_timeout_secs,
    )?;

    // Step 6b: stamp the Phala `app_id` onto the record the instant the CVM
    // exists — *before* the fallible hash verification and registration. The
    // secret is already on disk (Step 1b for a fresh worker, or the prior
    // record on a re-deploy); recording the `app_id` now means that whatever
    // fails next — a hash mismatch or the registry POST — `worker remove` can
    // name the orphaned CVM and `register-image --app-id <id>` can recover the
    // secret. A redeploy carries the existing `worker_id` so a mid-deploy
    // failure does not erase a still-registered worker's id. `upsert` keys on
    // `app_name`, so this updates the same record in place.
    persist_worker_record(
        cfg.active_network(),
        WorkerRecord {
            worker_id: existing_worker_id.clone(),
            app_id: actual.app_id.clone(),
            app_name: args.app_name.clone(),
            node_secret: node_secret.clone(),
            backend: worker_backend.clone(),
            provider_slots: (!provider_slots.is_empty()).then(|| provider_slots.clone()),
            provisional_secondary,
        },
    )?;

    // Step 7: verify hashes. The returned hashes are normalized
    // (lowercased, `sha256:` prefix stripped) so the loud check and the
    // registration in step 8 agree on the exact value.
    println!("Verifying hashes against registry approval ...");
    let verified = verify_hashes(&actual.hashes, approved)?;
    println!("  compose_hash  : OK ({})", verified.compose_sha256);
    println!("  os_image_hash : OK ({})", verified.os_image_hash);

    // Step 8: register the worker, carrying its node secret so the registry
    // stores it and serves it to the gateway, plus the CVM's endpoint. A
    // first deploy POSTs `/miners/register` (creates the hotkey identity +
    // worker #1); `worker add` POSTs `/miners/{hotkey}/workers`.
    println!("Registering worker with the registry ...");
    let worker_id = register_worker(
        client,
        registration,
        &WorkerImageArgs {
            compose_hash: &verified.compose_sha256,
            os_image_hash: &verified.os_image_hash,
            endpoint: &actual.endpoint,
            node_secret: Some(&node_secret),
            backend: worker_backend.as_deref(),
            provider_slots: (!provider_slots.is_empty()).then_some(&provider_slots),
            accepted_terms_version: Some(terms::CURRENT_TERMS_VERSION),
        },
    )
    .await?;

    // Step 9: stamp the registry's `worker_id` and the Phala `app_id` onto
    // the record. `upsert` keys on `app_name`, so this replaces whatever was
    // there — a fresh secret persisted before deploy, or the prior record on
    // a re-deploy — in place; now `worker list`/`remove` can map it back to
    // the Phala app_id.
    persist_worker_record(
        cfg.active_network(),
        WorkerRecord {
            worker_id: worker_id.clone(),
            app_id: actual.app_id.clone(),
            app_name: args.app_name.clone(),
            node_secret: node_secret.clone(),
            backend: worker_backend,
            provider_slots: (!provider_slots.is_empty()).then(|| provider_slots.clone()),
            // Registered: role is read from position, never this flag.
            provisional_secondary: false,
        },
    )?;

    print_deploy_summary(&worker_id, &actual.app_id, registration);
    deploy_streaming_advisory(cfg, &actual.endpoint, &node_secret).await;
    Ok(())
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
    let RegisterImageContext {
        node_secret,
        existing_app_name,
        backend: register_backend,
        provider_slots,
    } = register_image_context(&cfg, app_id)?;
    let network = cfg.active_network().to_owned();
    // Scope the same Phala key deploy would use (env or saved config key) onto
    // register-image's `phala cvms get`, so a recovery run works off the key
    // the deploy prompt persisted — not only a separate CLI login / env var.
    let phala_key = gm_miner_cli::phala::stored_key(cfg.phala_api_key.as_deref());
    let mut client = RegistryClient::new(cfg);

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
            // the backend recorded at deploy time so a recovery or resync
            // preserves the worker's provenance instead of relabeling it from
            // whatever global config is current later. If no local record
            // exists, current config is only a best-effort fallback.
            backend: register_backend.as_deref(),
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
                backend: register_backend,
                provider_slots: provider_slots.clone(),
                provisional_secondary: false,
            },
        )?;
    }

    println!("  worker_id : {worker_id}");
    Ok(())
}

fn register_image_backend(record: Option<&WorkerRecord>, cfg: &Config) -> Option<String> {
    if let Some(record) = record {
        record.backend.clone()
    } else {
        cfg.provider_keys
            .as_ref()
            .and_then(|keys| keys.worker_backend().map(str::to_owned))
    }
}

struct RegisterImageContext {
    node_secret: Option<String>,
    existing_app_name: Option<String>,
    backend: Option<String>,
    provider_slots: Option<std::collections::BTreeMap<String, Vec<String>>>,
}

fn register_image_context(cfg: &Config, app_id: &str) -> Result<RegisterImageContext> {
    let entry = cfg.active_network_entry();
    let tracked = entry.and_then(|n| n.worker_by_app_id(app_id));
    if let Some(tracked) =
        tracked.filter(|_| entry.is_some_and(|n| n.is_secondary_by_app_id(app_id)))
    {
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
        backend: register_image_backend(tracked, cfg),
        provider_slots,
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
    /// Worker provenance derived from configured upstream selectors.
    backend: Option<&'a str>,
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
        backend: args.backend,
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
        backend: args.backend,
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

    fn cfg_with_keys(keys: ProviderKeys) -> Config {
        Config {
            active_network: Some("testnet".to_owned()),
            provider_keys: Some(keys),
            networks: HashMap::from([("testnet".to_owned(), NetworkEntry::default())]),
            ..Default::default()
        }
    }

    #[test]
    fn register_image_backend_uses_recorded_backend_over_current_config() {
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
            backend: Some("bedrock".to_owned()),
            ..Default::default()
        };

        let backend = register_image_backend(Some(&record), &cfg);
        assert_eq!(backend.as_deref(), Some("bedrock"));

        let body = serde_json::to_value(WorkerCreateRequest {
            endpoint: "https://app_01J0A-8080s.dstack-prod5.phala.network",
            attestation_endpoint: "https://app_01J0A-8080s.dstack-prod5.phala.network",
            compose_hash: "a".repeat(64).as_str(),
            os_image_hash: "b".repeat(64).as_str(),
            node_secret: Some("secret"),
            backend: backend.as_deref(),
            provider_slots: None,
        })
        .expect("serialize register-image request");
        assert_eq!(body["backend"], "bedrock");
    }

    #[test]
    fn register_image_backend_falls_back_to_current_config_without_record() {
        let cfg = cfg_with_keys(ProviderKeys {
            openai_upstream: Some("azure".to_owned()),
            azure_openai_api_key: Some("azure-key".to_owned()),
            ..ProviderKeys::default()
        });

        assert_eq!(register_image_backend(None, &cfg).as_deref(), Some("azure"));
    }
}
