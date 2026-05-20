//! gm-miner CLI.
//!
//! Subcommands:
//!   set-api-keys    — persist provider API keys to ~/.gm-miner/config.json
//!   deploy          — trust-correct single-shot deploy: fetch approved hashes,
//!                     deploy via dstack-cloud, verify hashes, register image
//!   login           — Taostats device-code OAuth flow
//!   register-image  — register the miner image's compose hash with the registry
//!   list-products   — show the registry product catalog
//!   declare-product — register a miner-product offer with prices in USD/Mtok
//!   update-prices   — update prices on an existing offer
//!   status          — show current registration state and per-product eligibility
//!
//! All prices accepted by the CLI are in USD per million tokens (e.g. "3.00")
//! and are auto-converted to picodollars/Mtok before being sent to the registry.
//!
//! Contract: workstreams.md §W4

#![forbid(unsafe_code)]

use std::io::IsTerminal as _;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use gm_miner_cli::{
    auth,
    client::RegistryClient,
    config::{self, Config, ProviderKeys, TokenEntry},
    deploy::{
        fetch_supported_versions, format_created_at, prepare_deploy_target, select_version,
        verify_hashes, DstackClient, GcpConfig, ImageProvisioner, DEFAULT_BOOT_TIMEOUT_SECS,
    },
    node_secret, picodollar,
    types::{MinerPriceBlock, MinerStatus, Product, Provider},
};

#[derive(Parser)]
#[command(
    name = "gm-miner",
    version,
    about = "gm miner CLI — manage your miner's registration, products, and prices"
)]
struct Cli {
    /// Use testnet registry instead of mainnet.
    #[arg(long, global = true)]
    testnet: bool,

    /// Override the registry API URL (flag only; use `GM_REGISTRY_URL` env var for
    /// per-run overrides that should not be persisted — see `load_config`).
    #[arg(long, global = true)]
    api_url: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Persist provider API keys to ~/.gm-miner/config.json (mode 0600).
    ///
    /// Each flag, if provided, replaces the stored value.  Omitted flags
    /// leave existing values intact.  Key values are never echoed back.
    SetApiKeys {
        /// Anthropic API key (sk-ant-...).
        #[arg(long)]
        anthropic: Option<String>,

        /// `OpenAI` API key (sk-...).
        #[arg(long)]
        openai: Option<String>,

        /// Google API key.
        #[arg(long)]
        google: Option<String>,
    },

    /// Deploy the miner via dstack-cloud with trust-correct hash verification.
    ///
    /// Reads provider API keys from ~/.gm-miner/config.json (set them first
    /// with `gm-miner set-api-keys`), fetches the registry-approved image
    /// version, deploys via dstack-cloud, verifies the actual hashes match the
    /// registry approval, then registers the image automatically.
    ///
    /// On a fresh machine (no prior deploy) this automatically runs
    /// `dstack-cloud new` to scaffold the project before deploying.
    Deploy {
        /// Pre-built digest-pinned image reference (registry/repo/name@sha256:...).
        ///
        /// When set (or `GM_IMAGE_REF` is in env), the local image build is
        /// skipped and this ref is embedded in the compose file directly.
        /// When omitted, the miner image is built and pushed to Artifact
        /// Registry and the resulting digest is pinned automatically.
        #[arg(long, env = "GM_IMAGE_REF")]
        image_ref: Option<String>,

        /// Pin to a specific approved version by index (1 = newest).
        /// Defaults to the newest supported version.
        #[arg(long)]
        version: Option<usize>,

        /// dstack-cloud app name.
        #[arg(long, default_value = "gm-miner-1")]
        app_name: String,

        /// dstack project directory (the full path used verbatim).
        /// Defaults to `dist/<app_name>` relative to the current directory.
        #[arg(long)]
        dist_dir: Option<std::path::PathBuf>,

        /// GCP project ID for the dstack deployment. Required.
        #[arg(long, env = "GCP_PROJECT_ID")]
        gcp_project: String,

        /// GCP region for the GCS bucket / Artifact Registry repo.
        #[arg(long, env = "GCP_REGION", default_value = "us-central1")]
        gcp_region: String,

        /// GCP zone for the dstack CVM. Defaults to `<gcp-region>-a`.
        #[arg(long, env = "GCP_ZONE")]
        gcp_zone: Option<String>,

        /// Compute Engine machine type for the CVM.
        #[arg(long, env = "MACHINE_TYPE", default_value = "c3-standard-4")]
        machine_type: String,

        /// GCS bucket URI for dstack image upload.
        /// Defaults to `gs://<gcp-project>-dstack` (same convention as deploy.sh).
        #[arg(long, env = "GCS_BUCKET")]
        gcs_bucket: Option<String>,

        /// Artifact Registry repository name for the miner image.
        #[arg(long, env = "AR_REPO", default_value = "gm-miner")]
        ar_repo: String,

        /// Image tag applied to the build before digest resolution.
        #[arg(long, env = "IMAGE_TAG", default_value = "v0.1.0")]
        image_tag: String,

        /// dstack-cloud OS image URL pulled before deploy. Defaults to the
        /// pinned Phala meta-dstack-cloud release used by deploy.sh.
        #[arg(long, env = "DSTACK_OS_IMAGE_URL")]
        os_image_url: Option<String>,

        /// Repository root used as the Docker build context. Defaults to
        /// the current directory.
        #[arg(long)]
        repo_root: Option<std::path::PathBuf>,

        /// How long to wait for the CVM to boot and populate hashes in
        /// `dstack-cloud status --json` (seconds). Default: 300.
        #[arg(long, default_value_t = DEFAULT_BOOT_TIMEOUT_SECS)]
        boot_timeout_secs: u64,
    },

    /// Authenticate with Taostats (device-code OAuth flow) and store
    /// credentials in ~/.gm-miner/config.json.
    Login {
        /// Do not automatically open the browser.
        #[arg(long)]
        no_browser: bool,

        /// Override the auth server URL.
        #[arg(long, env = "GM_AUTH_URL")]
        auth_url: Option<String>,
    },

    /// Register this miner's image compose hash + capabilities with the registry.
    ///
    /// The normal operator flow uses `gm-miner deploy` which verifies and
    /// registers in one step.  Use this subcommand only for re-registering
    /// without redeploying (e.g. after a registry resync or for debugging).
    RegisterImage {
        /// Docker compose SHA256 (output of sha256sum docker-compose.yaml).
        #[arg(long, hide = true)]
        compose_hash: String,

        /// dstack OS image hash (from dstack-cloud status or the deployment log).
        #[arg(long, hide = true)]
        os_image_hash: String,
    },

    /// List all products in the registry catalog.
    ListProducts,

    /// Declare a miner-product offer with prices in USD per million tokens.
    DeclareProduct {
        /// Provider: anthropic, openai, or gemini.
        provider: Provider,

        /// Model identifier, e.g. claude-sonnet-4-6.
        model: String,

        /// Input token price in USD/Mtok (e.g. "2.80").
        #[arg(long)]
        price_input: String,

        /// Output token price in USD/Mtok (e.g. "14.00").
        #[arg(long)]
        price_output: String,

        /// Cache read price in USD/Mtok (optional).
        #[arg(long)]
        price_cache_read: Option<String>,

        /// Cache write 5m price in USD/Mtok (optional).
        #[arg(long)]
        price_cache_write_5m: Option<String>,

        /// Cache write 1h price in USD/Mtok (optional).
        #[arg(long)]
        price_cache_write_1h: Option<String>,
    },

    /// Update prices on an existing miner-product offer.
    UpdatePrices {
        /// Provider: anthropic, openai, or gemini.
        provider: Provider,

        /// Model identifier.
        model: String,

        /// Input token price in USD/Mtok.
        #[arg(long)]
        price_input: Option<String>,

        /// Output token price in USD/Mtok.
        #[arg(long)]
        price_output: Option<String>,

        /// Cache read price in USD/Mtok.
        #[arg(long)]
        price_cache_read: Option<String>,

        /// Cache write 5m price in USD/Mtok.
        #[arg(long)]
        price_cache_write_5m: Option<String>,

        /// Cache write 1h price in USD/Mtok.
        #[arg(long)]
        price_cache_write_1h: Option<String>,
    },

    /// Show the miner's current registration status and per-product eligibility.
    Status,
}

#[tokio::main]
#[expect(
    clippy::too_many_lines,
    reason = "main is a pure dispatch function; each arm is a one-liner or a \
              call to a dedicated cmd_* handler — no logic lives here"
)]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "warn".into()))
        .init();

    if std::env::args().len() == 1 && std::io::stdout().is_terminal() {
        println!("{BANNER}");
    }

    let cli = Cli::parse();

    match cli.command {
        Command::SetApiKeys {
            anthropic,
            openai,
            google,
        } => cmd_set_api_keys(anthropic, openai, google),
        Command::Deploy {
            image_ref,
            version,
            app_name,
            dist_dir,
            gcp_project,
            gcp_region,
            gcp_zone,
            machine_type,
            gcs_bucket,
            ar_repo,
            image_tag,
            os_image_url,
            repo_root,
            boot_timeout_secs,
        } => {
            let cfg = load_config(cli.testnet, cli.api_url)?;
            // --dist-dir is the project directory used verbatim. Default:
            // dist/<app_name> relative to cwd (matches deploy.sh). Resolve it
            // once here so every deploy step shares the same path.
            let project_dir =
                dist_dir.unwrap_or_else(|| std::path::PathBuf::from("dist").join(&app_name));
            cmd_deploy_subcommand(
                cfg,
                DeployArgs {
                    app_name,
                    image_ref,
                    project_dir,
                    gcp_project,
                    gcp_region,
                    gcp_zone,
                    machine_type,
                    gcs_bucket,
                    ar_repo,
                    image_tag,
                    os_image_url,
                    repo_root,
                    version,
                    boot_timeout_secs,
                },
            )
            .await
        }
        Command::Login {
            no_browser,
            auth_url,
        } => cmd_login(cli.testnet, auth_url, cli.api_url, !no_browser).await,
        Command::RegisterImage {
            compose_hash,
            os_image_hash,
        } => {
            let cfg = load_config(cli.testnet, cli.api_url)?;
            // Re-send the network's persisted node secret so a standalone
            // re-registration keeps the registry's stored copy in sync
            // with what the deployed envoy enforces. Absent (a miner
            // predating node-secret auth) means the registry leaves any
            // stored secret untouched.
            let node_secret = cfg
                .active_network_entry()
                .and_then(|n| n.node_secret.clone());
            let mut client = RegistryClient::new(cfg);
            cmd_register_image(
                &mut client,
                &compose_hash,
                &os_image_hash,
                node_secret.as_deref(),
            )
            .await
        }
        Command::ListProducts => {
            let cfg = load_config(cli.testnet, cli.api_url)?;
            let mut client = RegistryClient::new(cfg);
            cmd_list_products(&mut client).await
        }
        Command::DeclareProduct {
            provider,
            model,
            price_input,
            price_output,
            price_cache_read,
            price_cache_write_5m,
            price_cache_write_1h,
        } => {
            let price = build_price_block(
                &price_input,
                &price_output,
                price_cache_read.as_deref(),
                price_cache_write_5m.as_deref(),
                price_cache_write_1h.as_deref(),
            )?;
            let cfg = load_config(cli.testnet, cli.api_url)?;
            let mut client = RegistryClient::new(cfg);
            cmd_declare_product(&mut client, &provider, &model, price).await
        }
        Command::UpdatePrices {
            provider,
            model,
            price_input,
            price_output,
            price_cache_read,
            price_cache_write_5m,
            price_cache_write_1h,
        } => {
            let cfg = load_config(cli.testnet, cli.api_url)?;
            let mut client = RegistryClient::new(cfg);
            cmd_update_prices(
                &mut client,
                &provider,
                &model,
                price_input.as_deref(),
                price_output.as_deref(),
                price_cache_read.as_deref(),
                price_cache_write_5m.as_deref(),
                price_cache_write_1h.as_deref(),
            )
            .await
        }
        Command::Status => {
            let cfg = load_config(cli.testnet, cli.api_url)?;
            let mut client = RegistryClient::new(cfg);
            cmd_status(&mut client).await
        }
    }
}

// ── Banner ───────────────────────────────────────────────────────────────────

const BANNER: &str = r"
 .----------------------.
 |                      |
 |    ____ __  __       |
 |   / ___|  \/  |      |
 |  | |  _| |\/| |      |
 |  | |_| | |  | |      |
 |   \____|_|  |_|      |
 |                      |
 |   gm. wagmi.         |
 |                      |
 '----------------------'
        \
         \    .--.
              |o.o|
              =(_)=
";

// ── Helpers ─────────────────────────────────────────────────────────────────

fn load_config(testnet: bool, api_url_override: Option<String>) -> Result<Config> {
    let mut cfg = config::load().context("load config")?;

    // Always reset to the explicit choice on every invocation so the
    // active network reflects the current flag, not whatever the last
    // command left in the config. Without this, a single `--testnet`
    // call sticks across every subsequent command until the operator
    // hand-edits ~/.gm-miner/config.json.
    cfg.active_network = Some(if testnet { "testnet" } else { "mainnet" }.to_string());

    // Explicit --api-url flag wins; fall back to GM_REGISTRY_URL for a
    // this-run-only override that is never persisted.
    let effective = api_url_override.or_else(|| std::env::var("GM_REGISTRY_URL").ok());
    if let Some(url) = effective {
        cfg.active_entry_mut().api_url = Some(url);
    }

    Ok(cfg)
}

/// Convert an optional USD/Mtok string to an optional picodollar string.
fn opt_usd_to_pdollars(input: Option<&str>) -> Result<Option<String>> {
    match input {
        None => Ok(None),
        Some(s) => Ok(Some(picodollar::usd_per_mtok_to_pdollars(s)?.to_string())),
    }
}

fn build_price_block(
    price_input: &str,
    price_output: &str,
    price_cache_read: Option<&str>,
    price_cache_write_5m: Option<&str>,
    price_cache_write_1h: Option<&str>,
) -> Result<MinerPriceBlock> {
    Ok(MinerPriceBlock {
        input_per_mtok_pdollars: picodollar::usd_per_mtok_to_pdollars(price_input)?.to_string(),
        output_per_mtok_pdollars: picodollar::usd_per_mtok_to_pdollars(price_output)?.to_string(),
        cache_read_per_mtok_pdollars: opt_usd_to_pdollars(price_cache_read)?,
        cache_write_5m_per_mtok_pdollars: opt_usd_to_pdollars(price_cache_write_5m)?,
        cache_write_1h_per_mtok_pdollars: opt_usd_to_pdollars(price_cache_write_1h)?,
    })
}

/// Extract a human-readable error detail from a registry JSON error body.
///
/// Returns the `detail` string field if present, otherwise the whole body
/// re-serialized. Avoids leaking a `'static str` on every error path.
fn error_detail(json: &serde_json::Value) -> String {
    json.get("detail")
        .and_then(serde_json::Value::as_str)
        .map_or_else(|| json.to_string(), str::to_owned)
}

// ── Commands ────────────────────────────────────────────────────────────────

/// Parsed `gm-miner deploy` arguments, grouped so the dispatch match arm
/// and the subcommand entry point do not need a long positional list.
struct DeployArgs {
    app_name: String,
    image_ref: Option<String>,
    /// The resolved dstack project directory used verbatim by every step
    /// (`RealDstackClient`, `pull_os_image`, ...). Set once in
    /// `cmd_deploy_subcommand` from `--dist-dir` or the `dist/<app_name>`
    /// default, so no later step recomputes — and diverges from — it.
    project_dir: std::path::PathBuf,
    gcp_project: String,
    gcp_region: String,
    gcp_zone: Option<String>,
    machine_type: String,
    gcs_bucket: Option<String>,
    ar_repo: String,
    image_tag: String,
    os_image_url: Option<String>,
    repo_root: Option<std::path::PathBuf>,
    version: Option<usize>,
    boot_timeout_secs: u64,
}

/// Build and run the deploy subcommand from parsed CLI arguments.
///
/// Separated from `main` to keep the dispatch match arm small.
async fn cmd_deploy_subcommand(cfg: Config, args: DeployArgs) -> Result<()> {
    let dstack = gm_miner_cli::deploy::RealDstackClient {
        app_name: args.app_name.clone(),
        project_dir: args.project_dir.clone(),
    };

    // The basename check only matters when this directory still needs
    // `dstack-cloud new`, which creates `<cwd>/<app_name>/` — if the basename
    // differs the bootstrapped directory and the one we read/patch diverge.
    // An already-bootstrapped project (valid `app.json`) is deployed in place
    // via `current_dir`, so any path is fine; don't reject custom dist dirs.
    // The default `dist/<app_name>` always satisfies this, so the check only
    // bites a custom `--dist-dir` whose basename differs from `--app-name`.
    if !dstack.is_bootstrapped() {
        let basename = args
            .project_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if basename != args.app_name {
            bail!(
                "dist-dir basename must equal app-name when bootstrapping a fresh \
                 project; got dist-dir={}, app-name={app_name}",
                args.project_dir.display(),
                app_name = args.app_name
            );
        }
    }

    // zone defaults to `<region>-a`, mirroring deploy.sh.
    let zone = args
        .gcp_zone
        .clone()
        .unwrap_or_else(|| format!("{}-a", args.gcp_region));
    let bucket = args
        .gcs_bucket
        .clone()
        .unwrap_or_else(|| GcpConfig::default_bucket(&args.gcp_project));
    let gcp = GcpConfig {
        project: args.gcp_project.clone(),
        zone,
        machine_type: args.machine_type.clone(),
        instance_name: args.app_name.clone(),
        bucket,
    };
    let mut client = RegistryClient::new(cfg.clone());
    cmd_deploy(&cfg, &mut client, &dstack, &args, &gcp).await
}

/// Real [`ImageProvisioner`]: provisions GCP infrastructure and obtains the
/// digest-pinned image ref via `gcloud` / `docker`.
///
/// When `args.image_ref` is supplied only `gcloud` is preflighted; the
/// Artifact Registry setup and Docker steps are skipped entirely (the
/// operator may have no Docker daemon on the host). The non-build GCP
/// steps (project config, services, bucket) still run.
///
/// Without `--image-ref` this runs the full build flow: preflight for
/// both `gcloud` and `docker`, `gcloud` project / services / bucket /
/// Artifact-Registry setup, Docker auth, image build + push, and digest
/// resolution.
struct GcpImageProvisioner<'a> {
    args: &'a DeployArgs,
    gcp: &'a GcpConfig,
}

impl ImageProvisioner for GcpImageProvisioner<'_> {
    fn provision(&self) -> Result<String> {
        use gm_miner_cli::gcp as gcp_provision;

        let args = self.args;
        let gcp = self.gcp;

        // Configure the GCP project + service APIs regardless of whether we
        // build locally — `dstack-cloud deploy` needs compute / storage /
        // confidentialcomputing enabled and the GCS bucket present.
        println!("Provisioning GCP project {} ...", args.gcp_project);
        if let Some(pre_built) = &args.image_ref {
            // Pre-built image: only gcloud is needed (no Docker, no AR repo).
            gcp_provision::preflight_gcloud()?;
            gcp_provision::configure_project(&args.gcp_project)?;
            gcp_provision::ensure_bucket(&gcp.bucket, &args.gcp_region)?;
            println!("Using pre-built image ref (skipping local build): {pre_built}");
            return Ok(pre_built.clone());
        }

        // Local-build path: preflight both gcloud and docker, set up AR.
        gcp_provision::preflight_tools()?;
        gcp_provision::configure_project(&args.gcp_project)?;
        gcp_provision::ensure_bucket(&gcp.bucket, &args.gcp_region)?;
        gcp_provision::ensure_artifact_registry(&args.ar_repo, &args.gcp_region)?;

        let repo_root = args
            .repo_root
            .clone()
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        let coords = gcp_provision::ImageCoordinates::derive(
            &args.gcp_region,
            &args.gcp_project,
            &args.ar_repo,
            &args.app_name,
            &args.image_tag,
        );
        gcp_provision::configure_docker_auth(&coords.ar_host)?;

        let image_version = git_short_sha(&repo_root);
        println!("Building and pushing the miner image ...");
        gcp_provision::build_and_push_image(&coords, &args.app_name, &image_version, &repo_root)
    }
}

/// Resolve the short git commit SHA of `repo_root` for the image version,
/// falling back to `"unknown"` (matches deploy.sh's `GM_IMAGE_VERSION`).
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

/// Validate a key value passed to `set-api-keys`: reject empty / whitespace-only
/// strings with an actionable error rather than silently storing them.
fn validate_key(name: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        bail!("empty value for --{name}; either omit the flag or pass a non-empty key");
    }
    Ok(())
}

fn cmd_set_api_keys(
    anthropic: Option<String>,
    openai: Option<String>,
    google: Option<String>,
) -> Result<()> {
    // Reject empty values up front so they don't pass the deploy preflight.
    if let Some(ref k) = anthropic {
        validate_key("anthropic", k)?;
    }
    if let Some(ref k) = openai {
        validate_key("openai", k)?;
    }
    if let Some(ref k) = google {
        validate_key("google", k)?;
    }

    let mut cfg = config::load()
        .context("load gm-miner config (delete ~/.gm-miner/config.json if corrupted)")?;

    {
        let keys = cfg.provider_keys.get_or_insert_with(ProviderKeys::default);
        if let Some(k) = anthropic {
            keys.anthropic = Some(k);
        }
        if let Some(k) = openai {
            keys.openai = Some(k);
        }
        if let Some(k) = google {
            keys.google = Some(k);
        }
    }

    // Snapshot which keys are set before saving (only immutable borrow needed).
    let (has_anthropic, has_openai, has_google) =
        cfg.provider_keys
            .as_ref()
            .map_or((false, false, false), |k| {
                (
                    k.anthropic.is_some(),
                    k.openai.is_some(),
                    k.google.is_some(),
                )
            });

    config::save(&cfg).context("save config")?;

    let mut set_names: Vec<&str> = Vec::new();
    if has_anthropic {
        set_names.push("anthropic");
    }
    if has_openai {
        set_names.push("openai");
    }
    if has_google {
        set_names.push("google");
    }

    // Report which providers are now configured — never print the values.
    if set_names.is_empty() {
        println!("No keys stored (pass --anthropic, --openai, or --google to set one).");
    } else {
        println!("Provider keys updated.");
        for name in &set_names {
            println!("  {name}: set");
        }
    }
    Ok(())
}

async fn cmd_deploy(
    cfg: &Config,
    client: &mut RegistryClient,
    dstack: &dyn gm_miner_cli::deploy::DstackClient,
    args: &DeployArgs,
    gcp: &GcpConfig,
) -> Result<()> {
    // Step 1: ensure provider keys are configured.
    let keys = cfg
        .provider_keys
        .as_ref()
        .filter(|k| k.any_set())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no provider keys; run `gm-miner set-api-keys \
                 --anthropic <key>` (and/or --openai / --google) first"
            )
        })?;

    // Step 1b: resolve the node secret for the network this deploy
    // targets. Generated once per network and persisted to the CLI
    // config so the value baked into the container's env, what envoy
    // enforces, and what the registry stores all stay in lockstep across
    // re-deploys (Mechanism 1 of attestation-and-identity.md).
    let node_secret = resolve_node_secret(cfg.active_network())?;

    // Step 2: auth preflight. `dstack-cloud deploy` is slow and irreversible
    // for the operator (CVM created, GCS bytes uploaded), so we refuse to
    // start the deploy unless the registry will accept the eventual
    // `register-image` call. The preflight is a cheap `GET /miners/me` —
    // a missing token / 401 fails fast with an actionable message before
    // any CVM work.
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

    // Steps 5-7: prepare the deploy target. The dstack project is
    // bootstrapped (or its existing app.json trust-validated) *before* the
    // multi-minute image build+push, so a fresh-machine bootstrap failure is
    // hit cheaply instead of after a wasted build. `prepare_deploy_target`
    // then provisions GCP + the image (via `GcpImageProvisioner`, which owns
    // the build-vs-prebuilt branch) and renders the compose template.
    let provisioner = GcpImageProvisioner { args, gcp };
    let rendered = prepare_deploy_target(dstack, &provisioner, &args.app_name, gcp)?;

    // Step 8: pull the dstack-cloud OS image referenced by the deploy.
    // Use the single resolved `project_dir` (honours `--dist-dir`) so the
    // pull runs in the same directory `RealDstackClient` deploys from.
    let os_image_url = args
        .os_image_url
        .clone()
        .unwrap_or_else(|| gm_miner_cli::gcp::DEFAULT_DSTACK_OS_IMAGE_URL.to_owned());
    println!("Pulling the dstack-cloud OS image ...");
    gm_miner_cli::gcp::pull_os_image(&os_image_url, &args.project_dir)?;

    // Step 9: deploy via dstack-cloud, polling until hashes appear.
    // On re-deploy the deploy() call also refreshes gcp_config before running
    // `dstack-cloud deploy` so GCP coordinates stay current.
    println!(
        "Deploying via dstack-cloud (boot timeout: {}s) ...",
        args.boot_timeout_secs
    );
    let actual = dstack.deploy(&rendered, keys, &node_secret, gcp, args.boot_timeout_secs)?;

    // Step 10: verify hashes. The returned hashes are normalized
    // (lowercased, `sha256:` prefix stripped) so the loud check and the
    // registration in step 11 agree on the exact value.
    println!("Verifying hashes against registry approval ...");
    let verified = verify_hashes(&actual, approved)?;
    println!("  compose_hash  : OK ({})", verified.compose_sha256);
    println!("  os_image_hash : OK ({})", verified.os_image_hash);

    // Step 11: register the image, carrying the node secret so the
    // registry stores it and serves it to the gateway.
    println!("Registering image with the registry ...");
    cmd_register_image(
        client,
        &verified.compose_sha256,
        &verified.os_image_hash,
        Some(&node_secret),
    )
    .await
}

/// Resolve the miner's node secret for `network`: reuse the value
/// persisted in the CLI config, or generate a fresh one and persist it
/// on the first deploy.
fn resolve_node_secret(network: &str) -> Result<String> {
    let (secret, freshly_generated) = node_secret::resolve_persisted(network)?;
    if freshly_generated {
        println!("Generated a node secret and saved it to the gm-miner config.");
    }
    Ok(secret)
}

async fn cmd_login(
    testnet: bool,
    auth_url_override: Option<String>,
    api_url_override: Option<String>,
    open_browser: bool,
) -> Result<()> {
    // `config::load()` already returns Config::default() when the file
    // is absent (first-time login). A failure here means the file
    // exists but is unreadable or invalid JSON — surfacing that as a
    // hard error matches the other commands' behaviour and prevents
    // a normal re-login from silently wiping an operator's existing
    // mainnet/testnet tokens.
    let mut cfg = config::load()
        .context("load gm-miner config (delete ~/.gm-miner/config.json if corrupted)")?;

    // Reset on every login so a previous testnet session can't sticky-
    // overwrite mainnet credentials when the operator omits --testnet.
    cfg.active_network = Some(if testnet { "testnet" } else { "mainnet" }.to_string());

    let auth_url = auth_url_override.unwrap_or_else(|| cfg.auth_url());
    let resolved_api_url = api_url_override.unwrap_or_else(|| cfg.api_url());
    let client_id = cfg.client_id();

    let token = auth::device_login(&auth_url, &client_id, &["miner"], open_browser).await?;

    let entry = cfg.active_entry_mut();
    entry.auth_url = Some(auth_url.clone());
    entry.api_url = Some(resolved_api_url);
    entry.tokens = Some(TokenEntry {
        access_token: Some(token.access_token.clone()),
        token_expires_at: token.expires_in.map(|s| {
            #[expect(
                clippy::cast_possible_wrap,
                reason = "expires_in is a small positive number of seconds"
            )]
            let expiry = chrono::Utc::now() + chrono::Duration::seconds(s as i64);
            expiry.to_rfc3339()
        }),
    });

    config::save(&cfg).context("save config")?;

    println!("Login successful.");
    println!("Credentials saved to {}", config::config_path().display());
    Ok(())
}

async fn cmd_register_image(
    client: &mut RegistryClient,
    compose_hash: &str,
    os_image_hash: &str,
    node_secret: Option<&str>,
) -> Result<()> {
    let mut body = serde_json::json!({
        "compose_hash": compose_hash,
        "os_image_hash": os_image_hash,
    });
    // Include the node secret so the registry stores it and serves it to
    // the gateway (Mechanism 1 of attestation-and-identity.md). Omitted
    // when the miner has no secret — a miner predating node-secret auth.
    if let Some(secret) = node_secret {
        body["node_secret"] = serde_json::Value::String(secret.to_owned());
    }

    let resp = client
        .post("/miners/register", &body)
        .await
        .context("POST /miners/register")?;

    let status = resp.status();
    let json: serde_json::Value = resp.json().await.context("parse register response")?;

    if !status.is_success() {
        bail!("register-image failed ({status}): {}", error_detail(&json));
    }

    println!("Image registered.");
    if let Some(id) = json.get("miner_id").and_then(|v| v.as_str()) {
        println!("  Miner ID : {id}");
    }
    if let Some(s) = json.get("status").and_then(|v| v.as_str()) {
        println!("  Status   : {s}");
    }
    println!("  Compose  : {compose_hash}");
    println!("  OS image : {os_image_hash}");
    Ok(())
}

async fn cmd_list_products(client: &mut RegistryClient) -> Result<()> {
    let resp = client.get("/products").await.context("GET /products")?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        bail!("list-products failed ({status}): {body}");
    }

    let products: Vec<Product> = resp.json().await.context("parse products")?;

    if products.is_empty() {
        println!("No products in catalog.");
        return Ok(());
    }

    println!("{:<12} {:<40} STATUS", "PROVIDER", "MODEL");
    println!("{}", "-".repeat(60));
    for p in &products {
        println!("{:<12} {:<40} {}", p.provider, p.model, p.status);
    }
    println!("\n{} products total.", products.len());
    Ok(())
}

async fn cmd_declare_product(
    client: &mut RegistryClient,
    provider: &Provider,
    model: &str,
    price: MinerPriceBlock,
) -> Result<()> {
    // Serialize via the typed MinerPriceBlock so its skip_serializing_if
    // attrs kick in and unset cache_* fields are omitted entirely
    // (rather than sent as JSON null, which the registry rejects).
    let body = serde_json::json!({
        "provider": provider.as_str(),
        "model": model,
        "miner_price": price,
    });

    let resp = client
        .post("/miners/products", &body)
        .await
        .context("POST /miners/products")?;

    let status = resp.status();
    let json: serde_json::Value = resp
        .json()
        .await
        .context("parse declare-product response")?;

    if !status.is_success() {
        bail!("declare-product failed ({status}): {}", error_detail(&json));
    }

    // The price strings were produced by `usd_per_mtok_to_pdollars` so they
    // are valid u64s; surface any parse failure instead of silently showing
    // "$0.000000/Mtok", which would mask a bug rather than report it.
    let input_pico: u64 = price
        .input_per_mtok_pdollars
        .parse()
        .with_context(|| format!("parse input price '{}'", price.input_per_mtok_pdollars))?;
    let output_pico: u64 = price
        .output_per_mtok_pdollars
        .parse()
        .with_context(|| format!("parse output price '{}'", price.output_per_mtok_pdollars))?;
    let input_usd = picodollar::pdollars_to_usd_per_mtok(input_pico);
    let output_usd = picodollar::pdollars_to_usd_per_mtok(output_pico);

    println!("Product declared.");
    println!("  Provider : {provider}");
    println!("  Model    : {model}");
    println!("  Input    : ${input_usd}/Mtok");
    println!("  Output   : ${output_usd}/Mtok");
    Ok(())
}

#[expect(
    clippy::too_many_arguments,
    reason = "all args are distinct price fields; no better grouping"
)]
async fn cmd_update_prices(
    client: &mut RegistryClient,
    provider: &Provider,
    model: &str,
    price_input: Option<&str>,
    price_output: Option<&str>,
    price_cache_read: Option<&str>,
    price_cache_write_5m: Option<&str>,
    price_cache_write_1h: Option<&str>,
) -> Result<()> {
    if price_input.is_none()
        && price_output.is_none()
        && price_cache_read.is_none()
        && price_cache_write_5m.is_none()
        && price_cache_write_1h.is_none()
    {
        bail!("at least one --price-* flag must be specified");
    }

    let mut miner_price = serde_json::Map::new();
    if let Some(p) = price_input {
        miner_price.insert(
            "input_per_mtok_pdollars".into(),
            serde_json::Value::String(picodollar::usd_per_mtok_to_pdollars(p)?.to_string()),
        );
    }
    if let Some(p) = price_output {
        miner_price.insert(
            "output_per_mtok_pdollars".into(),
            serde_json::Value::String(picodollar::usd_per_mtok_to_pdollars(p)?.to_string()),
        );
    }
    if let Some(p) = price_cache_read {
        miner_price.insert(
            "cache_read_per_mtok_pdollars".into(),
            serde_json::Value::String(picodollar::usd_per_mtok_to_pdollars(p)?.to_string()),
        );
    }
    if let Some(p) = price_cache_write_5m {
        miner_price.insert(
            "cache_write_5m_per_mtok_pdollars".into(),
            serde_json::Value::String(picodollar::usd_per_mtok_to_pdollars(p)?.to_string()),
        );
    }
    if let Some(p) = price_cache_write_1h {
        miner_price.insert(
            "cache_write_1h_per_mtok_pdollars".into(),
            serde_json::Value::String(picodollar::usd_per_mtok_to_pdollars(p)?.to_string()),
        );
    }

    let path = format!("/miners/products/{}/{}/prices", provider.as_str(), model);
    let body = serde_json::json!({ "miner_price": miner_price });

    let resp = client.patch(&path, &body).await.context("PATCH prices")?;

    let status = resp.status();
    let json: serde_json::Value = resp.json().await.context("parse update-prices response")?;

    if !status.is_success() {
        bail!("update-prices failed ({status}): {}", error_detail(&json));
    }

    println!("Prices updated for {provider}/{model}.");
    Ok(())
}

async fn cmd_status(client: &mut RegistryClient) -> Result<()> {
    let resp = client
        .get(gm_miner_cli::client::ME_PATH)
        .await
        .context("GET /miners/me")?;

    let status_code = resp.status();
    if !status_code.is_success() {
        let body = resp.text().await.unwrap_or_default();
        bail!("status failed ({status_code}): {body}");
    }

    let miner: MinerStatus = resp.json().await.context("parse status response")?;

    println!("Miner status");
    println!("  Hotkey     : {}", miner.hotkey);
    println!("  Status     : {}", miner.status);
    println!(
        "  Last attest: {}",
        miner.last_attestation_at.as_deref().unwrap_or("never")
    );
    println!(
        "  Compose    : {}",
        miner.image_compose_hash.as_deref().unwrap_or("—")
    );

    if miner.products.is_empty() {
        println!("\nNo products declared.");
        return Ok(());
    }

    println!("\nProducts:");
    println!(
        "{:<12} {:<40} {:<10} {:<10}",
        "PROVIDER", "MODEL", "OFFERED", "ELIGIBLE"
    );
    println!("{}", "-".repeat(76));
    for p in &miner.products {
        println!(
            "{:<12} {:<40} {:<10} {:<10}",
            p.provider,
            p.model,
            if p.is_offered { "yes" } else { "no" },
            if p.is_eligible { "yes" } else { "no" },
        );
    }
    Ok(())
}
