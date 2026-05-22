//! gm-miner CLI.
//!
//! Subcommands:
//!   set-api-keys    — persist provider API keys to ~/.gm-miner/config.json
//!   deploy          — trust-correct single-shot deploy: fetch approved hashes,
//!                     deploy via Phala Cloud, verify hashes, register image
//!   login           — Taostats device-code OAuth flow
//!   register-image  — re-register the deployed miner's image hashes
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
    client::{get_auth_config, RegistryClient},
    config::{self, Config, ProviderKeys},
    deploy::{
        fetch_supported_versions, format_created_at, normalize_hash, parse_phala_cvm_detail,
        parse_phala_cvm_endpoint, preflight_phala_cli, prepare_deploy_target,
        resolve_registry_credentials, select_version, to_ratls_passthrough_endpoint, verify_hashes,
        ImageProvisioner, PhalaClient, DEFAULT_BOOT_TIMEOUT_SECS, DEFAULT_OS_IMAGE,
        PHALA_ENDPOINT_FIELD,
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

    /// Deploy the miner to Phala Cloud with trust-correct hash verification.
    ///
    /// Reads provider API keys from ~/.gm-miner/config.json (set them first
    /// with `gm-miner set-api-keys`), fetches the registry-approved image
    /// version, builds and pushes the miner image to a public registry,
    /// submits the compose stack to Phala Cloud, verifies the deployed CVM's
    /// measured hashes match the registry approval, then registers the
    /// image automatically.
    ///
    /// Phala Cloud manages the confidential VM, the KMS, and `app_id`
    /// authorization. Authentication uses a Phala Cloud API key — set
    /// `PHALA_CLOUD_API_KEY` or run `phala login` before deploying.
    Deploy {
        /// Pre-built digest-pinned image reference (registry/repo@sha256:...).
        ///
        /// When set (or `GM_IMAGE_REF` is in env), the local image build is
        /// skipped and this ref is embedded in the compose file directly.
        /// When omitted, the miner image is built and pushed to the public
        /// registry given by `--image-repo` and the resulting digest is
        /// pinned automatically.
        #[arg(long, env = "GM_IMAGE_REF")]
        image_ref: Option<String>,

        /// Pin to a specific approved version by index (1 = newest).
        /// Defaults to the newest supported version.
        #[arg(long)]
        version: Option<usize>,

        /// Phala Cloud CVM name.
        #[arg(long, default_value = "gm-miner-1")]
        app_name: String,

        /// Staging directory for the rendered compose + env files (the full
        /// path used verbatim). Defaults to `dist/<app_name>` relative to
        /// the current directory.
        #[arg(long)]
        dist_dir: Option<std::path::PathBuf>,

        /// Public container registry repo to build and push the miner image
        /// to — Phala Cloud pulls the image from here. Required unless
        /// `--image-ref` is supplied. Example: `ghcr.io/<owner>/gm-miner`.
        #[arg(long, env = "GM_IMAGE_REPO")]
        image_repo: Option<String>,

        /// Image tag applied to the build before digest resolution.
        #[arg(long, env = "IMAGE_TAG", default_value = "v0.1.0")]
        image_tag: String,

        /// Phala Cloud instance type for the CVM.
        #[arg(long, env = "PHALA_INSTANCE_TYPE", default_value = "tdx.medium")]
        instance_type: String,

        /// Disk size for the CVM (with unit, e.g. `40G`).
        #[arg(long, env = "PHALA_DISK_SIZE", default_value = "40G")]
        disk_size: String,

        /// Production OS image for the CVM (`phala deploy --image`). The
        /// version must match the dstack version of the Phala node the CVM
        /// lands on — prod5/prod9 currently run dstack v0.5.7.
        #[arg(long, env = "PHALA_OS_IMAGE", default_value = DEFAULT_OS_IMAGE)]
        os_image: String,

        /// Repository root used as the Docker build context. Defaults to
        /// the current directory.
        #[arg(long)]
        repo_root: Option<std::path::PathBuf>,

        /// How long to wait for the CVM to boot and report its measured
        /// hashes via `phala cvms get --json` (seconds). Default: 300.
        #[arg(long, default_value_t = DEFAULT_BOOT_TIMEOUT_SECS)]
        boot_timeout_secs: u64,
    },

    /// Authenticate with Taostats (device-code OAuth flow) and store
    /// credentials in ~/.gm-miner/config.json.
    Login {
        /// Do not automatically open the browser.
        #[arg(long)]
        no_browser: bool,
    },

    /// Register this miner's image compose hash + capabilities with the registry.
    ///
    /// The normal operator flow uses `gm-miner deploy` which verifies and
    /// registers in one step.  Use this subcommand only for re-registering
    /// without redeploying (e.g. after a registry resync or for debugging).
    ///
    /// The compose + OS image hashes are read automatically from the
    /// deployed CVM via `phala cvms get <app-id> --json`; the CVM must
    /// already be deployed (`gm-miner deploy`).
    RegisterImage {
        /// Phala Cloud app id of the deployed CVM (e.g. `app_abc123`).
        #[arg(long)]
        app_id: String,
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
            image_repo,
            image_tag,
            instance_type,
            disk_size,
            os_image,
            repo_root,
            boot_timeout_secs,
        } => {
            let cfg = load_config(cli.testnet, cli.api_url)?;
            let cfg = ensure_fresh_token(cfg).await?;
            // --dist-dir is the staging directory used verbatim. Default:
            // dist/<app_name> relative to cwd. Resolve it once here so every
            // deploy step shares the same path.
            let project_dir =
                dist_dir.unwrap_or_else(|| std::path::PathBuf::from("dist").join(&app_name));
            cmd_deploy_subcommand(
                cfg,
                DeployArgs {
                    app_name,
                    image_ref,
                    project_dir,
                    image_repo,
                    image_tag,
                    instance_type,
                    disk_size,
                    os_image,
                    repo_root,
                    version,
                    boot_timeout_secs,
                },
            )
            .await
        }
        Command::Login { no_browser } => cmd_login(cli.testnet, cli.api_url, !no_browser).await,
        Command::RegisterImage { app_id } => {
            let cfg = load_config(cli.testnet, cli.api_url)?;
            let cfg = ensure_fresh_token(cfg).await?;
            // Re-send the network's persisted node secret so a standalone
            // re-registration keeps the registry's stored copy in sync
            // with what the deployed envoy enforces. Absent (a miner
            // predating node-secret auth) means the registry leaves any
            // stored secret untouched.
            let node_secret = cfg
                .active_network_entry()
                .and_then(|n| n.node_secret.clone());
            let mut client = RegistryClient::new(cfg);
            cmd_register_image(&mut client, &app_id, node_secret.as_deref()).await
        }
        Command::ListProducts => {
            let cfg = load_config(cli.testnet, cli.api_url)?;
            let cfg = ensure_fresh_token(cfg).await?;
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
            let cfg = ensure_fresh_token(cfg).await?;
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
            let cfg = ensure_fresh_token(cfg).await?;
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
            let cfg = ensure_fresh_token(cfg).await?;
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

/// Ensure the active network's access token is usable, refreshing it silently
/// if it has expired (or is within the expiry margin).
///
/// Returns a [`Config`] whose active token is fresh. The sequence is:
///   1. Token still valid → return `cfg` untouched (no network call).
///   2. Token expired but a `refresh_token` is stored → POST the
///      `refresh_token` grant. On success the new tokens are persisted and
///      returned. The auth-gateway rotates the refresh token, so a rotated
///      value in the response replaces the stored one.
///   3. No refresh token, or the refresh was rejected (revoked / expired /
///      grant not permitted) → fall back to the full device-code flow.
///
/// `open_browser` only affects the step-3 fallback; the refresh path never
/// opens a browser.
///
/// # Errors
/// Returns an error if `/auth/config` cannot be fetched, the device-flow
/// fallback fails, or the refreshed config cannot be saved.
async fn ensure_fresh_token(mut cfg: Config) -> Result<Config> {
    let needs_refresh = cfg
        .active_tokens()
        .is_some_and(config::TokenEntry::is_expired_or_near);
    if !needs_refresh {
        return Ok(cfg);
    }

    let api_url = cfg.api_url();
    let auth_cfg = get_auth_config(&api_url)
        .await
        .with_context(|| format!("fetch auth config from {api_url}/auth/config"))?;

    let token = obtain_fresh_token(&cfg, &auth_cfg).await?;

    // A refresh response may omit `refresh_token` when the auth-gateway
    // chooses not to rotate it — keep the previously stored value so the
    // next refresh still has something to present.
    let previous_refresh = cfg.active_tokens().and_then(|t| t.refresh_token.clone());
    cfg.active_entry_mut().tokens = Some(token.to_entry_keeping(previous_refresh));
    config::save(&cfg).context("save refreshed token")?;
    Ok(cfg)
}

/// Obtain a fresh access token: try the stored `refresh_token` first, fall
/// back to the device-code flow when there is none or it is rejected.
///
/// Split out of [`ensure_fresh_token`] so the refresh-vs-device decision is a
/// single linear function with no config mutation.
async fn obtain_fresh_token(
    cfg: &Config,
    auth_cfg: &gm_miner_cli::client::AuthConfig,
) -> Result<auth::TokenResponse> {
    let stored_refresh = cfg.active_tokens().and_then(|t| t.refresh_token.clone());

    let Some(refresh) = stored_refresh else {
        eprintln!("Access token expired — re-authenticating.");
        return device_login_from(auth_cfg, true).await;
    };

    match auth::refresh_token(&auth_cfg.token_url, &auth_cfg.client_id, &refresh).await? {
        auth::RefreshOutcome::Refreshed(token) => {
            eprintln!("Access token refreshed.");
            Ok(token)
        }
        auth::RefreshOutcome::Rejected => {
            eprintln!("Stored credentials have expired — re-authenticating.");
            device_login_from(auth_cfg, true).await
        }
    }
}

/// Run the device-code flow using endpoints from an already-fetched
/// [`AuthConfig`]. Shared by `cmd_login` and the [`ensure_fresh_token`]
/// fallback so neither re-fetches `/auth/config`.
async fn device_login_from(
    auth_cfg: &gm_miner_cli::client::AuthConfig,
    open_browser: bool,
) -> Result<auth::TokenResponse> {
    auth::device_login(
        &auth_cfg.device_code_url,
        &auth_cfg.token_url,
        &auth_cfg.client_id,
        &auth_cfg.scopes,
        open_browser,
    )
    .await
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
    /// The resolved staging directory used verbatim by every deploy step.
    /// Set once in `cmd_deploy_subcommand` from `--dist-dir` or the
    /// `dist/<app_name>` default, so no later step recomputes — and
    /// diverges from — it.
    project_dir: std::path::PathBuf,
    image_repo: Option<String>,
    image_tag: String,
    instance_type: String,
    disk_size: String,
    os_image: String,
    repo_root: Option<std::path::PathBuf>,
    version: Option<usize>,
    boot_timeout_secs: u64,
}

/// Build and run the deploy subcommand from parsed CLI arguments.
///
/// Separated from `main` to keep the dispatch match arm small.
async fn cmd_deploy_subcommand(cfg: Config, args: DeployArgs) -> Result<()> {
    let phala = gm_miner_cli::deploy::RealPhalaClient::new(
        args.app_name.clone(),
        args.project_dir.clone(),
        args.instance_type.clone(),
        args.disk_size.clone(),
        args.os_image.clone(),
    );
    let mut client = RegistryClient::new(cfg.clone());
    cmd_deploy(&cfg, &mut client, &phala, &args).await
}

/// Real [`ImageProvisioner`]: builds the miner image and pushes it to a
/// public container registry, returning the digest-pinned ref.
///
/// When `args.image_ref` is supplied the build is skipped entirely and the
/// pre-built ref is returned as-is. Without it, `--image-repo` must be set:
/// the image is built with `docker buildx --push` to that public repo
/// (Phala Cloud pulls from there) and the pushed digest is pinned.
struct PublicRegistryProvisioner<'a> {
    args: &'a DeployArgs,
}

impl ImageProvisioner for PublicRegistryProvisioner<'_> {
    fn provision(&self) -> Result<String> {
        use gm_miner_cli::image;

        let args = self.args;

        if let Some(pre_built) = &args.image_ref {
            println!("Using pre-built image ref (skipping local build): {pre_built}");
            return Ok(pre_built.clone());
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
    phala: &dyn PhalaClient,
    args: &DeployArgs,
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

    // Step 1c: preflight that the `phala` CLI is installed. It is the
    // runtime dependency of the deploy — catch a missing CLI now, with an
    // install hint, before the multi-minute image build.
    preflight_phala_cli()?;

    // Step 2: auth preflight. The Phala Cloud deploy is slow and
    // irreversible for the operator (CVM created), so we refuse to start
    // the deploy unless the registry will accept the eventual
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

    // Step 5: prepare the deploy target — build and push the miner image
    // to the registry (or accept a pre-built `--image-ref`) and render the
    // compose template with the digest-pinned ref and the active network.
    let provisioner = PublicRegistryProvisioner { args };
    let target = prepare_deploy_target(&provisioner, cfg.active_network())?;

    // Step 5b: resolve private-registry pull credentials. The miner image
    // lives on a private GHCR repo, so the CVM's pre-launch script needs
    // `DSTACK_DOCKER_*` env vars to `docker login` and pull. Derived from
    // the image ref's registry host plus the operator-set
    // GHCR_PULL_USERNAME / GHCR_PULL_TOKEN env vars.
    let registry_creds = resolve_registry_credentials(&target.image_ref)?;

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

    // Step 7: verify hashes. The returned hashes are normalized
    // (lowercased, `sha256:` prefix stripped) so the loud check and the
    // registration in step 8 agree on the exact value.
    println!("Verifying hashes against registry approval ...");
    let verified = verify_hashes(&actual.hashes, approved)?;
    println!("  compose_hash  : OK ({})", verified.compose_sha256);
    println!("  os_image_hash : OK ({})", verified.os_image_hash);

    // Step 8: register the image, carrying the node secret so the
    // registry stores it and serves it to the gateway, and the CVM's
    // endpoint (the registry requires `endpoint` + `attestation_endpoint`
    // on every registration). The hashes are already verified against the
    // registry approval, so POST directly.
    println!("Registering image with the registry ...");
    post_register_image(
        client,
        &RegisterImageArgs {
            compose_hash: &verified.compose_sha256,
            os_image_hash: &verified.os_image_hash,
            endpoint: &actual.endpoint,
            node_secret: Some(&node_secret),
        },
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

    let api_url = api_url_override.unwrap_or_else(|| cfg.api_url());

    // Fetch OAuth endpoints and client identity from the registry. Nothing
    // auth-related is baked into the binary — it all comes from the registry
    // at login time.
    let auth_cfg = get_auth_config(&api_url)
        .await
        .with_context(|| format!("fetch auth config from {api_url}/auth/config"))?;

    let token = device_login_from(&auth_cfg, open_browser).await?;

    let entry = cfg.active_entry_mut();
    entry.api_url = Some(api_url);
    entry.tokens = Some(token.to_entry());

    config::save(&cfg).context("save config")?;

    println!("Login successful.");
    println!("Credentials saved to {}", config::config_path().display());
    Ok(())
}

/// `gm-miner register-image` — re-register the deployed miner's image with
/// the registry without a full redeploy.
///
/// Auto-discovers the deployed `compose_hash` + `os_image_hash` + public
/// endpoint by reading `phala cvms get <app-id> --json` (the same CVM-
/// detail read `gm-miner deploy` performs), then POSTs them — and the
/// persisted node secret — to `/miners/register`.
///
/// Fails with an actionable error if the CVM is not deployed or its
/// measured hashes / endpoint are not yet populated.
async fn cmd_register_image(
    client: &mut RegistryClient,
    app_id: &str,
    node_secret: Option<&str>,
) -> Result<()> {
    preflight_phala_cli()?;

    let out = std::process::Command::new("phala")
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
        .context("read deployed miner hashes from phala cvms get")?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no measured hashes for CVM '{app_id}' \
                 (compose_hash/os_image_hash not present in \
                 `phala cvms get {app_id} --json`); \
                 deploy first with `gm-miner deploy`"
            )
        })?;

    // The registry requires a non-empty `endpoint` on every registration —
    // read it from the same CVM-detail document already fetched above,
    // then rewrite it to the dstack TLS-passthrough (`s`-suffix) form so
    // the registered URL is the one on which the miner's RA-TLS
    // certificate is actually presented.
    let endpoint = parse_phala_cvm_endpoint(out.status.success(), &out.stdout)
        .context("read deployed miner endpoint from phala cvms get")?
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

    // Normalize before POST: `phala cvms get` may report a `sha256:`-prefixed
    // hash, but the registry's `/miners/register` only accepts bare lowercase
    // hex.
    post_register_image(
        client,
        &RegisterImageArgs {
            compose_hash: &normalize_hash(&hashes.compose_sha256),
            os_image_hash: &normalize_hash(&hashes.os_image_hash),
            endpoint: &endpoint,
            node_secret,
        },
    )
    .await
}

/// Fields sent to the registry's `/miners/register` endpoint.
struct RegisterImageArgs<'a> {
    compose_hash: &'a str,
    os_image_hash: &'a str,
    /// The miner's public envoy endpoint. The registry requires this.
    endpoint: &'a str,
    /// The miner's node secret, or `None` for a miner predating
    /// node-secret auth.
    node_secret: Option<&'a str>,
}

/// POST verified compose + OS image hashes to `/miners/register`.
///
/// Shared by `cmd_register_image` (auto-discovered hashes) and `cmd_deploy`
/// (hashes already verified against the registry approval).
async fn post_register_image(
    client: &mut RegistryClient,
    args: &RegisterImageArgs<'_>,
) -> Result<()> {
    // The registry requires both `endpoint` and `attestation_endpoint` as
    // non-empty strings. `attestation_endpoint` is reserved for future
    // attested-channel work and not yet consumed by the registry, so the
    // envoy endpoint is sent as a placeholder for both.
    let mut body = serde_json::json!({
        "compose_hash": args.compose_hash,
        "os_image_hash": args.os_image_hash,
        "endpoint": args.endpoint,
        "attestation_endpoint": args.endpoint,
    });
    // Include the node secret so the registry stores it and serves it to
    // the gateway (Mechanism 1 of attestation-and-identity.md). Omitted
    // when the miner has no secret — a miner predating node-secret auth.
    if let Some(secret) = args.node_secret {
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
    println!("  Compose  : {}", args.compose_hash);
    println!("  OS image : {}", args.os_image_hash);
    println!("  Endpoint : {}", args.endpoint);
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
