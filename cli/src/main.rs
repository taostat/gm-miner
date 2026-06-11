//! gm-miner CLI.
//!
//! Subcommands:
//!   set-api-keys     — persist provider API keys to ~/.gm-miner/config.json
//!   deploy           — trust-correct single-shot deploy: fetch approved hashes,
//!                      deploy via Phala Cloud, verify hashes, register image
//!   login            — Taostats device-code OAuth flow
//!   register-image   — re-register the deployed miner's image hashes
//!   list-products    — show the miner's declared offers (GET /miners/me)
//!   declare-product  — declare a single offer (--provider X --model Y --discount-pct N)
//!   declare-products — fan out one discount over the whole catalog, or one provider
//!   status           — show current registration state and per-product eligibility
//!
//! Pricing follows the registry's pct-discount model: a miner declares
//! a single `discount_bp` in `[0, 9990]` per (provider, model) offer, and
//! the gateway derives the miner payout as
//! `retail × (10_000 − discount_bp) / 10_000` at settlement. See
//! `docs/plans/miner-pct-discount-pricing.md` in the gm repo.
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
        DeployEnvInputs, DeployRequest, ImageProvisioner, PhalaClient, DEFAULT_BOOT_TIMEOUT_SECS,
        DEFAULT_OS_IMAGE, PHALA_ENDPOINT_FIELD,
    },
    node_secret,
    oauth_subscription::{self, OauthEnvVars, OauthProvider, PastedOauthAuth},
    tos,
    types::{
        MinerStatus, Product, ProductCatalogResponse, ProductDeclarationRequest, Provider,
        RetailDimensions,
    },
};

/// Inclusive upper bound on `discount_bp`. The registry's pydantic schema
/// pins the same value (`registry/.../schemas.py::ProductDeclarationRequest`);
/// kept in sync by the API-shape pin in the PR plan §3.1.
const MAX_DISCOUNT_BP: u32 = 9_990;

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
#[expect(
    clippy::large_enum_variant,
    reason = "clap parses exactly one variant per invocation, so the \
              enum is short-lived and stack size is not a concern"
)]
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

        /// Path to a `~/.codex/auth.json` (or Hermes `auth.json` carrying
        /// an `openai-codex` block) exported on your laptop. When set,
        /// the `OpenAI` provider is wired in `oauth_subscription` mode
        /// using your personal `ChatGPT` Plus subscription. See
        /// `docs/auth-modes.md` for the `ToS` guidance; a one-time
        /// confirmation banner is printed before the deploy proceeds.
        #[arg(long)]
        paste_codex_auth: Option<std::path::PathBuf>,

        /// Path to a `~/.claude/.credentials.json` (or Hermes
        /// `auth.json` carrying an `anthropic` block) exported on your
        /// laptop. Same Phase A manual-paste UX as `--paste-codex-auth`,
        /// but for the Claude Pro/Max subscription.
        #[arg(long)]
        paste_claude_auth: Option<std::path::PathBuf>,
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

    /// Show the miner's declared offers (`provider`, `model`, discount percent,
    /// `is_offered`, `is_eligible`) from `GET /miners/me`. Use `status` for
    /// the broader miner registration view.
    ListProducts,

    /// Declare a single miner-product offer.
    ///
    /// One POST to `/miners/products`. For batch declarations against the
    /// whole catalog (or one provider's slice), use `declare-products`.
    DeclareProduct {
        /// Provider: anthropic, openai, or gemini.
        #[arg(long)]
        provider: Provider,

        /// Model identifier, e.g. `claude-sonnet-4-6`.
        #[arg(long)]
        model: String,

        /// Percent off retail; range [0, 99.90]. You will receive
        /// (100 - PCT)% of retail per token (e.g. `--discount-pct 10.5`
        /// means you keep 89.5% of every per-Mtok dollar). `0` is at
        /// retail; the `99.90` cap keeps the per-request revenue
        /// strictly positive.
        #[arg(long = "discount-pct", value_name = "PCT", value_parser = parse_discount_pct)]
        discount_bp: u32,
    },

    /// Fan a single discount out across multiple offers.
    ///
    /// Discovers products via the public `GET /products` endpoint, filters
    /// by `--provider` when set, then POSTs one offer per surviving entry.
    /// Per-product failures are reported individually and do not abort the
    /// loop — the final summary lists ok/err counts.
    DeclareProducts {
        /// Optional provider filter. When set, only products from this
        /// provider are declared. Omit to fan out over the whole catalog.
        #[arg(long)]
        provider: Option<Provider>,

        /// Percent off retail; range [0, 99.90]. You will receive
        /// (100 - PCT)% of retail per token, applied to every product
        /// the fan-out touches.
        #[arg(long = "discount-pct", value_name = "PCT", value_parser = parse_discount_pct)]
        discount_bp: u32,
    },

    /// Show the miner's current registration status and per-product eligibility.
    Status,
}

#[tokio::main]
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
            paste_codex_auth,
            paste_claude_auth,
        } => {
            let cfg = load_config(cli.testnet, cli.api_url)?;
            let cfg = ensure_fresh_token(cfg).await?;
            // --dist-dir is the staging directory used verbatim. Default:
            // dist/<app_name> relative to cwd. Resolve it once here so every
            // deploy step shares the same path.
            let project_dir =
                dist_dir.unwrap_or_else(|| std::path::PathBuf::from("dist").join(&app_name));

            // Phase A OAuth subscription wiring. Either paste flag triggers
            // the one-time ToS confirmation banner before the deploy starts
            // (see `docs/auth-modes.md`); the parsed bundle then rides into
            // the encrypted `phala deploy` env as `GM_<PROVIDER>_OAUTH_*`.
            let (anthropic_oauth, openai_oauth) =
                resolve_oauth_pastes(paste_claude_auth.as_deref(), paste_codex_auth.as_deref())?;

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
                    anthropic_oauth,
                    openai_oauth,
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
            discount_bp,
        } => {
            let cfg = load_config(cli.testnet, cli.api_url)?;
            let cfg = ensure_fresh_token(cfg).await?;
            let mut client = RegistryClient::new(cfg);
            cmd_declare_product(&mut client, &provider, &model, discount_bp).await
        }
        Command::DeclareProducts {
            provider,
            discount_bp,
        } => {
            let cfg = load_config(cli.testnet, cli.api_url)?;
            let cfg = ensure_fresh_token(cfg).await?;
            let mut client = RegistryClient::new(cfg);
            cmd_declare_products(&mut client, provider.as_ref(), discount_bp).await
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

/// clap `value_parser` for `--discount-pct`.
///
/// Parses a percent string with up to two decimal places into the registry's
/// integer basis-point wire value without floating-point arithmetic.
fn parse_discount_pct(s: &str) -> Result<u32, String> {
    let mut parts = s.split('.');
    let whole_s = parts.next().unwrap_or_default();
    let cents_s = parts.next();
    if parts.next().is_some() {
        return Err(format!(
            "invalid --discount-pct {s:?}: use a percent in [0, 99.90] with at most one decimal point"
        ));
    }
    if whole_s.is_empty() || !whole_s.chars().all(|c| c.is_ascii_digit()) {
        return Err(format!(
            "invalid --discount-pct {s:?}: whole percent must be non-negative digits"
        ));
    }

    let whole = whole_s
        .parse::<u32>()
        .map_err(|_| format!("invalid --discount-pct {s:?}: whole percent is too large"))?;
    let cents = match cents_s {
        None | Some("") => 0,
        Some(cents_s) if cents_s.len() > 2 => {
            return Err(format!(
                "invalid --discount-pct {s:?}: use at most 2 decimal places"
            ));
        }
        Some(cents_s) if cents_s.chars().all(|c| c.is_ascii_digit()) => {
            let cents = cents_s.parse::<u32>().map_err(|_| {
                format!("invalid --discount-pct {s:?}: decimal percent is not parseable")
            })?;
            if cents_s.len() == 1 {
                cents * 10
            } else {
                cents
            }
        }
        _ => {
            return Err(format!(
                "invalid --discount-pct {s:?}: decimal percent must contain digits only"
            ));
        }
    };

    let parsed = whole
        .checked_mul(100)
        .and_then(|v| v.checked_add(cents))
        .ok_or_else(|| format!("invalid --discount-pct {s:?}: percent is too large"))?;
    if parsed > MAX_DISCOUNT_BP {
        return Err(format!(
            "--discount-pct {s:?} is above the cap of 99.90%; \
             the registry rejects anything above {MAX_DISCOUNT_BP} bp"
        ));
    }
    Ok(parsed)
}

fn format_discount_pct(discount_bp: u32) -> String {
    let whole = discount_bp / 100;
    let cents = discount_bp % 100;
    if cents == 0 {
        return whole.to_string();
    }
    format!("{whole}.{cents:02}")
        .trim_end_matches('0')
        .trim_end_matches('.')
        .to_owned()
}

/// Effective per-Mtok ndollars the miner receives for one dimension:
/// `floor(retail × (10_000 − discount_bp) / 10_000)`. Matches the
/// gateway's per-dimension floor in `gateway/src/money/settle.rs::
/// effective_per_mtok_prices`, so what we display here is byte-for-byte
/// the number the miner is paid.
fn effective_per_mtok_ndollars(retail_ndollars: u64, discount_bp: u32) -> u64 {
    let bp = u128::from(discount_bp.min(MAX_DISCOUNT_BP));
    let total = u128::from(retail_ndollars);
    let effective = (total * (10_000 - bp)) / 10_000;
    u64::try_from(effective).unwrap_or(retail_ndollars)
}

/// Render a per-Mtok ndollar value as a dollar amount with 3 decimal
/// places (e.g. `3_000_000_000 → "$3.000"`, `2_685_000_000 → "$2.685"`).
/// One nano-dollar is `10^-9` USD; 3 decimals is one-tenth of a cent
/// per Mtok, which is the resolution the operator actually cares about.
fn format_per_mtok_usd(ndollars: u64) -> String {
    let dollars = ndollars / 1_000_000_000;
    let millis = (ndollars % 1_000_000_000) / 1_000_000;
    format!("${dollars}.{millis:03}")
}

/// One-line summary of the per-Mtok rate the miner will receive on a
/// product, given retail dimensions and a discount. Shared between
/// the single-product declaration output and the fan-out summary so
/// every site renders the same shape.
fn effective_rate_summary(retail: &RetailDimensions, discount_bp: u32) -> String {
    let eff_in = effective_per_mtok_ndollars(retail.input_per_mtok_ndollars, discount_bp);
    let eff_out = effective_per_mtok_ndollars(retail.output_per_mtok_ndollars, discount_bp);
    format!(
        "{} in / {} out per Mtok",
        format_per_mtok_usd(eff_in),
        format_per_mtok_usd(eff_out)
    )
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
    /// Phase A OAuth subscription bundle for Anthropic, parsed from the
    /// operator-pasted Claude Code / Hermes auth.json (set via
    /// `--paste-claude-auth`). `None` keeps the existing `api_key` path.
    anthropic_oauth: Option<OauthEnvVars>,
    /// Phase A OAuth subscription bundle for `OpenAI` / Codex (set via
    /// `--paste-codex-auth`). Same shape as `anthropic_oauth`.
    openai_oauth: Option<OauthEnvVars>,
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
    // Step 1: ensure at least one provider credential is configured.
    // Accept either:
    //   - API keys via `gm-miner set-api-keys` (provider_keys.any_set()), or
    //   - OAuth subscription bundles via --paste-claude-auth / --paste-codex-auth
    //     flags on this command (args.anthropic_oauth / args.openai_oauth).
    // A deploy with only OAuth bundles renders with an empty ProviderKeys; the
    // sidecar + envoy route subscription traffic via the pasted refresh tokens.
    let oauth_configured = args.anthropic_oauth.is_some() || args.openai_oauth.is_some();
    let empty_keys = gm_miner_cli::config::ProviderKeys::default();
    let keys = match cfg.provider_keys.as_ref().filter(|k| k.any_set()) {
        Some(k) => k,
        None if oauth_configured => &empty_keys,
        None => {
            anyhow::bail!(
                "no provider credentials; run `gm-miner set-api-keys \
                 --anthropic <key>` (and/or --openai / --google) first, \
                 or pass --paste-claude-auth / --paste-codex-auth to use \
                 an OAuth subscription"
            );
        }
    };

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
    let actual = phala.deploy(&DeployRequest {
        compose_yaml: &target.rendered_compose,
        env: DeployEnvInputs {
            provider_keys: keys,
            node_secret: &node_secret,
            registry_creds: registry_creds.as_ref(),
            anthropic_oauth: args.anthropic_oauth.as_ref(),
            openai_oauth: args.openai_oauth.as_ref(),
        },
        boot_timeout_secs: args.boot_timeout_secs,
    })?;

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

/// Read and parse the OAuth subscription auth.json paste flags, gating
/// on a one-time `ToS` confirmation banner before the deploy proceeds.
///
/// Returns `(anthropic_bundle, openai_bundle)` — each `Some` only when
/// the corresponding `--paste-*-auth` flag was set. When at least one
/// flag is set the [`ToS confirmation`](gm_miner_cli::tos) is required;
/// declining (or piping the wrong phrase) aborts the deploy before any
/// CVM work runs.
///
/// # Errors
/// Returns an error if either file cannot be read, fails to parse, or
/// the operator declines the `ToS` prompt.
fn resolve_oauth_pastes(
    paste_claude_auth: Option<&std::path::Path>,
    paste_codex_auth: Option<&std::path::Path>,
) -> Result<(Option<OauthEnvVars>, Option<OauthEnvVars>)> {
    if paste_claude_auth.is_none() && paste_codex_auth.is_none() {
        return Ok((None, None));
    }

    // Either paste flag triggers the same one-time disclaimer. Read
    // stdin from a buffered handle so `require_confirmation` can pull a
    // single line. The banner goes to stderr to keep stdout clean.
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let mut err = std::io::stderr();
    tos::require_confirmation(&mut input, &mut err)
        .context("ToS confirmation required for OAuth subscription auth")?;

    let anthropic_oauth = paste_claude_auth
        .map(|path| parse_oauth_paste(path, OauthProvider::Anthropic))
        .transpose()?
        .map(|auth| OauthEnvVars::for_provider(OauthProvider::Anthropic, auth));
    let openai_oauth = paste_codex_auth
        .map(|path| parse_oauth_paste(path, OauthProvider::Openai))
        .transpose()?
        .map(|auth| OauthEnvVars::for_provider(OauthProvider::Openai, auth));
    Ok((anthropic_oauth, openai_oauth))
}

/// Read `path` and parse it as a pasted OAuth auth.json for `provider`.
fn parse_oauth_paste(path: &std::path::Path, provider: OauthProvider) -> Result<PastedOauthAuth> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("read pasted {provider} auth.json from {}", path.display()))?;
    oauth_subscription::parse_pasted_auth_json(&bytes, provider)
        .with_context(|| format!("parse pasted {provider} auth.json from {}", path.display()))
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

/// `gm-miner list-products` — show the miner's declared offers.
///
/// Calls `GET /miners/me` and tabulates each `ProductOfferStatus`. Helps the
/// operator verify what their `declare-product[s]` calls actually persisted.
async fn cmd_list_products(client: &mut RegistryClient) -> Result<()> {
    let resp = client
        .get(gm_miner_cli::client::ME_PATH)
        .await
        .context("GET /miners/me")?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        bail!("list-products failed ({status}): {body}");
    }

    let miner: MinerStatus = resp.json().await.context("parse miner status")?;

    if miner.products.is_empty() {
        println!("No products declared.");
        return Ok(());
    }

    // Join against the catalog so each row can render the effective
    // per-Mtok rate the miner actually receives. The catalog is the
    // single source of truth for retail; doing the join here avoids
    // adding a retail block to `/miners/me` on the registry side.
    let catalog = fetch_catalog(client).await?;
    let retail_by_key: std::collections::HashMap<_, _> = catalog
        .products
        .iter()
        .map(|p| {
            (
                (p.provider.clone(), p.model.as_str()),
                &p.retail_price.dimensions,
            )
        })
        .collect();

    println!(
        "{:<12} {:<32} {:<10} {:<38} {:<8} {:<8}",
        "PROVIDER", "MODEL", "DISCOUNT", "YOU RECEIVE / MTOK", "OFFERED", "ELIGIBLE"
    );
    println!("{}", "-".repeat(110));
    for p in &miner.products {
        let provider: Result<Provider, _> = p.provider.parse();
        let (discount_label, rate_label) = match (p.discount_bp, provider) {
            (Some(bp), Ok(prov)) => {
                let label = format!("{}%", format_discount_pct(bp));
                let rate = retail_by_key.get(&(prov, p.model.as_str())).map_or_else(
                    || "(retail unknown)".to_owned(),
                    |dims| effective_rate_summary(dims, bp),
                );
                (label, rate)
            }
            _ => ("—".to_owned(), "—".to_owned()),
        };
        println!(
            "{:<12} {:<32} {:<10} {:<38} {:<8} {:<8}",
            p.provider,
            p.model,
            discount_label,
            rate_label,
            if p.is_offered { "yes" } else { "no" },
            if p.is_eligible { "yes" } else { "no" },
        );
    }
    println!("\n{} offers total.", miner.products.len());
    Ok(())
}

/// `gm-miner declare-product` — POST one (provider, model, `discount_bp`)
/// offer to `/miners/products`. The registry treats POST as upsert, so this
/// also handles updating an existing offer's discount.
///
/// Fetches the catalog first so the success output can render retail +
/// the effective per-Mtok rate the miner will actually receive. The
/// extra HTTP call also catches "unknown product" before the POST goes
/// out, which lets the CLI fail with a clearer error than the registry's
/// generic 404.
async fn cmd_declare_product(
    client: &mut RegistryClient,
    provider: &Provider,
    model: &str,
    discount_bp: u32,
) -> Result<()> {
    let catalog = fetch_catalog(client).await?;
    let product = catalog
        .products
        .iter()
        .find(|p| &p.provider == provider && p.model == model)
        .ok_or_else(|| anyhow::anyhow!("{provider}/{model} is not in the registry catalog"))?;

    post_declare_product(client, provider, model, discount_bp).await?;

    let dims = &product.retail_price.dimensions;
    let retail_in = format_per_mtok_usd(dims.input_per_mtok_ndollars);
    let retail_out = format_per_mtok_usd(dims.output_per_mtok_ndollars);
    let eff_in = format_per_mtok_usd(effective_per_mtok_ndollars(
        dims.input_per_mtok_ndollars,
        discount_bp,
    ));
    let eff_out = format_per_mtok_usd(effective_per_mtok_ndollars(
        dims.output_per_mtok_ndollars,
        discount_bp,
    ));
    // What the miner keeps per token, as a percentage of retail. With
    // discount_bp = 0 this reads "100%"; at the 99.90% cap this is
    // "0.1% of retail" — the minimum positive payout.
    let kept_bp = 10_000_u32.saturating_sub(discount_bp);
    let kept_pct = format_discount_pct(kept_bp);

    println!("{provider}/{model}");
    println!("  Retail       : {retail_in} input / {retail_out} output per Mtok");
    println!("  Declared     : {}% off", format_discount_pct(discount_bp));
    println!("  You receive  : {eff_in} input / {eff_out} output per Mtok ({kept_pct}% of retail)");
    println!("  → ok");
    Ok(())
}

/// `gm-miner declare-products` — fan a single discount out over the catalog.
///
/// 1. Public `GET /products` discovers every active product.
/// 2. If `provider_filter` is set, drops products from other providers.
/// 3. Drops deprecated products (the registry rejects offers on them anyway).
/// 4. POSTs one offer per surviving product. Each result is printed
///    individually (`provider/model: N% → ok|ERROR …`).
/// 5. Reports a final ok/err summary.
///
/// Per-product failures do not abort the loop. The function returns `Ok(())`
/// when every POST succeeded and an aggregated error otherwise so the CLI
/// exits non-zero on partial failure.
async fn cmd_declare_products(
    client: &mut RegistryClient,
    provider_filter: Option<&Provider>,
    discount_bp: u32,
) -> Result<()> {
    let catalog = fetch_catalog(client).await?;
    let targets = filter_catalog(&catalog.products, provider_filter);

    if targets.is_empty() {
        let scope =
            provider_filter.map_or_else(|| "the catalog".to_owned(), |p| format!("provider {p}"));
        bail!("no active products found in {scope} to declare against");
    }

    let discount_pct = format_discount_pct(discount_bp);
    println!(
        "Declaring {discount_pct}% off retail on {} product(s)...",
        targets.len()
    );

    let mut ok_count = 0_usize;
    let mut err_count = 0_usize;
    for product in &targets {
        let rate = effective_rate_summary(&product.retail_price.dimensions, discount_bp);
        match post_declare_product(client, &product.provider, &product.model, discount_bp).await {
            Ok(()) => {
                println!(
                    "  {}/{}: {discount_pct}% off → {rate} → ok",
                    product.provider, product.model
                );
                ok_count += 1;
            }
            Err(err) => {
                println!(
                    "  {}/{}: {discount_pct}% off → {rate} → ERROR {err}",
                    product.provider, product.model
                );
                err_count += 1;
            }
        }
    }

    println!("\nSummary: {ok_count} ok, {err_count} failed.");
    if err_count > 0 {
        bail!("{err_count} of {} declarations failed", targets.len());
    }
    Ok(())
}

/// Issue one `POST /miners/products` and translate the result into a typed
/// `Result<(), anyhow::Error>` so both `declare-product` and
/// `declare-products` share the same wire-shape + error-detail logic.
async fn post_declare_product(
    client: &mut RegistryClient,
    provider: &Provider,
    model: &str,
    discount_bp: u32,
) -> Result<()> {
    let body = serde_json::to_value(ProductDeclarationRequest {
        provider: provider.as_str(),
        model,
        discount_bp,
    })
    .context("serialize declare-product body")?;

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
        bail!("registry returned {status}: {}", error_detail(&json));
    }
    Ok(())
}

/// Pull the catalog from the public `GET /products` endpoint.
async fn fetch_catalog(client: &mut RegistryClient) -> Result<ProductCatalogResponse> {
    let resp = client.get("/products").await.context("GET /products")?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        bail!("GET /products failed ({status}): {body}");
    }
    resp.json::<ProductCatalogResponse>()
        .await
        .context("parse product catalog")
}

/// Filter the catalog down to the set of products a fan-out should hit:
/// active, declarable, optionally narrowed to one provider.
///
/// `benchmark` entries are always dropped — every miner serves that pool
/// automatically (see `docs/plans/admission-benchmark.md`) and the
/// registry rejects declarations against it. Today the registry never
/// emits a benchmark row from `GET /products`; this filter is the
/// defence-in-depth that keeps the fan-out clean if that changes.
fn filter_catalog<'a>(
    products: &'a [Product],
    provider_filter: Option<&Provider>,
) -> Vec<&'a Product> {
    products
        .iter()
        .filter(|p| p.status == "active")
        .filter(|p| p.provider != Provider::Benchmark)
        .filter(|p| provider_filter.is_none_or(|target| &p.provider == target))
        .collect()
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
        "{:<12} {:<40} {:<12} {:<8} {:<8}",
        "PROVIDER", "MODEL", "DISCOUNT", "OFFERED", "ELIGIBLE"
    );
    println!("{}", "-".repeat(84));
    for p in &miner.products {
        let bp = p.discount_bp.map_or_else(
            || "—".to_owned(),
            |v| format!("{}%", format_discount_pct(v)),
        );
        println!(
            "{:<12} {:<40} {:<12} {:<8} {:<8}",
            p.provider,
            p.model,
            bp,
            if p.is_offered { "yes" } else { "no" },
            if p.is_eligible { "yes" } else { "no" },
        );
    }
    Ok(())
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "tests intentionally panic on unexpected values"
)]
mod tests {
    use super::{
        effective_per_mtok_ndollars, effective_rate_summary, filter_catalog, format_discount_pct,
        format_per_mtok_usd, parse_discount_pct, Cli, Command, Product, Provider, MAX_DISCOUNT_BP,
    };
    use gm_miner_cli::types::{RetailDimensions, RetailPrice};

    fn p(provider: Provider, model: &str, status: &str) -> Product {
        Product {
            provider,
            model: model.to_owned(),
            status: status.to_owned(),
            retail_price: RetailPrice {
                dimensions: RetailDimensions {
                    input_per_mtok_ndollars: 3_000_000_000,
                    output_per_mtok_ndollars: 15_000_000_000,
                },
            },
        }
    }

    #[test]
    fn discount_pct_accepts_examples() {
        assert_eq!(parse_discount_pct("0").unwrap(), 0);
        assert_eq!(parse_discount_pct("5").unwrap(), 500);
        assert_eq!(parse_discount_pct("10.5").unwrap(), 1050);
        assert_eq!(parse_discount_pct("10.55").unwrap(), 1055);
        assert_eq!(parse_discount_pct("99.90").unwrap(), MAX_DISCOUNT_BP);
    }

    #[test]
    fn discount_pct_rejects_negative() {
        let err = parse_discount_pct("-0.1").unwrap_err();
        assert!(err.contains("non-negative"), "got: {err}");
    }

    #[test]
    fn discount_pct_rejects_above_cap() {
        let err = parse_discount_pct("99.91").unwrap_err();
        assert!(err.contains("above the cap"), "got: {err}");
    }

    #[test]
    fn discount_pct_rejects_more_than_two_decimals() {
        let err = parse_discount_pct("10.555").unwrap_err();
        assert!(err.contains("at most 2 decimal"), "got: {err}");
    }

    #[test]
    fn discount_pct_rejects_unparseable() {
        let err = parse_discount_pct("abc").unwrap_err();
        assert!(err.contains("digits"), "got: {err}");
    }

    #[test]
    fn discount_pct_rejects_malformed() {
        let err = parse_discount_pct("10.5.5").unwrap_err();
        assert!(err.contains("at most one decimal point"), "got: {err}");
    }

    #[test]
    fn format_discount_pct_trims_trailing_zeroes() {
        assert_eq!(format_discount_pct(1050), "10.5");
        assert_eq!(format_discount_pct(1055), "10.55");
        assert_eq!(format_discount_pct(500), "5");
        assert_eq!(format_discount_pct(9990), "99.9");
        assert_eq!(format_discount_pct(0), "0");
        // 10_000 bp is what we keep when discount = 0, used by the
        // "you keep X% of retail" line in declare-product output.
        assert_eq!(format_discount_pct(10_000), "100");
        assert_eq!(format_discount_pct(10), "0.1");
    }

    #[test]
    fn effective_per_mtok_matches_gateway_floor() {
        // 6% discount on $3/Mtok retail → $2.82/Mtok per gateway settle.rs.
        assert_eq!(
            effective_per_mtok_ndollars(3_000_000_000, 600),
            2_820_000_000
        );
        // 10.5% discount on $3/Mtok input → $2.685/Mtok.
        assert_eq!(
            effective_per_mtok_ndollars(3_000_000_000, 1050),
            2_685_000_000
        );
        // Discount = 0 returns retail verbatim.
        assert_eq!(
            effective_per_mtok_ndollars(15_000_000_000, 0),
            15_000_000_000
        );
        // Discount = 99.90% leaves 0.10% of retail.
        assert_eq!(
            effective_per_mtok_ndollars(15_000_000_000, MAX_DISCOUNT_BP),
            15_000_000
        );
    }

    #[test]
    fn format_per_mtok_usd_renders_three_decimals() {
        assert_eq!(format_per_mtok_usd(3_000_000_000), "$3.000");
        assert_eq!(format_per_mtok_usd(2_685_000_000), "$2.685");
        assert_eq!(format_per_mtok_usd(15_000_000), "$0.015");
        assert_eq!(format_per_mtok_usd(0), "$0.000");
    }

    #[test]
    fn effective_rate_summary_renders_in_and_out() {
        let dims = RetailDimensions {
            input_per_mtok_ndollars: 3_000_000_000,
            output_per_mtok_ndollars: 15_000_000_000,
        };
        assert_eq!(
            effective_rate_summary(&dims, 1050),
            "$2.685 in / $13.425 out per Mtok"
        );
        assert_eq!(
            effective_rate_summary(&dims, 0),
            "$3.000 in / $15.000 out per Mtok"
        );
    }

    #[test]
    fn clap_accepts_discount_pct_for_single_declare() {
        let cli = <Cli as clap::Parser>::try_parse_from([
            "gm-miner",
            "declare-product",
            "--provider",
            "anthropic",
            "--model",
            "claude-sonnet-4-6",
            "--discount-pct",
            "10.55",
        ])
        .unwrap();

        assert!(matches!(
            cli.command,
            Command::DeclareProduct {
                discount_bp: 1055,
                ..
            }
        ));
    }

    #[test]
    fn clap_accepts_discount_pct_for_fan_out_declare() {
        let cli = <Cli as clap::Parser>::try_parse_from([
            "gm-miner",
            "declare-products",
            "--provider",
            "openai",
            "--discount-pct",
            "5",
        ])
        .unwrap();

        assert!(matches!(
            cli.command,
            Command::DeclareProducts {
                discount_bp: 500,
                ..
            }
        ));
    }

    #[test]
    fn clap_rejects_removed_discount_bp_flag() {
        let result = <Cli as clap::Parser>::try_parse_from([
            "gm-miner",
            "declare-product",
            "--provider",
            "anthropic",
            "--model",
            "claude-sonnet-4-6",
            "--discount-bp",
            "500",
        ]);
        assert!(result.is_err(), "expected --discount-bp to be rejected");
        let Some(err) = result.err() else {
            return;
        };
        assert!(err.to_string().contains("unexpected argument"));
    }

    #[test]
    fn filter_catalog_keeps_active_real_providers() {
        let products = [
            p(Provider::Anthropic, "claude-sonnet-4-6", "active"),
            p(Provider::OpenAI, "gpt-5.5", "active"),
            p(Provider::Gemini, "gemini-2.5-pro", "active"),
        ];
        let kept = filter_catalog(&products, None);
        assert_eq!(kept.len(), 3);
    }

    #[test]
    fn filter_catalog_drops_deprecated() {
        let products = [
            p(Provider::Anthropic, "claude-old", "deprecated"),
            p(Provider::OpenAI, "gpt-5.5", "active"),
        ];
        let kept = filter_catalog(&products, None);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].model, "gpt-5.5");
    }

    #[test]
    fn filter_catalog_drops_benchmark_even_when_active() {
        // The registry's benchmark pool is auto-synthesized; declarations
        // against it 404. If a future registry change ever exposes a
        // benchmark row in GET /products, the fan-out must still skip it.
        let products = [
            p(Provider::Benchmark, "gpt-bench", "active"),
            p(Provider::Anthropic, "claude-sonnet-4-6", "active"),
        ];
        let kept = filter_catalog(&products, None);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].provider, Provider::Anthropic);
    }

    #[test]
    fn filter_catalog_narrows_to_one_provider() {
        let products = [
            p(Provider::Anthropic, "claude-sonnet-4-6", "active"),
            p(Provider::OpenAI, "gpt-5.5", "active"),
        ];
        let kept = filter_catalog(&products, Some(&Provider::OpenAI));
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].provider, Provider::OpenAI);
    }
}
