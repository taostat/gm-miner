//! gmcli CLI.
//!
//! Subcommands:
//!   set-api-keys     — persist provider API keys to ~/.gmcli/config.json
//!   deploy           — trust-correct single-shot deploy: fetch approved hashes,
//!                      deploy via Phala Cloud, verify hashes, register image
//!   login            — Taostats device-code OAuth flow
//!   doctor           — preflight checklist (network, login, keys, phala, hotkey)
//!   register-hotkey  — record the serving hotkey (bring-your-own ss58, or
//!                      register a fresh one via the btcli bridge)
//!   register-image   — re-register the deployed miner's image hashes (hidden)
//!   declare-product  — declare a single offer (--provider X --model Y --discount-pct N)
//!   declare-products — fan out one discount over the whole catalog, or one provider
//!   status           — registration state + per-product eligibility and rates
//!                      (the hidden `list-products` alias runs the same code)
//!   worker add       — attach a new data-plane CVM under the existing hotkey
//!   worker list      — list the hotkey's live workers
//!   worker remove    — deregister a worker (CVM teardown is separate)
//!
//! Every command resolves a [`Network`] profile (testnet/mainnet) carrying the
//! subnet `netuid`, chain websocket, and default registry URL. The selection
//! is sticky: `--network` / `--testnet` persists it for later commands.
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
use chrono::Timelike as _;
use clap::{Parser, Subcommand};
use gm_miner_cli::{
    auth,
    btcli::{BtcliBridge, RealBtcli, Registration},
    client::{get_auth_config, RegistryClient},
    config::{self, Config, HotkeyRecord, ProviderKeys, WorkerRecord},
    dependency::{ensure_dependency, BTCLI},
    deploy::{
        fetch_supported_versions, format_created_at, normalize_hash, parse_phala_cvm_detail,
        parse_phala_cvm_endpoint, parse_phala_cvm_name, preflight_phala_cli, prepare_deploy_target,
        resolve_registry_credentials, select_version, to_ratls_passthrough_endpoint, verify_hashes,
        ImageProvisioner, PhalaClient, DEFAULT_BOOT_TIMEOUT_SECS, DEFAULT_OS_IMAGE,
        PHALA_ENDPOINT_FIELD,
    },
    earnings::{render_earnings, resolve_hotkey},
    network::Network,
    node_secret,
    register_hotkey::{confirm_registered, record_byo},
    types::{
        MinerStatus, Product, ProductCatalogResponse, ProductDeclarationRequest, Provider,
        RetailDimensions, WorkerCreateRequest, WorkerCreateResponse, WorkerListResponse,
    },
};

/// Inclusive upper bound on `discount_bp`. The registry's pydantic schema
/// pins the same value (`registry/.../schemas.py::ProductDeclarationRequest`);
/// kept in sync by the API-shape pin in the PR plan §3.1.
const MAX_DISCOUNT_BP: u32 = 9_990;

#[derive(Parser)]
#[command(
    name = "gmcli",
    version,
    about = "gm miner CLI — manage your miner's registration, products, and prices",
    after_help = "Examples:\n  \
        gmcli login                       # authenticate (mainnet by default)\n  \
        gmcli --network testnet login     # authenticate against testnet\n  \
        gmcli doctor                      # preflight checklist before deploying\n  \
        gmcli status                      # registration + products\n\n\
        The selected network is sticky: pass --network (or --testnet) once and\n\
        every later command targets it until you pass a different one."
)]
struct Cli {
    /// Network to target: `testnet` or `mainnet` (default: mainnet).
    ///
    /// Sticky — the choice is saved and reused by later commands until you
    /// pass a different one. `--testnet` is a shorthand for
    /// `--network testnet`.
    #[arg(long, global = true, value_name = "NETWORK")]
    network: Option<Network>,

    /// Shorthand for `--network testnet`.
    #[arg(long, global = true, conflicts_with = "network")]
    testnet: bool,

    /// Override the registry API URL (flag only; use `GM_REGISTRY_URL` env var for
    /// per-run overrides that should not be persisted — see `load_config`).
    #[arg(long, global = true)]
    api_url: Option<String>,

    #[command(subcommand)]
    command: Command,
}

impl Cli {
    /// The network the user explicitly selected this run, if any. `--testnet`
    /// is folded in as `Network::Testnet`. `None` means "use the sticky stored
    /// selection" (see [`load_config`]).
    fn explicit_network(&self) -> Option<Network> {
        self.network.or(self.testnet.then_some(Network::Testnet))
    }
}

#[derive(Subcommand)]
enum Command {
    /// Persist provider API keys to ~/.gmcli/config.json (mode 0600).
    ///
    /// Each flag, if provided, replaces the stored value.  Omitted flags
    /// leave existing values intact.  Key values are never echoed back.
    #[command(after_help = "Examples:\n  \
        gmcli set-api-keys --anthropic sk-ant-...\n  \
        gmcli set-api-keys --openai sk-... --google AIza...")]
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
    /// Reads provider API keys from ~/.gmcli/config.json (set them first
    /// with `gmcli set-api-keys`), fetches the registry-approved image
    /// version, builds and pushes the miner image to a public registry,
    /// submits the compose stack to Phala Cloud, verifies the deployed CVM's
    /// measured hashes match the registry approval, then registers the
    /// image automatically.
    ///
    /// Phala Cloud manages the confidential VM, the KMS, and `app_id`
    /// authorization. Authentication uses a Phala Cloud API key — set
    /// `PHALA_CLOUD_API_KEY` or run `phala login` before deploying.
    #[command(after_help = "Examples:\n  \
        gmcli deploy --image-repo ghcr.io/<owner>/gm-miner\n  \
        gmcli deploy --image-ref ghcr.io/<owner>/gm-miner@sha256:...")]
    Deploy {
        #[command(flatten)]
        flags: Box<DeployFlags>,
    },

    /// Authenticate with Taostats (device-code OAuth flow) and store
    /// credentials in ~/.gmcli/config.json.
    #[command(after_help = "Examples:\n  \
        gmcli login\n  \
        gmcli --network testnet login\n  \
        gmcli login --no-browser")]
    Login {
        /// Do not automatically open the browser.
        #[arg(long)]
        no_browser: bool,
    },

    /// Register this miner's image compose hash + capabilities with the registry.
    ///
    /// The normal operator flow uses `gmcli deploy` which verifies and
    /// registers in one step.  Use this subcommand only for re-registering
    /// without redeploying (e.g. after a registry resync or for debugging).
    ///
    /// The compose + OS image hashes are read automatically from the
    /// deployed CVM via `phala cvms get <app-id> --json`; the CVM must
    /// already be deployed (`gmcli deploy`).
    #[command(hide = true)]
    RegisterImage {
        /// Phala Cloud app id of the deployed CVM (e.g. `app_abc123`).
        #[arg(long)]
        app_id: String,
    },

    /// Alias for `status` — the product table is folded into `status`.
    ///
    /// Kept so existing muscle memory and scripts keep working; it runs the
    /// same code as `status`.
    #[command(hide = true, alias = "products")]
    ListProducts,

    /// Run a preflight checklist before deploying.
    ///
    /// Prints a green/red checklist of everything a deploy needs: the active
    /// network, login state, provider keys, the `phala` CLI and its API key,
    /// and whether your hotkey is registered on the subnet. Each red line
    /// names the command that fixes it.
    #[command(after_help = "Examples:\n  \
        gmcli doctor\n  \
        gmcli --network testnet doctor")]
    Doctor,

    /// Record (and optionally register) the hotkey your miner serves under.
    ///
    /// Two flows. If you already registered a hotkey elsewhere (a browser
    /// wallet, another machine), pass `--hotkey-ss58 <addr>` and gmcli just
    /// records it — no btcli needed. If you have not, omit `--hotkey-ss58` and
    /// pass `--wallet`/`--hotkey`: gmcli offers to register a fresh hotkey
    /// through btcli (which owns your wallet keys — gmcli never sees them).
    #[command(after_help = "Examples:\n  \
        gmcli register-hotkey --hotkey-ss58 5GrwvaEF...     # already registered elsewhere\n  \
        gmcli --network testnet register-hotkey --wallet miner --hotkey default\n  \
        gmcli register-hotkey --wallet miner --hotkey default --yes  # non-interactive")]
    RegisterHotkey {
        /// The ss58 address of a hotkey you already registered elsewhere.
        /// When set, gmcli records it (verifying via btcli if present) and
        /// never registers anything. When omitted, gmcli offers to register
        /// a fresh hotkey via btcli using `--wallet`/`--hotkey`.
        #[arg(long = "hotkey-ss58", value_name = "SS58")]
        hotkey_ss58: Option<String>,

        /// btcli coldkey (wallet) name. Required for the assisted flow.
        #[arg(long)]
        wallet: Option<String>,

        /// btcli hotkey name under the wallet. Required for the assisted flow.
        #[arg(long)]
        hotkey: Option<String>,

        /// Skip confirmation prompts (install offers, the spend gate) for
        /// non-interactive use.
        #[arg(long)]
        yes: bool,
    },

    /// Declare a single miner-product offer.
    ///
    /// One POST to `/miners/products`. For batch declarations against the
    /// whole catalog (or one provider's slice), use `declare-products`.
    #[command(after_help = "Examples:\n  \
        gmcli declare-product --provider anthropic --model claude-sonnet-4-6 --discount-pct 5\n  \
        gmcli declare-product --provider openai --model gpt-5.5 --discount-pct 10.5")]
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
    #[command(after_help = "Examples:\n  \
        gmcli declare-products --discount-pct 5            # whole catalog\n  \
        gmcli declare-products --provider openai --discount-pct 10")]
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
    ///
    /// Lists each declared offer with the per-Mtok rate you actually receive
    /// after the discount, plus whether it is offered and eligible.
    #[command(after_help = "Examples:\n  \
        gmcli status\n  \
        gmcli --network testnet status")]
    Status,

    /// Show your miner's current chain emission on the subnet.
    ///
    /// Reads your hotkey's neuron row straight from the subnet metagraph (via
    /// btcli) and reports uid, stake, and per-tempo emission in the subnet's
    /// alpha token. Reports on your own hotkey — taken from your login token,
    /// or the one recorded by `register-hotkey` — so there's nothing to pass.
    ///
    /// This is the on-chain emission view (v1). Your gm USD-spread earnings are
    /// a future (v2) view.
    #[command(after_help = "Examples:\n  \
        gmcli earnings\n  \
        gmcli --network testnet earnings")]
    Earnings {
        /// Skip the btcli install prompt for non-interactive use.
        #[arg(long)]
        yes: bool,
    },

    /// gm. (prints a small sunrise and a time-of-day greeting)
    #[command(hide = true)]
    Gm,

    /// gn. (the quiet counterpart to `gm`)
    #[command(hide = true)]
    Moon,

    /// Manage the data-plane workers (Phala CVMs) attached to your hotkey.
    ///
    /// The first `gmcli deploy` creates the hotkey identity and worker
    /// #1 in one shot. Use `worker add` to attach further capacity under
    /// the same hotkey, `worker list` to see every worker's status, and
    /// `worker remove` to deregister one.
    Worker {
        #[command(subcommand)]
        command: WorkerCommand,
    },
}

/// Deploy flags shared by `gmcli deploy` (worker #1) and
/// `gmcli worker add` (further capacity). Both submit one Phala CVM via
/// the same plumbing; they differ only in which registry endpoint records
/// the resulting worker.
#[derive(clap::Args)]
struct DeployFlags {
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

    /// Phala Cloud CVM name. Each worker needs its own name — a second
    /// worker must pass e.g. `--app-name gm-miner-2`.
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
}

#[derive(Subcommand)]
enum WorkerCommand {
    /// Deploy (or register an already-deployed) CVM as a new worker under
    /// the existing hotkey. Same plumbing as `deploy`, routed to
    /// `POST /miners/{hotkey}/workers`. Generates a fresh per-worker
    /// node secret. Pass a distinct `--app-name` for each worker.
    Add {
        #[command(flatten)]
        flags: Box<DeployFlags>,
    },

    /// List the hotkey's live workers with per-worker status and last
    /// attestation (`GET /miners/{hotkey}/workers`).
    List,

    /// Deregister a worker from the registry (`DELETE
    /// /miners/{hotkey}/workers/{worker_id}`). This does NOT tear down the
    /// Phala CVM — `phala cvms delete <app_id>` separately.
    Remove {
        /// The registry `worker_id` (ULID) of the worker to remove.
        worker_id: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "warn".into()))
        .init();

    if std::env::args().len() == 1 && std::io::stdout().is_terminal() {
        println!("{}", banner());
    }

    let cli = Cli::parse();
    dispatch(cli).await
}

/// Resolve the global flags and run the selected subcommand. Split from
/// [`main`] so the startup banner/tracing setup stays separate from the
/// per-command routing.
async fn dispatch(cli: Cli) -> Result<()> {
    let explicit_network = cli.explicit_network();
    let api_url = cli.api_url.clone();

    match cli.command {
        Command::SetApiKeys {
            anthropic,
            openai,
            google,
        } => cmd_set_api_keys(explicit_network, anthropic, openai, google),
        Command::Gm => {
            cmd_gm();
            Ok(())
        }
        Command::Moon => {
            cmd_moon();
            Ok(())
        }
        Command::Deploy { flags } => {
            let cfg = load_config(explicit_network, api_url)?;
            let cfg = ensure_fresh_token(cfg).await?;
            cmd_deploy_subcommand(
                cfg,
                deploy_args_from_flags(*flags),
                WorkerRegistration::First,
            )
            .await
        }
        Command::Worker {
            command: WorkerCommand::Add { flags },
        } => {
            let cfg = load_config(explicit_network, api_url)?;
            let cfg = ensure_fresh_token(cfg).await?;
            let args = deploy_args_from_flags(*flags);
            cmd_worker_add(cfg, args).await
        }
        Command::Worker {
            command: WorkerCommand::List,
        } => {
            let cfg = load_config(explicit_network, api_url)?;
            let cfg = ensure_fresh_token(cfg).await?;
            let mut client = RegistryClient::new(cfg);
            cmd_worker_list(&mut client).await
        }
        Command::Worker {
            command: WorkerCommand::Remove { worker_id },
        } => {
            let cfg = load_config(explicit_network, api_url)?;
            let cfg = ensure_fresh_token(cfg).await?;
            cmd_worker_remove(cfg, &worker_id).await
        }
        Command::Login { no_browser } => cmd_login(explicit_network, api_url, !no_browser).await,
        Command::Doctor => {
            let cfg = load_config(explicit_network, api_url)?;
            cmd_doctor(cfg).await
        }
        Command::RegisterHotkey {
            hotkey_ss58,
            wallet,
            hotkey,
            yes,
        } => {
            let cfg = load_config(explicit_network, api_url)?;
            cmd_register_hotkey(cfg, hotkey_ss58, wallet, hotkey, yes)
        }
        Command::RegisterImage { app_id } => {
            let cfg = load_config(explicit_network, api_url)?;
            let cfg = ensure_fresh_token(cfg).await?;
            cmd_register_image_subcommand(cfg, &app_id).await
        }
        Command::ListProducts | Command::Status => {
            let cfg = load_config(explicit_network, api_url)?;
            let cfg = ensure_fresh_token(cfg).await?;
            let mut client = RegistryClient::new(cfg);
            cmd_status(&mut client).await
        }
        Command::Earnings { yes } => {
            let cfg = load_config(explicit_network, api_url)?;
            cmd_earnings(&cfg, yes)
        }
        Command::DeclareProduct {
            provider,
            model,
            discount_bp,
        } => {
            let cfg = load_config(explicit_network, api_url)?;
            let cfg = ensure_fresh_token(cfg).await?;
            let mut client = RegistryClient::new(cfg);
            cmd_declare_product(&mut client, &provider, &model, discount_bp).await
        }
        Command::DeclareProducts {
            provider,
            discount_bp,
        } => {
            let cfg = load_config(explicit_network, api_url)?;
            let cfg = ensure_fresh_token(cfg).await?;
            let mut client = RegistryClient::new(cfg);
            cmd_declare_products(&mut client, provider.as_ref(), discount_bp).await
        }
    }
}

// ── Banner ───────────────────────────────────────────────────────────────────

/// The gm banner, greeting line picked by local time of day. `gm` = good
/// morning — the greeting reads "good morning/afternoon/evening/night" so a
/// 3am deploy says `gm. gn really.` energy without changing the art.
fn banner() -> String {
    format!(
        r"
 .----------------------.
 |                      |
 |    ____ __  __       |
 |   / ___|  \/  |      |
 |  | |  _| |\/| |      |
 |  | |_| | |  | |      |
 |   \____|_|  |_|      |
 |                      |
 |   {greeting:<18} |
 |                      |
 '----------------------'
        \
         \    .--.
              |o.o|
              =(_)=",
        greeting = greeting()
    )
}

/// A short greeting keyed off the local hour. Kept under 18 chars so it fits
/// the banner box.
fn greeting() -> &'static str {
    match chrono::Local::now().hour() {
        5..=11 => "gm. good morning.",
        12..=17 => "gm. good afternoon",
        18..=21 => "gm. good evening.",
        _ => "gm. good night.",
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Load config and resolve the active network.
///
/// `explicit_network` is the network the user named this run (`--network` /
/// `--testnet`), or `None` to use the sticky stored selection. An explicit
/// choice is persisted so later commands target it without retyping the flag;
/// the previous default-to-mainnet-every-run behaviour was the audit's biggest
/// day-2 footgun.
///
/// `--api-url` is *not* sticky: it is applied to the in-memory config for this
/// run only (falling back to `GM_REGISTRY_URL`) and never written back here.
fn load_config(
    explicit_network: Option<Network>,
    api_url_override: Option<String>,
) -> Result<Config> {
    let mut cfg = config::load().context("load config")?;

    if let Some(network) = explicit_network {
        // Persist the explicit choice so it sticks across later commands. An
        // empty stored value (or a different prior selection) is overwritten.
        let changed = cfg.resolved_network() != network || cfg.active_network.is_none();
        cfg.set_network(network);
        if changed {
            config::save(&cfg).context("persist selected network")?;
        }
    }

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

/// Non-interactively refresh the active token if it is expired and a
/// `refresh_token` is stored. Never opens a browser or runs the device-code
/// flow — a diagnostic like `doctor` must report state, not mutate auth by
/// launching an interactive login.
///
/// Returns the (possibly refreshed) config. Any failure — no refresh token,
/// a rejected refresh, an unreachable auth-gateway — leaves the config
/// untouched and returns it as-is, so the caller's checks report the real
/// logged-out/expired state.
async fn try_refresh_token(mut cfg: Config) -> Config {
    let needs_refresh = cfg
        .active_tokens()
        .is_some_and(config::TokenEntry::is_expired_or_near);
    if !needs_refresh {
        return cfg;
    }
    let Some(refresh) = cfg.active_tokens().and_then(|t| t.refresh_token.clone()) else {
        return cfg;
    };

    let api_url = cfg.api_url();
    let Ok(auth_cfg) = get_auth_config(&api_url).await else {
        return cfg;
    };
    let Ok(auth::RefreshOutcome::Refreshed(token)) =
        auth::refresh_token(&auth_cfg.token_url, &auth_cfg.client_id, &refresh).await
    else {
        return cfg;
    };

    let previous_refresh = cfg.active_tokens().and_then(|t| t.refresh_token.clone());
    cfg.active_entry_mut().tokens = Some(token.to_entry_keeping(previous_refresh));
    let _ = config::save(&cfg);
    cfg
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

/// Turn a failed `GET /miners/me` into an actionable error instead of dumping
/// the raw response body.
///
/// A 403/404 means the caller authenticated fine but the registry has no miner
/// for this hotkey — i.e. it isn't registered on the subnet. A 401 is handled
/// upstream by [`RegistryClient`], but together with 404 it can also mean the
/// command is pointed at the wrong network, so the hint names the active one.
fn me_error(network: Network, status: reqwest::StatusCode) -> anyhow::Error {
    let netuid = network.netuid();
    if matches!(status.as_u16(), 401 | 403 | 404) {
        return anyhow::anyhow!(
            "your hotkey isn't registered on subnet {netuid} (registry returned {status}).\n\
             Register it with btcli, then run `gmcli deploy` to attach a worker \
             (`gmcli register-hotkey` is coming).\n\
             Already registered? You're on the `{network}` network — pass \
             `--network mainnet` / `--network testnet` if that's not where your \
             hotkey lives."
        );
    }
    anyhow::anyhow!("registry request to {network} failed ({status})")
}

// ── Commands ────────────────────────────────────────────────────────────────

/// Parsed `gmcli deploy` arguments, grouped so the dispatch match arm
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

/// Which registry endpoint records the worker a deploy produces.
///
/// `First` is `gmcli deploy`: `POST /miners/register` creates the
/// hotkey identity and worker #1. `Add` is `gmcli worker add`:
/// `POST /miners/{hotkey}/workers` attaches further capacity to the named
/// hotkey, which `worker add` resolves and validates *before* any CVM work
/// so an unregistered hotkey fails fast.
#[derive(Debug, Clone, PartialEq, Eq)]
enum WorkerRegistration {
    First,
    Add { hotkey: String },
}

/// Resolve a [`DeployArgs`] from parsed CLI flags, computing the staging
/// directory once (`--dist-dir` or `dist/<app_name>`).
fn deploy_args_from_flags(flags: DeployFlags) -> DeployArgs {
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
    }
}

/// Build and run the deploy subcommand from parsed CLI arguments.
///
/// Separated from `main` to keep the dispatch match arm small.
async fn cmd_deploy_subcommand(
    cfg: Config,
    args: DeployArgs,
    registration: WorkerRegistration,
) -> Result<()> {
    let phala = gm_miner_cli::deploy::RealPhalaClient::new(
        args.app_name.clone(),
        args.project_dir.clone(),
        args.instance_type.clone(),
        args.disk_size.clone(),
        args.os_image.clone(),
    );
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
async fn cmd_worker_add(cfg: Config, args: DeployArgs) -> Result<()> {
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
    explicit_network: Option<Network>,
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

    let mut cfg =
        config::load().context("load gmcli config (delete ~/.gmcli/config.json if corrupted)")?;

    // Provider keys are network-independent, but an explicit --network here
    // is still the user's sticky selection — persist it so the promise holds
    // even when set-api-keys is the command that carries the flag.
    if let Some(network) = explicit_network {
        cfg.set_network(network);
    }

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
        println!("\nNext: gmcli deploy --image-repo ghcr.io/<owner>/gm-miner");
    }
    Ok(())
}

/// Reject a plain `gmcli deploy` aimed at a registered *secondary* worker.
///
/// `deploy` registers worker #1 via `/miners/register`, which refreshes the
/// miner's first worker. Pointed at the `--app-name` of a registered secondary
/// worker it would overwrite worker #1 in the registry and corrupt the local
/// mapping. A re-deploy of worker #1 (or a brand-new, untracked `--app-name`,
/// or a provisional record from an in-flight/failed deploy being retried) is
/// fine.
fn reject_secondary_worker_deploy(
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
fn existing_worker_id_for(cfg: &Config, app_name: &str) -> String {
    cfg.active_network_entry()
        .and_then(|e| e.worker_by_app_name(app_name))
        .map(|w| w.worker_id.clone())
        .unwrap_or_default()
}

async fn cmd_deploy(
    cfg: &Config,
    client: &mut RegistryClient,
    phala: &dyn PhalaClient,
    args: &DeployArgs,
    registration: &WorkerRegistration,
) -> Result<()> {
    // Step 0: a plain `deploy` may only target worker #1 (see guard).
    reject_secondary_worker_deploy(cfg, registration, &args.app_name)?;

    // Step 1: ensure provider keys are configured.
    let keys = cfg
        .provider_keys
        .as_ref()
        .filter(|k| k.any_set())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no provider keys; run `gmcli set-api-keys \
                 --anthropic <key>` (and/or --openai / --google) first"
            )
        })?;

    // Step 1b: resolve the per-worker node secret. Each worker (CVM)
    // carries its own `x-gm-node-key` secret, never shared with a sibling
    // — a leaked secret burns only one worker. A re-deploy of an existing
    // worker (matched on `--app-name`) reuses the same value so what the
    // container bakes into env, what envoy enforces, and what the registry
    // stores all stay in lockstep (Mechanism 1 of attestation-and-identity.md).
    // Only worker #1 (`deploy`) may inherit a pre-multi-worker legacy
    // secret; a `worker add` must always mint its own.
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
                provisional_secondary,
            },
        )?;
    }

    // Step 1c: preflight that the `phala` CLI is installed. It is the
    // runtime dependency of the deploy — catch a missing CLI now, with an
    // install hint, before the multi-minute image build.
    preflight_phala_cli()?;

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
            node_secret,
            // Registered: role is read from position, never this flag.
            provisional_secondary: false,
        },
    )?;

    print_deploy_summary(&worker_id, &actual.app_id, registration);
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

/// Upsert `record` into the active network's workers and save the config.
fn persist_worker_record(network: &str, record: WorkerRecord) -> Result<()> {
    let mut cfg = config::load().context("load gmcli config")?;
    cfg.active_network = Some(network.to_owned());
    cfg.active_entry_mut().upsert_worker(record);
    config::save(&cfg).context("persist worker record to gmcli config")
}

/// Fetch the calling miner's hotkey from `GET /miners/me`.
async fn fetch_hotkey(client: &mut RegistryClient) -> Result<String> {
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

async fn cmd_login(
    explicit_network: Option<Network>,
    api_url_override: Option<String>,
    open_browser: bool,
) -> Result<()> {
    // `config::load()` already returns Config::default() when the file
    // is absent (first-time login). A failure here means the file
    // exists but is unreadable or invalid JSON — surfacing that as a
    // hard error matches the other commands' behaviour and prevents
    // a normal re-login from silently wiping an operator's existing
    // mainnet/testnet tokens.
    let mut cfg =
        config::load().context("load gmcli config (delete ~/.gmcli/config.json if corrupted)")?;

    // An explicit --network/--testnet selects (and sticks) the network this
    // login targets; otherwise the stored sticky selection is kept so a
    // re-login doesn't silently switch networks.
    if let Some(network) = explicit_network {
        cfg.set_network(network);
    }

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

    println!("Login successful ({} network).", cfg.resolved_network());
    println!("Credentials saved to {}", config::config_path().display());
    println!("\nNext: gmcli set-api-keys --anthropic <key>  (and/or --openai / --google)");
    Ok(())
}

/// `gmcli register-image` — re-register an already-deployed worker's
/// image with the registry without a full redeploy.
///
/// Reuses the per-worker node secret persisted under the matching
/// `app_id`, auto-discovers the deployed compose/os-image hashes and the
/// public endpoint via `phala cvms get <app-id> --json`, re-registers
/// worker #1 (`POST /miners/register`), then refreshes the worker record
/// with the returned `worker_id`.
async fn cmd_register_image_subcommand(cfg: Config, app_id: &str) -> Result<()> {
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
    let (node_secret, existing_app_name) = {
        let entry = cfg.active_network_entry();
        let tracked = entry.and_then(|n| n.worker_by_app_id(app_id));
        if let Some(tracked) =
            tracked.filter(|_| entry.is_some_and(|n| n.is_secondary_by_app_id(app_id)))
        {
            // A provisional secondary has no worker_id yet; point `worker
            // remove` at the app_id, which it also accepts, so the command is
            // runnable in every case.
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
        // pre-multi-worker config falls back to the legacy network-level
        // secret so a resync still restores what envoy enforces; otherwise
        // the registry leaves its stored secret untouched.
        let node_secret = tracked.map(|w| w.node_secret.clone()).or_else(|| {
            entry
                .and_then(config::NetworkEntry::legacy_node_secret)
                .map(str::to_owned)
        });
        (node_secret, tracked.map(|w| w.app_name.clone()))
    };
    let network = cfg.active_network().to_owned();
    let mut client = RegistryClient::new(cfg);

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
                provisional_secondary: false,
            },
        )?;
    }

    println!("  worker_id : {worker_id}");
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
    let mut body = serde_json::json!({
        "compose_hash": args.compose_hash,
        "os_image_hash": args.os_image_hash,
        "endpoint": args.endpoint,
        "attestation_endpoint": args.endpoint,
    });
    // A present secret is stored and served to the gateway (Mechanism 1 of
    // attestation-and-identity.md). `None` omits the field so the registry
    // leaves any stored value untouched.
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
        bail!("register failed ({status}): {}", error_detail(&json));
    }

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
    })
    .context("serialize worker-add body")?;

    let path = format!("/miners/{hotkey}/workers");
    let resp = client
        .post(&path, &body)
        .await
        .with_context(|| format!("POST {path}"))?;

    let status = resp.status();
    let json: serde_json::Value = resp.json().await.context("parse worker-add response")?;

    if !status.is_success() {
        bail!("worker add failed ({status}): {}", error_detail(&json));
    }

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
async fn cmd_worker_list(client: &mut RegistryClient) -> Result<()> {
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
async fn cmd_worker_remove(cfg: Config, id: &str) -> Result<()> {
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
    // deregistered worker.
    let mut cfg = config::load().context("load gmcli config")?;
    cfg.active_network = Some(network);
    cfg.active_entry_mut().remove_worker_by_id(&worker_id);
    config::save(&cfg).context("persist worker removal to gmcli config")?;

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

/// Drop a provisional worker record (a deploy that never registered) from the
/// local config. No registry DELETE: nothing was ever registered.
fn remove_provisional_worker(network: &str, id: &str) -> Result<()> {
    let mut cfg = config::load().context("load gmcli config")?;
    cfg.active_network = Some(network.to_owned());
    let removed = cfg.active_entry_mut().remove_provisional_worker(id);
    config::save(&cfg).context("persist worker removal to gmcli config")?;

    match removed {
        Some(w) if !w.app_id.is_empty() => {
            println!(
                "Dropped the unregistered worker record for '{}'.\n\
                 Tear down its CVM separately:\n  phala cvms delete {}",
                w.app_name, w.app_id
            );
        }
        Some(w) => {
            println!(
                "Dropped the unregistered worker record for '{}'.",
                w.app_name
            );
        }
        None => println!("No provisional worker matched '{id}'."),
    }
    Ok(())
}

/// `gmcli declare-product` — POST one (provider, model, `discount_bp`)
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
    println!("\nNext: gmcli status   (confirm the offer)");
    Ok(())
}

/// `gmcli declare-products` — fan a single discount out over the catalog.
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
    println!("Next: gmcli status   (confirm offers + eligibility)");
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

// ── doctor ────────────────────────────────────────────────────────────────────

/// The state of one `doctor` checklist line.
#[derive(PartialEq, Eq)]
enum Status {
    /// Ready — nothing to do.
    Pass,
    /// A normal pre-deploy state worth surfacing but not a failure (e.g. the
    /// hotkey isn't registered yet — the first `deploy` registers it).
    Info,
    /// Needs the operator's attention before deploying.
    Fail,
}

/// One line of the `doctor` checklist: a status mark, a label, and an
/// optional note (the resolved detail for a pass, the actionable fix for a
/// fail, or context for an info line).
struct Check {
    status: Status,
    label: String,
    note: String,
}

impl Check {
    fn pass(label: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            status: Status::Pass,
            label: label.into(),
            note: detail.into(),
        }
    }

    fn info(label: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            status: Status::Info,
            label: label.into(),
            note: detail.into(),
        }
    }

    fn fail(label: impl Into<String>, fix: impl Into<String>) -> Self {
        Self {
            status: Status::Fail,
            label: label.into(),
            note: fix.into(),
        }
    }

    fn is_failure(&self) -> bool {
        self.status == Status::Fail
    }

    fn render(&self) {
        let (mark, note_prefix) = match self.status {
            Status::Pass => ("[ok]", "      "),
            Status::Info => ("[--]", "      "),
            Status::Fail => ("[!!]", "      → "),
        };
        println!("  {mark} {}", self.label);
        if !self.note.is_empty() {
            println!("{note_prefix}{}", self.note);
        }
    }
}

// ── register-hotkey ──────────────────────────────────────────────────────────

/// `gmcli register-hotkey` — record the hotkey the miner serves under.
///
/// Dispatches on `--hotkey-ss58`: present means bring-your-own (just record,
/// verify via btcli only if it happens to be installed); absent means the
/// assisted btcli flow (offer to install btcli, then register a fresh hotkey).
/// Either way the resulting [`HotkeyRecord`] is persisted to the active
/// network's config so login/deploy/doctor/earnings can reference it.
fn cmd_register_hotkey(
    cfg: Config,
    hotkey_ss58: Option<String>,
    wallet: Option<String>,
    hotkey: Option<String>,
    yes: bool,
) -> Result<()> {
    let network = cfg.resolved_network();
    match hotkey_ss58 {
        Some(ss58) => register_hotkey_byo(cfg, network, &ss58),
        None => register_hotkey_assisted(cfg, network, wallet, hotkey, yes),
    }
}

/// Bring-your-own: record an ss58 the operator registered elsewhere. Verifies
/// against the metagraph only when btcli is already on PATH — never installs it.
fn register_hotkey_byo(mut cfg: Config, network: Network, ss58: &str) -> Result<()> {
    let btcli = RealBtcli;
    let bridge: Option<&dyn BtcliBridge> =
        gm_miner_cli::dependency::on_path("btcli").then_some(&btcli);
    let outcome = record_byo(bridge, network, ss58)?;

    cfg.active_entry_mut()
        .set_registered_hotkey(outcome.record.clone());
    config::save(&cfg).context("persist registered hotkey")?;

    println!("Recorded hotkey {} for {network}.", outcome.record.ss58);
    println!("{}", outcome.note);
    println!("Next: `gmcli deploy` to launch a worker under this hotkey.");
    Ok(())
}

/// Assisted: register a fresh hotkey through btcli. The only flow that needs
/// btcli — so it (and only it) runs [`ensure_dependency`] for it.
fn register_hotkey_assisted(
    cfg: Config,
    network: Network,
    wallet: Option<String>,
    hotkey: Option<String>,
    yes: bool,
) -> Result<()> {
    let (wallet, hotkey) = require_wallet_and_hotkey(wallet, hotkey)?;
    ensure_dependency(&BTCLI, yes)?;
    let btcli = RealBtcli;

    // Resolve the ss58 up front — it is both proof the local wallet/hotkey
    // exists and the address we record afterwards. A `None` here means btcli's
    // wallet store has no such pair (a typoed `--wallet`/`--hotkey`), so we
    // refuse to spend TAO rather than register blind and persist an empty
    // address. The lookup also feeds the already-registered pre-check below, so
    // the wallet store is read exactly once.
    let Some(ss58) = btcli.hotkey_ss58(&wallet, &hotkey)? else {
        bail!(
            "btcli has no hotkey `{hotkey}` under wallet `{wallet}`.\n  \
             check the names with: btcli wallet list\n  \
             create one with: btcli wallet new-hotkey --wallet.name {wallet} --wallet.hotkey {hotkey}"
        );
    };

    if let Registration::Registered { uid } = btcli.registration_of(network, &ss58)? {
        return persist_already_registered(cfg, network, &wallet, &hotkey, &ss58, uid);
    }

    confirm_spend(network, &wallet, &hotkey, yes)?;
    btcli.register(network, &wallet, &hotkey, yes)?;
    finish_assisted(cfg, network, &btcli, &wallet, &hotkey, &ss58)
}

/// Both `--wallet` and `--hotkey` are required for the assisted flow; a missing
/// one points the operator at the bring-your-own escape hatch.
fn require_wallet_and_hotkey(
    wallet: Option<String>,
    hotkey: Option<String>,
) -> Result<(String, String)> {
    match (wallet, hotkey) {
        (Some(w), Some(h)) => Ok((w, h)),
        _ => bail!(
            "to register a new hotkey, pass both `--wallet <coldkey>` and `--hotkey <name>`.\n  \
             list your btcli wallets with: btcli wallet list\n  \
             already registered elsewhere? pass `--hotkey-ss58 <addr>` instead."
        ),
    }
}

/// Idempotent assisted path: the hotkey is already on the subnet, so record it
/// and exit 0 without spending TAO.
fn persist_already_registered(
    mut cfg: Config,
    network: Network,
    wallet: &str,
    hotkey: &str,
    ss58: &str,
    uid: u64,
) -> Result<()> {
    let record = HotkeyRecord {
        ss58: ss58.to_owned(),
        name: Some(hotkey.to_owned()),
        verified: true,
    };
    cfg.active_entry_mut().set_registered_hotkey(record);
    config::save(&cfg).context("persist registered hotkey")?;
    println!(
        "{wallet}/{hotkey} ({ss58}) is already registered on {network} — uid {uid}. \
         Nothing to do."
    );
    Ok(())
}

/// After a successful `btcli subnet register`, confirm the new uid and persist.
/// `ss58` is the address resolved (and validated to exist) before registering.
fn finish_assisted(
    mut cfg: Config,
    network: Network,
    btcli: &RealBtcli,
    wallet: &str,
    hotkey: &str,
    ss58: &str,
) -> Result<()> {
    let outcome = confirm_registered(btcli, network, ss58, hotkey)?;
    cfg.active_entry_mut().set_registered_hotkey(outcome.record);
    config::save(&cfg).context("persist registered hotkey")?;
    match outcome.uid {
        Some(uid) => {
            println!("Registered {wallet}/{hotkey} ({ss58}) on {network} — uid {uid}.");
            println!("Next: `gmcli deploy` to launch a worker under this hotkey.");
        }
        None => {
            // btcli succeeded but the metagraph hasn't caught up — the hotkey
            // is recorded; the uid lands within a block.
            println!(
                "Registered {wallet}/{hotkey} ({ss58}) on {network}. The metagraph is still \
                 catching up — run `gmcli status` shortly to see the uid."
            );
        }
    }
    Ok(())
}

/// Show the spend and gate on the operator's confirmation. `assume_yes` and a
/// non-TTY both skip the prompt. btcli prints the exact burn cost and prompts
/// again itself, so this is the gm-level "are you sure" before handing off.
fn confirm_spend(network: Network, wallet: &str, hotkey: &str, assume_yes: bool) -> Result<()> {
    println!("About to register a hotkey on-chain — this burns TAO:");
    println!("  network : {network} (netuid {})", network.netuid());
    println!("  wallet  : {wallet}");
    println!("  hotkey  : {hotkey}");
    println!("btcli will show the exact burn cost and ask for your wallet password.");
    if gm_miner_cli::dependency::confirm("Proceed?", false, assume_yes)? {
        Ok(())
    } else {
        bail!("aborted — no hotkey was registered.");
    }
}

// ── earnings ─────────────────────────────────────────────────────────────────

/// `gmcli earnings` — the miner's current chain emission on the subnet (v1).
///
/// Resolves the hotkey (`--hotkey-ss58` override, else the recorded one), then
/// reads its neuron row from the subnet metagraph via btcli. btcli is genuinely
/// required here (the chain read goes through it), so it is ensured lazily — the
/// command is the only place that pays the install cost. The summary is rendered
/// by [`render_earnings`]; a hotkey absent from the metagraph yields actionable
/// guidance, not a raw dump.
fn cmd_earnings(cfg: &Config, yes: bool) -> Result<()> {
    let network = cfg.resolved_network();
    let hotkey = resolve_hotkey(cfg, network)?;

    ensure_dependency(&BTCLI, yes)?;
    let stats = RealBtcli.neuron_stats(network, &hotkey.ss58)?;

    print!("{}", render_earnings(network, &hotkey, stats.as_ref()));
    Ok(())
}

/// `gmcli doctor` — a preflight checklist run before deploying.
///
/// Each check renders green/red with an actionable fix. The hotkey-
/// registration check probes `GET /miners/me`; a 401/403/404 renders as
/// "not registered on subnet N" rather than a raw body, and its remedy names
/// `register-hotkey`.
async fn cmd_doctor(cfg: Config) -> Result<()> {
    let network = cfg.resolved_network();
    println!(
        "gmcli doctor — preflight for {network} (netuid {})\n",
        network.netuid()
    );

    // Non-interactively refresh an expired-but-refreshable token up front so
    // the checklist reflects what a real deploy would see. Unlike the deploy
    // path's `ensure_fresh_token`, this never falls back to an interactive
    // device-code login — a preflight diagnostic must not open a browser or
    // block on auth. A refresh that can't happen leaves the config as-is and
    // `login_check`/`hotkey_check` report the true state.
    let cfg = try_refresh_token(cfg).await;

    let mut checks = vec![
        network_check(network, &cfg),
        login_check(&cfg),
        provider_keys_check(&cfg),
        phala_cli_check(),
        phala_api_key_check(),
    ];
    checks.push(hotkey_check(cfg).await);

    for check in &checks {
        check.render();
    }

    let failures = checks.iter().filter(|c| c.is_failure()).count();
    println!();
    if failures == 0 {
        println!("All checks passed — you're ready to `gmcli deploy`.");
        Ok(())
    } else {
        bail!("{failures} check(s) need attention before deploying (see above).");
    }
}

fn network_check(network: Network, cfg: &Config) -> Check {
    Check::pass(
        format!("Network: {network} (netuid {})", network.netuid()),
        format!("registry {} · chain {}", cfg.api_url(), network.chain_ws()),
    )
}

fn login_check(cfg: &Config) -> Check {
    match cfg.active_tokens() {
        Some(t) if t.access_token.is_some() && !t.is_expired_or_near() => {
            Check::pass("Logged in (token valid)", String::new())
        }
        // An expired access token with a stored refresh token is not a
        // failure: the next registry call refreshes it silently
        // (`ensure_fresh_token`), so the operator does not need to log in
        // again.
        Some(t) if t.access_token.is_some() && t.refresh_token.is_some() => {
            Check::pass("Logged in (token refreshes on next use)", String::new())
        }
        Some(t) if t.access_token.is_some() => {
            Check::fail("Logged in", "your session has expired — run `gmcli login`")
        }
        _ => Check::fail("Logged in", "not logged in — run `gmcli login`"),
    }
}

fn provider_keys_check(cfg: &Config) -> Check {
    let set: Vec<&str> = cfg.provider_keys.as_ref().map_or_else(Vec::new, |k| {
        let mut names = Vec::new();
        if k.anthropic.as_deref().is_some_and(|s| !s.trim().is_empty()) {
            names.push("anthropic");
        }
        if k.openai.as_deref().is_some_and(|s| !s.trim().is_empty()) {
            names.push("openai");
        }
        if k.google.as_deref().is_some_and(|s| !s.trim().is_empty()) {
            names.push("google");
        }
        names
    });
    if set.is_empty() {
        Check::fail(
            "Provider keys set",
            "no provider keys — run `gmcli set-api-keys --anthropic <key>` (and/or --openai / --google)",
        )
    } else {
        Check::pass(
            format!("Provider keys set ({})", set.join(", ")),
            String::new(),
        )
    }
}

fn phala_cli_check() -> Check {
    let on_path = std::process::Command::new("phala")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if on_path {
        Check::pass("`phala` CLI on PATH", String::new())
    } else {
        Check::fail(
            "`phala` CLI on PATH",
            "not found — install with `npm i -g phala`",
        )
    }
}

fn phala_api_key_check() -> Check {
    if std::env::var("PHALA_CLOUD_API_KEY").is_ok_and(|v| !v.trim().is_empty()) {
        return Check::pass("Phala Cloud API key (PHALA_CLOUD_API_KEY)", String::new());
    }
    // No env var — fall back to whether `phala` already holds a stored auth.
    // `phala whoami` exits non-zero when not authenticated (unlike `status`,
    // which reports state but still exits 0).
    let phala_logged_in = std::process::Command::new("phala")
        .arg("whoami")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if phala_logged_in {
        Check::pass("Phala Cloud auth (via `phala` CLI)", String::new())
    } else {
        Check::fail(
            "Phala Cloud API key",
            "set PHALA_CLOUD_API_KEY or run `phala auth login` (or `phala login`)",
        )
    }
}

/// Probe `GET /miners/me` and classify the result for the doctor checklist.
///
/// A 401/403/404 means the hotkey isn't registered on the subnet — rendered
/// as an actionable line, never the raw body. The 404 remedy names
/// `register-hotkey` (and its `--hotkey-ss58` bring-your-own escape hatch).
async fn hotkey_check(cfg: Config) -> Check {
    let network = cfg.resolved_network();
    let netuid = network.netuid();
    if cfg
        .active_tokens()
        .and_then(|t| t.access_token.as_deref())
        .is_none()
    {
        return Check::fail(
            format!("Hotkey registered on subnet {netuid}"),
            "can't check until you're logged in — run `gmcli login`",
        );
    }

    let mut client = RegistryClient::new(cfg);
    let resp = match client.get(gm_miner_cli::client::ME_PATH).await {
        Ok(resp) => resp,
        Err(err) => {
            return Check::fail(
                format!("Hotkey registered on subnet {netuid}"),
                format!("couldn't reach the registry: {err}"),
            );
        }
    };

    let label = format!("Hotkey registered on subnet {netuid}");
    let status = resp.status();
    if status.is_success() {
        let hotkey = resp
            .json::<MinerStatus>()
            .await
            .map_or_else(|_| "<registered>".to_owned(), |m| m.hotkey);
        return Check::pass(label, hotkey);
    }
    // A 404 is the expected state before the first deploy: the registry has no
    // miner record for this hotkey yet. Two steps clear it, in order: register
    // the hotkey on-chain (`register-hotkey`), then `deploy`, which posts
    // `/miners/register` and is what actually creates the record this probe
    // reads. Surface it as informational, not a failure — doctor *precedes*
    // both steps.
    if status.as_u16() == 404 {
        return Check::info(
            label,
            format!(
                "no miner record on `{network}` yet. First register your hotkey on-chain: \
                 `gmcli register-hotkey` (via btcli, or `--hotkey-ss58 <addr>` if you \
                 registered elsewhere). Then `gmcli deploy` creates the registry record. \
                 On the wrong network? Pass `--network mainnet`/`--network testnet`."
            ),
        );
    }
    // A 401/403 with a valid-looking token usually means the wrong network.
    if matches!(status.as_u16(), 401 | 403) {
        return Check::fail(
            label,
            format!(
                "registry rejected the request ({status}). On the wrong network? \
                 You're on `{network}` — pass `--network mainnet`/`--network testnet`."
            ),
        );
    }
    Check::fail(label, format!("registry returned {status}"))
}

// ── gm / moon ────────────────────────────────────────────────────────────────

/// `gmcli gm` — a tiny sunrise and the time-of-day greeting.
fn cmd_gm() {
    println!(
        r"        \   |   /
         .-''-.
   ---  (  ()  )  ---
         `-..-'
   ~~~~~~~~~~~~~~~~~~
   {greeting} wagmi.",
        greeting = greeting()
    );
}

/// `gmcli moon` — the quiet counterpart for the 3am deploys.
fn cmd_moon() {
    println!(
        r"          _.-''-._
        .'  .--.  `.
        :  (    )  :    gn. the miner runs while you sleep.
        `.  `--'  .'
          `-....-'"
    );
}

/// `gmcli status` — registration state plus the per-product offer table.
///
/// Folds in what `list-products` used to print: each offer's discount and the
/// per-Mtok rate the miner actually receives (joined against the public
/// catalog), alongside the broader hotkey/attestation/compose view.
async fn cmd_status(client: &mut RegistryClient) -> Result<()> {
    let network = client.config.resolved_network();
    let resp = client
        .get(gm_miner_cli::client::ME_PATH)
        .await
        .context("GET /miners/me")?;

    let status_code = resp.status();
    if !status_code.is_success() {
        return Err(me_error(network, status_code));
    }

    let miner: MinerStatus = resp.json().await.context("parse status response")?;

    println!("Miner status ({network})");
    println!("  Network    : {network} (netuid {})", network.netuid());
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
        println!("\nNo products declared. Declare some with `gmcli declare-products --discount-pct <pct>`.");
        return Ok(());
    }

    print_product_table(client, &miner).await
}

/// Render the per-offer table joining `/miners/me` offers against the public
/// catalog so each row shows the effective per-Mtok rate the miner receives.
async fn print_product_table(client: &mut RegistryClient, miner: &MinerStatus) -> Result<()> {
    // The catalog is the single source of truth for retail; join here rather
    // than adding a retail block to `/miners/me` on the registry side.
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

    println!("\nProducts:");
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
    println!("\n{} offer(s) total.", miner.products.len());
    Ok(())
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "tests intentionally panic on unexpected values"
)]
mod tests {
    use super::{
        effective_per_mtok_ndollars, effective_rate_summary, filter_catalog, format_discount_pct,
        format_per_mtok_usd, parse_discount_pct, Cli, Command, Product, Provider, WorkerCommand,
        MAX_DISCOUNT_BP,
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

    #[tokio::test]
    async fn worker_add_requires_a_tracked_worker_one() {
        use super::{cmd_worker_add, DeployArgs};
        use gm_miner_cli::config::{Config, NetworkEntry};

        // No tracked workers (fresh machine or an unmigrated legacy config):
        // `worker add` must refuse so the new worker can't be mistaken for
        // worker #1. The guard fires before any network/CVM work.
        let mut networks = std::collections::HashMap::new();
        networks.insert(
            "testnet".to_owned(),
            NetworkEntry {
                legacy_node_secret: Some("legacy-key".to_owned()),
                ..Default::default()
            },
        );
        let cfg = Config {
            networks,
            active_network: Some("testnet".to_owned()),
            provider_keys: None,
        };
        let args = DeployArgs {
            app_name: "gm-miner-2".to_owned(),
            image_ref: None,
            project_dir: std::path::PathBuf::from("dist/gm-miner-2"),
            image_repo: None,
            image_tag: "v0.1.0".to_owned(),
            instance_type: "tdx.medium".to_owned(),
            disk_size: "40G".to_owned(),
            os_image: "dstack-0.5.7".to_owned(),
            repo_root: None,
            version: None,
            boot_timeout_secs: 300,
        };

        let err = cmd_worker_add(cfg, args)
            .await
            .expect_err("worker add with no tracked worker #1 must be rejected");
        assert!(
            err.to_string().contains("no worker #1 is tracked"),
            "must direct the operator to deploy first; got: {err}"
        );
    }

    #[tokio::test]
    async fn worker_add_rejects_a_duplicate_app_name_before_any_deploy() {
        use super::{cmd_worker_add, DeployArgs};
        use gm_miner_cli::config::{Config, NetworkEntry, WorkerRecord};

        let mut networks = std::collections::HashMap::new();
        networks.insert(
            "testnet".to_owned(),
            NetworkEntry {
                workers: vec![WorkerRecord {
                    worker_id: "01J0A".to_owned(),
                    app_id: "app_01J0A".to_owned(),
                    app_name: "gm-miner-1".to_owned(),
                    node_secret: "secret".to_owned(),
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        let cfg = Config {
            networks,
            active_network: Some("testnet".to_owned()),
            provider_keys: None,
        };

        // --app-name gm-miner-1 already exists; the guard must bail before
        // any CVM work. No network mock is wired, so a network call would
        // surface as a different error than the one asserted here.
        let args = DeployArgs {
            app_name: "gm-miner-1".to_owned(),
            image_ref: None,
            project_dir: std::path::PathBuf::from("dist/gm-miner-1"),
            image_repo: None,
            image_tag: "v0.1.0".to_owned(),
            instance_type: "tdx.medium".to_owned(),
            disk_size: "40G".to_owned(),
            os_image: "dstack-0.5.7".to_owned(),
            repo_root: None,
            version: None,
            boot_timeout_secs: 300,
        };

        let err = cmd_worker_add(cfg, args)
            .await
            .expect_err("a duplicate app name must be rejected up front");
        assert!(
            err.to_string().contains("already registered"),
            "error must name the duplicate; got: {err}"
        );
    }

    #[tokio::test]
    async fn worker_add_allows_retrying_a_provisional_app_name() {
        use super::{cmd_worker_add, DeployArgs};
        use gm_miner_cli::config::{Config, NetworkEntry, WorkerRecord};

        // A provisional *secondary* stub (empty worker_id, empty app_id, flag
        // set) is a `worker add` that never finished registration. Re-running
        // `worker add` with that name must get past the guards rather than
        // dead-end — so it fails later (here: no provider keys / network).
        let mut networks = std::collections::HashMap::new();
        networks.insert(
            "testnet".to_owned(),
            NetworkEntry {
                workers: vec![
                    WorkerRecord {
                        worker_id: "01J0A".to_owned(),
                        app_id: "app_01J0A".to_owned(),
                        app_name: "gm-miner-1".to_owned(),
                        node_secret: "secret-1".to_owned(),
                        ..Default::default()
                    },
                    WorkerRecord {
                        worker_id: String::new(),
                        app_id: String::new(),
                        app_name: "gm-miner-2".to_owned(),
                        node_secret: "provisional".to_owned(),
                        provisional_secondary: true,
                    },
                ],
                ..Default::default()
            },
        );
        let cfg = Config {
            networks,
            active_network: Some("testnet".to_owned()),
            provider_keys: None,
        };
        let args = DeployArgs {
            app_name: "gm-miner-2".to_owned(),
            image_ref: None,
            project_dir: std::path::PathBuf::from("dist/gm-miner-2"),
            image_repo: None,
            image_tag: "v0.1.0".to_owned(),
            instance_type: "tdx.medium".to_owned(),
            disk_size: "40G".to_owned(),
            os_image: "dstack-0.5.7".to_owned(),
            repo_root: None,
            version: None,
            boot_timeout_secs: 300,
        };

        let err = cmd_worker_add(cfg, args)
            .await
            .expect_err("no network is wired, so the retry fails past the guard");
        let msg = err.to_string();
        assert!(
            !msg.contains("already registered")
                && !msg.contains("in-flight worker #1")
                && !msg.contains("never registered"),
            "a provisional secondary stub must not block a retry; got: {msg}"
        );
    }

    #[tokio::test]
    async fn worker_add_rejects_a_provisional_primary_stub() {
        use super::{cmd_worker_add, DeployArgs};
        use gm_miner_cli::config::{Config, NetworkEntry, WorkerRecord};

        // A provisional primary stub (empty worker_id, empty app_id, flag
        // unset) belongs to `deploy`. `worker add` against it must refuse and
        // send the operator back to `deploy`, not reuse worker #1's secret.
        let mut networks = std::collections::HashMap::new();
        networks.insert(
            "testnet".to_owned(),
            NetworkEntry {
                workers: vec![WorkerRecord {
                    worker_id: String::new(),
                    app_id: String::new(),
                    app_name: "gm-miner-1".to_owned(),
                    node_secret: "primary-stub".to_owned(),
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        let cfg = Config {
            networks,
            active_network: Some("testnet".to_owned()),
            provider_keys: None,
        };
        let args = DeployArgs {
            app_name: "gm-miner-1".to_owned(),
            image_ref: None,
            project_dir: std::path::PathBuf::from("dist/gm-miner-1"),
            image_repo: None,
            image_tag: "v0.1.0".to_owned(),
            instance_type: "tdx.medium".to_owned(),
            disk_size: "40G".to_owned(),
            os_image: "dstack-0.5.7".to_owned(),
            repo_root: None,
            version: None,
            boot_timeout_secs: 300,
        };

        let err = cmd_worker_add(cfg, args)
            .await
            .expect_err("a provisional primary stub must be rejected by worker add");
        assert!(
            err.to_string().contains("in-flight worker #1"),
            "must redirect to deploy; got: {err}"
        );
    }

    #[tokio::test]
    async fn worker_add_refuses_to_orphan_an_unregistered_cvm() {
        use super::{cmd_worker_add, DeployArgs};
        use gm_miner_cli::config::{Config, NetworkEntry, WorkerRecord};

        // A provisional record carrying a real app_id is a CVM that launched
        // but never registered. Re-running `worker add` must refuse and name
        // the orphan rather than silently deploying a second CVM.
        let mut networks = std::collections::HashMap::new();
        networks.insert(
            "testnet".to_owned(),
            NetworkEntry {
                workers: vec![WorkerRecord {
                    worker_id: String::new(),
                    app_id: "app_orphan".to_owned(),
                    app_name: "gm-miner-2".to_owned(),
                    node_secret: "provisional".to_owned(),
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        let cfg = Config {
            networks,
            active_network: Some("testnet".to_owned()),
            provider_keys: None,
        };
        let args = DeployArgs {
            app_name: "gm-miner-2".to_owned(),
            image_ref: None,
            project_dir: std::path::PathBuf::from("dist/gm-miner-2"),
            image_repo: None,
            image_tag: "v0.1.0".to_owned(),
            instance_type: "tdx.medium".to_owned(),
            disk_size: "40G".to_owned(),
            os_image: "dstack-0.5.7".to_owned(),
            repo_root: None,
            version: None,
            boot_timeout_secs: 300,
        };

        let err = cmd_worker_add(cfg, args)
            .await
            .expect_err("a provisional CVM must block a re-deploy");
        let msg = err.to_string();
        assert!(
            msg.contains("app_orphan") && msg.contains("phala cvms delete"),
            "must name the orphaned CVM and how to tear it down; got: {msg}"
        );
    }

    #[test]
    fn existing_worker_id_carries_through_a_redeploy_stub() {
        use super::existing_worker_id_for;
        use gm_miner_cli::config::{Config, NetworkEntry, WorkerRecord};

        let mut networks = std::collections::HashMap::new();
        networks.insert(
            "testnet".to_owned(),
            NetworkEntry {
                workers: vec![WorkerRecord {
                    worker_id: "01J0A".to_owned(),
                    app_id: "app_01J0A".to_owned(),
                    app_name: "gm-miner-1".to_owned(),
                    node_secret: "s".to_owned(),
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        let cfg = Config {
            networks,
            active_network: Some("testnet".to_owned()),
            provider_keys: None,
        };
        // A redeploy of a registered worker carries its worker_id, so a
        // mid-deploy failure can't erase it.
        assert_eq!(existing_worker_id_for(&cfg, "gm-miner-1"), "01J0A");
        // A brand-new worker has no id to carry.
        assert_eq!(existing_worker_id_for(&cfg, "gm-miner-2"), "");
    }

    #[tokio::test]
    async fn deploy_rejects_a_secondary_worker_app_name() {
        use super::{cmd_deploy, DeployArgs, RegistryClient, WorkerRegistration};
        use gm_miner_cli::config::{Config, NetworkEntry, ProviderKeys, WorkerRecord};
        use gm_miner_cli::deploy::{DeployOutcome, PhalaClient, RegistryCredentials};

        struct UnusedPhala;
        impl PhalaClient for UnusedPhala {
            fn deploy(
                &self,
                _compose: &str,
                _keys: &ProviderKeys,
                _node_secret: &str,
                _registry_creds: Option<&RegistryCredentials>,
                _boot_timeout_secs: u64,
            ) -> anyhow::Result<DeployOutcome> {
                anyhow::bail!("the step-0 guard must bail before any CVM work")
            }
        }

        let mut networks = std::collections::HashMap::new();
        networks.insert(
            "testnet".to_owned(),
            NetworkEntry {
                workers: vec![
                    WorkerRecord {
                        worker_id: "01J0A".to_owned(),
                        app_id: "app_01J0A".to_owned(),
                        app_name: "gm-miner-1".to_owned(),
                        node_secret: "secret-1".to_owned(),
                        ..Default::default()
                    },
                    WorkerRecord {
                        worker_id: "01J0B".to_owned(),
                        app_id: "app_01J0B".to_owned(),
                        app_name: "gm-miner-2".to_owned(),
                        node_secret: "secret-2".to_owned(),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            },
        );
        let cfg = Config {
            networks,
            active_network: Some("testnet".to_owned()),
            provider_keys: None,
        };

        // --app-name gm-miner-2 is a secondary worker; a plain `deploy`
        // would refresh worker #1 and corrupt the mapping. The step-0 guard
        // must bail before provider-key checks, auth, or any CVM work.
        let args = DeployArgs {
            app_name: "gm-miner-2".to_owned(),
            image_ref: None,
            project_dir: std::path::PathBuf::from("dist/gm-miner-2"),
            image_repo: None,
            image_tag: "v0.1.0".to_owned(),
            instance_type: "tdx.medium".to_owned(),
            disk_size: "40G".to_owned(),
            os_image: "dstack-0.5.7".to_owned(),
            repo_root: None,
            version: None,
            boot_timeout_secs: 300,
        };

        let mut client = RegistryClient::new(cfg.clone());
        let err = cmd_deploy(
            &cfg,
            &mut client,
            &UnusedPhala,
            &args,
            &WorkerRegistration::First,
        )
        .await
        .expect_err("a secondary worker app name must be rejected by deploy");
        assert!(
            err.to_string().contains("secondary worker"),
            "error must explain the secondary-worker rejection; got: {err}"
        );
    }

    #[test]
    fn deploy_allows_retrying_a_provisional_primary_redeploy() {
        use super::{reject_secondary_worker_deploy, WorkerRegistration};
        use gm_miner_cli::config::{Config, NetworkEntry, WorkerRecord};

        // A worker #1 redeploy under a new --app-name appended a provisional
        // stub after the registered primary, then failed. Retrying that same
        // deploy must NOT be rejected as secondary — the stub has no
        // worker_id, so it's an in-flight worker #1, recoverable on retry.
        let mut networks = std::collections::HashMap::new();
        networks.insert(
            "testnet".to_owned(),
            NetworkEntry {
                workers: vec![
                    WorkerRecord {
                        worker_id: "01J0A".to_owned(),
                        app_id: "app_01J0A".to_owned(),
                        app_name: "gm-miner-1".to_owned(),
                        node_secret: "secret-1".to_owned(),
                        ..Default::default()
                    },
                    WorkerRecord {
                        worker_id: String::new(),
                        app_id: "app_new".to_owned(),
                        app_name: "gm-miner-1b".to_owned(),
                        node_secret: "provisional".to_owned(),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            },
        );
        let cfg = Config {
            networks,
            active_network: Some("testnet".to_owned()),
            provider_keys: None,
        };

        reject_secondary_worker_deploy(&cfg, &WorkerRegistration::First, "gm-miner-1b")
            .expect("a provisional primary redeploy must be retryable");
    }

    #[test]
    fn deploy_rejects_a_provisional_worker_add_stub() {
        use super::{reject_secondary_worker_deploy, WorkerRegistration};
        use gm_miner_cli::config::{Config, NetworkEntry, WorkerRecord};

        // A `worker add` that launched a CVM then failed to register left a
        // provisional secondary stub. A plain `deploy --app-name` against it
        // must still be rejected — routing it through /miners/register would
        // overwrite worker #1 with the failed secondary's endpoint/secret.
        let mut networks = std::collections::HashMap::new();
        networks.insert(
            "testnet".to_owned(),
            NetworkEntry {
                workers: vec![
                    WorkerRecord {
                        worker_id: "01J0A".to_owned(),
                        app_id: "app_01J0A".to_owned(),
                        app_name: "gm-miner-1".to_owned(),
                        node_secret: "secret-1".to_owned(),
                        ..Default::default()
                    },
                    WorkerRecord {
                        worker_id: String::new(),
                        app_id: "app_add".to_owned(),
                        app_name: "gm-miner-2".to_owned(),
                        node_secret: "provisional".to_owned(),
                        provisional_secondary: true,
                    },
                ],
                ..Default::default()
            },
        );
        let cfg = Config {
            networks,
            active_network: Some("testnet".to_owned()),
            provider_keys: None,
        };

        let err = reject_secondary_worker_deploy(&cfg, &WorkerRegistration::First, "gm-miner-2")
            .expect_err("a provisional worker-add stub must stay off the worker-#1 path");
        assert!(err.to_string().contains("secondary worker"), "got: {err}");
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
            "gmcli",
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
            "gmcli",
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
            "gmcli",
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

    #[test]
    fn clap_parses_worker_add_with_app_name() {
        let cli = <Cli as clap::Parser>::try_parse_from([
            "gmcli",
            "worker",
            "add",
            "--app-name",
            "gm-miner-2",
            "--image-ref",
            "ghcr.io/o/m@sha256:abc",
        ])
        .unwrap();
        let Command::Worker {
            command: WorkerCommand::Add { flags },
        } = cli.command
        else {
            unreachable!("expected worker add");
        };
        assert_eq!(flags.app_name, "gm-miner-2");
        assert_eq!(flags.image_ref.as_deref(), Some("ghcr.io/o/m@sha256:abc"));
    }

    #[test]
    fn clap_parses_worker_list() {
        let cli = <Cli as clap::Parser>::try_parse_from(["gmcli", "worker", "list"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Worker {
                command: WorkerCommand::List
            }
        ));
    }

    #[test]
    fn clap_parses_worker_remove_with_positional_id() {
        let cli =
            <Cli as clap::Parser>::try_parse_from(["gmcli", "worker", "remove", "01J0C"]).unwrap();
        let Command::Worker {
            command: WorkerCommand::Remove { worker_id },
        } = cli.command
        else {
            unreachable!("expected worker remove");
        };
        assert_eq!(worker_id, "01J0C");
    }

    #[test]
    fn clap_worker_remove_requires_a_worker_id() {
        let result = <Cli as clap::Parser>::try_parse_from(["gmcli", "worker", "remove"]);
        assert!(result.is_err(), "worker remove must require a worker_id");
    }

    #[test]
    fn explicit_network_resolves_flag_and_testnet_shorthand() {
        use super::Network;

        let cli =
            <Cli as clap::Parser>::try_parse_from(["gmcli", "--network", "testnet", "status"])
                .unwrap();
        assert_eq!(cli.explicit_network(), Some(Network::Testnet));

        let cli = <Cli as clap::Parser>::try_parse_from(["gmcli", "--testnet", "status"]).unwrap();
        assert_eq!(cli.explicit_network(), Some(Network::Testnet));

        let cli = <Cli as clap::Parser>::try_parse_from(["gmcli", "status"]).unwrap();
        assert_eq!(
            cli.explicit_network(),
            None,
            "no flag means: use the sticky stored selection"
        );
    }

    #[test]
    fn clap_rejects_network_and_testnet_together() {
        let result = <Cli as clap::Parser>::try_parse_from([
            "gmcli",
            "--network",
            "mainnet",
            "--testnet",
            "status",
        ]);
        assert!(result.is_err(), "--network and --testnet must conflict");
    }

    #[test]
    fn clap_parses_doctor_and_gm() {
        assert!(matches!(
            <Cli as clap::Parser>::try_parse_from(["gmcli", "doctor"])
                .unwrap()
                .command,
            Command::Doctor
        ));
        assert!(matches!(
            <Cli as clap::Parser>::try_parse_from(["gmcli", "gm"])
                .unwrap()
                .command,
            Command::Gm
        ));
        // `list-products` is kept as a hidden alias that runs `status`.
        assert!(matches!(
            <Cli as clap::Parser>::try_parse_from(["gmcli", "list-products"])
                .unwrap()
                .command,
            Command::ListProducts
        ));
    }

    #[test]
    fn clap_parses_register_hotkey_both_flows() {
        // Bring-your-own: just the ss58.
        let byo = <Cli as clap::Parser>::try_parse_from([
            "gmcli",
            "register-hotkey",
            "--hotkey-ss58",
            "5Grw",
        ])
        .unwrap()
        .command;
        assert!(matches!(
            byo,
            Command::RegisterHotkey {
                hotkey_ss58: Some(s),
                wallet: None,
                hotkey: None,
                yes: false,
            } if s == "5Grw"
        ));

        // Assisted: wallet + hotkey + --yes, no ss58.
        let assisted = <Cli as clap::Parser>::try_parse_from([
            "gmcli",
            "register-hotkey",
            "--wallet",
            "miner",
            "--hotkey",
            "default",
            "--yes",
        ])
        .unwrap()
        .command;
        assert!(matches!(
            assisted,
            Command::RegisterHotkey {
                hotkey_ss58: None,
                wallet: Some(w),
                hotkey: Some(h),
                yes: true,
            } if w == "miner" && h == "default"
        ));
    }

    #[test]
    fn clap_parses_earnings_and_rejects_a_hotkey_arg() {
        use super::Network;

        let bare = <Cli as clap::Parser>::try_parse_from(["gmcli", "earnings"])
            .unwrap()
            .command;
        assert!(matches!(bare, Command::Earnings { yes: false }));

        let cli = <Cli as clap::Parser>::try_parse_from([
            "gmcli",
            "--network",
            "testnet",
            "earnings",
            "--yes",
        ])
        .unwrap();
        assert_eq!(cli.explicit_network(), Some(Network::Testnet));
        assert!(matches!(cli.command, Command::Earnings { yes: true }));

        // The hotkey is derived (login token / register-hotkey), never passed.
        assert!(<Cli as clap::Parser>::try_parse_from([
            "gmcli",
            "earnings",
            "--hotkey-ss58",
            "5Grw"
        ])
        .is_err());
    }
}
