//! gmcli CLI.
//!
//! Subcommands:
//!   set-api-keys     — persist provider API keys to ~/.gmcli/config.json
//!   deploy           — trust-correct single-shot deploy: fetch approved hashes,
//!                      deploy via Phala Cloud, verify hashes, register image
//!   login            — Taostats device-code OAuth flow
//!   doctor           — preflight checklist (network, login, keys, phala, hotkey)
//!   register-hotkey  — record the serving hotkey (bring-your-own ss58, or
//!                      print the btcli register command to run yourself)
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
//!
//! `main.rs` is pure coordination — the clap surface plus the [`dispatch`] /
//! [`dispatch_worker`] routers. Every command handler lives in a focused
//! submodule under [`mod@commands`].

#![forbid(unsafe_code)]

mod commands;

use std::io::IsTerminal as _;

use anyhow::Result;
use chrono::Timelike as _;
use clap::{Parser, Subcommand};
use gm_miner_cli::{
    client::RegistryClient,
    deploy::{DEFAULT_BOOT_TIMEOUT_SECS, DEFAULT_OS_IMAGE},
    network::Network,
    pricing::parse_discount_pct,
    types::Provider,
};

use crate::commands::deploy::{
    cmd_deploy_subcommand, cmd_publish_image_version, cmd_register_image_subcommand,
    cmd_worker_add, cmd_worker_list, cmd_worker_remove, deploy_args_from_flags, WorkerRegistration,
};
use crate::commands::doctor::cmd_doctor;
use crate::commands::earnings::cmd_earnings;
use crate::commands::fun::{cmd_gm, cmd_moon};
use crate::commands::hotkey::cmd_register_hotkey;
use crate::commands::keys::cmd_set_api_keys;
use crate::commands::persist::{cmd_login, ensure_fresh_token, load_config};
use crate::commands::products::{cmd_declare_product, cmd_declare_products, cmd_status};
use crate::commands::wizard::cmd_init;

// Re-exports so the in-file `mod tests` block can keep reaching items it moved
// out via `super::` paths, unchanged. Each name here is referenced only by the
// tests, so the block is `cfg(test)`-gated to stay clippy-clean in real builds.
#[cfg(test)]
use crate::commands::deploy::{
    cmd_deploy, existing_worker_id_for, reject_secondary_worker_deploy, DeployArgs,
};
#[cfg(test)]
use crate::commands::products::filter_catalog;
#[cfg(test)]
use crate::commands::status_error;
#[cfg(test)]
use crate::commands::wizard::{
    has_deployed_worker, has_valid_login, hotkey_step_done, provider_keys_done,
};
#[cfg(test)]
use gm_miner_cli::types::Product;

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
        gmcli set-api-keys --openai sk-... --google AIza...\n  \
        gmcli set-api-keys --chutes cpk-...")]
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

        /// Chutes API key (cpk_...).
        #[arg(long)]
        chutes: Option<String>,
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
    /// `PHALA_API_KEY` / `PHALA_CLOUD_API_KEY`, pass `--phala-api-key`, or
    /// run `phala auth login` before deploying.
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

    /// Compute a released image's compose/OS hashes offline and publish them
    /// to the target network's registry allow-list.
    ///
    /// Run by the release pipeline, not operators. dstack's `compose_hash` is
    /// re-derivable offline (sha256 over the canonical `app_compose`
    /// serialization) and `os_image_hash` is the pinned OS image's published
    /// measurement, so this needs no Phala Cloud deploy: it renders the
    /// compose for the target network, computes both hashes from source, and
    /// POSTs them to that network's `POST /admin/image-versions` (idempotent
    /// upsert). Authenticates with the registry admin key
    /// (`REGISTRY_ADMIN_KEY`), not the operator OAuth token or a Phala key.
    #[command(hide = true)]
    PublishImageVersion {
        #[command(flatten)]
        flags: Box<PublishImageVersionFlags>,
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

    /// Record the hotkey your miner serves under.
    ///
    /// Two flows. If you already registered a hotkey elsewhere (a browser
    /// wallet, another machine), pass `--hotkey-ss58 <addr>` and gmcli just
    /// records it — no btcli needed. If you have not, omit `--hotkey-ss58` and
    /// pass `--wallet`/`--hotkey`: gmcli prints the btcli register command for
    /// you to run yourself, then verifies the result via read-only chain state.
    #[command(after_help = "Examples:\n  \
        gmcli register-hotkey --hotkey-ss58 5GrwvaEF...     # already registered elsewhere\n  \
        gmcli --network testnet register-hotkey --wallet miner --hotkey default\n  \
        gmcli register-hotkey --wallet miner --hotkey default --yes  # non-interactive")]
    RegisterHotkey {
        /// The ss58 address of a hotkey you already registered elsewhere.
        /// When set, gmcli records it (verifying via btcli if present) and
        /// never registers anything. When omitted, gmcli resolves the local
        /// btcli hotkey and prints the register command for you to run.
        #[arg(long = "hotkey-ss58", value_name = "SS58")]
        hotkey_ss58: Option<String>,

        /// btcli coldkey (wallet) name. Required for the assisted flow.
        #[arg(long)]
        wallet: Option<String>,

        /// btcli hotkey name under the wallet. Required for the assisted flow.
        #[arg(long)]
        hotkey: Option<String>,

        /// Skip prompts (install offers, ss58 paste prompt) for non-interactive use.
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
        /// Provider: anthropic, openai, gemini, or chutes.
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

    /// Guided onboarding: walk a new miner through the whole setup in order.
    ///
    /// Runs the lifecycle one step at a time — register your hotkey, log in,
    /// deploy a worker, set provider keys, declare products — showing the
    /// exact command for each and asking before it runs. Steps already done
    /// (a recorded hotkey, a valid login, a deployed worker, set keys) are
    /// detected and skipped, so a returning miner breezes through.
    #[command(after_help = "Examples:\n  \
        gmcli init\n  \
        gmcli --network testnet init")]
    Init {
        /// Run non-interactively: never prompt. Each step runs if its inputs
        /// are already configured (stored keys, env, flags) and is skipped
        /// when it would otherwise need a prompt. Useful for a returning
        /// miner re-checking setup, or a scripted run.
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
pub(crate) struct DeployFlags {
    /// Pre-built digest-pinned image reference (registry/repo@sha256:...).
    ///
    /// Overrides the default. When set (or `GM_IMAGE_REF` is in env), this
    /// ref is embedded in the compose file directly with no build. When
    /// omitted, `gmcli deploy` defaults to the registry's latest supported
    /// image — a normal miner deploys the gm-published image and never
    /// builds. Pass `--image-repo` instead to build and push your own.
    #[arg(long, env = "GM_IMAGE_REF")]
    pub(crate) image_ref: Option<String>,

    /// Pin to a specific approved version by index (1 = newest).
    /// Defaults to the newest supported version.
    #[arg(long)]
    pub(crate) version: Option<usize>,

    /// Phala Cloud CVM name. Each worker needs its own name — a second
    /// worker must pass e.g. `--app-name gm-miner-2`.
    #[arg(long, default_value = "gm-miner-1")]
    pub(crate) app_name: String,

    /// Staging directory for the rendered compose + env files (the full
    /// path used verbatim). Defaults to `dist/<app_name>` relative to
    /// the current directory.
    #[arg(long)]
    pub(crate) dist_dir: Option<std::path::PathBuf>,

    /// Opt into building the miner image yourself: the public container
    /// registry repo to build and push to — Phala Cloud pulls the image from
    /// here. Most miners omit this and deploy the gm-published image. Example:
    /// `ghcr.io/<owner>/gm-miner`.
    #[arg(long, env = "GM_IMAGE_REPO")]
    pub(crate) image_repo: Option<String>,

    /// Image tag applied to the build before digest resolution.
    #[arg(long, env = "IMAGE_TAG", default_value = "v0.1.0")]
    pub(crate) image_tag: String,

    /// Phala Cloud instance type for the CVM.
    #[arg(long, env = "PHALA_INSTANCE_TYPE", default_value = "tdx.medium")]
    pub(crate) instance_type: String,

    /// Disk size for the CVM (with unit, e.g. `40G`).
    #[arg(long, env = "PHALA_DISK_SIZE", default_value = "40G")]
    pub(crate) disk_size: String,

    /// Production OS image for the CVM (`phala deploy --image`). The
    /// version must match the dstack version of the Phala node the CVM
    /// lands on — prod5/prod9 currently run dstack v0.5.7.
    #[arg(long, env = "PHALA_OS_IMAGE", default_value = DEFAULT_OS_IMAGE)]
    pub(crate) os_image: String,

    /// Repository root used as the Docker build context. Defaults to
    /// the current directory.
    #[arg(long)]
    pub(crate) repo_root: Option<std::path::PathBuf>,

    /// How long to wait for the CVM to boot and report its measured
    /// hashes via `phala cvms get --json` (seconds). Default: 300.
    #[arg(long, default_value_t = DEFAULT_BOOT_TIMEOUT_SECS)]
    pub(crate) boot_timeout_secs: u64,

    /// Phala Cloud API key. Overrides the stored key for this run only (not
    /// persisted). When omitted, gmcli uses `PHALA_API_KEY` /
    /// `PHALA_CLOUD_API_KEY`, then the key saved in config, then prompts.
    #[arg(long = "phala-api-key", value_name = "KEY")]
    pub(crate) phala_api_key: Option<String>,

    /// Skip interactive prompts (the Phala key paste, the `phala` install
    /// offer) for non-interactive use. A deploy that would need to prompt
    /// instead prints guidance and exits.
    #[arg(long)]
    pub(crate) yes: bool,

    /// Record acceptance of the gm miner terms without an interactive prompt.
    /// Equivalent to setting `GMCLI_ACCEPT_TERMS=1`. Lets scripted deploys
    /// proceed while still recording the accepted terms version locally and
    /// on the registry's miner record.
    #[arg(long)]
    pub(crate) accept_terms: bool,
}

/// Flags for `gmcli publish-image-version`. The release pipeline supplies
/// the digest-pinned image ref, the registry admin key, and the git
/// provenance; both hashes are computed offline from source.
#[derive(clap::Args)]
pub(crate) struct PublishImageVersionFlags {
    /// Digest-pinned released image reference (registry/repo@sha256:...).
    /// The compose is rendered around this exactly as `deploy` would.
    #[arg(long, env = "GM_IMAGE_REF")]
    pub(crate) image_ref: String,

    /// Registry admin API key (the `X-API-Key` for `/admin/image-versions`).
    #[arg(
        long = "registry-admin-key",
        env = "REGISTRY_ADMIN_KEY",
        value_name = "KEY"
    )]
    pub(crate) registry_admin_key: String,

    /// Release tag recorded on the published row (e.g. `v0.1.2`).
    #[arg(long)]
    pub(crate) git_tag: Option<String>,

    /// Release commit SHA (40-hex) recorded on the published row.
    #[arg(long)]
    pub(crate) git_commit: Option<String>,

    /// `owner/repo` slug recorded on the published row.
    #[arg(long, default_value = "taostat/gm-miner")]
    pub(crate) git_repo: String,
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
            chutes,
        } => cmd_set_api_keys(explicit_network, anthropic, openai, google, chutes),
        Command::Init { yes } => cmd_init(explicit_network, api_url, yes).await,
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
        Command::Worker { command } => dispatch_worker(command, explicit_network, api_url).await,
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
            cmd_register_hotkey(&cfg, hotkey_ss58, wallet, hotkey, yes)
        }
        Command::RegisterImage { app_id } => {
            let cfg = load_config(explicit_network, api_url)?;
            let cfg = ensure_fresh_token(cfg).await?;
            cmd_register_image_subcommand(cfg, &app_id).await
        }
        Command::PublishImageVersion { flags } => {
            // No OAuth: the registry admin key authenticates the publish, and
            // the registry URL comes from the network default or --api-url.
            let cfg = load_config(explicit_network, api_url)?;
            cmd_publish_image_version(&cfg, *flags).await
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

/// Route the `worker` subcommands. Each loads config, refreshes the token,
/// then hands off to the matching `cmd_worker_*`. Split from [`dispatch`] so
/// the top-level router stays under the line limit.
async fn dispatch_worker(
    command: WorkerCommand,
    explicit_network: Option<Network>,
    api_url: Option<String>,
) -> Result<()> {
    let cfg = load_config(explicit_network, api_url)?;
    let cfg = ensure_fresh_token(cfg).await?;
    match command {
        WorkerCommand::Add { flags } => cmd_worker_add(cfg, deploy_args_from_flags(*flags)).await,
        WorkerCommand::List => cmd_worker_list(&mut RegistryClient::new(cfg)).await,
        WorkerCommand::Remove { worker_id } => cmd_worker_remove(cfg, &worker_id).await,
    }
}

// ── Banner ───────────────────────────────────────────────────────────────────

/// The gm banner: block-letter GM art, version, and a time-of-day greeting.
fn banner() -> String {
    format!(
        " ██████╗ ███╗   ███╗\n\
         ██╔════╝ ████╗ ████║\n\
         ██║  ███╗██╔████╔██║\n\
         ██║   ██║██║╚██╔╝██║\n\
         ╚██████╔╝██║ ╚═╝ ██║\n\
          ╚═════╝ ╚═╝     ╚═╝\n\
         ───────────────────\n\
         gmcli v{version}\n\
         {greeting}",
        version = env!("CARGO_PKG_VERSION"),
        greeting = greeting()
    )
}

/// A short greeting keyed off the local hour.
pub(crate) fn greeting() -> &'static str {
    match chrono::Local::now().hour() {
        5..=11 => "gm. good morning.",
        12..=17 => "gm. good afternoon.",
        18..=21 => "gm. good evening.",
        _ => "gm. good night.",
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "tests intentionally panic on unexpected values"
)]
mod tests {
    use super::{filter_catalog, status_error, Cli, Command, Product, Provider, WorkerCommand};
    use gm_miner_cli::types::{RetailDimensions, RetailPrice};

    #[test]
    fn status_error_surfaces_non_json_5xx_body() {
        // An intermediary returns a 502 with an HTML body — not JSON. The
        // error must name the status and carry the raw body verbatim so the
        // operator sees the real failure, not a generic JSON-parse error.
        let err = status_error(
            "register",
            reqwest::StatusCode::BAD_GATEWAY,
            "<html><body>502 Bad Gateway</body></html>",
        );
        let msg = err.to_string();
        assert!(
            msg.contains("register failed"),
            "names the operation: {msg}"
        );
        assert!(msg.contains("502"), "names the status: {msg}");
        assert!(
            msg.contains("502 Bad Gateway"),
            "carries the raw body: {msg}"
        );
    }

    #[test]
    fn status_error_extracts_json_detail() {
        let err = status_error(
            "worker add",
            reqwest::StatusCode::CONFLICT,
            r#"{"detail":"hotkey already has a worker"}"#,
        );
        let msg = err.to_string();
        assert!(msg.contains("worker add failed (409"), "{msg}");
        assert!(msg.contains("hotkey already has a worker"), "{msg}");
        assert!(
            !msg.contains("detail"),
            "the JSON envelope must be unwrapped, not dumped: {msg}"
        );
    }

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
            phala_api_key: None,
            api_url_override: None,
            accepted_terms: None,
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
            phala_api_key: None,
            assume_yes: false,
            accept_terms: false,
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
            phala_api_key: None,
            api_url_override: None,
            accepted_terms: None,
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
            phala_api_key: None,
            assume_yes: false,
            accept_terms: false,
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
            phala_api_key: None,
            api_url_override: None,
            accepted_terms: None,
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
            phala_api_key: None,
            assume_yes: false,
            accept_terms: false,
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
            phala_api_key: None,
            api_url_override: None,
            accepted_terms: None,
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
            phala_api_key: None,
            assume_yes: false,
            accept_terms: false,
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
            phala_api_key: None,
            api_url_override: None,
            accepted_terms: None,
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
            phala_api_key: None,
            assume_yes: false,
            accept_terms: false,
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
            phala_api_key: None,
            api_url_override: None,
            accepted_terms: None,
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
            phala_api_key: None,
            api_url_override: None,
            accepted_terms: None,
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
            phala_api_key: None,
            assume_yes: false,
            accept_terms: false,
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
            phala_api_key: None,
            api_url_override: None,
            accepted_terms: None,
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
            phala_api_key: None,
            api_url_override: None,
            accepted_terms: None,
        };

        let err = reject_secondary_worker_deploy(&cfg, &WorkerRegistration::First, "gm-miner-2")
            .expect_err("a provisional worker-add stub must stay off the worker-#1 path");
        assert!(err.to_string().contains("secondary worker"), "got: {err}");
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

    // ── init wizard: detect-and-skip predicates ───────────────────────────────

    mod wizard {
        use super::super::{
            has_deployed_worker, has_valid_login, hotkey_step_done, provider_keys_done,
        };
        use gm_miner_cli::config::{
            Config, HotkeyRecord, NetworkEntry, ProviderKeys, TokenEntry, WorkerRecord,
        };
        use std::collections::HashMap;

        /// A config for `testnet` carrying the given network entry.
        fn cfg_with(entry: NetworkEntry) -> Config {
            let mut networks = HashMap::new();
            networks.insert("testnet".to_owned(), entry);
            Config {
                networks,
                active_network: Some("testnet".to_owned()),
                provider_keys: None,
                phala_api_key: None,
                api_url_override: None,
                accepted_terms: None,
            }
        }

        /// A non-expired token (expiry far in the future).
        fn fresh_token() -> TokenEntry {
            TokenEntry {
                access_token: Some("tok".to_owned()),
                token_expires_at: Some("2999-01-01T00:00:00Z".to_owned()),
                refresh_token: None,
            }
        }

        #[test]
        fn login_skipped_only_with_a_fresh_token() {
            assert!(
                !has_valid_login(&Config::default()),
                "no token → must log in"
            );
            let expired = cfg_with(NetworkEntry {
                tokens: Some(TokenEntry {
                    access_token: Some("tok".to_owned()),
                    token_expires_at: Some("2000-01-01T00:00:00Z".to_owned()),
                    refresh_token: None,
                }),
                ..Default::default()
            });
            assert!(!has_valid_login(&expired), "expired token → must log in");
            let fresh = cfg_with(NetworkEntry {
                tokens: Some(fresh_token()),
                ..Default::default()
            });
            assert!(has_valid_login(&fresh), "fresh token → login step skipped");
        }

        #[test]
        fn register_skipped_when_recorded_or_logged_in() {
            assert!(
                !hotkey_step_done(&Config::default()),
                "no hotkey, no login → register step runs"
            );
            // A recorded hotkey skips register even without a login.
            let recorded = cfg_with(NetworkEntry {
                registered_hotkey: Some(HotkeyRecord {
                    ss58: "5Test".to_owned(),
                    name: None,
                    verified: false,
                }),
                ..Default::default()
            });
            assert!(hotkey_step_done(&recorded));
            // A valid login alone proves on-chain registration.
            let logged_in = cfg_with(NetworkEntry {
                tokens: Some(fresh_token()),
                ..Default::default()
            });
            assert!(hotkey_step_done(&logged_in));
        }

        #[test]
        fn deploy_skip_offered_only_with_a_tracked_worker() {
            assert!(
                !has_deployed_worker(&Config::default()),
                "no workers → deploy step runs"
            );
            let deployed = cfg_with(NetworkEntry {
                workers: vec![WorkerRecord {
                    worker_id: "01J0A".to_owned(),
                    app_id: "app_01J0A".to_owned(),
                    app_name: "gm-miner-1".to_owned(),
                    node_secret: "s".to_owned(),
                    ..Default::default()
                }],
                ..Default::default()
            });
            assert!(has_deployed_worker(&deployed));
        }

        /// A config with `provider_keys.anthropic` set to `value`.
        fn cfg_with_anthropic(value: &str) -> Config {
            Config {
                provider_keys: Some(ProviderKeys {
                    anthropic: Some(value.to_owned()),
                    openai: None,
                    google: None,
                    chutes: None,
                }),
                ..Default::default()
            }
        }

        #[test]
        fn provider_keys_skipped_when_any_set() {
            assert!(
                !provider_keys_done(&Config::default()),
                "no keys → set-api-keys step runs"
            );
            assert!(provider_keys_done(&cfg_with_anthropic("sk-ant")));
            // A blank key does not count as set.
            assert!(
                !provider_keys_done(&cfg_with_anthropic("   ")),
                "whitespace key is not set"
            );
        }
    }
}
