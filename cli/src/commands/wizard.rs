//! `gmcli init` — guided onboarding through the full miner lifecycle.
//!
//! A pure orchestrator over the existing `cmd_*` handlers: it walks the
//! lifecycle steps in dependency order, each gated on a `[Y/n/skip]` prompt and
//! detect-and-skipped when already done.

use anyhow::Result;

use gm_miner_cli::{
    config::{Config, ProviderKeys},
    network::Network,
    pricing::{format_discount_pct, parse_discount_pct},
    wizard::{ask_step, prompt_line, StepChoice},
};

use crate::commands::deploy::{
    cmd_deploy_subcommand, default_deploy_flags, deploy_args_from_flags, WorkerRegistration,
};
use crate::commands::hotkey::cmd_register_hotkey;
use crate::commands::keys::{cmd_set_api_keys, FoundryArgs};
use crate::commands::persist::{cmd_login, ensure_fresh_token, load_config};
use crate::commands::products::cmd_declare_products;

/// Whether the wizard should keep going (`Continue`) or stop here (`Stop`).
///
/// A step returns `Stop` only when the miner answered `n` to its prompt; a
/// `skip` answer and a successful run both `Continue`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WizardFlow {
    Continue,
    Stop,
}

/// Drive a wizard step from a `[Y/n/skip]` prompt: on `Run` evaluate `$body`
/// (which may `.await`) and continue; on `Skip` continue; on `Stop` stop the
/// wizard. Collapses the identical three-arm match every step would otherwise
/// repeat. `$body` is `Result<_>` — the `?` propagates a step failure.
macro_rules! run_wizard_step {
    ($title:expr, $command:expr, $assume_yes:expr, $body:expr) => {
        match ask_step($title, $command, $assume_yes)? {
            StepChoice::Run => {
                $body?;
                Ok(WizardFlow::Continue)
            }
            StepChoice::Skip => Ok(WizardFlow::Continue),
            StepChoice::Stop => Ok(WizardFlow::Stop),
        }
    };
}

/// Whether the active network has a usable (non-expired) login token. A valid
/// token both lets the login step skip itself and proves the hotkey is already
/// registered on-chain (the auth-gateway only mints one for a registered
/// Owner), so the register step can skip too.
pub(crate) fn has_valid_login(cfg: &Config) -> bool {
    cfg.active_tokens()
        .is_some_and(|t| t.access_token.is_some() && !t.is_expired_or_near())
}

/// Whether the register-hotkey step is already satisfied: a hotkey is recorded
/// locally, or a valid login proves on-chain registration.
pub(crate) fn hotkey_step_done(cfg: &Config) -> bool {
    cfg.registered_hotkey().is_some() || has_valid_login(cfg)
}

/// Whether the active network has a *registered* worker — one the registry
/// assigned a `worker_id`. A provisional stub (empty `worker_id`, written
/// before registration by a deploy that then failed) does not count: its CVM
/// may never have come up, so the wizard must still offer the deploy step.
pub(crate) fn has_deployed_worker(cfg: &Config) -> bool {
    cfg.active_network_entry()
        .is_some_and(|e| e.workers.iter().any(|w| !w.worker_id.is_empty()))
}

/// Whether any provider key is already set.
pub(crate) fn provider_keys_done(cfg: &Config) -> bool {
    cfg.provider_keys
        .as_ref()
        .is_some_and(ProviderKeys::any_set)
}

/// `gmcli init` — guided onboarding through the full miner lifecycle.
///
/// Walks the steps in dependency order (register-hotkey precedes login because
/// the auth-gateway only mints a token for an on-chain-registered Owner), each
/// gated on a `[Y/n/skip]` prompt and detect-and-skipped when already done.
/// Config is reloaded between steps because each underlying command persists to
/// disk; the wizard is a pure orchestrator over the existing `cmd_*` functions.
pub(crate) async fn cmd_init(
    explicit_network: Option<Network>,
    api_url: Option<String>,
    assume_yes: bool,
) -> Result<()> {
    let cfg = load_config(explicit_network, api_url.clone())?;
    let network = cfg.resolved_network();
    println!(
        "gmcli init — onboarding for {network} (netuid {})",
        network.netuid()
    );
    if assume_yes {
        println!(
            "Running non-interactively (--yes): steps run when already configured, else skip."
        );
    } else {
        println!("Each step shows its command and asks before running. Press Enter to run, `n` to stop, `skip` to skip.");
    }

    // Provider keys precede deploy: `cmd_deploy` refuses to start without at
    // least one key (it bakes them into the CVM env), so the wizard must
    // collect them first or the deploy step would fail before doing anything.
    if wizard_register_hotkey(&cfg, assume_yes)? == WizardFlow::Stop {
        return Ok(());
    }
    if wizard_login(explicit_network, api_url.clone(), assume_yes).await? == WizardFlow::Stop {
        return Ok(());
    }
    let cfg = load_config(explicit_network, api_url.clone())?;
    if wizard_provider_keys(explicit_network, &cfg, assume_yes)? == WizardFlow::Stop {
        return Ok(());
    }
    let cfg = load_config(explicit_network, api_url.clone())?;
    if wizard_deploy(cfg, assume_yes).await? == WizardFlow::Stop {
        return Ok(());
    }
    let cfg = load_config(explicit_network, api_url)?;
    if wizard_declare_products(cfg, assume_yes).await? == WizardFlow::Stop {
        return Ok(());
    }

    println!("\nAll set. Check your miner anytime:");
    println!("  $ gmcli status     # registration + product table");
    println!("  $ gmcli earnings   # on-chain emission");
    Ok(())
}

/// Wizard step 1: register the serving hotkey.
///
/// Skipped when a hotkey is already recorded locally or a valid login token
/// exists (the token proves on-chain registration). Otherwise the miner is
/// asked whether they already registered a hotkey elsewhere:
/// - Yes → prompt for their ss58; use the bring-your-own path.
/// - No  → prompt for wallet/hotkey name; use the assisted path.
fn wizard_register_hotkey(cfg: &Config, assume_yes: bool) -> Result<WizardFlow> {
    let title = "Step 1/5 · register hotkey";
    if hotkey_step_done(cfg) {
        let detail = cfg.registered_hotkey().map_or_else(
            || "logged in (hotkey already registered)".to_owned(),
            |record| format!("hotkey {} recorded", record.ss58),
        );
        gm_miner_cli::wizard::already_done(title, &detail);
        return Ok(WizardFlow::Continue);
    }

    let network = cfg.resolved_network();
    if registered_elsewhere(network, assume_yes)? {
        // Miner has a hotkey registered elsewhere — collect the ss58 and record it.
        let Some(ss58) = prompt_byo_ss58(assume_yes)? else {
            println!("  Run `gmcli register-hotkey --hotkey-ss58 <addr>` when ready.");
            return Ok(WizardFlow::Continue);
        };
        let command = describe_register_command(Some(&ss58), None, None);
        return run_wizard_step!(
            title,
            &command,
            assume_yes,
            cmd_register_hotkey(cfg, Some(ss58), None, None, assume_yes)
        );
    }

    // No recorded hotkey and nothing to go on non-interactively — register
    // needs the operator's wallet/hotkey, which only a prompt supplies.
    let Some((wallet, hotkey)) = prompt_fresh_inputs(assume_yes)? else {
        gm_miner_cli::wizard::already_done(
            title,
            "skipped (no input) — run `gmcli register-hotkey` when ready",
        );
        return Ok(WizardFlow::Continue);
    };
    let command = describe_register_command(None, Some(&wallet), hotkey.as_deref());
    run_wizard_step!(
        title,
        &command,
        assume_yes,
        cmd_register_hotkey(cfg, None, Some(wallet), hotkey, assume_yes)
    )
}

/// Ask whether the miner already has a hotkey registered on `network`.
/// `assume_yes` and a non-TTY answer "no" so a scripted `init` falls through
/// to the register step (which then skips when it has no inputs).
fn registered_elsewhere(network: Network, assume_yes: bool) -> Result<bool> {
    gm_miner_cli::dependency::confirm(
        &format!(
            "Already registered a hotkey on subnet {} — via btcli, another machine, \
             or a Bittensor wallet app?",
            network.netuid()
        ),
        false,
        assume_yes,
    )
}

/// Prompt for the ss58 of a hotkey the miner registered elsewhere.
/// Returns `None` in non-interactive mode or when the miner leaves it blank.
fn prompt_byo_ss58(assume_yes: bool) -> Result<Option<String>> {
    prompt_line("ss58 address of your registered hotkey:", assume_yes)
}

/// Prompt for a wallet name and optional hotkey name for the assisted flow.
/// Returns `None` in non-interactive mode or when the wallet name is blank.
/// The hotkey defaults to `"default"` when left blank.
fn prompt_fresh_inputs(assume_yes: bool) -> Result<Option<(String, Option<String>)>> {
    let Some(wallet) = prompt_line("btcli wallet (coldkey) name:", assume_yes)? else {
        return Ok(None);
    };
    let hotkey = prompt_line("btcli hotkey name (blank for \"default\"):", assume_yes)?;
    Ok(Some((wallet, hotkey)))
}

/// Render the `register-hotkey` command the wizard will run, for display.
fn describe_register_command(
    ss58: Option<&str>,
    wallet: Option<&str>,
    hotkey: Option<&str>,
) -> String {
    if let Some(ss58) = ss58 {
        return format!("gmcli register-hotkey --hotkey-ss58 {ss58}");
    }
    let wallet = wallet.unwrap_or("<wallet>");
    let hotkey = hotkey.unwrap_or("<hotkey>");
    format!("gmcli register-hotkey --wallet {wallet} --hotkey {hotkey}")
}

/// Wizard step 2: log in. Skipped when a non-expired token already exists.
async fn wizard_login(
    explicit_network: Option<Network>,
    api_url: Option<String>,
    assume_yes: bool,
) -> Result<WizardFlow> {
    let title = "Step 2/5 · login";
    let cfg = load_config(explicit_network, api_url.clone())?;
    if has_valid_login(&cfg) {
        gm_miner_cli::wizard::already_done(title, "a valid login token is stored");
        return Ok(WizardFlow::Continue);
    }
    // Login is a browser device-code flow — it cannot run unattended, so a
    // non-interactive run skips it with guidance rather than hanging.
    if assume_yes {
        gm_miner_cli::wizard::already_done(title, "skipped — run `gmcli login` interactively");
        return Ok(WizardFlow::Continue);
    }
    run_wizard_step!(
        title,
        "gmcli login",
        assume_yes,
        cmd_login(explicit_network, api_url, true).await
    )
}

/// Wizard step 4: deploy worker #1. This step is worker #1 onboarding only —
/// `gmcli deploy` registers `WorkerRegistration::First`. A miner who already
/// has a registered worker has finished onboarding, so the step is skipped
/// with a pointer to `gmcli worker add` (the correct command for more
/// capacity); the wizard never re-runs `deploy` over a registered worker #1,
/// which would replace its registry endpoint.
async fn wizard_deploy(cfg: Config, assume_yes: bool) -> Result<WizardFlow> {
    let title = "Step 4/5 · deploy worker";
    if has_deployed_worker(&cfg) {
        gm_miner_cli::wizard::already_done(
            title,
            "worker #1 is already deployed (add more with `gmcli worker add`)",
        );
        return Ok(WizardFlow::Continue);
    }
    // `cmd_deploy` refuses without a provider key (it bakes them into the CVM
    // env). If the keys step was skipped, a deploy would fail immediately —
    // skip it here with guidance rather than running a doomed command.
    if !provider_keys_done(&cfg) {
        gm_miner_cli::wizard::already_done(
            title,
            "skipped — deploy needs a provider key first (`gmcli set-api-keys`)",
        );
        return Ok(WizardFlow::Continue);
    }
    let mut flags = default_deploy_flags();
    flags.yes = assume_yes;
    let args = deploy_args_from_flags(flags);
    run_wizard_step!(
        title,
        "gmcli deploy",
        assume_yes,
        cmd_deploy_subcommand(cfg, args, WorkerRegistration::First).await
    )
}

/// Wizard step 3: set provider keys. Skipped when any key is already set.
fn wizard_provider_keys(
    explicit_network: Option<Network>,
    cfg: &Config,
    assume_yes: bool,
) -> Result<WizardFlow> {
    let title = "Step 3/5 · provider keys";
    if provider_keys_done(cfg) {
        gm_miner_cli::wizard::already_done(title, "provider keys already set");
        return Ok(WizardFlow::Continue);
    }
    let keys = prompt_provider_keys(assume_yes)?;
    if keys.anthropic.is_none()
        && keys.openai.is_none()
        && keys.google.is_none()
        && keys.chutes.is_none()
        && keys.zai.is_none()
        && keys.moonshot.is_none()
        && keys.deepinfra.is_none()
    {
        println!("  No keys entered — skipping. Set them later with `gmcli set-api-keys`.");
        return Ok(WizardFlow::Continue);
    }
    let command = describe_keys_command(&keys);
    run_wizard_step!(
        title,
        &command,
        assume_yes,
        cmd_set_api_keys(
            explicit_network,
            keys.anthropic,
            keys.anthropic_upstream,
            keys.bedrock_region,
            keys.bedrock_api_key,
            // The wizard prompts for direct provider keys only; cloud backends
            // (Bedrock, Foundry, Azure OpenAI) are configured with the explicit
            // `set-api-keys` flags. Carry through whatever is already stored.
            FoundryArgs {
                endpoint: keys.azure_foundry_endpoint,
                api_key: keys.azure_foundry_api_key,
                tenant_id: keys.azure_foundry_tenant_id,
                subscription_id: keys.azure_foundry_subscription_id,
                resource_group: keys.azure_foundry_resource_group,
                client_id: keys.azure_foundry_client_id,
                client_secret: keys.azure_foundry_client_secret,
            },
            keys.openai,
            keys.openai_upstream,
            keys.azure_openai_endpoint,
            keys.azure_openai_api_key,
            keys.azure_tenant_id,
            keys.azure_subscription_id,
            keys.azure_resource_group,
            keys.azure_client_id,
            keys.azure_client_secret,
            keys.google,
            keys.chutes,
            keys.zai,
            keys.moonshot,
            keys.deepinfra,
        )
    )
}

/// Prompt for each provider key in turn (blank to skip a provider).
fn prompt_provider_keys(assume_yes: bool) -> Result<ProviderKeys> {
    Ok(ProviderKeys {
        anthropic: prompt_line("Anthropic API key (blank to skip):", assume_yes)?,
        anthropic_upstream: None,
        bedrock_region: None,
        bedrock_api_key: None,
        azure_foundry_endpoint: None,
        azure_foundry_api_key: None,
        azure_foundry_tenant_id: None,
        azure_foundry_subscription_id: None,
        azure_foundry_resource_group: None,
        azure_foundry_client_id: None,
        azure_foundry_client_secret: None,
        openai: prompt_line("OpenAI API key (blank to skip):", assume_yes)?,
        openai_upstream: None,
        azure_openai_endpoint: None,
        azure_openai_api_key: None,
        azure_tenant_id: None,
        azure_subscription_id: None,
        azure_resource_group: None,
        azure_client_id: None,
        azure_client_secret: None,
        google: prompt_line("Google API key (blank to skip):", assume_yes)?,
        chutes: prompt_line("Chutes API key (blank to skip):", assume_yes)?,
        zai: prompt_line("Z.ai API key (blank to skip):", assume_yes)?,
        moonshot: prompt_line("Moonshot API key (blank to skip):", assume_yes)?,
        deepinfra: prompt_line("DeepInfra API key (blank to skip):", assume_yes)?,
    })
}

/// Render the `set-api-keys` command for display, naming only the providers
/// the miner supplied (never echoing the secret values).
fn describe_keys_command(keys: &ProviderKeys) -> String {
    let mut cmd = String::from("gmcli set-api-keys");
    if keys.anthropic.is_some() {
        cmd.push_str(" --anthropic <key>");
    }
    if keys.anthropic_upstream.as_deref() == Some("bedrock") {
        cmd.push_str(" --anthropic-upstream bedrock");
    }
    if keys.bedrock_api_key.is_some() {
        cmd.push_str(" --bedrock-region <region> --bedrock-api-key <key>");
    }
    if keys.openai.is_some() {
        cmd.push_str(" --openai <key>");
    }
    if keys.openai_upstream.as_deref() == Some("azure") {
        cmd.push_str(" --openai-upstream azure");
    }
    if keys.azure_openai_api_key.is_some() {
        cmd.push_str(" --azure-openai-endpoint <url> --azure-openai-api-key <key>");
    }
    if keys.google.is_some() {
        cmd.push_str(" --google <key>");
    }
    if keys.chutes.is_some() {
        cmd.push_str(" --chutes <key>");
    }
    if keys.zai.is_some() {
        cmd.push_str(" --zai <key>");
    }
    if keys.moonshot.is_some() {
        cmd.push_str(" --moonshot <key>");
    }
    if keys.deepinfra.is_some() {
        cmd.push_str(" --deepinfra <key>");
    }
    cmd
}

/// Wizard step 5: declare products across the catalog at one discount.
async fn wizard_declare_products(cfg: Config, assume_yes: bool) -> Result<WizardFlow> {
    let title = "Step 5/5 · declare products";
    let Some(discount_bp) = prompt_discount(assume_yes)? else {
        println!("  No discount entered — skipping. Declare later with `gmcli declare-products --discount-pct <pct>`.");
        return Ok(WizardFlow::Continue);
    };
    let pct = format_discount_pct(discount_bp);
    let command = format!("gmcli declare-products --discount-pct {pct}");
    run_wizard_step!(
        title,
        &command,
        assume_yes,
        declare_all_products(cfg, discount_bp).await
    )
}

/// Refresh the token, then fan the discount across the catalog. The token
/// refresh is folded in here (the wizard's other steps go through `dispatch`,
/// which refreshes before the command; the declare step calls the command
/// directly, so it does its own refresh).
async fn declare_all_products(cfg: Config, discount_bp: u32) -> Result<()> {
    let mut client = gm_miner_cli::client::RegistryClient::new(ensure_fresh_token(cfg).await?);
    cmd_declare_products(&mut client, None, discount_bp).await
}

/// Prompt for the catalog-wide discount percent, parsed into basis points.
/// A blank answer (or a non-TTY / `--yes`) returns `None` so the step skips.
fn prompt_discount(assume_yes: bool) -> Result<Option<u32>> {
    let Some(raw) = prompt_line(
        "Percent off retail to offer on every product (e.g. 5):",
        assume_yes,
    )?
    else {
        return Ok(None);
    };
    parse_discount_pct(&raw)
        .map(Some)
        .map_err(|e| anyhow::anyhow!(e))
}
