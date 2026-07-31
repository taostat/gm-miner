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
use crate::commands::products::{cmd_declare_products, DeclareOutcome};

/// What a wizard step actually left behind.
///
/// The distinction that matters is `Done` vs `Outstanding`: a step can be
/// skipped, declined, or short of the input it needs, and in every one of
/// those cases onboarding is not finished. Collapsing them into "carry on"
/// is what let `cmd_init` print its success banner after a step that did
/// nothing — so the outcome carries the command that would finish the step,
/// and [`closing_lines`] reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum StepOutcome {
    /// Ran to completion, or was already satisfied before the wizard started.
    Done,
    /// Did not happen. Carries the command that finishes it later.
    Outstanding(String),
    /// The miner answered `n`: stop the wizard here.
    Stop,
}

/// Whether the wizard should keep going (`Continue`) or stop here (`Stop`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WizardFlow {
    Continue,
    Stop,
}

/// Drive a wizard step from a `[Y/n/skip]` prompt: on `Run` evaluate `$body`
/// (which may `.await`); on `Skip` record the command as outstanding; on
/// `Stop` stop the wizard. Collapses the identical three-arm match every step
/// would otherwise repeat. `$body` is `Result<_>` — the `?` propagates a step
/// failure.
macro_rules! run_wizard_step {
    ($title:expr, $command:expr, $assume_yes:expr, $body:expr) => {{
        let command = $command;
        match ask_step($title, command, $assume_yes)? {
            StepChoice::Run => {
                $body?;
                Ok(StepOutcome::Done)
            }
            StepChoice::Skip => Ok(StepOutcome::Outstanding(command.to_string())),
            StepChoice::Stop => Ok(StepOutcome::Stop),
        }
    }};
}

/// Fold one step's outcome into the run's outstanding list, and say whether
/// the wizard should carry on.
fn record(outcome: StepOutcome, outstanding: &mut Vec<String>) -> WizardFlow {
    match outcome {
        StepOutcome::Done => WizardFlow::Continue,
        StepOutcome::Outstanding(command) => {
            outstanding.push(command);
            WizardFlow::Continue
        }
        StepOutcome::Stop => WizardFlow::Stop,
    }
}

/// The wizard's closing summary.
///
/// "All set" is claimed only when every step actually ran. A banner that
/// contradicts what just happened survived three fixes on this branch aimed at
/// the *message*, so the decision now depends on what the steps returned, and
/// lives in a pure function that can be asserted on without the wizard's IO.
///
/// `stopped` means the miner answered `n` partway: the steps after that point
/// were never attempted, so the list is partial and the copy must not imply
/// otherwise.
fn closing_lines(outstanding: &[String], stopped: bool) -> Vec<String> {
    let mut lines = vec![String::new()];
    if stopped {
        lines.push("Stopped — the remaining steps were not attempted.".to_owned());
        if !outstanding.is_empty() {
            lines.push("Outstanding from the steps you did reach:".to_owned());
            lines.extend(outstanding.iter().map(|command| format!("  $ {command}")));
        }
        lines.push("Re-run `gmcli init` to pick up where you left off.".to_owned());
        return lines;
    }
    if outstanding.is_empty() {
        lines.push("All set. Check your miner anytime:".to_owned());
        lines.push("  $ gmcli status     # registration + product table".to_owned());
        lines.push("  $ gmcli earnings   # on-chain emission".to_owned());
        return lines;
    }
    lines.push(format!(
        "Not finished — {} step(s) still to do:",
        outstanding.len()
    ));
    lines.extend(outstanding.iter().map(|command| format!("  $ {command}")));
    lines.push(String::new());
    lines.push("Run those when you are ready, or `gmcli init` again to be walked".to_owned());
    lines.push("through them. `gmcli status` shows what the registry has now.".to_owned());
    lines
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

    let (outstanding, stopped) = run_steps(explicit_network, api_url, cfg, assume_yes).await?;
    for line in closing_lines(&outstanding, stopped) {
        println!("{line}");
    }
    Ok(())
}

/// Run the five steps in dependency order, collecting the commands that would
/// finish whatever did not happen.
///
/// Returns that list plus whether the miner stopped partway. Config is
/// reloaded between steps because each underlying command persists to disk.
///
/// Provider keys precede deploy: `cmd_deploy` refuses to start without at
/// least one key (it bakes them into the CVM env), so the wizard must collect
/// them first or the deploy step would fail before doing anything.
async fn run_steps(
    explicit_network: Option<Network>,
    api_url: Option<String>,
    cfg: Config,
    assume_yes: bool,
) -> Result<(Vec<String>, bool)> {
    let mut outstanding = Vec::new();

    if record(wizard_register_hotkey(&cfg, assume_yes)?, &mut outstanding) == WizardFlow::Stop {
        return Ok((outstanding, true));
    }
    let login = wizard_login(explicit_network, api_url.clone(), assume_yes).await?;
    if record(login, &mut outstanding) == WizardFlow::Stop {
        return Ok((outstanding, true));
    }

    let cfg = load_config(explicit_network, api_url.clone())?;
    let keys = wizard_provider_keys(explicit_network, &cfg, assume_yes)?;
    if record(keys, &mut outstanding) == WizardFlow::Stop {
        return Ok((outstanding, true));
    }

    let cfg = load_config(explicit_network, api_url.clone())?;
    if record(wizard_deploy(cfg, assume_yes).await?, &mut outstanding) == WizardFlow::Stop {
        return Ok((outstanding, true));
    }

    let cfg = load_config(explicit_network, api_url)?;
    let declare = wizard_declare_products(cfg, assume_yes).await?;
    if record(declare, &mut outstanding) == WizardFlow::Stop {
        return Ok((outstanding, true));
    }

    Ok((outstanding, false))
}

/// Wizard step 1: register the serving hotkey.
///
/// Skipped when a hotkey is already recorded locally or a valid login token
/// exists (the token proves on-chain registration). Otherwise the miner is
/// asked whether they already registered a hotkey elsewhere:
/// - Yes → prompt for their ss58; use the bring-your-own path.
/// - No  → prompt for wallet/hotkey name; use the assisted path.
fn wizard_register_hotkey(cfg: &Config, assume_yes: bool) -> Result<StepOutcome> {
    let title = "Step 1/5 · register hotkey";
    if hotkey_step_done(cfg) {
        let detail = cfg.registered_hotkey().map_or_else(
            || "logged in (hotkey already registered)".to_owned(),
            |record| format!("hotkey {} recorded", record.ss58),
        );
        gm_miner_cli::wizard::already_done(title, &detail);
        return Ok(StepOutcome::Done);
    }

    let network = cfg.resolved_network();
    if registered_elsewhere(network, assume_yes)? {
        // Miner has a hotkey registered elsewhere — collect the ss58 and record it.
        let Some(ss58) = prompt_byo_ss58(assume_yes)? else {
            println!("  Run `gmcli register-hotkey --hotkey-ss58 <addr>` when ready.");
            return Ok(StepOutcome::Outstanding(
                "gmcli register-hotkey --hotkey-ss58 <addr>".to_owned(),
            ));
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
        return Ok(StepOutcome::Outstanding("gmcli register-hotkey".to_owned()));
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
) -> Result<StepOutcome> {
    let title = "Step 2/5 · login";
    let cfg = load_config(explicit_network, api_url.clone())?;
    if has_valid_login(&cfg) {
        gm_miner_cli::wizard::already_done(title, "a valid login token is stored");
        return Ok(StepOutcome::Done);
    }
    // Login is a browser device-code flow — it cannot run unattended, so a
    // non-interactive run skips it with guidance rather than hanging.
    if assume_yes {
        gm_miner_cli::wizard::already_done(title, "skipped — run `gmcli login` interactively");
        return Ok(StepOutcome::Outstanding("gmcli login".to_owned()));
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
async fn wizard_deploy(cfg: Config, assume_yes: bool) -> Result<StepOutcome> {
    let title = "Step 4/5 · deploy worker";
    if has_deployed_worker(&cfg) {
        gm_miner_cli::wizard::already_done(
            title,
            "worker #1 is already deployed (add more with `gmcli worker add`)",
        );
        return Ok(StepOutcome::Done);
    }
    // `cmd_deploy` refuses without a provider key (it bakes them into the CVM
    // env). If the keys step was skipped, a deploy would fail immediately —
    // skip it here with guidance rather than running a doomed command.
    if !provider_keys_done(&cfg) {
        gm_miner_cli::wizard::already_done(
            title,
            "skipped — deploy needs a provider key first (`gmcli set-api-keys`)",
        );
        return Ok(StepOutcome::Outstanding("gmcli deploy".to_owned()));
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
) -> Result<StepOutcome> {
    let title = "Step 3/5 · provider keys";
    if provider_keys_done(cfg) {
        gm_miner_cli::wizard::already_done(title, "provider keys already set");
        return Ok(StepOutcome::Done);
    }
    let keys = prompt_provider_keys(assume_yes)?;
    if keys.anthropic.is_none()
        && keys.openai.is_none()
        && keys.google.is_none()
        && keys.chutes.is_none()
        && keys.zai.is_none()
        && keys.moonshot.is_none()
        && keys.deepinfra.is_none()
        && keys.kubetee.is_none()
        && keys.engy.is_none()
    {
        println!("  No keys entered — skipping. Set them later with `gmcli set-api-keys`.");
        return Ok(StepOutcome::Outstanding("gmcli set-api-keys".to_owned()));
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
            keys.kubetee,
            keys.engy,
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
        kubetee: prompt_line("KubeTEE API key (blank to skip):", assume_yes)?,
        engy: prompt_line("Engy API key (blank to skip):", assume_yes)?,
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
    if keys.kubetee.is_some() {
        cmd.push_str(" --kubetee <key>");
    }
    if keys.engy.is_some() {
        cmd.push_str(" --engy <key>");
    }
    cmd
}

/// Wizard step 5: declare products across the catalog at one discount.
async fn wizard_declare_products(cfg: Config, assume_yes: bool) -> Result<StepOutcome> {
    let title = "Step 5/5 · declare products";
    let Some(discount_bp) = prompt_discount(assume_yes)? else {
        println!("  No discount entered — skipping. Declare later with `gmcli declare-products --discount-pct <pct>`.");
        return Ok(StepOutcome::Outstanding(
            "gmcli declare-products --discount-pct <pct>".to_owned(),
        ));
    };
    let pct = format_discount_pct(discount_bp);
    let command = format!("gmcli declare-products --discount-pct {pct}");
    // Not `run_wizard_step!`: that macro treats a completed `Run` as `Done`,
    // and this step has a fourth path. The miner can accept the step, read the
    // prices the discount works out to, and then decline the confirmation — at
    // which point nothing was declared, and the run is no more finished than
    // if they had skipped the step outright.
    match ask_step(title, &command, assume_yes)? {
        StepChoice::Run => match declare_all_products(cfg, discount_bp, assume_yes).await? {
            DeclareOutcome::Declared => Ok(StepOutcome::Done),
            DeclareOutcome::Cancelled => Ok(StepOutcome::Outstanding(command)),
        },
        StepChoice::Skip => Ok(StepOutcome::Outstanding(command)),
        StepChoice::Stop => Ok(StepOutcome::Stop),
    }
}

/// Refresh the token, then fan the discount across the catalog. The token
/// refresh is folded in here (the wizard's other steps go through `dispatch`,
/// which refreshes before the command; the declare step calls the command
/// directly, so it does its own refresh).
async fn declare_all_products(
    cfg: Config,
    discount_bp: u32,
    assume_yes: bool,
) -> Result<DeclareOutcome> {
    let mut client = gm_miner_cli::client::RegistryClient::new(ensure_fresh_token(cfg).await?);
    cmd_declare_products(&mut client, None, discount_bp, assume_yes).await
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

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::panic,
    reason = "test assertions intentionally panic on unexpected values"
)]
mod tests {
    use super::{
        closing_lines, record, run_steps, wizard_declare_products, wizard_deploy, wizard_login,
        wizard_provider_keys, wizard_register_hotkey, Config, StepOutcome, WizardFlow,
    };

    /// The banner that must appear if and only if onboarding actually finished.
    const SUCCESS_BANNER: &str = "All set";

    fn outstanding_after(outcomes: Vec<StepOutcome>) -> Vec<String> {
        let mut outstanding = Vec::new();
        for outcome in outcomes {
            assert_eq!(record(outcome, &mut outstanding), WizardFlow::Continue);
        }
        outstanding
    }

    #[test]
    fn a_run_where_every_step_ran_is_the_only_one_that_claims_success() {
        let rendered =
            closing_lines(&outstanding_after(vec![StepOutcome::Done; 5]), false).join("\n");
        assert!(rendered.contains(SUCCESS_BANNER), "{rendered}");
        assert!(rendered.contains("gmcli status"), "{rendered}");
    }

    #[test]
    fn a_skipped_step_suppresses_the_success_banner() {
        // The bug this pins: the wizard printed the skip notice *and then* the
        // success banner, so a miner left onboarding believing offers were
        // live. Asserting the skip line alone passes against that exact bug —
        // the absence of the banner is the assertion that matters.
        let outstanding = outstanding_after(vec![
            StepOutcome::Done,
            StepOutcome::Done,
            StepOutcome::Done,
            StepOutcome::Done,
            StepOutcome::Outstanding("gmcli declare-products --discount-pct 5".to_owned()),
        ]);
        let rendered = closing_lines(&outstanding, false).join("\n");

        assert!(
            !rendered.contains(SUCCESS_BANNER),
            "a run that declared nothing must not claim success:\n{rendered}"
        );
        assert!(
            rendered.contains("Not finished — 1 step(s) still to do:"),
            "{rendered}"
        );
        assert!(
            rendered.contains("  $ gmcli declare-products --discount-pct 5"),
            "{rendered}"
        );
    }

    #[test]
    fn every_outstanding_step_is_named_with_the_command_that_finishes_it() {
        let outstanding = outstanding_after(vec![
            StepOutcome::Outstanding("gmcli login".to_owned()),
            StepOutcome::Done,
            StepOutcome::Outstanding("gmcli set-api-keys".to_owned()),
            StepOutcome::Outstanding("gmcli deploy".to_owned()),
            StepOutcome::Done,
        ]);
        let rendered = closing_lines(&outstanding, false).join("\n");

        assert!(!rendered.contains(SUCCESS_BANNER), "{rendered}");
        assert!(rendered.contains("3 step(s) still to do"), "{rendered}");
        for command in ["gmcli login", "gmcli set-api-keys", "gmcli deploy"] {
            assert!(rendered.contains(&format!("  $ {command}")), "{rendered}");
        }
    }

    #[test]
    fn stopping_partway_never_claims_success_and_does_not_imply_a_full_list() {
        // `n` leaves the later steps unattempted, so the outstanding list is
        // partial — the copy must not read as "here is everything left".
        let mut outstanding = Vec::new();
        assert_eq!(
            record(
                StepOutcome::Outstanding("gmcli login".to_owned()),
                &mut outstanding
            ),
            WizardFlow::Continue
        );
        assert_eq!(
            record(StepOutcome::Stop, &mut outstanding),
            WizardFlow::Stop
        );

        let rendered = closing_lines(&outstanding, true).join("\n");
        assert!(!rendered.contains(SUCCESS_BANNER), "{rendered}");
        assert!(
            rendered.contains("the remaining steps were not attempted"),
            "{rendered}"
        );
        assert!(rendered.contains("  $ gmcli login"), "{rendered}");
        assert!(rendered.contains("Re-run `gmcli init`"), "{rendered}");
        assert!(!rendered.contains("still to do"), "{rendered}");
    }

    #[test]
    fn stopping_at_the_very_first_step_prints_no_empty_outstanding_block() {
        let rendered = closing_lines(&[], true).join("\n");
        assert!(!rendered.contains(SUCCESS_BANNER), "{rendered}");
        assert!(!rendered.contains("Outstanding from"), "{rendered}");
        assert!(rendered.contains("Re-run `gmcli init`"), "{rendered}");
    }

    // ── the real step mappings ───────────────────────────────────────────
    //
    // The tests above inject synthetic outcomes, which pins `closing_lines`
    // but not what feeds it: reverting any step's early return to `Done`
    // leaves them green. These drive the real step functions.
    //
    // `assume_yes` stands in for a non-interactive stdin throughout — both
    // short-circuit the same prompts — so nothing here blocks on input.

    /// `GMCLI_CONFIG_DIR` is process-global, so tests that mutate it must not
    /// run concurrently. Serialise them on a local mutex, and clear the
    /// override on drop even if the test panics.
    static CONFIG_DIR_ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct ConfigDirGuard {
        /// Held to serialise env mutation; never read.
        _lock: std::sync::MutexGuard<'static, ()>,
        /// Owns the tempdir so it outlives the test; never read.
        _dir: tempfile::TempDir,
    }

    impl ConfigDirGuard {
        fn new() -> Self {
            let lock = CONFIG_DIR_ENV
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let dir = tempfile::tempdir().expect("tempdir");
            // The held lock serialises this against every other env mutation in
            // this test binary. No `unsafe` block: the bin crate is
            // `#![forbid(unsafe_code)]`, and on edition 2021 `set_var` is
            // still callable directly.
            std::env::set_var("GMCLI_CONFIG_DIR", dir.path());
            Self {
                _lock: lock,
                _dir: dir,
            }
        }
    }

    impl Drop for ConfigDirGuard {
        fn drop(&mut self) {
            // Still holding the lock until after this returns.
            std::env::remove_var("GMCLI_CONFIG_DIR");
        }
    }

    /// A miner at the very start: no hotkey, no token, no keys, no worker.
    fn fresh_config() -> Config {
        Config {
            active_network: Some("testnet".to_owned()),
            ..Default::default()
        }
    }

    fn command_of(outcome: &StepOutcome) -> &str {
        match outcome {
            StepOutcome::Outstanding(command) => command,
            other => panic!("expected an outstanding step, got {other:?}"),
        }
    }

    #[test]
    fn a_register_step_with_no_input_is_outstanding() {
        let outcome = wizard_register_hotkey(&fresh_config(), true).expect("step runs");
        assert!(
            command_of(&outcome).starts_with("gmcli register-hotkey"),
            "{outcome:?}"
        );
    }

    #[test]
    fn a_keys_step_with_no_keys_entered_is_outstanding() {
        let outcome = wizard_provider_keys(None, &fresh_config(), true).expect("step runs");
        assert_eq!(command_of(&outcome), "gmcli set-api-keys");
    }

    #[tokio::test]
    async fn a_deploy_step_blocked_on_a_missing_provider_key_is_outstanding() {
        let outcome = wizard_deploy(fresh_config(), true)
            .await
            .expect("step runs");
        assert_eq!(command_of(&outcome), "gmcli deploy");
    }

    #[tokio::test]
    async fn a_declare_step_with_no_discount_entered_is_outstanding() {
        let outcome = wizard_declare_products(fresh_config(), true)
            .await
            .expect("step runs");
        assert_eq!(
            command_of(&outcome),
            "gmcli declare-products --discount-pct <pct>"
        );
    }

    #[tokio::test]
    async fn a_login_step_that_cannot_run_unattended_is_outstanding() {
        let _guard = ConfigDirGuard::new();
        let outcome = wizard_login(None, None, true).await.expect("step runs");
        assert_eq!(command_of(&outcome), "gmcli login");
    }

    #[tokio::test]
    async fn a_deploy_step_over_a_registered_worker_is_done_not_outstanding() {
        // The other direction: a step that is genuinely satisfied must report
        // `Done`, or every run would hold back the banner and the summary
        // would be as wrong as the one it replaced — just wrong the other way.
        let mut cfg = fresh_config();
        cfg.networks
            .entry("testnet".to_owned())
            .or_default()
            .workers
            .push(gm_miner_cli::config::WorkerRecord {
                worker_id: "worker-1".to_owned(),
                ..Default::default()
            });

        assert_eq!(
            wizard_deploy(cfg, true).await.expect("step runs"),
            StepOutcome::Done
        );
    }

    #[tokio::test]
    async fn a_run_that_finishes_nothing_reaches_the_closing_summary_without_the_banner() {
        // The composition, through the real steps and the real fold: a fresh
        // miner who supplies no input finishes none of the five, and the
        // summary that follows must not claim success. This is what a
        // synthetic-outcome test cannot catch — reverting any step's early
        // return to `Done` drops it from this list and the count fails.
        let _guard = ConfigDirGuard::new();
        let (outstanding, stopped) = run_steps(None, None, fresh_config(), true)
            .await
            .expect("a fully non-interactive run completes");

        assert!(!stopped, "nothing answered `n`");
        assert_eq!(outstanding.len(), 5, "{outstanding:?}");
        for expected in [
            "gmcli register-hotkey",
            "gmcli login",
            "gmcli set-api-keys",
            "gmcli deploy",
            "gmcli declare-products",
        ] {
            assert!(
                outstanding.iter().any(|c| c.starts_with(expected)),
                "missing {expected}: {outstanding:?}"
            );
        }

        let rendered = closing_lines(&outstanding, stopped).join("\n");
        assert!(
            !rendered.contains(SUCCESS_BANNER),
            "a run that finished nothing must not claim success:\n{rendered}"
        );
    }

    #[test]
    fn a_done_step_records_nothing() {
        let mut outstanding = Vec::new();
        assert_eq!(
            record(StepOutcome::Done, &mut outstanding),
            WizardFlow::Continue
        );
        assert!(outstanding.is_empty());
    }
}
