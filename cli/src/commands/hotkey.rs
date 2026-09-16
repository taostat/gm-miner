//! `gmcli register-hotkey` — record the hotkey the miner serves under.

use anyhow::{bail, Context as _, Result};

use gm_miner_cli::{
    btcli::{BtcliBridge, RealBtcli, Registration},
    config::Config,
    dependency::{ensure_dependency, BTCLI},
    network::Network,
};

use crate::commands::persist::persist_registered_hotkey;

/// `gmcli register-hotkey` — record the hotkey the miner serves under.
///
/// Dispatches on `--hotkey-ss58`: present means bring-your-own (just record,
/// verify directly on-chain); absent means the
/// assisted btcli flow (offer to install btcli, resolve the local hotkey, and
/// print the register command for the operator when needed).
/// Either way the resulting [`HotkeyRecord`] is persisted to the active
/// network's config so login/deploy/doctor/earnings can reference it.
pub(crate) async fn cmd_register_hotkey(
    cfg: &Config,
    hotkey_ss58: Option<String>,
    wallet: Option<String>,
    hotkey: Option<String>,
    yes: bool,
) -> Result<()> {
    let network = cfg.resolved_network();
    match hotkey_ss58 {
        Some(ss58) => register_hotkey_byo(network, &ss58).await,
        None => register_hotkey_assisted(network, wallet, hotkey, yes).await,
    }
}

/// Bring-your-own: record an ss58 the operator registered elsewhere. Verifies
/// with a direct Substrate read; btcli is never consulted.
async fn register_hotkey_byo(network: Network, ss58: &str) -> Result<()> {
    let registration = gm_miner_cli::chain::registration_of(network, ss58.trim()).await?;
    let outcome = gm_miner_cli::register_hotkey::record_byo(registration, network, ss58)?;

    persist_registered_hotkey(network.as_str(), outcome.record.clone())
        .context("persist registered hotkey")?;

    println!("Recorded hotkey {} for {network}.", outcome.record.ss58);
    println!("{}", outcome.note);
    println!("Next: `gmcli deploy` to launch a worker under this hotkey.");
    Ok(())
}

/// Assisted: resolve a local btcli hotkey and verify it. The only flow that
/// needs btcli up front — so it (and only it) runs [`ensure_dependency`] for it.
async fn register_hotkey_assisted(
    network: Network,
    wallet: Option<String>,
    hotkey: Option<String>,
    yes: bool,
) -> Result<()> {
    let (wallet, hotkey) = require_wallet_and_hotkey(wallet, hotkey)?;
    ensure_dependency(&BTCLI, yes)?;
    let btcli = RealBtcli;

    // Resolve the ss58 up front — it is both proof the local wallet/hotkey
    // exists and the address we verify. If the hotkey is not local, or is local
    // but not registered on the subnet, we hand the btcli register command to
    // the operator. gmcli never shells out to key-generation or signing
    // commands — those stay with the operator.
    let Some(ss58) = btcli.hotkey_ss58(&wallet, &hotkey)? else {
        let register_command = btcli_register_command(network, &wallet, &hotkey);
        println!(
            "Hotkey `{hotkey}` not found under wallet `{wallet}`.\n\
             Run these commands in your terminal, then paste the ss58 below:\n\
             \n\
               btcli wallet new-hotkey --wallet.name {wallet} --wallet.hotkey {hotkey}\n\
               {register_command}\n"
        );
        let Some(ss58) = gm_miner_cli::wizard::prompt_line(
            "Hotkey ss58 address (from `btcli wallet list` after the above):",
            yes,
        )?
        else {
            bail!(
                "No ss58 provided. Run the commands above, then re-run \
                 `gmcli register-hotkey --wallet {wallet} --hotkey {hotkey}`."
            );
        };
        // Verify the supplied address directly on-chain and record it.
        return register_hotkey_byo(network, &ss58).await;
    };

    if let Registration::Registered { uid } =
        gm_miner_cli::chain::registration_of(network, &ss58).await?
    {
        return persist_already_registered(network, &wallet, &hotkey, &ss58, uid);
    }

    let register_command = btcli_register_command(network, &wallet, &hotkey);
    println!(
        "{wallet}/{hotkey} ({ss58}) is not registered on {network} (netuid {}).\n\
         Run this command in your terminal:\n\
         \n\
           {register_command}\n\
         \n\
         Then re-run `gmcli register-hotkey --wallet {wallet} --hotkey {hotkey}` to verify \
         and record it.",
        network.netuid()
    );
    Ok(())
}

fn btcli_register_command(network: Network, wallet: &str, hotkey: &str) -> String {
    let netuid = network.netuid();
    let chain = gm_miner_cli::btcli::btcli_network(network);
    format!(
        "btcli subnet register --wallet.name {wallet} --wallet.hotkey {hotkey} \
         --netuid {netuid} --network {chain}"
    )
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
    network: Network,
    wallet: &str,
    hotkey: &str,
    ss58: &str,
    uid: u64,
) -> Result<()> {
    let mut record =
        gm_miner_cli::register_hotkey::record_byo(Registration::Registered { uid }, network, ss58)?
            .record;
    record.name = Some(hotkey.to_owned());
    persist_registered_hotkey(network.as_str(), record).context("persist registered hotkey")?;
    println!(
        "{wallet}/{hotkey} ({ss58}) is already registered on {network} — uid {uid}. \
         Nothing to do."
    );
    Ok(())
}
