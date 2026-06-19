//! `gmcli register-hotkey` — record the hotkey the miner serves under.

use anyhow::{bail, Context as _, Result};

use gm_miner_cli::{
    btcli::{BtcliBridge, RealBtcli, Registration},
    config::{Config, HotkeyRecord},
    dependency::{ensure_dependency, BTCLI},
    network::Network,
    register_hotkey::record_byo,
};

use crate::commands::persist::persist_registered_hotkey;

/// `gmcli register-hotkey` — record the hotkey the miner serves under.
///
/// Dispatches on `--hotkey-ss58`: present means bring-your-own (just record,
/// verify via btcli only if it happens to be installed); absent means the
/// assisted btcli flow (offer to install btcli, resolve the local hotkey, and
/// print the register command for the operator when needed).
/// Either way the resulting [`HotkeyRecord`] is persisted to the active
/// network's config so login/deploy/doctor/earnings can reference it.
pub(crate) fn cmd_register_hotkey(
    cfg: &Config,
    hotkey_ss58: Option<String>,
    wallet: Option<String>,
    hotkey: Option<String>,
    yes: bool,
) -> Result<()> {
    let network = cfg.resolved_network();
    match hotkey_ss58 {
        Some(ss58) => register_hotkey_byo(network, &ss58),
        None => register_hotkey_assisted(network, wallet, hotkey, yes),
    }
}

/// Bring-your-own: record an ss58 the operator registered elsewhere. Verifies
/// against the metagraph only when btcli is already on PATH — never installs it.
fn register_hotkey_byo(network: Network, ss58: &str) -> Result<()> {
    let btcli = RealBtcli;
    let bridge: Option<&dyn BtcliBridge> =
        gm_miner_cli::dependency::on_path("btcli").then_some(&btcli);
    let outcome = record_byo(bridge, network, ss58)?;

    persist_registered_hotkey(network.as_str(), outcome.record.clone())
        .context("persist registered hotkey")?;

    println!("Recorded hotkey {} for {network}.", outcome.record.ss58);
    println!("{}", outcome.note);
    println!("Next: `gmcli deploy` to launch a worker under this hotkey.");
    Ok(())
}

/// Assisted: resolve a local btcli hotkey and verify it. The only flow that
/// needs btcli up front — so it (and only it) runs [`ensure_dependency`] for it.
fn register_hotkey_assisted(
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
        // Switch to the BYO read-only path: verify on the metagraph and record.
        return register_hotkey_byo(network, &ss58);
    };

    if let Registration::Registered { uid } = btcli.registration_of(network, &ss58)? {
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
    let record = HotkeyRecord {
        ss58: ss58.to_owned(),
        name: Some(hotkey.to_owned()),
        verified: true,
    };
    persist_registered_hotkey(network.as_str(), record).context("persist registered hotkey")?;
    println!(
        "{wallet}/{hotkey} ({ss58}) is already registered on {network} — uid {uid}. \
         Nothing to do."
    );
    Ok(())
}
