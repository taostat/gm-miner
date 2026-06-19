//! `gmcli earnings` — the miner's current chain emission on the subnet (v1).

use anyhow::Result;

use gm_miner_cli::{
    btcli::{BtcliBridge as _, RealBtcli},
    config::Config,
    dependency::{ensure_dependency, BTCLI},
    earnings::{render_earnings, resolve_hotkey},
};

/// `gmcli earnings` — the miner's current chain emission on the subnet (v1).
///
/// Resolves the hotkey (`--hotkey-ss58` override, else the recorded one), then
/// reads its neuron row from the subnet metagraph via btcli. btcli is genuinely
/// required here (the chain read goes through it), so it is ensured lazily — the
/// command is the only place that pays the install cost. The summary is rendered
/// by [`render_earnings`]; a hotkey absent from the metagraph yields actionable
/// guidance, not a raw dump.
pub(crate) fn cmd_earnings(cfg: &Config, yes: bool) -> Result<()> {
    let network = cfg.resolved_network();
    let hotkey = resolve_hotkey(cfg, network)?;

    ensure_dependency(&BTCLI, yes)?;
    let stats = RealBtcli.neuron_stats(network, &hotkey.ss58)?;

    print!("{}", render_earnings(network, &hotkey, stats.as_ref()));
    Ok(())
}
