//! `gmcli earnings` — served earnings from the selected registry.

use anyhow::Result;

use gm_miner_cli::{
    config::Config,
    earnings::{fetch_earnings, render_earnings, resolve_hotkey},
};

/// Uses the public registry endpoint without installing btcli or refreshing auth.
pub(crate) async fn cmd_earnings(cfg: &Config) -> Result<()> {
    let network = cfg.resolved_network();
    let hotkey = resolve_hotkey(cfg, network)?;

    let earnings = fetch_earnings(&cfg.api_url(), &hotkey.ss58).await?;

    print!("{}", render_earnings(network, &hotkey, &earnings)?);
    Ok(())
}
