//! `gmcli notifications` — the miner's notifications on the registry.

use std::io::{IsTerminal as _, Write as _};

use anyhow::{Context as _, Result};

use gm_miner_cli::{
    client::RegistryClient,
    notifications::{channel, fetch_inbox, render_inbox, Listing},
};

pub(crate) async fn cmd_notifications_list(
    client: &mut RegistryClient,
    listing: Listing,
) -> Result<()> {
    let network = client.config.resolved_network();
    let inbox = fetch_inbox(client, listing).await?;
    let stdout = std::io::stdout();
    let width = if stdout.is_terminal() {
        terminal_size::terminal_size().map_or(78, |(width, _)| usize::from(width.0).min(78))
    } else {
        78
    };
    stdout
        .lock()
        .write_all(render_inbox(&inbox, network, width).as_bytes())
        .context("write notifications to stdout")
}

pub(crate) async fn cmd_notifications_set(
    client: &mut RegistryClient,
    destination: &str,
    digest: bool,
) -> Result<()> {
    print!(
        "{}",
        channel::set_channel(client, destination, digest).await?
    );
    Ok(())
}

pub(crate) async fn cmd_notifications_confirm(
    client: &mut RegistryClient,
    code: &str,
) -> Result<()> {
    print!("{}", channel::confirm_channel(client, code).await?);
    Ok(())
}

pub(crate) async fn cmd_notifications_status(client: &mut RegistryClient) -> Result<()> {
    print!("{}", channel::channel_status(client).await?);
    Ok(())
}

pub(crate) async fn cmd_notifications_off(client: &mut RegistryClient) -> Result<()> {
    print!("{}", channel::off_channel(client).await?);
    Ok(())
}
