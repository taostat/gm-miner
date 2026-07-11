//! `gmcli pricing` — how the miner's offers rank against the eligible field.

use anyhow::Result;

use gm_miner_cli::{
    client::RegistryClient, pricing::render_pricing, types::PricingCompetitiveness,
};

use crate::commands::get_me_json;

const PRICING_PATH: &str = "/miners/me/pricing-competitiveness";

pub(crate) async fn cmd_pricing(client: &mut RegistryClient) -> Result<()> {
    let network = client.config.resolved_network();
    let body: PricingCompetitiveness = get_me_json(client, PRICING_PATH).await?;

    println!("{}", render_pricing(network, &body.products).join("\n"));
    Ok(())
}
