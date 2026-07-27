//! `gmcli sources` — the sourcing routes a miner can serve, plus the shared
//! `GET /miners/products/sources` fetch that `declare-product` resolves
//! against.

use std::fmt::Write as _;

use anyhow::{Context as _, Result};

use gm_miner_cli::{
    client::RegistryClient,
    network::Network,
    pricing::format_per_mtok_usd,
    types::{SourceProduct, SourceProductsResponse},
};

use crate::commands::status_error;

const SOURCES_PATH: &str = "/miners/products/sources";

pub(crate) async fn cmd_sources(client: &mut RegistryClient) -> Result<()> {
    let network = client.config.resolved_network();
    let sources = fetch_sources(client).await?;

    println!("{}", render_sources(network, &sources).join("\n"));
    Ok(())
}

/// Pull the miner's sourcing routes. Source products are filtered out of the
/// buyer-facing `GET /products`, so this endpoint is the only place they
/// surface — both for `gmcli sources` and for `declare-product`'s lookup.
pub(crate) async fn fetch_sources(client: &mut RegistryClient) -> Result<Vec<SourceProduct>> {
    let resp = client
        .get(SOURCES_PATH)
        .await
        .context("GET /miners/products/sources")?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(status_error("sources", status, &body));
    }
    let body = resp
        .json::<SourceProductsResponse>()
        .await
        .context("parse sourcing routes")?;
    Ok(body.sources)
}

const SOURCE_COLUMNS: [(&str, usize); 5] = [
    ("ROUTE", 38),
    ("SERVES", 22),
    ("BUYER RETAIL / MTOK", 26),
    ("YOUR KEY", 16),
    ("OFFERED", 7),
];

fn source_row(cells: &[String; 5]) -> String {
    let mut row = String::new();
    for (i, ((_, width), cell)) in SOURCE_COLUMNS.iter().zip(cells).enumerate() {
        if i > 0 {
            row.push(' ');
        }
        let _ = write!(row, "{cell:<width$}");
    }
    row
}

fn source_rule() -> String {
    let cells: usize = SOURCE_COLUMNS.iter().map(|&(_, width)| width).sum();
    "-".repeat(cells + SOURCE_COLUMNS.len() - 1)
}

fn render_sources(network: Network, sources: &[SourceProduct]) -> Vec<String> {
    if sources.is_empty() {
        return vec![
            format!("Sourcing routes ({network})"),
            String::new(),
            "None available to you. A sourcing route serves a buyer product from a".to_owned(),
            "cheaper upstream; one appears here when the registry publishes it.".to_owned(),
            "`gmcli pricing` lists the buyer products you can serve directly.".to_owned(),
        ];
    }

    let mut lines = vec![
        format!("Sourcing routes ({network})"),
        "Serve a buyer product from a cheaper upstream. You are paid the buyer".to_owned(),
        "product's retail less your discount, so the gap between that and what the".to_owned(),
        "upstream charges you is your spread.".to_owned(),
        String::new(),
        source_row(&SOURCE_COLUMNS.map(|(name, _)| name.to_owned())),
        source_rule(),
    ];
    lines.extend(sources.iter().map(route_line));
    lines.extend(keyless_lines(sources));
    lines.extend(declare_lines(sources));
    lines
}

fn route_line(source: &SourceProduct) -> String {
    let retail = &source.retail_price.dimensions;
    source_row(&[
        format!("{}/{}", source.provider, source.model),
        format!("{}/{}", source.buyer_provider, source.buyer_model),
        format!(
            "{} in / {} out",
            format_per_mtok_usd(retail.input_per_mtok_ndollars),
            format_per_mtok_usd(retail.output_per_mtok_ndollars),
        ),
        key_cell(source.capable_worker_count),
        if source.already_offered { "yes" } else { "no" }.to_owned(),
    ])
}

fn key_cell(capable_worker_count: u32) -> String {
    match capable_worker_count {
        0 => "no".to_owned(),
        1 => "yes (1 worker)".to_owned(),
        n => format!("yes ({n} workers)"),
    }
}

/// Routes no worker can serve yet. Declaring one now buys nothing: the
/// registry's capability probe has no key to reach the upstream with, so the
/// offer lands ineligible.
fn keyless_lines(sources: &[SourceProduct]) -> Vec<String> {
    let keyless: Vec<_> = sources
        .iter()
        .filter(|s| s.capable_worker_count == 0)
        .collect();
    if keyless.is_empty() {
        return Vec::new();
    }

    let mut lines = vec![
        String::new(),
        format!(
            "No worker of yours holds a key for these upstreams ({}):",
            keyless.len()
        ),
    ];
    lines.extend(
        keyless
            .iter()
            .map(|s| format!("  {}/{}", s.provider, s.model)),
    );
    lines.push(
        "  Set the key with `gmcli set-api-keys`, then `gmcli deploy` to roll it out.".to_owned(),
    );
    lines
}

fn declare_lines(sources: &[SourceProduct]) -> Vec<String> {
    let ready: Vec<_> = sources
        .iter()
        .filter(|s| !s.already_offered && s.capable_worker_count > 0)
        .collect();
    if ready.is_empty() {
        if sources.iter().all(|s| s.already_offered) {
            return vec![
                String::new(),
                "Every route above is already declared — `gmcli status` shows how each is doing."
                    .to_owned(),
            ];
        }
        return Vec::new();
    }

    let mut lines = vec![String::new(), "Declare a route:".to_owned()];
    lines.extend(ready.iter().map(|s| {
        format!(
            "  gmcli declare-product --provider {} --model {} --discount-pct <pct>",
            s.provider, s.model
        )
    }));
    lines
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test assertions intentionally panic on unexpected values"
)]
mod tests {
    use super::{render_sources, source_row, source_rule, Network, SourceProduct, SOURCE_COLUMNS};

    fn sources(value: serde_json::Value) -> Vec<SourceProduct> {
        serde_json::from_value(value).expect("decode sourcing routes")
    }

    fn deepinfra_glm(capable_worker_count: u32, already_offered: bool) -> serde_json::Value {
        serde_json::json!({
            "provider": "deepinfra",
            "model": "zai-org/GLM-5.2",
            "buyer_provider": "zai",
            "buyer_model": "glm-5.2",
            "retail_price": {
                "dimensions": {
                    "input_per_mtok_ndollars": 1_400_000_000_u64,
                    "output_per_mtok_ndollars": 4_400_000_000_u64,
                }
            },
            "capable_worker_count": capable_worker_count,
            "already_offered": already_offered,
        })
    }

    #[test]
    fn the_rule_is_exactly_as_wide_as_a_row() {
        let row = source_row(&SOURCE_COLUMNS.map(|(name, _)| name.to_owned()));
        assert_eq!(source_rule().chars().count(), row.chars().count());
    }

    #[test]
    fn a_servable_route_shows_its_buyer_product_retail_and_the_declare_command() {
        let rendered = render_sources(
            Network::Mainnet,
            &sources(serde_json::json!([deepinfra_glm(1, false)])),
        )
        .join("\n");

        assert!(rendered.contains("deepinfra/zai-org/GLM-5.2"));
        assert!(rendered.contains("zai/glm-5.2"));
        assert!(rendered.contains("$1.400 in / $4.400 out"));
        assert!(rendered.contains("yes (1 worker)"));
        assert!(rendered.contains(
            "gmcli declare-product --provider deepinfra --model zai-org/GLM-5.2 --discount-pct <pct>"
        ));
        assert!(!rendered.contains("No worker of yours holds a key"));
    }

    #[test]
    fn a_route_with_no_capable_worker_names_the_key_fix_and_is_not_offered_as_declarable() {
        let rendered = render_sources(
            Network::Mainnet,
            &sources(serde_json::json!([deepinfra_glm(0, false)])),
        )
        .join("\n");

        assert!(rendered.contains("No worker of yours holds a key for these upstreams (1):"));
        assert!(rendered.contains("`gmcli set-api-keys`"));
        assert!(rendered.contains("`gmcli deploy`"));
        // Declaring without a key only produces an ineligible offer, so the
        // command must not be suggested until the key is in place.
        assert!(!rendered.contains("--discount-pct <pct>"));
    }

    #[test]
    fn an_already_declared_route_is_marked_and_not_suggested_again() {
        let rendered = render_sources(
            Network::Mainnet,
            &sources(serde_json::json!([deepinfra_glm(2, true)])),
        )
        .join("\n");

        assert!(rendered.contains("yes (2 workers)"));
        assert!(rendered.contains("Every route above is already declared"));
        assert!(!rendered.contains("gmcli declare-product"));
    }

    #[test]
    fn no_routes_explains_itself_rather_than_printing_an_empty_table() {
        let rendered = render_sources(Network::Mainnet, &[]).join("\n");

        assert!(rendered.contains("Sourcing routes (mainnet)"));
        assert!(rendered.contains("None available to you."));
        assert!(!rendered.contains("ROUTE"));
        assert!(!rendered.contains("----"));
    }
}
