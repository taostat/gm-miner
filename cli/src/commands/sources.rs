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
const SOURCING_DOC_URL: &str = concat!(env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/sourcing.md");

pub(crate) async fn cmd_sources(client: &mut RegistryClient) -> Result<()> {
    let network = client.config.resolved_network();
    let sources = fetch_sources(client).await?;

    println!("{}", render_sources(network, &sources).join("\n"));
    Ok(())
}

/// What the sourcing-routes lookup found.
///
/// `Unsupported` is a registry that predates the endpoint, kept distinct from
/// an empty route list so `gmcli sources` can say which it is and
/// `declare-product` can still reject an unknown product on its own terms.
#[derive(Debug)]
pub(crate) enum SourceLookup {
    Routes(Vec<SourceProduct>),
    Unsupported,
}

impl SourceLookup {
    /// The routes, with an unsupported registry read as "none" — a caller
    /// doing a membership test cannot act on the difference.
    pub(crate) fn into_routes(self) -> Vec<SourceProduct> {
        match self {
            Self::Routes(routes) => routes,
            Self::Unsupported => Vec::new(),
        }
    }
}

/// Pull the miner's sourcing routes. Source products are filtered out of the
/// buyer-facing `GET /products`, so this endpoint is the only place they
/// surface — both for `gmcli sources` and for `declare-product`'s lookup.
pub(crate) async fn fetch_sources(client: &mut RegistryClient) -> Result<SourceLookup> {
    let resp = client
        .get(SOURCES_PATH)
        .await
        .context("GET /miners/products/sources")?;

    let status = resp.status();
    // A 404 uniquely means the registry predates this endpoint: once deployed
    // it answers 401 unauthenticated and 200 with an empty list when the miner
    // has no routes. Surfacing it as an error would turn every mistyped model
    // into FastAPI's bare "sources failed (404 Not Found): Not Found".
    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(SourceLookup::Unsupported);
    }
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(status_error("sources", status, &body));
    }
    let body = resp
        .json::<SourceProductsResponse>()
        .await
        .context("parse sourcing routes")?;
    Ok(SourceLookup::Routes(body.sources))
}

const SOURCE_COLUMNS: [(&str, usize); 5] = [
    ("ROUTE", 38),
    ("SERVES", 22),
    ("BUYER RETAIL / MTOK", 26),
    ("YOU SERVE", 16),
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

/// A no-table result: the two lines of `why`, then the shared tail. Both empty
/// states end at the same two pointers, so a third cannot forget the doc link.
fn empty_state(network: Network, why: [&str; 2]) -> Vec<String> {
    vec![
        format!("Sourcing routes ({network})"),
        String::new(),
        why[0].to_owned(),
        why[1].to_owned(),
        "`gmcli pricing` lists the buyer products you can serve directly.".to_owned(),
        String::new(),
        format!("What a sourcing route is: {SOURCING_DOC_URL}"),
    ]
}

fn render_sources(network: Network, lookup: &SourceLookup) -> Vec<String> {
    let sources = match lookup {
        SourceLookup::Routes(routes) => routes.as_slice(),
        SourceLookup::Unsupported => {
            return empty_state(
                network,
                [
                    "This registry does not publish sourcing routes yet — nothing on your",
                    "side to fix; routes appear here once it is updated.",
                ],
            );
        }
    };

    if sources.is_empty() {
        return empty_state(
            network,
            [
                "None available to you. A sourcing route serves a buyer product from a",
                "cheaper upstream; one appears here when the registry publishes it.",
            ],
        );
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
    lines.extend(unserved_lines(sources));
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
        serving_cell(source.capable_worker_count),
        if source.already_offered { "yes" } else { "no" }.to_owned(),
    ])
}

fn serving_cell(capable_worker_count: u32) -> String {
    match capable_worker_count {
        0 => "no".to_owned(),
        1 => "yes (1 worker)".to_owned(),
        n => format!("yes ({n} workers)"),
    }
}

/// Routes no worker serves yet. Declaring one now buys nothing: the registry
/// routes to workers that advertise the upstream, so the offer lands
/// ineligible.
///
/// A zero count is not proof the key is missing — the control loop clears a
/// worker's supported models when it is un-probed or just restored from
/// suspension — so the copy states only what the count actually says.
fn unserved_lines(sources: &[SourceProduct]) -> Vec<String> {
    let unserved: Vec<_> = sources
        .iter()
        .filter(|s| s.capable_worker_count == 0)
        .collect();
    if unserved.is_empty() {
        return Vec::new();
    }

    let mut lines = vec![
        String::new(),
        format!(
            "No worker of yours is currently serving these routes ({}):",
            unserved.len()
        ),
    ];
    lines.extend(
        unserved
            .iter()
            .map(|s| format!("  {}/{}", s.provider, s.model)),
    );
    lines.push("  A worker serves a route once it holds the upstream key and has been".to_owned());
    lines.push(
        "  probed. If the key is not set, `gmcli set-api-keys` then `gmcli deploy`.".to_owned(),
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
    use gm_miner_cli::{
        client::RegistryClient,
        config::{Config, NetworkEntry, TokenEntry},
    };
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    use super::{
        fetch_sources, render_sources, source_row, source_rule, Network, SourceLookup,
        SOURCE_COLUMNS,
    };

    fn sources(value: serde_json::Value) -> SourceLookup {
        SourceLookup::Routes(serde_json::from_value(value).expect("decode sourcing routes"))
    }

    /// The registry's real `PriceBlock`: `dimensions` alongside the
    /// `modifiers` and `surcharges` blocks it always sends.
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
                    "cache_read_per_mtok_ndollars": null,
                },
                "modifiers": {"batch_multiplier_bps": 5000},
                "surcharges": {},
            },
            "capable_worker_count": capable_worker_count,
            "already_offered": already_offered,
        })
    }

    fn config_for(server: &MockServer) -> Config {
        let mut networks = std::collections::HashMap::new();
        networks.insert(
            "testnet".to_owned(),
            NetworkEntry {
                api_url: Some(server.uri()),
                tokens: Some(TokenEntry {
                    access_token: Some("test-token".to_owned()),
                    refresh_token: None,
                    token_expires_at: None,
                }),
                ..Default::default()
            },
        );
        Config {
            active_network: Some("testnet".to_owned()),
            networks,
            ..Default::default()
        }
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
        assert!(!rendered.contains("No worker of yours is currently serving"));
    }

    #[test]
    fn a_route_with_no_capable_worker_says_so_without_asserting_the_key_is_missing() {
        let rendered = render_sources(
            Network::Mainnet,
            &sources(serde_json::json!([deepinfra_glm(0, false)])),
        )
        .join("\n");

        assert!(rendered.contains("No worker of yours is currently serving these routes (1):"));
        // An un-probed or just-restored worker reports zero with the key
        // already set, so the copy must not claim the key is absent.
        assert!(!rendered.contains("holds a key for these upstreams"));
        assert!(rendered.contains("If the key is not set, `gmcli set-api-keys`"));
        assert!(rendered.contains("`gmcli deploy`"));
        // Declaring a route nothing serves only produces an ineligible
        // offer, so the command must not be suggested yet.
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
        let rendered =
            render_sources(Network::Mainnet, &SourceLookup::Routes(Vec::new())).join("\n");

        assert!(rendered.contains("Sourcing routes (mainnet)"));
        assert!(rendered.contains("None available to you."));
        assert!(!rendered.contains("ROUTE"));
        assert!(!rendered.contains("----"));
        // The miner with no routes has nowhere else to learn what one is.
        assert!(rendered.contains(super::SOURCING_DOC_URL));
    }

    #[test]
    fn a_registry_without_the_endpoint_says_so_rather_than_blaming_the_miner() {
        let rendered = render_sources(Network::Mainnet, &SourceLookup::Unsupported).join("\n");

        assert!(rendered.contains("Sourcing routes (mainnet)"));
        assert!(rendered.contains("does not publish sourcing routes yet"));
        assert!(
            !rendered.contains("None available to you."),
            "an un-deployed endpoint must not read as 'you have no routes'"
        );
        assert!(!rendered.contains("ROUTE"));
        assert!(rendered.contains(super::SOURCING_DOC_URL));
    }

    #[tokio::test]
    async fn a_registry_that_predates_the_endpoint_is_unsupported_not_an_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/miners/products/sources"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "detail": "Not Found",
            })))
            .mount(&server)
            .await;

        let mut client = RegistryClient::new(config_for(&server));
        let lookup = fetch_sources(&mut client)
            .await
            .expect("a 404 is a rollout gap, not a command failure");

        let rendered = render_sources(Network::Mainnet, &lookup).join("\n");
        assert!(rendered.contains("does not publish sourcing routes yet"));
        assert!(
            !rendered.contains("404"),
            "the raw status must not reach the miner; got: {rendered}"
        );
    }

    #[tokio::test]
    async fn a_server_error_still_fails_loudly() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/miners/products/sources"))
            .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
                "detail": "database is on fire",
            })))
            .mount(&server)
            .await;

        let mut client = RegistryClient::new(config_for(&server));
        let err = fetch_sources(&mut client)
            .await
            .expect_err("a 5xx must not be laundered into an empty result");

        assert!(
            err.to_string().contains("database is on fire"),
            "got: {err}"
        );
    }
}
