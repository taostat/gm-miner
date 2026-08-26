//! `gmcli sources` — the sourcing routes a miner can serve, plus the shared
//! `GET /miners/products/sources` fetch that `declare-product` resolves
//! against.

use anyhow::{Context as _, Result};

use gm_miner_cli::{
    client::RegistryClient,
    network::Network,
    pricing::{extra_dimension_count, format_usd},
    table,
    types::{RetailDimensions, SourceProduct, SourceProductsResponse, SupplierRoutesResponse},
};

use crate::commands::status_error;

const SOURCES_PATH: &str = "/miners/products/sources";
const ROUTES_PATH: &str = "/miners/products/routes";
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
    /// Complete explicit route set, including self routes.
    Routes(Vec<SourceProduct>),
    /// Compatibility response from a registry predating the route endpoint.
    LegacyRoutes(Vec<SourceProduct>),
    Unsupported,
}

impl SourceLookup {
    pub(crate) fn routes(&self) -> &[SourceProduct] {
        match self {
            Self::Routes(routes) | Self::LegacyRoutes(routes) => routes,
            Self::Unsupported => &[],
        }
    }

    pub(crate) fn is_complete(&self) -> bool {
        matches!(self, Self::Routes(_))
    }
}

/// Pull the miner's sourcing routes. Source products are filtered out of the
/// buyer-facing `GET /products`, so this endpoint is the only place they
/// surface — both for `gmcli sources` and for `declare-product`'s lookup.
pub(crate) async fn fetch_sources(client: &mut RegistryClient) -> Result<SourceLookup> {
    let routes_resp = client
        .get(ROUTES_PATH)
        .await
        .context("GET /miners/products/routes")?;
    let routes_status = routes_resp.status();
    if routes_status.is_success() {
        let body = routes_resp
            .json::<SupplierRoutesResponse>()
            .await
            .context("parse supplier routes")?;
        return Ok(SourceLookup::Routes(body.routes));
    }
    if routes_status != reqwest::StatusCode::NOT_FOUND {
        let body = routes_resp.text().await.unwrap_or_default();
        return Err(status_error("routes", routes_status, &body));
    }

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
    Ok(SourceLookup::LegacyRoutes(body.sources))
}

const SOURCE_HEADERS: [&str; 5] = [
    "ROUTE",
    "SERVES",
    "BUYER RETAIL / MTOK",
    "YOU SERVE",
    "OFFERED",
];

/// A no-table result: the two lines of `why`, then the shared tail. Both empty
/// states end at the same two pointers, so a third cannot forget the doc link.
fn empty_state(network: Network, why: [&str; 2]) -> Vec<String> {
    vec![
        format!("Sourcing routes ({network})"),
        String::new(),
        why[0].to_owned(),
        why[1].to_owned(),
        "`gmcli pricing` lists the buyer products your routes can serve.".to_owned(),
        String::new(),
        format!("What a sourcing route is: {SOURCING_DOC_URL}"),
    ]
}

fn render_sources(network: Network, lookup: &SourceLookup) -> Vec<String> {
    let sources = match lookup {
        SourceLookup::Routes(routes) | SourceLookup::LegacyRoutes(routes) => routes.as_slice(),
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
    ];
    let rows: Vec<Vec<String>> = sources.iter().map(route_row).collect();
    lines.extend(table::render(&SOURCE_HEADERS, &rows));
    lines.extend(unserved_lines(sources));
    lines.extend(declare_lines(sources));
    lines
}

fn route_row(source: &SourceProduct) -> Vec<String> {
    let retail = &source.retail_price.dimensions;
    vec![
        format!("{}/{}", source.provider, source.model),
        format!("{}/{}", source.buyer_provider, source.buyer_model),
        buyer_retail_cell(retail),
        serving_cell(source.capable_worker_count),
        if source.already_offered { "yes" } else { "no" }.to_owned(),
    ]
}

/// The buyer product's retail anchors, plus a count of the dimensions it
/// prices beyond them.
///
/// Settlement is on the buyer product's whole price vector, not just input and
/// output, so a route whose buyer product prices a prompt cache has to say so —
/// `gmcli declare-product` then prints every dimension in full.
fn buyer_retail_cell(retail: &RetailDimensions) -> String {
    let anchors = format!(
        "{} in / {} out",
        format_usd(retail.input_per_mtok_ndollars),
        format_usd(retail.output_per_mtok_ndollars),
    );
    match extra_dimension_count(retail) {
        0 => anchors,
        n => format!("{anchors} +{n}"),
    }
}

fn serving_cell(capable_worker_count: u32) -> String {
    match capable_worker_count {
        0 => "no".to_owned(),
        1 => "yes (1 worker)".to_owned(),
        n => format!("yes ({n} workers)"),
    }
}

/// Providers the registry can route through a cloud backend, per its
/// `LEGACY_BACKEND_PROVIDER` map. For these the control loop probes each offer
/// individually instead of grouping the provider, so one offer says nothing
/// about the provider's other routes.
const CLOUD_BACKABLE: [&str; 2] = ["anthropic", "openai"];

/// Whether this provider has a live sourcing-route offer, which is the closest
/// this endpoint gets to "the registry has it in the probe set".
///
/// The probe set is keyed by *provider*, not by route: `control_loop/driver.py`
/// groups a miner's offers into `offers_by_provider` and probes each key once,
/// so one offer anywhere under a provider pulls every model it serves into the
/// worker's supported set. Without an offer nothing can put a capability entry
/// there, which is what separates a zero that cannot move from a zero that is
/// about the route.
///
/// Named for what it observes, deliberately. An offer is a *precondition* for
/// probing, not evidence a probe has run — one declared seconds ago is still
/// queued — and its absence today says nothing about whether an earlier offer
/// was probed before being withdrawn. Copy driven off this must claim neither.
///
/// Two things make this a proxy rather than the real predicate, and they fail in
/// opposite directions:
///
/// - It sees only cross-product source routes, and a **self-route** offer under the same
///   provider also puts it in the probe set. The provider is then probed while
///   no visible route is offered, so this answers `false` — it suggests a
///   declare that was not needed, costing one ineligible offer. Harmless enough
///   to leave.
/// - A **cloud-backed** provider is not grouped at all: `driver.py` probes those
///   offers one at a time through `cloud_capability` and removes them before the
///   grouping. One offer there does not probe the provider's other routes, so
///   this would answer `true` when it should not and *withhold* a declare line
///   the miner needs. That is the cycle this module exists to break, so it is
///   guarded rather than tolerated: [`CLOUD_BACKABLE`] never counts as offered.
///
/// The guard means a future provider carrying both route shapes costs a
/// redundant declaration suggestion rather than hiding a declarable route.
fn provider_has_live_offer(sources: &[SourceProduct], provider: &str) -> bool {
    if CLOUD_BACKABLE.contains(&provider) {
        return false;
    }
    sources
        .iter()
        .any(|s| s.provider == provider && s.already_offered)
}

/// Routes no worker serves yet, split by whether the zero is informative.
///
/// An *unprobed* provider (no offer under it at all) reads zero however the
/// worker is configured, so the only way forward is to declare. A provider that
/// already has an offer has been probed, so its zero is real evidence about that
/// model and declaring buys another ineligible offer instead of an answer.
///
/// A zero is still not proof the key is missing — the control loop also clears a
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

    let any_unprobed = unserved
        .iter()
        .any(|s| !provider_has_live_offer(sources, &s.provider));
    if any_unprobed {
        lines.push(
            "  A provider you have no offer under is not probed, so its routes read".to_owned(),
        );
        lines.push(
            "  zero whatever the worker holds. Declaring one puts the provider in the".to_owned(),
        );
        lines.push(
            "  probe set, which is what lets the count move at all — it still has to".to_owned(),
        );
        lines.push("  reach the upstream before it does.".to_owned());
    }
    if unserved
        .iter()
        .any(|s| provider_has_live_offer(sources, &s.provider))
    {
        lines.push(
            "  For a provider you already offer, no worker of yours currently qualifies".to_owned(),
        );
        lines.push(
            "  for that route — a second offer will not change that. If you declared it".to_owned(),
        );
        lines.push(
            "  only just now, give the control loop a cycle first. A worker counts".to_owned(),
        );
        lines.push(
            "  only while it is active, on an approved image, and holds the route in its"
                .to_owned(),
        );
        lines.push("  probed capability; `gmcli worker list` shows the first two.".to_owned());
    }
    lines
}

fn declare_lines(sources: &[SourceProduct]) -> Vec<String> {
    // Suggest a route when a worker already serves it, and additionally when its
    // provider has no offer at all: that provider is outside the registry's
    // probe set, so its count cannot leave zero until something is declared —
    // withholding the command there is a cycle a miner cannot break from here.
    // Once the provider IS probed, a zero is informative and a second offer
    // under it would only sit ineligible, so the gate still applies per model.
    let ready: Vec<_> = sources
        .iter()
        .filter(|s| {
            !s.already_offered
                && (s.capable_worker_count > 0 || !provider_has_live_offer(sources, &s.provider))
        })
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

    use super::{fetch_sources, render_sources, Network, SourceLookup};

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

    /// A second route under one provider, so a test can put both an offered and
    /// an unoffered route under the same key — the case that separates "never
    /// probed" from "probed and unreachable".
    fn engy_route(
        model: &str,
        capable_worker_count: u32,
        already_offered: bool,
    ) -> serde_json::Value {
        serde_json::json!({
            "provider": "engy",
            "model": model,
            "buyer_provider": if model == "glm-5.2" { "zai" } else { "moonshot" },
            "buyer_model": model,
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

    /// A route whose upstream is one the registry can put behind a cloud
    /// backend — the case `CLOUD_BACKABLE` guards.
    fn cloud_backable_route(
        provider: &str,
        model: &str,
        capable_worker_count: u32,
        already_offered: bool,
    ) -> serde_json::Value {
        serde_json::json!({
            "provider": provider,
            "model": model,
            "buyer_provider": provider,
            "buyer_model": model,
            "retail_price": {
                "dimensions": {
                    "input_per_mtok_ndollars": 1_000_000_000_u64,
                    "output_per_mtok_ndollars": 2_000_000_000_u64,
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
    fn every_route_row_is_the_width_of_the_rule_not_just_the_header() {
        // Same defect as the rank table: the old test compared the rule
        // against the header alone, so a retail cell wider than its column
        // passed. A cheap buyer product pricing a full vector is the case.
        let rendered = render_sources(
            Network::Mainnet,
            &sources(serde_json::json!([
                deepinfra_glm(1, false),
                {
                    "provider": "chutes",
                    "model": "some-org/a-very-cheap-model",
                    "buyer_provider": "zai",
                    "buyer_model": "glm-5.2-air",
                    "retail_price": {
                        "dimensions": {
                            "input_per_mtok_ndollars": 999_999_u64,
                            "output_per_mtok_ndollars": 999_u64,
                            "cache_read_per_mtok_ndollars": 500_u64,
                            "cache_write_5m_per_mtok_ndollars": 500_u64,
                        },
                    },
                    "capable_worker_count": 1,
                    "already_offered": false,
                },
            ])),
        );

        // The table block is header, rule, then one line per route.
        let start = rendered
            .iter()
            .position(|line| line.starts_with("ROUTE"))
            .expect("the table has a header");
        let table = &rendered[start..start + 4];
        let width = table[0].chars().count();
        for line in table {
            assert_eq!(
                line.chars().count(),
                width,
                "row is not the table's width:\n{}",
                table.join("\n")
            );
        }
        assert!(
            table
                .join("\n")
                .contains("$0.000999999 in / $0.000000999 out +2"),
            "{}",
            table.join("\n")
        );
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
        assert!(rendered.contains("no offer under is not probed"));
        // Declaring is what puts the provider in the registry's probe set, so
        // the command must be offered precisely when the count is still zero —
        // withholding it is the cycle this test used to lock in. Named in full:
        // a bare `--discount-pct <pct>` would pass on any suggested route.
        assert!(rendered.contains(
            "gmcli declare-product --provider deepinfra --model zai-org/GLM-5.2 --discount-pct <pct>"
        ));
    }

    /// The circularity is per *provider*: the registry groups a miner's offers
    /// into `offers_by_provider` and probes each key once, so one engy offer
    /// gets every engy model into the worker's supported set. A zero on the
    /// second engy route is then a real answer, and suggesting a declare for it
    /// would only mint another ineligible offer.
    #[test]
    fn a_zero_under_an_already_offered_provider_is_not_treated_as_unprobed() {
        let rendered = render_sources(
            Network::Mainnet,
            &sources(serde_json::json!([
                engy_route("kimi-k3", 1, true),
                engy_route("glm-5.2", 0, false),
            ])),
        )
        .join("\n");

        assert!(rendered.contains("No worker of yours is currently serving these routes (1):"));
        assert!(rendered.contains("engy/glm-5.2"));
        // engy is already probed via the kimi-k3 offer, so the copy must give
        // the real diagnosis rather than telling the miner to declare.
        assert!(rendered.contains("no worker of yours currently qualifies"));
        assert!(!rendered.contains("no offer under is not probed"));
        assert!(
            !rendered.contains("--discount-pct <pct>"),
            "declaring a probed-but-unreachable route only adds an ineligible offer:\n{rendered}"
        );
    }

    /// A provider the registry can put behind a cloud backend is probed per
    /// offer, not per provider, so one offer there does not cover its other
    /// routes. Suppressing the declare line would strand the second route in the
    /// cycle this module exists to break, so the guard must keep offering it.
    #[test]
    fn a_cloud_backable_provider_is_never_treated_as_covered_by_one_offer() {
        let rendered = render_sources(
            Network::Mainnet,
            &sources(serde_json::json!([
                cloud_backable_route("anthropic", "claude-a", 1, true),
                cloud_backable_route("anthropic", "claude-b", 0, false),
            ])),
        )
        .join("\n");

        assert!(
            rendered.contains(
                "gmcli declare-product --provider anthropic --model claude-b --discount-pct <pct>"
            ),
            "a cloud-backable provider's second route must stay declarable:\n{rendered}"
        );
        assert!(rendered.contains("no offer under is not probed"));
    }

    /// The mirror of the above: no engy route is offered, so engy is outside the
    /// probe set entirely and declaring is the only way out.
    #[test]
    fn a_zero_under_a_provider_with_no_offers_still_suggests_declaring() {
        let rendered = render_sources(
            Network::Mainnet,
            &sources(serde_json::json!([
                engy_route("kimi-k3", 0, false),
                engy_route("glm-5.2", 0, false),
            ])),
        )
        .join("\n");

        assert!(rendered.contains("no offer under is not probed"));
        assert!(rendered.contains(
            "gmcli declare-product --provider engy --model glm-5.2 --discount-pct <pct>"
        ));
        assert!(rendered.contains(
            "gmcli declare-product --provider engy --model kimi-k3 --discount-pct <pct>"
        ));
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
