//! Product declaration + status commands: `declare-product`,
//! `declare-products`, and `status` (which folds in the product table).

use anyhow::{bail, Context as _, Result};

use gm_miner_cli::{
    client::RegistryClient,
    pricing::{
        effective_per_mtok_ndollars, effective_rate_summary, format_discount_pct,
        format_per_mtok_usd,
    },
    types::{
        MinerStatus, Product, ProductCatalogResponse, ProductDeclarationRequest,
        ProductOfferStatus, Provider, RetailDimensions, SourceProduct,
    },
};

use crate::commands::{get_me_json, sources::fetch_sources, status_error};

/// `gmcli declare-product` — POST one (provider, model, `discount_bp`)
/// offer to `/miners/products`. The registry treats POST as upsert, so this
/// also handles updating an existing offer's discount.
///
/// Fetches the catalog first so the success output can render retail +
/// the effective per-Mtok rate the miner will actually receive. The
/// extra HTTP call also catches "unknown product" before the POST goes
/// out, which lets the CLI fail with a clearer error than the registry's
/// generic 404.
///
/// A product the catalog does not carry may still be a sourcing route — the
/// registry keeps those out of the buyer-facing `GET /products` — so the
/// miner's routes are consulted before the declaration is rejected.
pub(crate) async fn cmd_declare_product(
    client: &mut RegistryClient,
    provider: &Provider,
    model: &str,
    discount_bp: u32,
    upstream_model: Option<&str>,
) -> Result<()> {
    let catalog = fetch_catalog(client).await?;
    let catalog_hit = catalog
        .products
        .iter()
        .find(|p| &p.provider == provider && p.model == model);

    let lines = if let Some(product) = catalog_hit {
        post_declare_product(client, provider, model, discount_bp, upstream_model).await?;
        declaration_lines(
            &format!("{provider}/{model}"),
            "Retail",
            &product.retail_price.dimensions,
            discount_bp,
        )
    } else {
        let source = resolve_source(client, provider, model).await?;
        post_declare_product(client, provider, model, discount_bp, upstream_model).await?;
        source_declaration_lines(provider, model, &source, discount_bp)
    };

    for line in lines {
        println!("{line}");
    }
    println!("\nNext: gmcli status   (confirm the offer)");
    Ok(())
}

/// The declaration summary for a sourcing route: the buyer-retail economics,
/// plus a warning when no worker serves the route yet.
///
/// A route with no capable worker is declarable but earns nothing — the
/// registry routes only to workers advertising the upstream — and the plain
/// summary is indistinguishable from a working offer's.
fn source_declaration_lines(
    provider: &Provider,
    model: &str,
    source: &SourceProduct,
    discount_bp: u32,
) -> Vec<String> {
    let mut lines = declaration_lines(
        &format!(
            "{provider}/{model}  (sources → {}/{})",
            source.buyer_provider, source.buyer_model
        ),
        "Retail (buyer)",
        &source.retail_price.dimensions,
        discount_bp,
    );
    if source.capable_worker_count == 0 {
        lines.push(
            "  ! No worker of yours is currently serving this route, so the offer will".to_owned(),
        );
        lines.push(
            "    sit ineligible until one does — `gmcli status` names the reason.".to_owned(),
        );
    }
    lines
}

/// Find the product among the miner's sourcing routes, or reject it.
///
/// Reached only after the catalog missed, so failing here means the product
/// exists nowhere and no POST is issued.
async fn resolve_source(
    client: &mut RegistryClient,
    provider: &Provider,
    model: &str,
) -> Result<SourceProduct> {
    fetch_sources(client)
        .await?
        .into_routes()
        .into_iter()
        .find(|s| s.provider == provider.as_str() && s.model == model)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "unknown product {provider}/{model} — it is in neither the buyer catalog \
                 nor your sourcing routes (`gmcli sources`)"
            )
        })
}

/// The declaration summary: retail, the declared discount, and the per-Mtok
/// rate the miner receives.
///
/// `retail_label` names *which* retail the numbers are. A sourcing route
/// settles on the buyer product's retail, not the upstream's, and the miner
/// has to be able to tell the two apart on sight.
fn declaration_lines(
    header: &str,
    retail_label: &str,
    retail: &RetailDimensions,
    discount_bp: u32,
) -> Vec<String> {
    let width = retail_label.len().max("You receive".len()) + 2;
    let retail_in = format_per_mtok_usd(retail.input_per_mtok_ndollars);
    let retail_out = format_per_mtok_usd(retail.output_per_mtok_ndollars);
    let eff_in = format_per_mtok_usd(effective_per_mtok_ndollars(
        retail.input_per_mtok_ndollars,
        discount_bp,
    ));
    let eff_out = format_per_mtok_usd(effective_per_mtok_ndollars(
        retail.output_per_mtok_ndollars,
        discount_bp,
    ));
    // What the miner keeps per token, as a percentage of retail. With
    // discount_bp = 0 this reads "100%"; at the 99.90% cap this is
    // "0.1% of retail" — the minimum positive payout.
    let kept_pct = format_discount_pct(10_000_u32.saturating_sub(discount_bp));

    vec![
        header.to_owned(),
        format!("  {retail_label:<width$}: {retail_in} input / {retail_out} output per Mtok"),
        format!(
            "  {:<width$}: {}% off",
            "Declared",
            format_discount_pct(discount_bp)
        ),
        format!(
            "  {:<width$}: {eff_in} input / {eff_out} output per Mtok ({kept_pct}% of retail)",
            "You receive"
        ),
        "  → ok".to_owned(),
    ]
}

/// `gmcli declare-products` — fan a single discount out over the catalog.
///
/// 1. Public `GET /products` discovers every active product.
/// 2. If `provider_filter` is set, drops products from other providers.
/// 3. Drops deprecated products (the registry rejects offers on them anyway).
/// 4. POSTs one offer per surviving product. Each result is printed
///    individually (`provider/model: N% → ok|ERROR …`).
/// 5. Reports a final ok/err summary.
///
/// Per-product failures do not abort the loop. The function returns `Ok(())`
/// when every POST succeeded and an aggregated error otherwise so the CLI
/// exits non-zero on partial failure.
///
/// Deliberately catalog-only: sourcing routes are not swept in here. A source
/// offer commits the miner to buying from a specific upstream with a key it
/// holds, so it stays a single, explicit `declare-product` — see
/// `gmcli sources`.
pub(crate) async fn cmd_declare_products(
    client: &mut RegistryClient,
    provider_filter: Option<&Provider>,
    discount_bp: u32,
) -> Result<()> {
    let catalog = fetch_catalog(client).await?;
    let targets = filter_catalog(&catalog.products, provider_filter);

    if targets.is_empty() {
        let scope =
            provider_filter.map_or_else(|| "the catalog".to_owned(), |p| format!("provider {p}"));
        bail!("no active products found in {scope} to declare against");
    }

    let discount_pct = format_discount_pct(discount_bp);
    println!(
        "Declaring {discount_pct}% off retail on {} product(s)...",
        targets.len()
    );

    let mut ok_count = 0_usize;
    let mut err_count = 0_usize;
    for product in &targets {
        let rate = effective_rate_summary(&product.retail_price.dimensions, discount_bp);
        match post_declare_product(client, &product.provider, &product.model, discount_bp, None)
            .await
        {
            Ok(()) => {
                println!(
                    "  {}/{}: {discount_pct}% off → {rate} → ok",
                    product.provider, product.model
                );
                ok_count += 1;
            }
            Err(err) => {
                println!(
                    "  {}/{}: {discount_pct}% off → {rate} → ERROR {err}",
                    product.provider, product.model
                );
                err_count += 1;
            }
        }
    }

    println!("\nSummary: {ok_count} ok, {err_count} failed.");
    if err_count > 0 {
        bail!("{err_count} of {} declarations failed", targets.len());
    }
    println!("Next: gmcli status   (confirm offers + eligibility)");
    Ok(())
}

/// Issue one `POST /miners/products` and translate the result into a typed
/// `Result<(), anyhow::Error>` so both `declare-product` and
/// `declare-products` share the same wire-shape + error-detail logic.
async fn post_declare_product(
    client: &mut RegistryClient,
    provider: &Provider,
    model: &str,
    discount_bp: u32,
    upstream_model: Option<&str>,
) -> Result<()> {
    let body = serde_json::to_value(ProductDeclarationRequest {
        provider: provider.as_str(),
        model,
        discount_bp,
        upstream_model,
    })
    .context("serialize declare-product body")?;

    let resp = client
        .post("/miners/products", &body)
        .await
        .context("POST /miners/products")?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(status_error("declare-product", status, &body));
    }
    Ok(())
}

/// Pull the catalog from the public `GET /products` endpoint.
async fn fetch_catalog(client: &mut RegistryClient) -> Result<ProductCatalogResponse> {
    let resp = client.get("/products").await.context("GET /products")?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        bail!("GET /products failed ({status}): {body}");
    }
    resp.json::<ProductCatalogResponse>()
        .await
        .context("parse product catalog")
}

/// Filter the catalog down to the set of products a fan-out should hit:
/// active, declarable, optionally narrowed to one provider.
///
/// `benchmark` entries are always dropped — every miner serves that pool
/// automatically (see `docs/plans/admission-benchmark.md`) and the
/// registry rejects declarations against it. Today the registry never
/// emits a benchmark row from `GET /products`; this filter is the
/// defence-in-depth that keeps the fan-out clean if that changes.
pub(crate) fn filter_catalog<'a>(
    products: &'a [Product],
    provider_filter: Option<&Provider>,
) -> Vec<&'a Product> {
    products
        .iter()
        .filter(|p| p.status == "active")
        .filter(|p| p.provider != Provider::Benchmark)
        .filter(|p| provider_filter.is_none_or(|target| &p.provider == target))
        .collect()
}

/// `gmcli status` — registration state plus the per-product offer table.
///
/// Folds in what `list-products` used to print: each offer's discount and the
/// per-Mtok rate the miner actually receives (joined against the public
/// catalog), alongside the broader hotkey/attestation/compose view.
pub(crate) async fn cmd_status(client: &mut RegistryClient) -> Result<()> {
    let network = client.config.resolved_network();
    let miner: MinerStatus = get_me_json(client, gm_miner_cli::client::ME_PATH).await?;

    println!("Miner status ({network})");
    println!("  Network    : {network} (netuid {})", network.netuid());
    println!("  Hotkey     : {}", miner.hotkey);
    println!("  Status     : {}", miner.status);
    println!(
        "  Last attest: {}",
        miner.last_attestation_at.as_deref().unwrap_or("never")
    );
    println!(
        "  Compose    : {}",
        miner.image_compose_hash.as_deref().unwrap_or("—")
    );

    if miner.products.is_empty() {
        println!("\nNo products declared. Declare some with `gmcli declare-products --discount-pct <pct>`.");
        return Ok(());
    }

    print_product_table(client, &miner).await
}

/// Render the per-offer table joining `/miners/me` offers against the public
/// catalog so each row shows the effective per-Mtok rate the miner receives.
async fn print_product_table(client: &mut RegistryClient, miner: &MinerStatus) -> Result<()> {
    // The catalog is the single source of truth for retail; join here rather
    // than adding a retail block to `/miners/me` on the registry side.
    let catalog = fetch_catalog(client).await?;
    let retail_by_key: std::collections::HashMap<_, _> = catalog
        .products
        .iter()
        .map(|p| {
            (
                (p.provider.clone(), p.model.as_str()),
                &p.retail_price.dimensions,
            )
        })
        .collect();

    println!("\nProducts:");
    println!(
        "{:<12} {:<32} {:<10} {:<38} {:<8} {:<8}",
        "PROVIDER", "MODEL", "DISCOUNT", "YOU RECEIVE / MTOK", "OFFERED", "ELIGIBLE"
    );
    println!("{}", "-".repeat(110));
    for p in &miner.products {
        let provider: Result<Provider, _> = p.provider.parse();
        let (discount_label, rate_label) = match (p.discount_bp, provider) {
            (Some(bp), Ok(prov)) => {
                let label = format!("{}%", format_discount_pct(bp));
                let rate = retail_by_key.get(&(prov, p.model.as_str())).map_or_else(
                    || "(retail unknown)".to_owned(),
                    |dims| effective_rate_summary(dims, bp),
                );
                (label, rate)
            }
            _ => ("—".to_owned(), "—".to_owned()),
        };
        println!(
            "{:<12} {:<32} {:<10} {:<38} {:<8} {:<8}",
            p.provider,
            p.model,
            discount_label,
            rate_label,
            if p.is_offered { "yes" } else { "no" },
            if p.is_eligible { "yes" } else { "no" },
        );
    }
    println!("\n{} offer(s) total.", miner.products.len());
    for line in ineligible_detail_lines(&miner.products) {
        println!("{line}");
    }
    println!("\nRanked against the field? `gmcli pricing`");
    Ok(())
}

/// Explain every ineligible offer beneath the table, one block each.
fn ineligible_detail_lines(products: &[ProductOfferStatus]) -> Vec<String> {
    let broken: Vec<_> = products.iter().filter(|p| !p.is_eligible).collect();
    if broken.is_empty() {
        return Vec::new();
    }
    let mut lines = vec![
        String::new(),
        format!(
            "Not eligible — these earn nothing until fixed ({}):",
            broken.len()
        ),
    ];
    for p in broken {
        lines.push(String::new());
        lines.push(format!("  {}/{}", p.provider, p.model));
        match p.ineligible_reason.as_deref() {
            Some(reason) => lines.push(format!("    reason : {reason}")),
            // The registry clears the reason the moment an offer goes eligible
            // and writes one on every failure, so a blank reason on an
            // ineligible offer means the control loop has not judged it yet.
            None => lines.push(
                "    reason : not yet checked — the control loop probes every cycle".to_owned(),
            ),
        }
        if let Some(hint) = p.ineligible_hint.as_deref() {
            lines.push(format!("    fix    : {hint}"));
        }
        if let Some(passed) = p.capability_check_passed_at.as_deref() {
            lines.push(format!("    last ok : {passed}"));
        }
    }
    lines
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test assertions intentionally panic on unexpected values"
)]
mod tests {
    use gm_miner_cli::config::{Config, NetworkEntry, TokenEntry};
    use wiremock::{
        matchers::{body_json, method, path},
        Mock, MockServer, ResponseTemplate,
    };

    use super::*;

    fn offers(value: serde_json::Value) -> Vec<ProductOfferStatus> {
        serde_json::from_value(value).expect("decode offers")
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

    /// The registry's real `PriceBlock`: every response carries `modifiers`
    /// and `surcharges` beside `dimensions`, so the fixture must too or a
    /// future shape change would pass here and fail on the wire.
    fn retail(input_ndollars: u64, output_ndollars: u64) -> serde_json::Value {
        serde_json::json!({
            "dimensions": {
                "input_per_mtok_ndollars": input_ndollars,
                "output_per_mtok_ndollars": output_ndollars,
                "cache_read_per_mtok_ndollars": null,
                "cache_write_5m_per_mtok_ndollars": null,
            },
            "modifiers": {"batch_multiplier_bps": 5000},
            "surcharges": {
                "anthropic_web_search": {"kind": "per_event", "unit_ndollars": 10_000_000_u64},
            },
        })
    }

    async fn mount_catalog(server: &MockServer, products: serde_json::Value) {
        Mock::given(method("GET"))
            .and(path("/products"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "products": products,
                "generated_at": "2026-07-27T10:00:00Z",
            })))
            .mount(server)
            .await;
    }

    async fn mount_sources(server: &MockServer, sources: serde_json::Value) {
        Mock::given(method("GET"))
            .and(path("/miners/products/sources"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sources": sources,
                "generated_at": "2026-07-27T10:00:00Z",
            })))
            .mount(server)
            .await;
    }

    async fn mount_declare(server: &MockServer, expected_body: serde_json::Value) {
        Mock::given(method("POST"))
            .and(path("/miners/products"))
            .and(body_json(expected_body))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "is_offered": true,
                "is_eligible": false,
            })))
            .mount(server)
            .await;
    }

    /// Every request the mock server saw against `path`.
    async fn hits(server: &MockServer, verb: &str, at: &str) -> usize {
        server
            .received_requests()
            .await
            .expect("request recording is on")
            .iter()
            .filter(|r| r.method.as_str() == verb && r.url.path() == at)
            .count()
    }

    #[tokio::test]
    async fn a_catalog_product_declares_without_consulting_sources() {
        let server = MockServer::start().await;
        mount_catalog(
            &server,
            serde_json::json!([{
                "provider": "anthropic", "model": "claude-sonnet-4-6", "status": "active",
                "retail_price": retail(3_000_000_000, 15_000_000_000),
            }]),
        )
        .await;
        mount_declare(
            &server,
            serde_json::json!({
                "provider": "anthropic",
                "model": "claude-sonnet-4-6",
                "discount_bp": 500,
            }),
        )
        .await;

        let mut client = RegistryClient::new(config_for(&server));
        cmd_declare_product(
            &mut client,
            &Provider::Anthropic,
            "claude-sonnet-4-6",
            500,
            None,
        )
        .await
        .expect("a catalog product declares");

        assert_eq!(hits(&server, "POST", "/miners/products").await, 1);
        assert_eq!(
            hits(&server, "GET", "/miners/products/sources").await,
            0,
            "a catalog hit must not spend a round-trip on the sources endpoint"
        );
    }

    #[tokio::test]
    async fn a_source_product_absent_from_the_catalog_still_declares() {
        let server = MockServer::start().await;
        mount_catalog(&server, serde_json::json!([])).await;
        mount_sources(
            &server,
            serde_json::json!([{
                "provider": "deepinfra",
                "model": "zai-org/GLM-5.2",
                "buyer_provider": "zai",
                "buyer_model": "glm-5.2",
                "retail_price": retail(1_400_000_000, 4_400_000_000),
                "capable_worker_count": 1,
                "already_offered": false,
            }]),
        )
        .await;
        mount_declare(
            &server,
            serde_json::json!({
                "provider": "deepinfra",
                "model": "zai-org/GLM-5.2",
                "discount_bp": 500,
            }),
        )
        .await;

        let mut client = RegistryClient::new(config_for(&server));
        cmd_declare_product(
            &mut client,
            &Provider::DeepInfra,
            "zai-org/GLM-5.2",
            500,
            None,
        )
        .await
        .expect("a sourcing route declares even though GET /products omits it");

        // The declare mock only answers the exact body above, so one hit here
        // proves the wire shape as well as the call.
        assert_eq!(hits(&server, "POST", "/miners/products").await, 1);
    }

    #[tokio::test]
    async fn a_product_in_neither_place_fails_before_any_post() {
        let server = MockServer::start().await;
        mount_catalog(&server, serde_json::json!([])).await;
        mount_sources(&server, serde_json::json!([])).await;
        Mock::given(method("POST"))
            .and(path("/miners/products"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let mut client = RegistryClient::new(config_for(&server));
        let err = cmd_declare_product(&mut client, &Provider::OpenAI, "gpt-typo", 500, None)
            .await
            .expect_err("a typo'd model must not be declared");

        assert!(
            err.to_string().contains("unknown product openai/gpt-typo"),
            "got: {err}"
        );
        assert!(err.to_string().contains("gmcli sources"), "got: {err}");
        assert_eq!(
            hits(&server, "POST", "/miners/products").await,
            0,
            "the typo path must never reach the registry"
        );
    }

    #[tokio::test]
    async fn a_registry_without_the_sources_endpoint_keeps_the_typo_error() {
        // The registry deploy and the CLI release are separate events, so
        // every miner on the new CLI meets a 404 here for a window. A typo
        // must still read as a typo, not as "sources failed (404 Not Found)".
        let server = MockServer::start().await;
        mount_catalog(&server, serde_json::json!([])).await;
        Mock::given(method("GET"))
            .and(path("/miners/products/sources"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "detail": "Not Found",
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/miners/products"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let mut client = RegistryClient::new(config_for(&server));
        let err = cmd_declare_product(&mut client, &Provider::OpenAI, "gpt-typo", 500, None)
            .await
            .expect_err("a typo'd model must not be declared");

        assert!(
            err.to_string().contains("unknown product openai/gpt-typo"),
            "got: {err}"
        );
        assert!(
            !err.to_string().contains("404"),
            "the rollout gap must not leak a raw status; got: {err}"
        );
        assert_eq!(hits(&server, "POST", "/miners/products").await, 0);
    }

    #[test]
    fn a_catalog_declaration_keeps_its_layout() {
        let dims = RetailDimensions {
            input_per_mtok_ndollars: 3_000_000_000,
            output_per_mtok_ndollars: 15_000_000_000,
        };
        assert_eq!(
            declaration_lines("anthropic/claude-sonnet-4-6", "Retail", &dims, 1050),
            vec![
                "anthropic/claude-sonnet-4-6",
                "  Retail       : $3.000 input / $15.000 output per Mtok",
                "  Declared     : 10.5% off",
                "  You receive  : $2.685 input / $13.425 output per Mtok (89.5% of retail)",
                "  → ok",
            ]
        );
    }

    fn glm_route(capable_worker_count: u32) -> SourceProduct {
        serde_json::from_value(serde_json::json!({
            "provider": "deepinfra",
            "model": "zai-org/GLM-5.2",
            "buyer_provider": "zai",
            "buyer_model": "glm-5.2",
            "retail_price": retail(1_400_000_000, 4_400_000_000),
            "capable_worker_count": capable_worker_count,
            "already_offered": false,
        }))
        .expect("decode sourcing route")
    }

    #[test]
    fn a_source_declaration_is_priced_off_the_buyer_retail() {
        // Settlement basis is the buyer product (zai/glm-5.2) at $1.40/$4.40,
        // never what deepinfra charges the miner for the same tokens.
        assert_eq!(
            source_declaration_lines(&Provider::DeepInfra, "zai-org/GLM-5.2", &glm_route(1), 500),
            vec![
                "deepinfra/zai-org/GLM-5.2  (sources → zai/glm-5.2)",
                "  Retail (buyer)  : $1.400 input / $4.400 output per Mtok",
                "  Declared        : 5% off",
                "  You receive     : $1.330 input / $4.180 output per Mtok (95% of retail)",
                "  → ok",
            ]
        );
    }

    #[test]
    fn a_route_no_worker_serves_declares_with_a_warning_not_a_bare_ok() {
        let rendered =
            source_declaration_lines(&Provider::DeepInfra, "zai-org/GLM-5.2", &glm_route(0), 500)
                .join("\n");

        assert!(rendered.contains("No worker of yours is currently serving this route"));
        assert!(rendered.contains("sit ineligible until one does"));
        assert!(rendered.contains("gmcli status"));
    }

    #[test]
    fn an_all_eligible_table_prints_no_detail_block() {
        let products = offers(serde_json::json!([{
            "provider": "openai", "model": "gpt-5.6",
            "is_offered": true, "is_eligible": true, "discount_bp": 500,
        }]));
        assert!(ineligible_detail_lines(&products).is_empty());
    }

    #[test]
    fn each_ineligible_offer_gets_its_reason_and_fix() {
        let products = offers(serde_json::json!([
            {
                "provider": "openai", "model": "gpt-5.6",
                "is_offered": true, "is_eligible": true, "discount_bp": 500,
            },
            {
                "provider": "anthropic", "model": "claude-sonnet-4-6",
                "is_offered": true, "is_eligible": false, "discount_bp": 500,
                "ineligible_reason": "capability_probe_failed: upstream rejected key (401)",
                "ineligible_hint": "Set a valid key with `gmcli set-api-keys`.",
            },
        ]));

        let rendered = ineligible_detail_lines(&products).join("\n");
        assert!(rendered.contains("Not eligible — these earn nothing until fixed (1):"));
        assert!(rendered.contains("  anthropic/claude-sonnet-4-6"));
        assert!(rendered.contains("reason : capability_probe_failed: upstream rejected key (401)"));
        assert!(rendered.contains("fix    : Set a valid key with `gmcli set-api-keys`."));
        assert!(!rendered.contains("gpt-5.6"));
    }

    #[test]
    fn an_offer_that_was_working_shows_when_it_last_passed() {
        let products = offers(serde_json::json!([{
            "provider": "anthropic", "model": "claude-sonnet-4-6",
            "is_offered": true, "is_eligible": false, "discount_bp": 500,
            "ineligible_reason": "capability_probe_failed: upstream rejected key (401)",
            "capability_check_passed_at": "2026-07-10T22:15:00+00:00",
        }]));

        let rendered = ineligible_detail_lines(&products).join("\n");
        assert!(rendered.contains("last ok : 2026-07-10T22:15:00+00:00"));
    }

    #[test]
    fn an_offer_that_never_passed_shows_no_last_ok_line() {
        let products = offers(serde_json::json!([{
            "provider": "anthropic", "model": "claude-sonnet-4-6",
            "is_offered": true, "is_eligible": false, "discount_bp": 500,
        }]));

        assert!(!ineligible_detail_lines(&products)
            .join("\n")
            .contains("last ok"));
    }

    #[test]
    fn an_unjudged_offer_says_so_rather_than_going_blank() {
        let products = offers(serde_json::json!([{
            "provider": "openai", "model": "gpt-5.6",
            "is_offered": true, "is_eligible": false, "discount_bp": 500,
        }]));

        let rendered = ineligible_detail_lines(&products).join("\n");
        assert!(rendered.contains("reason : not yet checked"));
        assert!(!rendered.contains("fix    :"));
    }
}
