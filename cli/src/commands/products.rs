//! Product declaration + status commands: `declare-product`,
//! `declare-products`, their `undeclare-` counterparts, and `status` (which
//! folds in the product table).

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

/// What may appear in an offer path unescaped: RFC 3986's unreserved set plus
/// `/`. The slash is deliberate — the route is `{model_id:path}`, so a source
/// id like `zai-org/GLM-5.2` is one model id and escaping its slash would 404.
///
/// Everything else is escaped because the path is interpolated into a URL:
/// an unescaped `#` in a model id ends the path at a fragment and `?` starts
/// a query, either of which would send the DELETE at a *different* offer than
/// the one named on the command line.
const OFFER_PATH: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~')
    .remove(b'/');

/// The registry route for one offer, with the model id escaped as path data.
///
/// `provider` is a `&str` rather than a [`Provider`]: the fan-out withdraws
/// what `/miners/me` reports, and the registry's spelling is authoritative
/// there — a provider added after this CLI was built must still be
/// withdrawable.
pub(crate) fn offer_path(provider: &str, model: &str) -> String {
    let provider = percent_encoding::utf8_percent_encode(provider, OFFER_PATH);
    let model = percent_encoding::utf8_percent_encode(model, OFFER_PATH);
    format!("/miners/products/{provider}/{model}")
}

/// Reject a model id whose path segments would be resolved away rather than
/// sent, so a `.`/`..` segment cannot silently retarget the DELETE at another
/// offer — or another endpoint. `.` stays legal *within* a segment, which is
/// where real model ids use it (`gpt-5.5`).
fn reject_dot_segments(model: &str) -> Result<()> {
    if model.split('/').any(|seg| seg == "." || seg == "..") {
        bail!("invalid model id {model:?}: `.` and `..` are not model path segments");
    }
    Ok(())
}

/// Issue one `DELETE /miners/products/{provider}/{model}` — shared by
/// `undeclare-product` and the fan-out so both read the registry's statuses
/// the same way. A 404 means the registry has no offer row for the pair —
/// the common typo case — and must not read as "the endpoint is missing".
async fn delete_offer(client: &mut RegistryClient, provider: &str, model: &str) -> Result<()> {
    reject_dot_segments(model)?;
    let path = offer_path(provider, model);
    let resp = client
        .delete(&path)
        .await
        .with_context(|| format!("DELETE {path}"))?;

    let status = resp.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        bail!(
            "no offer for {provider}/{model} — nothing to withdraw; \
             `gmcli status` lists what you have declared"
        );
    }
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(status_error("undeclare-product", status, &body));
    }
    Ok(())
}

/// `gmcli undeclare-product` — withdraw one offer.
///
/// The registry keeps the row for audit (`is_offered` goes false, reason
/// `withdrawn_by_miner`), so withdrawal is fully reversible: re-running
/// `declare-product` re-offers the pair.
pub(crate) async fn cmd_undeclare_product(
    client: &mut RegistryClient,
    provider: &Provider,
    model: &str,
) -> Result<()> {
    delete_offer(client, provider.as_str(), model).await?;
    println!("{provider}/{model} withdrawn — buyers are no longer routed to it.");
    println!("Changed your mind? `gmcli declare-product` re-offers it.");
    Ok(())
}

/// The offers a fan-out withdrawal should touch: still standing
/// (`is_offered`), optionally one provider's slice.
///
/// An offer already withdrawn keeps its registry row with `is_offered:
/// false`, so re-deleting it would spend a round-trip to change nothing —
/// and its 404-adjacent failure would pollute the summary.
pub(crate) fn withdrawable_offers<'a>(
    offers: &'a [ProductOfferStatus],
    provider_filter: Option<&Provider>,
) -> Vec<&'a ProductOfferStatus> {
    offers
        .iter()
        .filter(|o| o.is_offered)
        .filter(|o| provider_filter.is_none_or(|target| o.provider == target.as_str()))
        .collect()
}

/// `gmcli undeclare-products` — withdraw every standing offer, or one
/// provider's slice.
///
/// Targets come from the miner's own `GET /miners/me` rather than the public
/// catalog: the catalog omits sourcing routes, and only `/miners/me` knows
/// which offers are still standing. Mirrors `cmd_declare_products`: each
/// result is printed individually, per-offer failures do not abort the loop,
/// and a partial failure returns an aggregated error so the CLI exits
/// non-zero.
pub(crate) async fn cmd_undeclare_products(
    client: &mut RegistryClient,
    provider_filter: Option<&Provider>,
) -> Result<()> {
    let miner: MinerStatus = get_me_json(client, gm_miner_cli::client::ME_PATH).await?;
    let targets = withdrawable_offers(&miner.products, provider_filter);

    if targets.is_empty() {
        let scope =
            provider_filter.map_or_else(|| "any provider".to_owned(), |p| format!("provider {p}"));
        bail!("no standing offers from {scope} to withdraw — `gmcli status` shows what you offer");
    }

    println!("Withdrawing {} offer(s)...", targets.len());

    let mut ok_count = 0_usize;
    let mut err_count = 0_usize;
    for offer in &targets {
        // The provider goes back to the registry exactly as it came from
        // `/miners/me`. Round-tripping it through the `Provider` enum would
        // make `--all` skip any offer whose provider postdates this CLI
        // build — silently leaving it standing after a sweep that said it
        // withdrew everything.
        match delete_offer(client, &offer.provider, &offer.model).await {
            Ok(()) => {
                println!("  {}/{}: withdrawn", offer.provider, offer.model);
                ok_count += 1;
            }
            Err(err) => {
                println!("  {}/{}: ERROR {err}", offer.provider, offer.model);
                err_count += 1;
            }
        }
    }

    println!("\nSummary: {ok_count} ok, {err_count} failed.");
    if err_count > 0 {
        bail!("{err_count} of {} withdrawals failed", targets.len());
    }
    println!("Re-offer any time: `gmcli declare-product` / `gmcli declare-products`.");
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

    async fn mount_me(server: &MockServer, products: serde_json::Value) {
        Mock::given(method("GET"))
            .and(path("/miners/me"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "hotkey": "5Grw...",
                "status": "active",
                "last_attestation_at": null,
                "image_compose_hash": null,
                "products": products,
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

    // ── undeclare ────────────────────────────────────────────────────────

    /// Every path a DELETE was issued against, in order.
    async fn deleted_paths(server: &MockServer) -> Vec<String> {
        server
            .received_requests()
            .await
            .expect("request recording is on")
            .iter()
            .filter(|r| r.method.as_str() == "DELETE")
            .map(|r| r.url.path().to_owned())
            .collect()
    }

    async fn mount_withdraw(server: &MockServer, at: &str, status: u16) {
        Mock::given(method("DELETE"))
            .and(path(at.to_owned()))
            .respond_with(ResponseTemplate::new(status))
            .mount(server)
            .await;
    }

    #[test]
    fn a_slashed_source_model_keeps_its_slashes_in_the_path() {
        // `zai-org/GLM-5.2` is one model id, and the registry route is
        // `{model_id:path}` — collapsing or escaping the slash would 404.
        assert_eq!(
            offer_path(Provider::DeepInfra.as_str(), "zai-org/GLM-5.2"),
            "/miners/products/deepinfra/zai-org/GLM-5.2"
        );
    }

    #[test]
    fn a_reserved_character_cannot_truncate_the_path() {
        // Unescaped, the `#` would end the URL's path and the DELETE would
        // land on `openai/gpt-5` — withdrawing an offer nobody named.
        assert_eq!(
            offer_path("openai", "gpt-5#5"),
            "/miners/products/openai/gpt-5%235"
        );
        assert_eq!(
            offer_path("openai", "gpt-5?x=1"),
            "/miners/products/openai/gpt-5%3Fx%3D1"
        );
    }

    #[test]
    fn a_normal_model_id_is_still_written_plainly() {
        // Escaping must not reach the characters real model ids are made of,
        // or every path in an error message becomes unreadable.
        assert_eq!(
            offer_path("anthropic", "claude-sonnet-4-6"),
            "/miners/products/anthropic/claude-sonnet-4-6"
        );
        assert_eq!(
            offer_path("openai", "gpt-5.5"),
            "/miners/products/openai/gpt-5.5"
        );
    }

    #[tokio::test]
    async fn a_dot_segment_model_id_is_refused_before_the_wire() {
        // `..` would be resolved away by URL normalisation, aiming the DELETE
        // at a path the operator never typed.
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;

        let mut client = RegistryClient::new(config_for(&server));
        let err = cmd_undeclare_product(&mut client, &Provider::OpenAI, "../../admin/products")
            .await
            .expect_err("a dot segment is not a model id");

        assert!(
            err.to_string().contains("not model path segments"),
            "got: {err}"
        );
        assert!(deleted_paths(&server).await.is_empty());
    }

    #[tokio::test]
    async fn undeclaring_withdraws_exactly_that_offer() {
        let server = MockServer::start().await;
        mount_withdraw(&server, "/miners/products/anthropic/claude-sonnet-4-6", 204).await;

        let mut client = RegistryClient::new(config_for(&server));
        cmd_undeclare_product(&mut client, &Provider::Anthropic, "claude-sonnet-4-6")
            .await
            .expect("a declared offer withdraws");

        assert_eq!(
            deleted_paths(&server).await,
            vec!["/miners/products/anthropic/claude-sonnet-4-6"]
        );
    }

    #[tokio::test]
    async fn undeclaring_a_source_route_hits_the_slashed_path() {
        let server = MockServer::start().await;
        mount_withdraw(&server, "/miners/products/deepinfra/zai-org/GLM-5.2", 204).await;

        let mut client = RegistryClient::new(config_for(&server));
        cmd_undeclare_product(&mut client, &Provider::DeepInfra, "zai-org/GLM-5.2")
            .await
            .expect("a sourcing route withdraws");

        assert_eq!(
            deleted_paths(&server).await,
            vec!["/miners/products/deepinfra/zai-org/GLM-5.2"]
        );
    }

    #[tokio::test]
    async fn undeclaring_what_was_never_declared_says_so() {
        // The registry 404s an offer it has no row for. That is the common
        // typo case, and it must not read as "the endpoint is missing".
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/miners/products/anthropic/claude-sonnet-4-6"))
            .respond_with(
                ResponseTemplate::new(404)
                    .set_body_json(serde_json::json!({"detail": "offer not found"})),
            )
            .mount(&server)
            .await;

        let mut client = RegistryClient::new(config_for(&server));
        let err = cmd_undeclare_product(&mut client, &Provider::Anthropic, "claude-sonnet-4-6")
            .await
            .expect_err("a missing offer is an error, not a silent success");

        assert!(
            err.to_string()
                .contains("no offer for anthropic/claude-sonnet-4-6"),
            "got: {err}"
        );
        assert!(err.to_string().contains("gmcli status"), "got: {err}");
    }

    #[tokio::test]
    async fn a_registry_failure_surfaces_its_detail() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/miners/products/openai/gpt-5.6"))
            .respond_with(
                ResponseTemplate::new(500)
                    .set_body_json(serde_json::json!({"detail": "database is down"})),
            )
            .mount(&server)
            .await;

        let mut client = RegistryClient::new(config_for(&server));
        let err = cmd_undeclare_product(&mut client, &Provider::OpenAI, "gpt-5.6")
            .await
            .expect_err("a 500 is not a withdrawal");

        assert!(err.to_string().contains("database is down"), "got: {err}");
        assert!(
            !err.to_string().contains("no offer for"),
            "only a 404 means the offer is absent; got: {err}"
        );
    }

    fn offer_row(provider: &str, model: &str, is_offered: bool) -> serde_json::Value {
        serde_json::json!({
            "provider": provider, "model": model,
            "is_offered": is_offered, "is_eligible": is_offered, "discount_bp": 500,
        })
    }

    #[test]
    fn the_fan_out_targets_only_offers_still_standing() {
        // An offer already withdrawn keeps its row with `is_offered: false`.
        // Re-deleting it would spend a round-trip to change nothing.
        let all = offers(serde_json::json!([
            offer_row("anthropic", "claude-sonnet-4-6", true),
            offer_row("anthropic", "claude-opus-4-6", false),
        ]));

        let targets = withdrawable_offers(&all, None);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].model, "claude-sonnet-4-6");
    }

    #[test]
    fn the_fan_out_honours_the_provider_filter() {
        let all = offers(serde_json::json!([
            offer_row("anthropic", "claude-sonnet-4-6", true),
            offer_row("openai", "gpt-5.6", true),
        ]));

        let targets = withdrawable_offers(&all, Some(&Provider::OpenAI));
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].provider, "openai");
    }

    #[tokio::test]
    async fn the_fan_out_withdraws_one_provider_and_leaves_the_rest() {
        let server = MockServer::start().await;
        mount_me(
            &server,
            serde_json::json!([
                offer_row("anthropic", "claude-sonnet-4-6", true),
                offer_row("anthropic", "claude-haiku-4-6", true),
                offer_row("openai", "gpt-5.6", true),
            ]),
        )
        .await;
        mount_withdraw(&server, "/miners/products/anthropic/claude-sonnet-4-6", 204).await;
        mount_withdraw(&server, "/miners/products/anthropic/claude-haiku-4-6", 204).await;

        let mut client = RegistryClient::new(config_for(&server));
        cmd_undeclare_products(&mut client, Some(&Provider::Anthropic))
            .await
            .expect("withdrawing one provider's offers succeeds");

        let mut paths = deleted_paths(&server).await;
        paths.sort();
        assert_eq!(
            paths,
            vec![
                "/miners/products/anthropic/claude-haiku-4-6",
                "/miners/products/anthropic/claude-sonnet-4-6",
            ],
            "the openai offer must survive a provider-scoped withdrawal"
        );
    }

    #[tokio::test]
    async fn a_sweep_withdraws_providers_this_build_has_never_heard_of() {
        // The registry can gain a provider between CLI releases, and a miner
        // can hold an offer on it. `--all` that quietly skipped such a row
        // would report a clean sweep while leaving the offer serving.
        let server = MockServer::start().await;
        mount_me(
            &server,
            serde_json::json!([offer_row("brandnew", "wonder-model-1", true)]),
        )
        .await;
        mount_withdraw(&server, "/miners/products/brandnew/wonder-model-1", 204).await;

        let mut client = RegistryClient::new(config_for(&server));
        cmd_undeclare_products(&mut client, None)
            .await
            .expect("an unknown provider is the registry's business, not the CLI's");

        assert_eq!(
            deleted_paths(&server).await,
            vec!["/miners/products/brandnew/wonder-model-1"]
        );
    }

    #[tokio::test]
    async fn the_fan_out_with_nothing_to_withdraw_stops_before_any_delete() {
        let server = MockServer::start().await;
        mount_me(
            &server,
            serde_json::json!([offer_row("openai", "gpt-5.6", true)]),
        )
        .await;

        let mut client = RegistryClient::new(config_for(&server));
        let err = cmd_undeclare_products(&mut client, Some(&Provider::Anthropic))
            .await
            .expect_err("an empty target set is a failed command, not a silent no-op");

        assert!(err.to_string().contains("anthropic"), "got: {err}");
        assert!(deleted_paths(&server).await.is_empty());
    }

    #[tokio::test]
    async fn one_failed_withdrawal_does_not_abandon_the_others() {
        let server = MockServer::start().await;
        mount_me(
            &server,
            serde_json::json!([
                offer_row("anthropic", "claude-sonnet-4-6", true),
                offer_row("anthropic", "claude-haiku-4-6", true),
            ]),
        )
        .await;
        mount_withdraw(&server, "/miners/products/anthropic/claude-sonnet-4-6", 500).await;
        mount_withdraw(&server, "/miners/products/anthropic/claude-haiku-4-6", 204).await;

        let mut client = RegistryClient::new(config_for(&server));
        let err = cmd_undeclare_products(&mut client, Some(&Provider::Anthropic))
            .await
            .expect_err("a partial failure must exit non-zero");

        assert!(err.to_string().contains("1 of 2"), "got: {err}");
        assert_eq!(
            deleted_paths(&server).await.len(),
            2,
            "the second withdrawal must still be attempted"
        );
    }
}
