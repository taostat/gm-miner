//! Product declaration + status commands: `declare-product`,
//! `declare-products`, and `status` (which folds in the product table).

use anyhow::{bail, Context as _, Result};

use gm_miner_cli::{
    client::RegistryClient,
    pricing::{
        effective_per_mtok_ndollars, effective_rate_summary, format_discount_pct,
        format_per_mtok_usd,
    },
    types::{MinerStatus, Product, ProductCatalogResponse, ProductDeclarationRequest, Provider},
};

use crate::commands::{me_error, status_error};

/// `gmcli declare-product` — POST one (provider, model, `discount_bp`)
/// offer to `/miners/products`. The registry treats POST as upsert, so this
/// also handles updating an existing offer's discount.
///
/// Fetches the catalog first so the success output can render retail +
/// the effective per-Mtok rate the miner will actually receive. The
/// extra HTTP call also catches "unknown product" before the POST goes
/// out, which lets the CLI fail with a clearer error than the registry's
/// generic 404.
pub(crate) async fn cmd_declare_product(
    client: &mut RegistryClient,
    provider: &Provider,
    model: &str,
    discount_bp: u32,
) -> Result<()> {
    let catalog = fetch_catalog(client).await?;
    let product = catalog
        .products
        .iter()
        .find(|p| &p.provider == provider && p.model == model)
        .ok_or_else(|| anyhow::anyhow!("{provider}/{model} is not in the registry catalog"))?;

    post_declare_product(client, provider, model, discount_bp).await?;

    let dims = &product.retail_price.dimensions;
    let retail_in = format_per_mtok_usd(dims.input_per_mtok_ndollars);
    let retail_out = format_per_mtok_usd(dims.output_per_mtok_ndollars);
    let eff_in = format_per_mtok_usd(effective_per_mtok_ndollars(
        dims.input_per_mtok_ndollars,
        discount_bp,
    ));
    let eff_out = format_per_mtok_usd(effective_per_mtok_ndollars(
        dims.output_per_mtok_ndollars,
        discount_bp,
    ));
    // What the miner keeps per token, as a percentage of retail. With
    // discount_bp = 0 this reads "100%"; at the 99.90% cap this is
    // "0.1% of retail" — the minimum positive payout.
    let kept_bp = 10_000_u32.saturating_sub(discount_bp);
    let kept_pct = format_discount_pct(kept_bp);

    println!("{provider}/{model}");
    println!("  Retail       : {retail_in} input / {retail_out} output per Mtok");
    println!("  Declared     : {}% off", format_discount_pct(discount_bp));
    println!("  You receive  : {eff_in} input / {eff_out} output per Mtok ({kept_pct}% of retail)");
    println!("  → ok");
    println!("\nNext: gmcli status   (confirm the offer)");
    Ok(())
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
        match post_declare_product(client, &product.provider, &product.model, discount_bp).await {
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
) -> Result<()> {
    let body = serde_json::to_value(ProductDeclarationRequest {
        provider: provider.as_str(),
        model,
        discount_bp,
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
    let resp = client
        .get(gm_miner_cli::client::ME_PATH)
        .await
        .context("GET /miners/me")?;

    let status_code = resp.status();
    if !status_code.is_success() {
        return Err(me_error(network, status_code));
    }

    let miner: MinerStatus = resp.json().await.context("parse status response")?;

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
    Ok(())
}
