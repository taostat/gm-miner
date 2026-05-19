//! gm-miner CLI.
//!
//! Subcommands:
//!   login           — Taostats device-code OAuth flow
//!   register-image  — register the miner image's compose hash with the registry
//!   list-products   — show the registry product catalog
//!   declare-product — register a miner-product offer with prices in USD/Mtok
//!   update-prices   — update prices on an existing offer
//!   status          — show current registration state and per-product eligibility
//!
//! All prices accepted by the CLI are in USD per million tokens (e.g. "3.00")
//! and are auto-converted to picodollars/Mtok before being sent to the registry.
//!
//! Contract: workstreams.md §W4

#![forbid(unsafe_code)]

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use gm_miner_cli::{
    auth,
    client::RegistryClient,
    config::{self, Config, TokenEntry},
    picodollar,
    types::{MinerPriceBlock, MinerStatus, Product, Provider},
};

#[derive(Parser)]
#[command(
    name = "gm-miner",
    version,
    about = "gm miner CLI — manage your miner's registration, products, and prices"
)]
struct Cli {
    /// Use testnet registry instead of mainnet.
    #[arg(long, global = true)]
    testnet: bool,

    /// Override the registry API URL.
    #[arg(long, global = true, env = "GM_REGISTRY_URL")]
    api_url: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Authenticate with Taostats (device-code OAuth flow) and store
    /// credentials in ~/.gm-miner/config.json.
    Login {
        /// Do not automatically open the browser.
        #[arg(long)]
        no_browser: bool,

        /// Override the auth server URL.
        #[arg(long, env = "GM_AUTH_URL")]
        auth_url: Option<String>,
    },

    /// Register this miner's image compose hash + capabilities with the registry.
    /// Run once after deploying a new image version.
    RegisterImage {
        /// Docker compose SHA256 (output of sha256sum docker-compose.yaml).
        #[arg(long)]
        compose_hash: String,

        /// dstack OS image hash (from dstack-cloud status or the deployment log).
        #[arg(long)]
        os_image_hash: String,
    },

    /// List all products in the registry catalog.
    ListProducts,

    /// Declare a miner-product offer with prices in USD per million tokens.
    DeclareProduct {
        /// Provider: anthropic, openai, or gemini.
        provider: Provider,

        /// Model identifier, e.g. claude-sonnet-4-6.
        model: String,

        /// Input token price in USD/Mtok (e.g. "2.80").
        #[arg(long)]
        price_input: String,

        /// Output token price in USD/Mtok (e.g. "14.00").
        #[arg(long)]
        price_output: String,

        /// Cache read price in USD/Mtok (optional).
        #[arg(long)]
        price_cache_read: Option<String>,

        /// Cache write 5m price in USD/Mtok (optional).
        #[arg(long)]
        price_cache_write_5m: Option<String>,

        /// Cache write 1h price in USD/Mtok (optional).
        #[arg(long)]
        price_cache_write_1h: Option<String>,
    },

    /// Update prices on an existing miner-product offer.
    UpdatePrices {
        /// Provider: anthropic, openai, or gemini.
        provider: Provider,

        /// Model identifier.
        model: String,

        /// Input token price in USD/Mtok.
        #[arg(long)]
        price_input: Option<String>,

        /// Output token price in USD/Mtok.
        #[arg(long)]
        price_output: Option<String>,

        /// Cache read price in USD/Mtok.
        #[arg(long)]
        price_cache_read: Option<String>,

        /// Cache write 5m price in USD/Mtok.
        #[arg(long)]
        price_cache_write_5m: Option<String>,

        /// Cache write 1h price in USD/Mtok.
        #[arg(long)]
        price_cache_write_1h: Option<String>,
    },

    /// Show the miner's current registration status and per-product eligibility.
    Status,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "warn".into()))
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Login {
            no_browser,
            auth_url,
        } => cmd_login(cli.testnet, auth_url, cli.api_url, !no_browser).await,
        Command::RegisterImage {
            compose_hash,
            os_image_hash,
        } => {
            let cfg = load_config(cli.testnet, cli.api_url)?;
            let mut client = RegistryClient::new(cfg);
            cmd_register_image(&mut client, &compose_hash, &os_image_hash).await
        }
        Command::ListProducts => {
            let cfg = load_config(cli.testnet, cli.api_url)?;
            let mut client = RegistryClient::new(cfg);
            cmd_list_products(&mut client).await
        }
        Command::DeclareProduct {
            provider,
            model,
            price_input,
            price_output,
            price_cache_read,
            price_cache_write_5m,
            price_cache_write_1h,
        } => {
            let price = build_price_block(
                &price_input,
                &price_output,
                price_cache_read.as_deref(),
                price_cache_write_5m.as_deref(),
                price_cache_write_1h.as_deref(),
            )?;
            let cfg = load_config(cli.testnet, cli.api_url)?;
            let mut client = RegistryClient::new(cfg);
            cmd_declare_product(&mut client, &provider, &model, price).await
        }
        Command::UpdatePrices {
            provider,
            model,
            price_input,
            price_output,
            price_cache_read,
            price_cache_write_5m,
            price_cache_write_1h,
        } => {
            let cfg = load_config(cli.testnet, cli.api_url)?;
            let mut client = RegistryClient::new(cfg);
            cmd_update_prices(
                &mut client,
                &provider,
                &model,
                price_input.as_deref(),
                price_output.as_deref(),
                price_cache_read.as_deref(),
                price_cache_write_5m.as_deref(),
                price_cache_write_1h.as_deref(),
            )
            .await
        }
        Command::Status => {
            let cfg = load_config(cli.testnet, cli.api_url)?;
            let mut client = RegistryClient::new(cfg);
            cmd_status(&mut client).await
        }
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn load_config(testnet: bool, api_url_override: Option<String>) -> Result<Config> {
    let mut cfg = config::load().context("load config")?;

    // Always reset to the explicit choice on every invocation so the
    // active network reflects the current flag, not whatever the last
    // command left in the config. Without this, a single `--testnet`
    // call sticks across every subsequent command until the operator
    // hand-edits ~/.gm-miner/config.json.
    cfg.active_network = Some(if testnet { "testnet" } else { "mainnet" }.to_string());

    if let Some(url) = api_url_override {
        cfg.active_entry_mut().api_url = Some(url);
    }

    Ok(cfg)
}

/// Convert an optional USD/Mtok string to an optional picodollar string.
fn opt_usd_to_pdollars(input: Option<&str>) -> Result<Option<String>> {
    match input {
        None => Ok(None),
        Some(s) => Ok(Some(picodollar::usd_per_mtok_to_pdollars(s)?.to_string())),
    }
}

fn build_price_block(
    price_input: &str,
    price_output: &str,
    price_cache_read: Option<&str>,
    price_cache_write_5m: Option<&str>,
    price_cache_write_1h: Option<&str>,
) -> Result<MinerPriceBlock> {
    Ok(MinerPriceBlock {
        input_per_mtok_pdollars: picodollar::usd_per_mtok_to_pdollars(price_input)?.to_string(),
        output_per_mtok_pdollars: picodollar::usd_per_mtok_to_pdollars(price_output)?.to_string(),
        cache_read_per_mtok_pdollars: opt_usd_to_pdollars(price_cache_read)?,
        cache_write_5m_per_mtok_pdollars: opt_usd_to_pdollars(price_cache_write_5m)?,
        cache_write_1h_per_mtok_pdollars: opt_usd_to_pdollars(price_cache_write_1h)?,
    })
}

// ── Commands ────────────────────────────────────────────────────────────────

async fn cmd_login(
    testnet: bool,
    auth_url_override: Option<String>,
    api_url_override: Option<String>,
    open_browser: bool,
) -> Result<()> {
    // `config::load()` already returns Config::default() when the file
    // is absent (first-time login). A failure here means the file
    // exists but is unreadable or invalid JSON — surfacing that as a
    // hard error matches the other commands' behaviour and prevents
    // a normal re-login from silently wiping an operator's existing
    // mainnet/testnet tokens.
    let mut cfg = config::load()
        .context("load gm-miner config (delete ~/.gm-miner/config.json if corrupted)")?;

    // Reset on every login so a previous testnet session can't sticky-
    // overwrite mainnet credentials when the operator omits --testnet.
    cfg.active_network = Some(if testnet { "testnet" } else { "mainnet" }.to_string());

    let auth_url = auth_url_override
        .or_else(|| {
            cfg.networks
                .get(cfg.active_network())
                .and_then(|n| n.auth_url.clone())
        })
        .unwrap_or_else(|| "https://auth.taostats.io".to_string());

    let client_id = cfg.client_id();

    let token = auth::device_login(&auth_url, &client_id, &["miner"], open_browser).await?;

    let entry = cfg.active_entry_mut();
    entry.auth_url = Some(auth_url.clone());
    let resolved_api_url = api_url_override
        .or_else(|| entry.api_url.clone())
        .unwrap_or_else(|| {
            if testnet {
                "https://api-testnet.gm.taostats.io".to_string()
            } else {
                "https://api.gm.taostats.io".to_string()
            }
        });
    entry.api_url = Some(resolved_api_url);
    entry.tokens = Some(TokenEntry {
        access_token: Some(token.access_token.clone()),
        refresh_token: token.refresh_token.clone(),
        token_expires_at: token.expires_in.map(|s| {
            #[expect(
                clippy::cast_possible_wrap,
                reason = "expires_in is a small positive number of seconds"
            )]
            let expiry = chrono::Utc::now() + chrono::Duration::seconds(s as i64);
            expiry.to_rfc3339()
        }),
    });

    config::save(&cfg).context("save config")?;

    println!("Login successful.");
    println!("Credentials saved to {}", config::config_path().display());
    Ok(())
}

async fn cmd_register_image(
    client: &mut RegistryClient,
    compose_hash: &str,
    os_image_hash: &str,
) -> Result<()> {
    let body = serde_json::json!({
        "compose_hash": compose_hash,
        "os_image_hash": os_image_hash,
    });

    let resp = client
        .post("/miners/register", &body)
        .await
        .context("POST /miners/register")?;

    let status = resp.status();
    let json: serde_json::Value = resp.json().await.context("parse register response")?;

    if !status.is_success() {
        bail!(
            "register-image failed ({status}): {}",
            json.get("detail")
                .and_then(|v| v.as_str())
                .unwrap_or_else(|| json.to_string().leak())
        );
    }

    println!("Image registered.");
    if let Some(id) = json.get("miner_id").and_then(|v| v.as_str()) {
        println!("  Miner ID : {id}");
    }
    if let Some(s) = json.get("status").and_then(|v| v.as_str()) {
        println!("  Status   : {s}");
    }
    println!("  Compose  : {compose_hash}");
    println!("  OS image : {os_image_hash}");
    Ok(())
}

async fn cmd_list_products(client: &mut RegistryClient) -> Result<()> {
    let resp = client.get("/products").await.context("GET /products")?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        bail!("list-products failed ({status}): {body}");
    }

    let products: Vec<Product> = resp.json().await.context("parse products")?;

    if products.is_empty() {
        println!("No products in catalog.");
        return Ok(());
    }

    println!("{:<12} {:<40} STATUS", "PROVIDER", "MODEL");
    println!("{}", "-".repeat(60));
    for p in &products {
        println!("{:<12} {:<40} {}", p.provider, p.model, p.status);
    }
    println!("\n{} products total.", products.len());
    Ok(())
}

async fn cmd_declare_product(
    client: &mut RegistryClient,
    provider: &Provider,
    model: &str,
    price: MinerPriceBlock,
) -> Result<()> {
    // Serialize via the typed MinerPriceBlock so its skip_serializing_if
    // attrs kick in and unset cache_* fields are omitted entirely
    // (rather than sent as JSON null, which the registry rejects).
    let body = serde_json::json!({
        "provider": provider.as_str(),
        "model": model,
        "miner_price": price,
    });

    let resp = client
        .post("/miners/products", &body)
        .await
        .context("POST /miners/products")?;

    let status = resp.status();
    let json: serde_json::Value = resp
        .json()
        .await
        .context("parse declare-product response")?;

    if !status.is_success() {
        bail!(
            "declare-product failed ({status}): {}",
            json.get("detail")
                .and_then(|v| v.as_str())
                .unwrap_or_else(|| json.to_string().leak())
        );
    }

    let input_usd =
        picodollar::pdollars_to_usd_per_mtok(price.input_per_mtok_pdollars.parse().unwrap_or(0));
    let output_usd =
        picodollar::pdollars_to_usd_per_mtok(price.output_per_mtok_pdollars.parse().unwrap_or(0));

    println!("Product declared.");
    println!("  Provider : {provider}");
    println!("  Model    : {model}");
    println!("  Input    : ${input_usd}/Mtok");
    println!("  Output   : ${output_usd}/Mtok");
    Ok(())
}

#[expect(
    clippy::too_many_arguments,
    reason = "all args are distinct price fields; no better grouping"
)]
async fn cmd_update_prices(
    client: &mut RegistryClient,
    provider: &Provider,
    model: &str,
    price_input: Option<&str>,
    price_output: Option<&str>,
    price_cache_read: Option<&str>,
    price_cache_write_5m: Option<&str>,
    price_cache_write_1h: Option<&str>,
) -> Result<()> {
    if price_input.is_none()
        && price_output.is_none()
        && price_cache_read.is_none()
        && price_cache_write_5m.is_none()
        && price_cache_write_1h.is_none()
    {
        bail!("at least one --price-* flag must be specified");
    }

    let mut miner_price = serde_json::Map::new();
    if let Some(p) = price_input {
        miner_price.insert(
            "input_per_mtok_pdollars".into(),
            serde_json::Value::String(picodollar::usd_per_mtok_to_pdollars(p)?.to_string()),
        );
    }
    if let Some(p) = price_output {
        miner_price.insert(
            "output_per_mtok_pdollars".into(),
            serde_json::Value::String(picodollar::usd_per_mtok_to_pdollars(p)?.to_string()),
        );
    }
    if let Some(p) = price_cache_read {
        miner_price.insert(
            "cache_read_per_mtok_pdollars".into(),
            serde_json::Value::String(picodollar::usd_per_mtok_to_pdollars(p)?.to_string()),
        );
    }
    if let Some(p) = price_cache_write_5m {
        miner_price.insert(
            "cache_write_5m_per_mtok_pdollars".into(),
            serde_json::Value::String(picodollar::usd_per_mtok_to_pdollars(p)?.to_string()),
        );
    }
    if let Some(p) = price_cache_write_1h {
        miner_price.insert(
            "cache_write_1h_per_mtok_pdollars".into(),
            serde_json::Value::String(picodollar::usd_per_mtok_to_pdollars(p)?.to_string()),
        );
    }

    let path = format!("/miners/products/{}/{}/prices", provider.as_str(), model);
    let body = serde_json::json!({ "miner_price": miner_price });

    let resp = client.patch(&path, &body).await.context("PATCH prices")?;

    let status = resp.status();
    let json: serde_json::Value = resp.json().await.context("parse update-prices response")?;

    if !status.is_success() {
        bail!(
            "update-prices failed ({status}): {}",
            json.get("detail")
                .and_then(|v| v.as_str())
                .unwrap_or_else(|| json.to_string().leak())
        );
    }

    println!("Prices updated for {provider}/{model}.");
    Ok(())
}

async fn cmd_status(client: &mut RegistryClient) -> Result<()> {
    let resp = client.get("/miners/me").await.context("GET /miners/me")?;

    let status_code = resp.status();
    if !status_code.is_success() {
        let body = resp.text().await.unwrap_or_default();
        bail!("status failed ({status_code}): {body}");
    }

    let miner: MinerStatus = resp.json().await.context("parse status response")?;

    println!("Miner status");
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
        println!("\nNo products declared.");
        return Ok(());
    }

    println!("\nProducts:");
    println!(
        "{:<12} {:<40} {:<10} {:<10}",
        "PROVIDER", "MODEL", "OFFERED", "ELIGIBLE"
    );
    println!("{}", "-".repeat(76));
    for p in &miner.products {
        println!(
            "{:<12} {:<40} {:<10} {:<10}",
            p.provider,
            p.model,
            if p.is_offered { "yes" } else { "no" },
            if p.is_eligible { "yes" } else { "no" },
        );
    }
    Ok(())
}
