use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, Response, StatusCode};
use axum::routing::{any, get};
use axum::{Json, Router};
use gm_miner_attestd::chutes_verify::admission::{Admissions, ChutesApi};
use gm_miner_attestd::chutes_verify::{client, references, ChutesVerifier, LiveChutes, TARGETS};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

const BIND_ADDR: &str = "127.0.0.1:8083";
/// Spaces `--verify-once` discoveries to stay within the per-minute budget.
const DISCOVERY_SPACING: std::time::Duration = std::time::Duration::from_secs(
    60 / gm_miner_attestd::chutes_verify::admission::DISCOVERIES_PER_MINUTE as u64 + 1,
);

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            error!(error = %format!("{error:#}"), "Chutes verification proxy failed");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("install rustls ring provider"))?;
    let entries = references::published()?.len();
    info!(
        sha256 = references::PUBLISHED_SHA256,
        entries, "Chutes measurement references loaded"
    );
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if arguments.iter().any(|argument| argument == "--verify-once") {
        let model = option_value(&arguments, "--model")?;
        return verify_once(model).await;
    }
    let address: SocketAddr = BIND_ADDR.parse().context("parse bind address")?;
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .context("bind Chutes verification proxy")?;
    let app = Router::new()
        .route("/healthz", get(health))
        .route("/v1/models", get(models))
        .fallback(any(forward))
        .with_state(Arc::new(ChutesVerifier::new(LiveChutes::new()?)));
    info!(bind_addr = BIND_ADDR, "Chutes verification proxy listening");
    axum::serve(listener, app)
        .await
        .context("serve Chutes verification proxy")
}

/// Check every compiled target against Chutes' model list, then admit one
/// instance of each (or of `--model`) with `CHUTES_API_KEY`, spaced by
/// [`DISCOVERY_SPACING`], sending no inference.
async fn verify_once(model: Option<&str>) -> Result<()> {
    let targets = TARGETS
        .into_iter()
        .filter(|target| model.is_none_or(|model| target.model == model))
        .collect::<Vec<_>>();
    anyhow::ensure!(
        !targets.is_empty(),
        "--model is not a compiled Chutes target"
    );
    client::check_target_ids(&targets).await?;
    let api_key = std::env::var("CHUTES_API_KEY").context("CHUTES_API_KEY is not set")?;
    let admissions = Admissions::new(Arc::new(LiveChutes::new()?));
    let mut failures = 0;
    for (index, target) in targets.into_iter().enumerate() {
        if index > 0 {
            tokio::time::sleep(DISCOVERY_SPACING).await;
        }
        match admissions.ticket(&api_key, target.chute_id).await {
            Ok(ticket) => info!(model = target.model, instance = %ticket.instance_id, "admitted"),
            Err(error) => {
                failures += 1;
                error!(model = target.model, status = %error.status(), cause = %error, "not admitted");
            }
        }
    }
    anyhow::ensure!(failures == 0, "{failures} Chutes targets failed admission");
    Ok(())
}

fn option_value<'a>(arguments: &'a [String], option: &str) -> Result<Option<&'a str>> {
    let Some(index) = arguments.iter().position(|argument| argument == option) else {
        return Ok(None);
    };
    arguments
        .get(index + 1)
        .map(String::as_str)
        .map(Some)
        .with_context(|| format!("{option} requires a value"))
}

async fn health() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn models() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "object": "list",
        "data": TARGETS.map(|target| serde_json::json!({
            "id": target.model,
            "object": "model",
            "owned_by": "chutes",
        })),
    }))
}

async fn forward<A: ChutesApi>(
    State(verifier): State<Arc<ChutesVerifier<A>>>,
    request: Request<Body>,
) -> Response<Body> {
    verifier.forward(request).await
}
