use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, Response, StatusCode};
use axum::routing::{any, get};
use axum::{Json, Router};
use gm_miner_attestd::kubetee_verify::{
    error_response, KubeteeVerifier, BIND_ADDR, HOST_NAME, IMAGE_MODELS, TARGETS,
};
use gm_miner_attestd::upstream_proxy::option_value;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(error = %format!("{error:#}"), "KubeTEE verification proxy failed");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("install rustls ring provider"))?;
    let verifier = Arc::new(KubeteeVerifier::new()?);
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if arguments.iter().any(|argument| argument == "--verify-once") {
        return verify_once(&verifier, option_value(&arguments, "--model")?).await;
    }
    let address: SocketAddr = BIND_ADDR
        .parse()
        .context("parse KubeTEE proxy bind address")?;
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .context("bind KubeTEE verification proxy")?;
    let app = Router::new()
        .route("/healthz", get(health))
        .route("/v1/models", get(models))
        .fallback(any(proxy))
        .with_state(verifier);
    info!(
        bind_addr = BIND_ADDR,
        "KubeTEE verification proxy listening"
    );
    axum::serve(listener, app)
        .await
        .context("serve KubeTEE verification proxy")
}

/// Attest `llm.kubetee.ai` once, sending no inference. The quote is per
/// host, not per model, so `--model` only checks the id is a compiled target.
async fn verify_once(verifier: &KubeteeVerifier, model: Option<&str>) -> Result<()> {
    if let Some(model) = model {
        anyhow::ensure!(
            TARGETS.contains(&model),
            "--model is not in the compiled KubeTEE target allowlist"
        );
    }
    let attested = verifier
        .preflight()
        .await
        .with_context(|| format!("verify KubeTEE endpoint {HOST_NAME}"))?;
    info!(
        host = HOST_NAME,
        peer = %attested.peer,
        pod = attested.pod,
        "KubeTEE endpoint attestation verified"
    );
    Ok(())
}

async fn health() -> StatusCode {
    StatusCode::NO_CONTENT
}

// Envoy authenticates the caller and selects a configured key slot before
// reaching this loopback route. Discovery neither reads that key/body nor
// contacts the supplier; only the direct image route remains available.
async fn models(_request: Request<Body>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "object": "list",
        "data": IMAGE_MODELS.map(|model| serde_json::json!({
            "id": model,
            "object": "model",
            "owned_by": "kubetee",
        })),
    }))
}

async fn proxy(
    State(verifier): State<Arc<KubeteeVerifier>>,
    request: Request<Body>,
) -> Response<Body> {
    verifier
        .forward(request)
        .await
        .unwrap_or_else(|error| error_response(&error))
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test failures report invalid responses")]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::body::Bytes;
    use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
    use axum::response::IntoResponse as _;
    use http_body_util::BodyExt as _;

    #[tokio::test]
    async fn image_discovery_is_local_and_never_reads_the_caller_body() {
        let polls = Arc::new(AtomicUsize::new(0));
        let body_polls = Arc::clone(&polls);
        let body = futures_util::stream::poll_fn(move |_| {
            body_polls.fetch_add(1, Ordering::SeqCst);
            std::task::Poll::Ready(Some(Err::<Bytes, _>(std::io::Error::other(
                "local discovery must not poll the caller body",
            ))))
        });
        let request = Request::builder()
            .uri("/v1/models")
            .header(AUTHORIZATION, "Bearer supplier-key-sentinel")
            .body(Body::from_stream(body))
            .unwrap();
        let response = models(request).await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[CONTENT_TYPE], "application/json");
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let catalog: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            catalog,
            serde_json::json!({
                "object": "list",
                "data": IMAGE_MODELS.map(|model| serde_json::json!({
                    "id": model,
                    "object": "model",
                    "owned_by": "kubetee",
                })),
            })
        );
        assert!(catalog["data"]
            .as_array()
            .unwrap()
            .iter()
            .all(|model| !TARGETS.contains(&model["id"].as_str().unwrap())));
        assert_eq!(polls.load(Ordering::SeqCst), 0);
    }
}
