//! `GET /attestation/info` handler.
//!
//! Wire contract: `gm/docs/contracts/gateway-attestation-info.md`. The
//! caller (the gm registry's control loop) supplies a fresh random
//! nonce as a base64 (STANDARD) query parameter; the server echoes it
//! back in the response and binds it into the quote's `report_data`.
//!
//! This endpoint is public by contract — no node-secret auth. Envoy
//! routes this one path to the attestation server and skips its
//! inbound `x-gm-node-key` filter for it (see `image/envoy.yaml`);
//! the registry probes it without that header.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::header::{HeaderName, HeaderValue};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use serde::Deserialize;
use serde_json::json;

use crate::provider::{AttestationError, AttestationProvider};

/// Maximum decoded nonce length. 32 bytes is the recommended size per
/// the contract; 64 bytes is the ceiling (the SHA-512 input bound).
const MAX_NONCE_BYTES: usize = 64;
/// Minimum decoded nonce length. The contract specifies a freshly
/// random 32-byte value; anything shorter weakens replay protection.
const MIN_NONCE_BYTES: usize = 16;

/// Axum router state — the attestation provider behind the endpoint.
pub type AppState = Arc<dyn AttestationProvider>;

/// Query string shape for `GET /attestation/info?nonce=...`.
#[derive(Debug, Deserialize)]
pub struct AttestationInfoQuery {
    /// Base64 STANDARD encoded nonce bytes. Required — the handler
    /// returns 400 if missing, per the contract's "forgetting the
    /// nonce" call-out.
    pub nonce: String,
}

/// `GET /attestation/info` handler.
pub async fn attestation_info(
    State(provider): State<AppState>,
    Query(query): Query<AttestationInfoQuery>,
) -> Response {
    let nonce_bytes = match decode_nonce(&query.nonce) {
        Ok(b) => b,
        Err(e) => return error_response(StatusCode::BAD_REQUEST, e),
    };
    match provider.build_info(&nonce_bytes).await {
        Ok(info) => success_response(&info),
        Err(e) => error_response_from(&e),
    }
}

/// Decode and validate the caller-supplied nonce.
fn decode_nonce(b64: &str) -> Result<Vec<u8>, &'static str> {
    if b64.is_empty() {
        return Err("nonce_required");
    }
    let bytes = BASE64_STANDARD
        .decode(b64)
        .map_err(|_| "nonce_not_base64")?;
    if bytes.len() < MIN_NONCE_BYTES {
        return Err("nonce_too_short");
    }
    if bytes.len() > MAX_NONCE_BYTES {
        return Err("nonce_too_long");
    }
    Ok(bytes)
}

fn success_response(info: &crate::provider::AttestationInfo) -> Response {
    let mut response = Json(info).into_response();
    apply_cors(&mut response);
    response
}

fn error_response(status: StatusCode, code: &str) -> Response {
    let body = json!({ "error": { "code": code } });
    let mut response = (status, Json(body)).into_response();
    apply_cors(&mut response);
    response
}

fn error_response_from(err: &AttestationError) -> Response {
    // Every dstack-side failure is a transient infrastructure fault —
    // the guest agent is unreachable or returned an error. 503 lets the
    // registry's control loop treat it as a retryable probe failure.
    let code = match err {
        AttestationError::DstackQuote(_) => "dstack_quote_failed",
        AttestationError::DstackKey(_) => "dstack_key_failed",
        AttestationError::DstackInfo(_) => "dstack_info_failed",
    };
    tracing::warn!(error = %err, "attestation build failed");
    error_response(StatusCode::SERVICE_UNAVAILABLE, code)
}

/// Apply the CORS header set. The attestation endpoint serves public,
/// read-only data — no credentials, no preflight machinery — so an
/// auditor or a browser-based verifier can fetch it directly.
fn apply_cors(response: &mut Response) {
    let headers = response.headers_mut();
    headers.insert(
        HeaderName::from_static("access-control-allow-origin"),
        HeaderValue::from_static("*"),
    );
    headers.insert(
        HeaderName::from_static("access-control-allow-methods"),
        HeaderValue::from_static("GET, OPTIONS"),
    );
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn missing_nonce_rejected() {
        assert_eq!(decode_nonce(""), Err("nonce_required"));
    }

    #[test]
    fn non_base64_nonce_rejected() {
        assert_eq!(decode_nonce("!not-base64!"), Err("nonce_not_base64"));
    }

    #[test]
    fn short_nonce_rejected() {
        let b64 = BASE64_STANDARD.encode([0u8; 8]);
        assert_eq!(decode_nonce(&b64), Err("nonce_too_short"));
    }

    #[test]
    fn long_nonce_rejected() {
        let b64 = BASE64_STANDARD.encode([0u8; 128]);
        assert_eq!(decode_nonce(&b64), Err("nonce_too_long"));
    }

    #[test]
    fn valid_nonce_accepted() {
        let nonce = [7u8; 32];
        let b64 = BASE64_STANDARD.encode(nonce);
        assert_eq!(decode_nonce(&b64).unwrap().as_slice(), &nonce);
    }
}
