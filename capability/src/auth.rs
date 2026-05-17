//! Bearer-token authentication middleware for capability endpoints.
//!
//! The registry sends the token derived from the miner's active
//! `NodeSecret` (BLAKE2b-hashed, per blockmachine's rotation pattern).
//! If `CAPABILITY_BEARER_TOKEN` is unset, every request is rejected
//! with 401 — do not allow unauthenticated access (the endpoint
//! reveals which providers this miner has keys for).

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};

/// Shared state threaded into the auth middleware.
#[derive(Clone)]
pub struct BearerState {
    /// Expected token, or None if the server started without one.
    pub token: Option<String>,
}

/// Axum middleware: validates `Authorization: Bearer <token>`.
///
/// # Errors
/// Returns `StatusCode::UNAUTHORIZED` if the token is missing, wrong, or
/// if the server was started without a `CAPABILITY_BEARER_TOKEN`.
pub async fn require_bearer(
    State(state): State<BearerState>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let expected = match &state.token {
        Some(t) => t.as_str(),
        None => return Err(StatusCode::UNAUTHORIZED),
    };

    let provided = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    match provided {
        Some(tok) if tok == expected => Ok(next.run(request).await),
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}
