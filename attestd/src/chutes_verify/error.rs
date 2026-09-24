use axum::body::Body;
use axum::http::{header, HeaderValue, Response, StatusCode};
use tracing::warn;

/// Why a Chutes request did not complete. Every variant fails closed: no
/// request is sent upstream unencrypted and no unauthenticated byte is
/// forwarded to the caller.
#[derive(Debug, thiserror::Error)]
pub enum ChutesError {
    /// The caller's request is not one this proxy serves.
    #[error("{0}")]
    BadRequest(String),
    /// Envoy did not inject a Chutes credential.
    #[error("the request carries no Chutes bearer credential")]
    MissingCredential,
    /// Chutes answered a non-success status; it is passed through.
    #[error("Chutes {stage} answered {status}")]
    Upstream {
        stage: &'static str,
        status: StatusCode,
    },
    /// Admission could not run: an attestation or Chutes service was
    /// unreachable or refused, and no cached admission covers the chute.
    #[error("attestation unavailable: {0:#}")]
    Unavailable(anyhow::Error),
    /// Chutes refused an attestation call under its rate limit, and no cached
    /// admission covers the chute.
    #[error("attestation unavailable: Chutes {stage} answered 429 Too Many Requests")]
    RateLimited { stage: &'static str },
    /// Chutes serves no evidence for this chute's version.
    #[error("attestation rejected: the chute's version is below Chutes' evidence minimum")]
    BelowEvidenceMinimum,
    /// Evidence was obtained and failed verification.
    #[error("attestation rejected: {0:#}")]
    Rejected(anyhow::Error),
    /// The encrypted response failed decryption or its checks.
    #[error("response rejected: {0:#}")]
    BadResponse(anyhow::Error),
}

impl ChutesError {
    #[must_use]
    pub fn status(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::MissingCredential => StatusCode::UNAUTHORIZED,
            Self::Upstream { status, .. } => *status,
            Self::Unavailable(_) | Self::RateLimited { .. } => StatusCode::SERVICE_UNAVAILABLE,
            Self::BelowEvidenceMinimum | Self::Rejected(_) | Self::BadResponse(_) => {
                StatusCode::BAD_GATEWAY
            }
        }
    }

    fn kind(&self) -> &'static str {
        match self {
            Self::BadRequest(_) => "gm_chutes_bad_request",
            Self::MissingCredential => "gm_chutes_missing_credential",
            Self::Upstream { .. } => "gm_chutes_upstream_status",
            Self::Unavailable(_) | Self::RateLimited { .. } => "gm_chutes_attestation_unavailable",
            Self::BelowEvidenceMinimum | Self::Rejected(_) => "gm_chutes_attestation_rejected",
            Self::BadResponse(_) => "gm_chutes_response_rejected",
        }
    }

    /// The JSON error response carrying the status and the cause.
    #[must_use]
    pub fn into_response(self) -> Response<Body> {
        let status = self.status();
        let message = self.to_string();
        warn!(%status, kind = self.kind(), cause = %message, "Chutes request failed closed");
        let body = serde_json::json!({"error": {"type": self.kind(), "message": message}});
        let mut response = Response::new(Body::from(body.to_string()));
        *response.status_mut() = status;
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        response
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test bodies are local JSON")]
mod tests {
    use super::*;
    use http_body_util::BodyExt as _;

    #[tokio::test]
    async fn upstream_status_passes_through_with_its_cause() {
        let response = ChutesError::Upstream {
            stage: "invoke",
            status: StatusCode::TOO_MANY_REQUESTS,
        }
        .into_response();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["error"]["type"], "gm_chutes_upstream_status");
        assert_eq!(
            body["error"]["message"],
            "Chutes invoke answered 429 Too Many Requests"
        );
    }

    #[tokio::test]
    async fn verification_failures_are_bad_gateway_and_name_their_cause() {
        let error =
            anyhow::anyhow!("MRTD is not in the published references").context("admit instance");
        let response = ChutesError::Rejected(error).into_response();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(
            text.contains("MRTD is not in the published references"),
            "{text}"
        );
    }
}
