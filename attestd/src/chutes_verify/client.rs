//! The live Chutes API: discovery, evidence admission and encrypted invoke.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::time::Instant;

use anyhow::{ensure, Context, Result};
use async_trait::async_trait;
use dcap_qvl::collateral::CollateralClient;
use serde_json::Value;
use tracing::{info, warn};

use crate::chutes_verify::admission::{deadline, ChutesApi, Invocation, Verdict};
use crate::chutes_verify::error::ChutesError;
use crate::chutes_verify::evidence::{self, DiscoveredInstance, Discovery, EvidenceResponse};
use crate::chutes_verify::{references, CHAT_COMPLETIONS};
use crate::tee_evidence;
use crate::tee_evidence::nras::{self, Jwks, NrasClient};

const API_ORIGIN: &str = "https://api.chutes.ai";
const API_TIMEOUT: Duration = Duration::from_secs(30);
/// Matches the Envoy route timeout for the longest completions.
const INVOKE_TIMEOUT: Duration = Duration::from_secs(1_800);
const MAX_DISCOVERY_BYTES: usize = 512 * 1024;
const MAX_EVIDENCE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone)]
pub struct LiveChutes {
    api: reqwest::Client,
    invoke: reqwest::Client,
    collateral: CollateralClient,
    nras: NrasClient,
}

impl std::fmt::Debug for LiveChutes {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("LiveChutes").finish_non_exhaustive()
    }
}

impl LiveChutes {
    /// Build the Chutes, Intel collateral and NVIDIA clients.
    ///
    /// # Errors
    ///
    /// Returns an error when a client cannot be built.
    pub fn new() -> Result<Self> {
        let client = |timeout| {
            reqwest::Client::builder()
                .https_only(true)
                .redirect(reqwest::redirect::Policy::none())
                .timeout(timeout)
                .build()
                .context("build Chutes API client")
        };
        Ok(Self {
            api: client(API_TIMEOUT)?,
            invoke: client(INVOKE_TIMEOUT)?,
            collateral: tee_evidence::collateral_client()?,
            nras: NrasClient::new()?,
        })
    }

    async fn get(
        &self,
        api_key: &str,
        path: &str,
        stage: &'static str,
        limit: usize,
    ) -> Result<Vec<u8>, ChutesError> {
        let response = self
            .api
            .get(format!("{API_ORIGIN}{path}"))
            .bearer_auth(api_key)
            .send()
            .await
            .map_err(|error| {
                ChutesError::Unavailable(
                    anyhow::Error::new(error).context(format!("reach Chutes {stage}")),
                )
            })?;
        if !response.status().is_success() {
            return Err(upstream_failure(stage, response).await);
        }
        read_bounded(response, limit).await.map_err(|error| {
            ChutesError::Unavailable(error.context(format!("read Chutes {stage}")))
        })
    }

    /// Verify one discovered instance against its evidence row, returning the
    /// Unix second its evidence expires: the earliest of the NRAS tokens, the
    /// proxy certificate and the Intel collateral.
    async fn admit_instance(
        &self,
        instance: &DiscoveredInstance,
        evidence: &EvidenceResponse,
        nonce_hex: &str,
        jwks: &Jwks,
    ) -> Result<u64> {
        let row = evidence
            .evidence
            .iter()
            .find(|row| row.instance_id.as_deref() == Some(instance.instance_id.as_str()))
            .context("Chutes returned no evidence for this instance")?;
        let signed = evidence::verify_signed_row(row, nonce_hex)?;
        let claims = tee_evidence::verify_quote(&self.collateral, &signed.quote).await?;
        let td = tee_evidence::td_report(&claims.report)?;
        let binding = evidence::key_binding(nonce_hex, &instance.e2e_pubkey);
        // [0..32] binds our nonce to the ML-KEM key requests are encrypted to;
        // [32..64] binds the evidence certificate's key to the attested VM.
        evidence::check_report_data(&td.report_data, &binding, &signed.spki_sha256)?;
        let reference = references::match_td(references::published()?, td)?;
        let arch = reference.gpu_arch.with_context(|| {
            format!(
                "reference {} names no known GPU architecture",
                reference.name
            )
        })?;
        let gpu_count = signed.gpu_evidence.len();
        ensure!(
            (1..=reference.gpu_count).contains(&gpu_count),
            "{gpu_count} GPUs attested, {} carries 1..={}",
            reference.name,
            reference.gpu_count
        );
        let gpu_nonce = hex::encode(binding);
        let request = nras_request(&signed.gpu_evidence, &gpu_nonce, arch)?;
        let response = self.nras.attest_v4(&request).await?;
        let now = tee_evidence::unix_now()?;
        let gpus_expire = nras::appraise_v4(&response, jwks, &gpu_nonce, gpu_count, now)?;
        let expires = gpus_expire
            .min(signed.certificate_expires)
            .min(claims.earliest_expiration_date);
        ensure!(
            expires > now,
            "instance evidence expires before admission completes"
        );
        info!(
            instance = %instance.instance_id,
            release = %reference.version,
            hardware = %reference.name,
            gpus = gpu_count,
            "Chutes instance admitted"
        );
        Ok(expires)
    }
}

fn nras_request(gpu_evidence: &[Value], nonce_hex: &str, arch: &str) -> Result<Value> {
    let evidence_list = gpu_evidence
        .iter()
        .map(|item| {
            let field = |name| item.get(name).and_then(Value::as_str).context("GPU evidence item is incomplete");
            ensure!(
                field("arch")?.eq_ignore_ascii_case(arch),
                "GPU evidence is not {arch} as the reference hardware requires"
            );
            Ok(serde_json::json!({"evidence": field("evidence")?, "certificate": field("certificate")?}))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(serde_json::json!({
        "nonce": nonce_hex,
        "evidence_list": evidence_list,
        "arch": arch,
        "claims_version": "3.0",
    }))
}

const BELOW_EVIDENCE_MINIMUM: &str = "chute version below the evidence minimum";
const DETAIL_READ_BYTES: usize = 4096;
const DETAIL_WITHHELD: &str = "upstream detail withheld";

// Chutes `detail` prefixes mapped to gm-authored log text; no body text is logged.
const KNOWN_DETAILS: [(&str, &str); 7] = [
    (
        "Instances requires chutes_version >= 0.6.0",
        BELOW_EVIDENCE_MINIMUM,
    ),
    ("Rate limit exceeded", "Chutes rate limit reached"),
    ("Chute not found", "chute not found"),
    ("No active instances found", "chute has no active instances"),
    (
        "No E2E-capable instances",
        "chute has no E2E-capable instances",
    ),
    ("Instance is at maximum capacity", "instance at capacity"),
    (
        "Instance has no deployment_id",
        "instance not yet TEE-verified",
    ),
];

// Evidence is rate-limited per fixed window and refused by chute version; both shape the backoff.
async fn upstream_failure(stage: &'static str, response: reqwest::Response) -> ChutesError {
    let status = response.status();
    // Known from the status alone, so a stalled body read cannot lose it.
    if stage == "evidence" && status == reqwest::StatusCode::TOO_MANY_REQUESTS {
        warn!(stage, %status, "Chutes rate-limited evidence");
        return ChutesError::RateLimited { stage };
    }
    let detail = error_detail(response).await;
    warn!(stage, %status, detail = %detail, "Chutes answered an error");
    upstream_error(stage, status, detail)
}

fn upstream_error(
    stage: &'static str,
    status: reqwest::StatusCode,
    detail: &'static str,
) -> ChutesError {
    if stage == "evidence" && detail == BELOW_EVIDENCE_MINIMUM {
        return ChutesError::BelowEvidenceMinimum;
    }
    ChutesError::Upstream { stage, status }
}

/// A gm-authored description of a Chutes error body, for operator logs.
async fn error_detail(mut response: reqwest::Response) -> &'static str {
    let mut body = Vec::with_capacity(DETAIL_READ_BYTES);
    while body.len() < DETAIL_READ_BYTES {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                let room = DETAIL_READ_BYTES - body.len();
                body.extend_from_slice(&chunk[..chunk.len().min(room)]);
            }
            Ok(None) | Err(_) => break,
        }
    }
    describe_detail(&body)
}

fn describe_detail(body: &[u8]) -> &'static str {
    let detail = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|value| value.get("detail")?.as_str().map(str::to_owned));
    detail
        .and_then(|detail| {
            KNOWN_DETAILS
                .iter()
                .find(|(prefix, _)| detail.starts_with(prefix))
                .map(|(_, description)| *description)
        })
        .unwrap_or(DETAIL_WITHHELD)
}

async fn read_bounded(mut response: reqwest::Response, limit: usize) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            body.len() + chunk.len() <= limit,
            "response exceeds {limit} bytes"
        );
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[async_trait]
impl ChutesApi for LiveChutes {
    async fn discover(&self, api_key: &str, chute_id: &str) -> Result<Discovery, ChutesError> {
        let body = self
            .get(
                api_key,
                &format!("/e2e/instances/{chute_id}"),
                "discovery",
                MAX_DISCOVERY_BYTES,
            )
            .await?;
        Discovery::parse(&body).map_err(ChutesError::Rejected)
    }

    async fn admit(
        &self,
        api_key: &str,
        chute_id: &str,
        instances: &[DiscoveredInstance],
    ) -> Result<Vec<Verdict>, ChutesError> {
        // Deadlines are anchored before any network call, so a slow batch
        // shortens later verdicts instead of extending earlier ones.
        let anchor = Instant::now();
        let anchor_wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| ChutesError::Unavailable(anyhow::Error::new(error)))?;
        let nonce_hex = hex::encode(tee_evidence::random_nonce());
        let path = format!("/chutes/{chute_id}/evidence?nonce={nonce_hex}");
        let body = self
            .get(api_key, &path, "evidence", MAX_EVIDENCE_BYTES)
            .await
            .map_err(|error| match error {
                ChutesError::Upstream { stage, status } => {
                    ChutesError::Unavailable(anyhow::anyhow!("Chutes {stage} answered {status}"))
                }
                other => other,
            })?;
        let evidence: EvidenceResponse = serde_json::from_slice(&body)
            .context("decode Chutes evidence")
            .map_err(ChutesError::Rejected)?;
        let jwks =
            self.nras.jwks().await.map_err(|error| {
                ChutesError::Unavailable(error.context("fetch NVIDIA NRAS keys"))
            })?;
        let mut verdicts = Vec::with_capacity(instances.len());
        for instance in instances {
            let outcome = self
                .admit_instance(instance, &evidence, &nonce_hex, &jwks)
                .await
                .map(|expires| deadline(anchor, anchor_wall, expires))
                .map_err(|error| {
                    warn!(instance = %instance.instance_id, cause = %format!("{error:#}"), "Chutes instance rejected");
                    format!("{error:#}")
                });
            verdicts.push(Verdict {
                instance_id: instance.instance_id.clone(),
                e2e_pubkey: instance.e2e_pubkey.clone(),
                outcome,
            });
        }
        Ok(verdicts)
    }

    async fn invoke(
        &self,
        api_key: &str,
        invocation: Invocation,
    ) -> Result<reqwest::Response, ChutesError> {
        self.invoke
            .post(format!("{API_ORIGIN}/e2e/invoke"))
            .bearer_auth(api_key)
            .header("X-Chute-Id", invocation.chute_id)
            .header("X-Instance-Id", invocation.ticket.instance_id)
            .header("X-E2E-Nonce", invocation.ticket.nonce)
            .header(
                "X-E2E-Stream",
                if invocation.stream { "true" } else { "false" },
            )
            .header("X-E2E-Path", CHAT_COMPLETIONS)
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(invocation.blob)
            .send()
            .await
            .map_err(|error| {
                ChutesError::Unavailable(anyhow::Error::new(error).context("reach Chutes invoke"))
            })
    }
}

/// Check each target's chute id against Chutes' public model list.
///
/// # Errors
///
/// Returns an error when the list cannot be fetched or a pair differs.
pub async fn check_target_ids(targets: &[crate::chutes_verify::ChutesTarget]) -> Result<()> {
    let listed: Value = reqwest::Client::builder()
        .https_only(true)
        .timeout(API_TIMEOUT)
        .build()?
        .get("https://llm.chutes.ai/v1/models")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await
        .context("decode llm.chutes.ai model list")?;
    let models = listed["data"]
        .as_array()
        .context("llm.chutes.ai lists no models")?;
    for target in targets {
        let listed_id = models
            .iter()
            .find(|model| model["id"] == target.model)
            .and_then(|model| model["chute_id"].as_str());
        ensure!(
            listed_id == Some(target.chute_id),
            "{} is served by chute {listed_id:?}, compiled {}",
            target.model,
            target.chute_id
        );
    }
    Ok(())
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test fixtures fail the test")]
mod tests {
    use super::*;

    #[test]
    fn known_details_map_to_fixed_text_and_all_else_is_withheld() {
        let describe = |body: &str| describe_detail(body.as_bytes());
        assert_eq!(
            describe(
                r#"{"detail":"Instances requires chutes_version >= 0.6.0 to retrieve evidence."}"#
            ),
            "chute version below the evidence minimum"
        );
        assert_eq!(
            describe(r#"{"detail":"Rate limit exceeded. Try again later."}"#),
            "Chutes rate limit reached"
        );
        for withheld in [
            r#"{"detail":"invalid credential cpk_secret"}"#,
            r#"{"detail":"invalid credential cpk_\u0041bcdefghijklmnopqrstuvwxyz"}"#,
            r#"{"detail":"Authorization: Bearer abc"}"#,
            r#"{"detail":"got eyJhbGciOiJFUzM4NCJ9.eyJzdWIiOiJ4In0 back"}"#,
            r#"{"detail":{"nested":"Rate limit exceeded"}}"#,
            r#"{"message":"Rate limit exceeded"}"#,
            "Rate limit exceeded",
            "",
        ] {
            assert_eq!(describe(withheld), DETAIL_WITHHELD, "{withheld}");
        }
    }

    #[test]
    fn evidence_rate_limits_and_version_refusals_are_told_apart() {
        let below = describe_detail(
            br#"{"detail":"Instances requires chutes_version >= 0.6.0 to retrieve evidence."}"#,
        );
        let limited = describe_detail(br#"{"detail":"Rate limit exceeded. Try again later."}"#);
        let status = |stage, status, detail| upstream_error(stage, status, detail).status();
        assert_eq!(
            status("evidence", reqwest::StatusCode::BAD_REQUEST, below),
            reqwest::StatusCode::BAD_GATEWAY
        );
        assert_eq!(
            status("discovery", reqwest::StatusCode::TOO_MANY_REQUESTS, limited),
            reqwest::StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            status(
                "evidence",
                reqwest::StatusCode::BAD_REQUEST,
                DETAIL_WITHHELD
            ),
            reqwest::StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_evidence_rate_limit_is_known_before_its_body_arrives() {
        let stalled = futures_util::stream::pending::<Result<Vec<u8>, std::io::Error>>();
        let response = axum::http::Response::builder()
            .status(429)
            .body(reqwest::Body::wrap_stream(stalled))
            .unwrap();
        let failure = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            upstream_failure("evidence", reqwest::Response::from(response)),
        )
        .await
        .unwrap();
        let ChutesError::RateLimited { stage } = failure else {
            unreachable!("an evidence 429 must be a rate limit, got {failure}");
        };
        assert_eq!(stage, "evidence");
    }

    #[tokio::test]
    async fn a_body_past_the_read_limit_is_truncated_inside_a_chunk() {
        let body = format!(
            r#"{{"pad":"{}","detail":"Rate limit exceeded. Try again later."}}"#,
            "x".repeat(5_000)
        );
        let (first, second) = body.as_bytes().split_at(3_000);
        let chunks = vec![Ok::<_, std::io::Error>(first.to_vec()), Ok(second.to_vec())];
        let response = axum::http::Response::builder()
            .status(429)
            .body(reqwest::Body::wrap_stream(futures_util::stream::iter(
                chunks,
            )))
            .unwrap();
        let detail = error_detail(reqwest::Response::from(response)).await;
        assert_eq!(detail, DETAIL_WITHHELD);
    }

    #[test]
    fn nras_request_requires_the_reference_architecture() {
        let item = serde_json::json!({"arch": "HOPPER", "evidence": "ZQ==", "certificate": "Yw=="});
        let request = nras_request(std::slice::from_ref(&item), "ab", "HOPPER").unwrap();
        assert_eq!(
            request["evidence_list"][0],
            serde_json::json!({"evidence": "ZQ==", "certificate": "Yw=="})
        );
        assert_eq!(request["nonce"], "ab");
        assert!(nras_request(&[item], "ab", "BLACKWELL").is_err());
        assert!(nras_request(&[serde_json::json!({"arch": "HOPPER"})], "ab", "HOPPER").is_err());
    }
}
