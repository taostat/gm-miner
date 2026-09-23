//! NVIDIA Remote Attestation Service verdicts.
//!
//! NEAR reads the aggregate verdict of an NRAS v3 response. Chutes submits
//! evidence to NRAS v4 and additionally verifies every returned token against
//! NVIDIA's published ES384 keys before reading a claim.

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{bail, ensure, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ring::signature::{UnparsedPublicKey, ECDSA_P384_SHA384_FIXED};
use serde::Deserialize;
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};

pub const NRAS_ORIGIN: &str = "https://nras.attestation.nvidia.com";
const NRAS_V4_ATTEST: &str = "https://nras.attestation.nvidia.com/v4/attest/gpu";
const NRAS_JWKS: &str = "https://nras.attestation.nvidia.com/.well-known/jwks.json";
const NRAS_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_NRAS_BYTES: usize = 4 * 1024 * 1024;

// NRAS asserts these per GPU; any absent or false one fails admission.
const REQUIRED_GPU_CLAIMS: [&str; 10] = [
    "x-nvidia-gpu-attestation-report-signature-verified",
    "x-nvidia-gpu-attestation-report-nonce-match",
    "x-nvidia-gpu-arch-check",
    "x-nvidia-gpu-attestation-report-cert-chain-fwid-match",
    "x-nvidia-gpu-driver-rim-signature-verified",
    "x-nvidia-gpu-driver-rim-version-match",
    "x-nvidia-gpu-driver-rim-measurements-available",
    "x-nvidia-gpu-vbios-rim-signature-verified",
    "x-nvidia-gpu-vbios-rim-version-match",
    "x-nvidia-gpu-vbios-rim-measurements-available",
];

/// The aggregate verdict token of an NRAS response: `response[0][1]`.
///
/// # Errors
///
/// Returns an error when the response has no such string.
pub fn aggregate_token(response: &Value) -> Result<&str> {
    response
        .as_array()
        .and_then(|outer| outer.first())
        .and_then(Value::as_array)
        .and_then(|entry| entry.get(1))
        .and_then(Value::as_str)
        .context("NVIDIA NRAS response has no verdict token")
}

/// The JSON claims carried in a compact JWT's payload segment. Callers that
/// need the signature verified use [`Jwks::verify`], which returns the same
/// claims after checking it.
///
/// # Errors
///
/// Returns an error when the token is not a JWT with a JSON payload.
pub fn unverified_claims(token: &str) -> Result<Value> {
    let payload = token
        .split('.')
        .nth(1)
        .context("NVIDIA NRAS verdict is not a JWT")?;
    let bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .context("decode NVIDIA NRAS verdict payload")?;
    serde_json::from_slice(&bytes).context("parse NVIDIA NRAS verdict payload")
}

/// Require `x-nvidia-overall-att-result` to be boolean `true`.
///
/// # Errors
///
/// Returns an error for any other value, including a missing claim.
pub fn require_overall_success(claims: &Value) -> Result<()> {
    if claims
        .get("x-nvidia-overall-att-result")
        .and_then(Value::as_bool)
        != Some(true)
    {
        bail!("NVIDIA NRAS did not return a successful GPU attestation verdict");
    }
    Ok(())
}

#[derive(Deserialize)]
struct Jwk {
    kid: String,
    kty: String,
    crv: String,
    x: String,
    y: String,
}

/// NVIDIA's NRAS signing keys, as uncompressed P-384 points by key id.
#[derive(Clone, Debug, Default)]
pub struct Jwks {
    keys: BTreeMap<String, Vec<u8>>,
}

impl Jwks {
    /// Parse a JWKS document, keeping its EC P-384 keys.
    ///
    /// # Errors
    ///
    /// Returns an error when the document is malformed or has no P-384 key.
    pub fn parse(body: &[u8]) -> Result<Self> {
        #[derive(Deserialize)]
        struct Document {
            keys: Vec<Value>,
        }
        let document: Document = serde_json::from_slice(body).context("decode NVIDIA JWKS")?;
        let mut keys = BTreeMap::new();
        for value in document.keys {
            let Ok(key) = serde_json::from_value::<Jwk>(value) else {
                continue;
            };
            if key.kty != "EC" || key.crv != "P-384" {
                continue;
            }
            let x = URL_SAFE_NO_PAD
                .decode(&key.x)
                .context("decode NVIDIA JWK x")?;
            let y = URL_SAFE_NO_PAD
                .decode(&key.y)
                .context("decode NVIDIA JWK y")?;
            ensure!(
                x.len() == 48 && y.len() == 48,
                "NVIDIA JWK {} is not a P-384 point",
                key.kid
            );
            let mut point = Vec::with_capacity(97);
            point.push(4);
            point.extend_from_slice(&x);
            point.extend_from_slice(&y);
            keys.insert(key.kid, point);
        }
        ensure!(!keys.is_empty(), "NVIDIA JWKS has no P-384 signing key");
        Ok(Self { keys })
    }

    /// Verify an ES384 compact JWT and return its claims.
    ///
    /// # Errors
    ///
    /// Returns an error when the token is malformed, names an unknown key or
    /// another algorithm, or its signature does not verify.
    pub fn verify(&self, token: &str) -> Result<Value> {
        let Some((signed, signature)) = token.rsplit_once('.') else {
            bail!("NVIDIA token is not a compact JWT");
        };
        let Some((header, payload)) = signed.split_once('.') else {
            bail!("NVIDIA token is not a compact JWT");
        };
        let header: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(header)
                .context("decode NVIDIA token header")?,
        )
        .context("parse NVIDIA token header")?;
        ensure!(
            header.get("alg").and_then(Value::as_str) == Some("ES384"),
            "NVIDIA token is not ES384"
        );
        let kid = header
            .get("kid")
            .and_then(Value::as_str)
            .context("NVIDIA token header has no kid")?;
        let key = self
            .keys
            .get(kid)
            .with_context(|| format!("NVIDIA token kid {kid} is not in the JWKS"))?;
        let signature = URL_SAFE_NO_PAD
            .decode(signature)
            .context("decode NVIDIA token signature")?;
        UnparsedPublicKey::new(&ECDSA_P384_SHA384_FIXED, key)
            .verify(signed.as_bytes(), &signature)
            .map_err(|_| anyhow::anyhow!("NVIDIA token signature is invalid"))?;
        serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(payload)
                .context("decode NVIDIA token")?,
        )
        .context("parse NVIDIA token claims")
    }
}

/// Appraise a signed NRAS v4 response for `gpu_count` GPUs attested under
/// `nonce_hex`, returning the earliest token expiry (Unix seconds).
///
/// Every token must verify against `jwks`, carry the nonce and NRAS as
/// issuer, and be unexpired at `now`. The aggregate must succeed and commit to
/// each per-GPU token by SHA-256; each GPU must report success on measurement,
/// secure boot, debug-disabled and the report and RIM checks.
///
/// # Errors
///
/// Returns an error naming the first failing check.
pub fn appraise_v4(
    response: &Value,
    jwks: &Jwks,
    nonce_hex: &str,
    gpu_count: usize,
    now: u64,
) -> Result<u64> {
    let (aggregate, gpu_tokens) = split_v4(response)?;
    ensure!(
        gpu_tokens.len() == gpu_count,
        "NRAS returned {} GPU verdicts for {gpu_count} submitted GPUs",
        gpu_tokens.len()
    );
    let aggregate = jwks
        .verify(aggregate)
        .context("verify NRAS aggregate token")?;
    let mut expires = token_expiry(&aggregate, nonce_hex, now)?;
    require_overall_success(&aggregate)?;
    let digests = aggregate
        .get("submods")
        .and_then(Value::as_object)
        .context("NRAS aggregate token has no submods")?;
    for (name, token) in gpu_tokens {
        let token = token
            .as_str()
            .with_context(|| format!("NRAS verdict {name} is not a token"))?;
        let committed = digests
            .get(name)
            .and_then(|digest| digest.pointer("/1/1"))
            .and_then(Value::as_str)
            .with_context(|| format!("NRAS aggregate commits to no digest for {name}"))?;
        ensure!(
            committed.eq_ignore_ascii_case(&hex::encode(Sha256::digest(token.as_bytes()))),
            "NRAS verdict {name} differs from the digest in the aggregate token"
        );
        let claims = jwks
            .verify(token)
            .with_context(|| format!("verify NRAS verdict {name}"))?;
        expires = expires.min(token_expiry(&claims, nonce_hex, now)?);
        appraise_gpu(&claims).with_context(|| format!("NRAS verdict {name}"))?;
    }
    Ok(expires)
}

fn split_v4(response: &Value) -> Result<(&str, &Map<String, Value>)> {
    let outer = response
        .as_array()
        .filter(|outer| outer.len() == 2)
        .context("NRAS v4 response is not [aggregate, per-GPU]")?;
    let aggregate = outer[0]
        .as_array()
        .filter(|pair| pair.len() == 2 && pair[0].as_str() == Some("JWT"))
        .and_then(|pair| pair[1].as_str())
        .context("NRAS v4 response has no aggregate JWT")?;
    let gpus = outer[1]
        .as_object()
        .context("NRAS v4 response has no per-GPU verdicts")?;
    Ok((aggregate, gpus))
}

fn token_expiry(claims: &Value, nonce_hex: &str, now: u64) -> Result<u64> {
    ensure!(
        claims.get("iss").and_then(Value::as_str) == Some(NRAS_ORIGIN),
        "NRAS token issuer is not {NRAS_ORIGIN}"
    );
    let nonce = claims
        .get("eat_nonce")
        .and_then(Value::as_str)
        .context("NRAS token has no eat_nonce")?;
    ensure!(
        nonce.eq_ignore_ascii_case(nonce_hex),
        "NRAS token nonce does not match the attested nonce"
    );
    let expires = claims
        .get("exp")
        .and_then(Value::as_u64)
        .context("NRAS token has no exp")?;
    ensure!(expires > now, "NRAS token expired at {expires}");
    Ok(expires)
}

fn appraise_gpu(claims: &Value) -> Result<()> {
    ensure!(
        claims.get("measres").and_then(Value::as_str) == Some("success"),
        "GPU measurement result is not success"
    );
    ensure!(
        claims.get("secboot").and_then(Value::as_bool) == Some(true),
        "GPU secure boot is not on"
    );
    ensure!(
        claims.get("dbgstat").and_then(Value::as_str) == Some("disabled"),
        "GPU debug is not disabled"
    );
    for name in REQUIRED_GPU_CLAIMS {
        ensure!(
            claims.get(name).and_then(Value::as_bool) == Some(true),
            "GPU claim {name} is not true"
        );
    }
    Ok(())
}

/// NRAS v4 client: fetches NVIDIA's JWKS and submits GPU evidence.
#[derive(Clone, Debug)]
pub struct NrasClient {
    http: reqwest::Client,
}

impl NrasClient {
    /// Build an HTTPS-only client with a bounded timeout.
    ///
    /// # Errors
    ///
    /// Returns an error when the HTTP client cannot be built.
    pub fn new() -> Result<Self> {
        let http = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(NRAS_TIMEOUT)
            .build()
            .context("build NVIDIA NRAS client")?;
        Ok(Self { http })
    }

    /// Fetch NVIDIA's current NRAS signing keys.
    ///
    /// # Errors
    ///
    /// Returns an error when the request fails or the JWKS is malformed.
    pub async fn jwks(&self) -> Result<Jwks> {
        let body = self.get_bounded(self.http.get(NRAS_JWKS)).await?;
        Jwks::parse(&body)
    }

    /// Submit GPU evidence to NRAS v4 and return its raw response.
    ///
    /// # Errors
    ///
    /// Returns an error when the request fails or NRAS answers non-2xx.
    pub async fn attest_v4(&self, request: &Value) -> Result<Value> {
        let body = self
            .get_bounded(self.http.post(NRAS_V4_ATTEST).json(request))
            .await?;
        serde_json::from_slice(&body).context("decode NVIDIA NRAS response")
    }

    async fn get_bounded(&self, request: reqwest::RequestBuilder) -> Result<Vec<u8>> {
        let mut response = request.send().await.context("reach NVIDIA NRAS")?;
        let status = response.status();
        ensure!(status.is_success(), "NVIDIA NRAS answered {status}");
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .context("read NVIDIA NRAS response")?
        {
            ensure!(
                body.len() + chunk.len() <= MAX_NRAS_BYTES,
                "NVIDIA NRAS response exceeds {MAX_NRAS_BYTES} bytes"
            );
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test fixtures fail the test")]
pub(crate) mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair as _, ECDSA_P384_SHA384_FIXED_SIGNING};

    pub(crate) const NOW: u64 = 1_800_000_000;

    /// An NRAS signing key and the JWKS that publishes it.
    pub(crate) struct Signer {
        pair: EcdsaKeyPair,
        pub(crate) jwks: Jwks,
    }

    impl Signer {
        pub(crate) fn new() -> Self {
            let rng = SystemRandom::new();
            let pkcs8 =
                EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &rng).unwrap();
            let pair =
                EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, pkcs8.as_ref(), &rng)
                    .unwrap();
            let point = pair.public_key().as_ref();
            let jwks = Jwks::parse(
                serde_json::json!({"keys": [{
                    "kid": "test", "kty": "EC", "crv": "P-384",
                    "x": URL_SAFE_NO_PAD.encode(&point[1..49]),
                    "y": URL_SAFE_NO_PAD.encode(&point[49..]),
                }]})
                .to_string()
                .as_bytes(),
            )
            .unwrap();
            Self { pair, jwks }
        }

        pub(crate) fn sign(&self, claims: &Value) -> String {
            let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"ES384","kid":"test"}"#);
            let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
            let input = format!("{header}.{payload}");
            let signature = self
                .pair
                .sign(&SystemRandom::new(), input.as_bytes())
                .unwrap();
            format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.as_ref()))
        }

        /// A passing v4 response for `gpus` GPUs under `nonce_hex`.
        pub(crate) fn response(&self, nonce_hex: &str, gpus: usize) -> Value {
            self.response_with(nonce_hex, gpus, |_| {})
        }

        pub(crate) fn response_with(
            &self,
            nonce_hex: &str,
            gpus: usize,
            edit_gpu: impl Fn(&mut Value),
        ) -> Value {
            let mut tokens = Map::new();
            let mut submods = Map::new();
            for index in 0..gpus {
                let mut claims = gpu_claims(nonce_hex);
                edit_gpu(&mut claims);
                let token = self.sign(&claims);
                let digest = hex::encode(Sha256::digest(token.as_bytes()));
                submods.insert(
                    format!("GPU-{index}"),
                    serde_json::json!(["DIGEST", ["SHA256", digest]]),
                );
                tokens.insert(format!("GPU-{index}"), Value::String(token));
            }
            let aggregate = self.sign(&serde_json::json!({
                "iss": NRAS_ORIGIN, "eat_nonce": nonce_hex, "exp": NOW + 600,
                "x-nvidia-overall-att-result": true, "submods": submods,
            }));
            serde_json::json!([["JWT", aggregate], tokens])
        }
    }

    fn gpu_claims(nonce_hex: &str) -> Value {
        let mut claims = serde_json::json!({
            "iss": NRAS_ORIGIN, "eat_nonce": nonce_hex, "exp": NOW + 300,
            "measres": "success", "secboot": true, "dbgstat": "disabled",
        });
        for name in REQUIRED_GPU_CLAIMS {
            claims[name] = Value::Bool(true);
        }
        claims
    }

    const NONCE: &str = "ab";

    #[test]
    fn signed_passing_response_is_admitted_until_the_earliest_expiry() {
        let signer = Signer::new();
        let expires = appraise_v4(&signer.response(NONCE, 2), &signer.jwks, NONCE, 2, NOW).unwrap();
        assert_eq!(expires, NOW + 300);
    }

    #[test]
    fn nonce_mismatch_fails_closed() {
        let signer = Signer::new();
        let error =
            appraise_v4(&signer.response("cd", 1), &signer.jwks, NONCE, 1, NOW).unwrap_err();
        assert!(format!("{error:#}").contains("nonce"), "{error:#}");
    }

    #[test]
    fn expired_token_fails_closed() {
        let signer = Signer::new();
        let error = appraise_v4(
            &signer.response(NONCE, 1),
            &signer.jwks,
            NONCE,
            1,
            NOW + 400,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("expired"), "{error:#}");
    }

    #[test]
    fn a_token_signed_by_another_key_fails_closed() {
        let signer = Signer::new();
        let other = Signer::new();
        let error =
            appraise_v4(&signer.response(NONCE, 1), &other.jwks, NONCE, 1, NOW).unwrap_err();
        assert!(format!("{error:#}").contains("signature"), "{error:#}");
    }

    #[test]
    fn gpu_count_mismatch_fails_closed() {
        let signer = Signer::new();
        assert!(appraise_v4(&signer.response(NONCE, 1), &signer.jwks, NONCE, 2, NOW).is_err());
    }

    #[test]
    fn a_failing_gpu_claim_fails_closed() {
        let signer = Signer::new();
        for (claim, value) in [
            ("dbgstat", Value::from("enabled")),
            ("secboot", Value::Bool(false)),
            ("measres", Value::from("fail")),
            (
                "x-nvidia-gpu-attestation-report-nonce-match",
                Value::Bool(false),
            ),
        ] {
            let response = signer.response_with(NONCE, 1, |gpu| gpu[claim] = value.clone());
            let error = appraise_v4(&response, &signer.jwks, NONCE, 1, NOW).unwrap_err();
            assert!(format!("{error:#}").contains("GPU"), "{claim}: {error:#}");
        }
    }

    #[test]
    fn a_gpu_token_swapped_out_of_the_aggregate_fails_closed() {
        let signer = Signer::new();
        let mut response = signer.response(NONCE, 1);
        response[1]["GPU-0"] = Value::String(signer.sign(&gpu_claims(NONCE)));
        let error = appraise_v4(&response, &signer.jwks, NONCE, 1, NOW).unwrap_err();
        assert!(format!("{error:#}").contains("digest"), "{error:#}");
    }

    #[test]
    fn aggregate_failure_fails_closed() {
        let signer = Signer::new();
        let mut response = signer.response(NONCE, 1);
        let mut aggregate = unverified_claims(response[0][1].as_str().unwrap()).unwrap();
        aggregate["x-nvidia-overall-att-result"] = Value::Bool(false);
        response[0][1] = Value::String(signer.sign(&aggregate));
        assert!(appraise_v4(&response, &signer.jwks, NONCE, 1, NOW).is_err());
    }
}
