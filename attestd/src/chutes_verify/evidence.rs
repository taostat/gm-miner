//! Chutes discovery and signed-evidence documents, and the checks that bind a
//! discovered instance key to a TDX quote.

use std::time::Duration;

use anyhow::{ensure, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ring::signature::{UnparsedPublicKey, RSA_PKCS1_2048_8192_SHA256};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use x509_parser::parse_x509_certificate;
use x509_parser::public_key::PublicKey;

use crate::chutes_verify::crypto::validate_public_key;
use crate::tee_evidence;

const MAX_INSTANCES: usize = 5;
const MAX_NONCE_LIFETIME_SECS: u64 = 75;

/// `GET /e2e/instances/{chute_id}`.
#[derive(Clone, Debug, Deserialize)]
pub struct Discovery {
    pub instances: Vec<DiscoveredInstance>,
    pub nonce_expires_in: u64,
}

#[derive(Clone, Deserialize)]
pub struct DiscoveredInstance {
    pub instance_id: String,
    pub e2e_pubkey: String,
    pub nonces: Vec<String>,
}

impl std::fmt::Debug for DiscoveredInstance {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DiscoveredInstance")
            .field("instance_id", &self.instance_id)
            .field("nonces", &self.nonces.len())
            .finish_non_exhaustive()
    }
}

impl Discovery {
    /// Parse and validate a discovery body.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty or oversized instance list, a bad nonce
    /// lifetime, a malformed key, or a duplicated instance or key.
    pub fn parse(body: &[u8]) -> Result<Self> {
        let discovery: Self = serde_json::from_slice(body).context("decode Chutes discovery")?;
        ensure!(
            (1..=MAX_INSTANCES).contains(&discovery.instances.len()),
            "Chutes discovery returned {} instances",
            discovery.instances.len()
        );
        ensure!(
            (1..=MAX_NONCE_LIFETIME_SECS).contains(&discovery.nonce_expires_in),
            "Chutes nonce lifetime {}s is outside 1..={MAX_NONCE_LIFETIME_SECS}s",
            discovery.nonce_expires_in
        );
        for (index, instance) in discovery.instances.iter().enumerate() {
            validate_public_key(&instance.e2e_pubkey)
                .with_context(|| format!("instance {}", instance.instance_id))?;
            ensure!(
                discovery.instances[..index].iter().all(|other| {
                    other.instance_id != instance.instance_id
                        && other.e2e_pubkey != instance.e2e_pubkey
                }),
                "Chutes discovery repeats instance {} or its key",
                instance.instance_id
            );
        }
        let mut nonces = std::collections::HashSet::new();
        for nonce in discovery
            .instances
            .iter()
            .flat_map(|instance| &instance.nonces)
        {
            ensure!(
                nonces.insert(nonce),
                "Chutes discovery repeats an invocation nonce"
            );
        }
        Ok(discovery)
    }

    #[must_use]
    pub fn nonce_lifetime(&self) -> Duration {
        Duration::from_secs(self.nonce_expires_in)
    }
}

/// `GET /chutes/{chute_id}/evidence?nonce=…`.
#[derive(Debug, Deserialize)]
pub struct EvidenceResponse {
    pub evidence: Vec<EvidenceRow>,
}

#[derive(Debug, Deserialize)]
pub struct EvidenceRow {
    pub instance_id: Option<String>,
    pub quote: String,
    pub gpu_evidence: Vec<Value>,
    pub certificate: String,
    pub signature: Option<String>,
    pub attested_body: Option<String>,
}

/// An evidence row whose attestation-proxy signature and body checked out.
#[derive(Debug)]
pub struct SignedEvidence {
    pub quote: Vec<u8>,
    pub gpu_evidence: Vec<Value>,
    pub spki_sha256: [u8; 32],
    /// The proxy certificate's `notAfter`, Unix seconds.
    pub certificate_expires: u64,
}

/// `report_data[0..32]`: SHA-256 over the nonce hex followed by the instance
/// key's base64 text, exactly as the instance hashes them.
#[must_use]
pub fn key_binding(nonce_hex: &str, e2e_pubkey_b64: &str) -> [u8; 32] {
    Sha256::digest([nonce_hex.as_bytes(), e2e_pubkey_b64.as_bytes()].concat()).into()
}

/// Verify the attestation proxy signed exactly this row for `nonce_hex`.
///
/// The row's certificate must be currently valid and hold an RSA key; its
/// PKCS#1 v1.5 SHA-256 signature must cover `attested_body`, and that body
/// must carry `nonce_hex` and the same quote and GPU evidence as the row.
///
/// # Errors
///
/// Returns an error naming the first failing check.
pub fn verify_signed_row(row: &EvidenceRow, nonce_hex: &str) -> Result<SignedEvidence> {
    let certificate_der = BASE64
        .decode(&row.certificate)
        .context("decode attestation proxy certificate")?;
    let (rest, certificate) = parse_x509_certificate(&certificate_der)
        .map_err(|error| anyhow::anyhow!("parse attestation proxy certificate: {error}"))?;
    ensure!(
        rest.is_empty(),
        "attestation proxy certificate has trailing bytes"
    );
    ensure!(
        certificate.validity().is_valid(),
        "attestation proxy certificate is outside its validity period"
    );
    let Ok(PublicKey::RSA(_)) = certificate.public_key().parsed() else {
        anyhow::bail!("attestation proxy certificate does not hold an RSA key");
    };
    let signature = BASE64
        .decode(
            row.signature
                .as_deref()
                .context("evidence row is unsigned")?,
        )
        .context("decode evidence signature")?;
    let body = BASE64
        .decode(
            row.attested_body
                .as_deref()
                .context("evidence row has no attested body")?,
        )
        .context("decode attested body")?;
    UnparsedPublicKey::new(
        &RSA_PKCS1_2048_8192_SHA256,
        &certificate.public_key().subject_public_key.data,
    )
    .verify(&body, &signature)
    .map_err(|_| {
        anyhow::anyhow!("evidence signature does not verify under the proxy certificate")
    })?;
    check_attested_body(&body, row, nonce_hex)?;
    Ok(SignedEvidence {
        quote: BASE64.decode(&row.quote).context("decode TDX quote")?,
        gpu_evidence: row.gpu_evidence.clone(),
        spki_sha256: tee_evidence::spki_sha256(&certificate_der)?,
        certificate_expires: u64::try_from(certificate.validity().not_after.timestamp())
            .context("attestation proxy certificate expires before 1970")?,
    })
}

fn check_attested_body(body: &[u8], row: &EvidenceRow, nonce_hex: &str) -> Result<()> {
    let body: Value = serde_json::from_slice(body).context("decode attested body")?;
    ensure!(
        body.get("nonce").and_then(Value::as_str) == Some(nonce_hex),
        "attested body carries a different nonce"
    );
    ensure!(
        body.pointer("/evidence/tdx_quote").and_then(Value::as_str) == Some(row.quote.as_str()),
        "attested body carries a different TDX quote"
    );
    // sek8s serialises the GPU evidence as a JSON string inside the body.
    let gpu: Value = match body.pointer("/evidence/nvtrust_evidence") {
        Some(Value::String(encoded)) => {
            serde_json::from_str(encoded).context("decode attested GPU evidence")?
        }
        Some(inline) => inline.clone(),
        None => anyhow::bail!("attested body has no GPU evidence"),
    };
    ensure!(
        gpu.as_array() == Some(&row.gpu_evidence),
        "attested body carries different GPU evidence"
    );
    Ok(())
}

/// Require `report_data` to bind the nonce and instance key in its first half
/// and the evidence certificate's key in its second.
///
/// `report_data[32..64]` binds the evidence certificate's key to the attested
/// VM; request confidentiality comes from the ML-KEM key bound, with our
/// nonce, in `report_data[0..32]`.
///
/// # Errors
///
/// Returns an error naming the half that does not match.
pub fn check_report_data(
    report_data: &[u8; 64],
    key_binding: &[u8; 32],
    spki_sha256: &[u8; 32],
) -> Result<()> {
    ensure!(
        report_data[..32] == key_binding[..],
        "TDX report_data does not bind our nonce and the instance E2E key"
    );
    ensure!(
        report_data[32..] == spki_sha256[..],
        "TDX report_data does not bind the evidence certificate key"
    );
    Ok(())
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test fixtures fail the test")]
mod tests {
    use super::*;
    use crate::chutes_verify::crypto::tests::Instance;

    const NONCE: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    // A self-signed RSA certificate and its signature over
    // {"evidence":{"tdx_quote":"BAA=","nvtrust_evidence":"[]"},"nonce":NONCE},
    // generated offline with disposable keys.
    const CERTIFICATE: &str = "MIIDIzCCAgugAwIBAgIULMyGR+V4H2m5blpKHLWszyeGqWEwDQYJKoZIhvcNAQELBQAwITEfMB0GA1UEAwwWUzM3IHN5bnRoZXRpYyBldmlkZW5jZTAeFw0yNjA5MTcwMDMwMDJaFw0zNjA5MTQwMDMwMDJaMCExHzAdBgNVBAMMFlMzNyBzeW50aGV0aWMgZXZpZGVuY2UwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDRyMwVThA6a8+04gtytDHhPu+GP5FHNPj0OpDnAZMgkagt56DV/OSKsmCiMzavLIf9RGmyQ1FAahPz0nUWBuluR9Z1YSJn41Ql1gT1DXMAQSzql2q3DgFKIkyhhdOEmyQ9ib7HKEiQHnNbCBPvQ0T9U3r5/0mgqH7kGdJWdCVgiEBIymGcT23iWgoc4hrSqRAGKz9py96Drd2xNddG46MlmXDjX6msRk4727xcOBBFfBL5MC67xpTpJEW7oofPZ8KEMC7eeX7dzPKvIApcKTpJLsScCgz9ZTc4solSQlXkiBK/FtFkAPOt08uXoTQsnET+WPiaqNKM106+44PHz6NxAgMBAAGjUzBRMB0GA1UdDgQWBBTVY+ihXwbi8nzTLnO7I3now3huvTAfBgNVHSMEGDAWgBTVY+ihXwbi8nzTLnO7I3now3huvTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAVrpkUrKD9+tpQcqiinwfD1z3QahDsXJ8aAlBZGFOCqc/f2LetK+8Ru//ZtKW24x5uSp8rGThMa5yYoKI6JyuGQ2yWhvrjVrvWUq+onywnUVn7tseYqGeCdhgh38/katK1cMvCo9le10GoODx+64KMhswUYSujQudEhRCetwJ7VzcSS1cS3bRT1PKpO5FYchE1+oBpB8GYIevRpr3CqdgOsJ5iSpqqWg5EwdvryHeeLBdXOCBZhNMJoF9L2xrNL22xC8FWbCUW1kwpJTRbVKv5Cz1UFvHY1frLDE30cI+QObxjiGtL9BavUdjrCl0javvGe8eF6iv8h8FMcSUkH1dW";
    const SIGNATURE: &str = "ZMXN/RijJDzHwX3U+zZzDxYcZUi03BTYXVvq0GWEQklmhm1e6LlkarBxBAYp0CPYIfs2XMKGeEE5/V43GIRXZu20SxlOoRAhzMj/39Puy/TZs6cZISbmV/mUVV10JDRzsw8XTFbHrvPIBxQbIzp7IQzpPm7O6zjh4KelH0U5CppBzAc5EkFl4xZtRtvF6Eh/LyORTd2sE/nPp+ZSB933lIAs1pnBZh3L+ToZ7+/3nQ6UeIDK1vG6itaL0USPQo/MElrzQpCUoy/yNBJAkEMpXIRjLrpEttF4OsuPySWebFA/iq71pMS0c+kRhez2F7qYU/iLqCmetfEFfFjS0Csmgg==";
    const ATTESTED_BODY: &str = "eyJldmlkZW5jZSI6eyJ0ZHhfcXVvdGUiOiJCQUE9IiwibnZ0cnVzdF9ldmlkZW5jZSI6W119LCJub25jZSI6IjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYifQ==";

    fn row() -> EvidenceRow {
        EvidenceRow {
            instance_id: Some("00000000-0000-4000-8000-000000000001".to_owned()),
            quote: "BAA=".to_owned(),
            gpu_evidence: Vec::new(),
            certificate: CERTIFICATE.to_owned(),
            signature: Some(SIGNATURE.to_owned()),
            attested_body: Some(ATTESTED_BODY.to_owned()),
        }
    }

    #[test]
    fn a_row_signed_by_its_proxy_certificate_verifies() {
        let signed = verify_signed_row(&row(), NONCE).unwrap();
        assert_eq!(signed.quote, [4, 0]);
        let der = BASE64.decode(CERTIFICATE).unwrap();
        assert_eq!(signed.spki_sha256, tee_evidence::spki_sha256(&der).unwrap());
    }

    #[test]
    fn a_row_for_another_nonce_fails_closed() {
        let error = verify_signed_row(&row(), &NONCE.replace('0', "f")).unwrap_err();
        assert!(error.to_string().contains("nonce"), "{error:#}");
    }

    #[test]
    fn tampered_signature_body_or_quote_fails_closed() {
        let mut signature = row();
        signature.signature = Some(format!("A{}", &SIGNATURE[1..]));
        let mut body = row();
        body.attested_body = Some(format!("A{}", &ATTESTED_BODY[1..]));
        let mut quote = row();
        quote.quote = "BAE=".to_owned();
        let mut unsigned = row();
        unsigned.signature = None;
        for tampered in [signature, body, quote, unsigned] {
            assert!(verify_signed_row(&tampered, NONCE).is_err());
        }
    }

    #[test]
    fn report_data_must_bind_nonce_key_and_evidence_certificate_key() {
        let instance = Instance::new();
        let binding = key_binding(NONCE, &instance.public_b64);
        let spki = [7_u8; 32];
        let mut report_data = [0_u8; 64];
        report_data[..32].copy_from_slice(&binding);
        report_data[32..].copy_from_slice(&spki);
        check_report_data(&report_data, &binding, &spki).unwrap();

        let wrong_nonce = key_binding(&NONCE.replace('1', "2"), &instance.public_b64);
        let error = check_report_data(&report_data, &wrong_nonce, &spki).unwrap_err();
        assert!(error.to_string().contains("nonce"), "{error:#}");

        let swapped_key = key_binding(NONCE, &Instance::new().public_b64);
        assert!(check_report_data(&report_data, &swapped_key, &spki).is_err());

        let error = check_report_data(&report_data, &binding, &[8_u8; 32]).unwrap_err();
        assert!(error.to_string().contains("certificate"), "{error:#}");
    }

    #[test]
    fn key_binding_hashes_the_nonce_hex_then_the_key_text() {
        let expected: [u8; 32] = Sha256::digest(format!("{NONCE}KEY").as_bytes()).into();
        assert_eq!(key_binding(NONCE, "KEY"), expected);
    }

    #[test]
    fn discovery_rejects_repeats_bad_keys_and_bad_lifetimes() {
        let (first, second) = (Instance::new(), Instance::new());
        let entry = |id: &str, key: &str, nonces: &[&str]| serde_json::json!({"instance_id": id, "e2e_pubkey": key, "nonces": nonces});
        let body = |instances: Vec<Value>, lifetime: u64| {
            serde_json::json!({"instances": instances, "nonce_expires_in": lifetime}).to_string()
        };
        let a = |nonces: &[&str]| entry("a", &first.public_b64, nonces);
        let b = |nonces: &[&str]| entry("b", &second.public_b64, nonces);
        let good = body(vec![a(&["n1", "n2"]), b(&["n3"])], 60);
        assert_eq!(
            Discovery::parse(good.as_bytes()).unwrap().instances.len(),
            2
        );
        for bad in [
            body(vec![], 60),
            body(vec![a(&["n1"])], 0),
            body(vec![a(&["n1"])], 600),
            body(vec![entry("a", "AAAA", &["n1"])], 60),
            body(vec![a(&["n1"]), entry("b", &first.public_b64, &["n2"])], 60),
            body(vec![a(&["n1", "n1"])], 60),
            body(vec![a(&["n1"]), b(&["n1"])], 60),
        ] {
            assert!(Discovery::parse(bad.as_bytes()).is_err(), "{bad}");
        }
    }
}
