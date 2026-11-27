//! AMD SEV-SNP evidence checks for the `kubetee.attestation.v2` gateway.
//!
//! The `kubetee` gateway runs on AMD SEV-SNP (`kata-qemu-snp-runtime-rs`), so
//! its `/v1/attestation` response carries SNP evidence in `evidence.snp`
//! (`raw_report`, `cert_chain`) rather than an Intel TDX `quote`. This module
//! appraises that evidence:
//!
//!   1. **Parse** `evidence.snp.raw_report` (the exact 1184-byte AMD-signed
//!      report) with `sev`'s `AttestationReport::from_bytes` — the signed bytes
//!      are verified directly (no JSON reconstruction, so the `to_bytes` layout
//!      footgun is avoided).
//!   2. **AMD chain + root pin** — ARK→ASK→VCEK built from `cert_chain`, each
//!      chain leg verified *and the ARK pinned to a known AMD root of trust*
//!      (Milan/Genoa/Turin from `sev::certs::snp::builtin`). Without the pin a
//!      forged self-signed chain would verify; the pin is what makes the chain
//!      genuinely traceable to AMD.
//!   3. **Report signature** — the report's ECDSA P-384/SHA-384 signature over
//!      `to_bytes()[..0x2a0]`, checked against the root-anchored VCEK.
//!   4. **Policy + identity** — the guest policy debug bit is clear, and the
//!      measured registers (`measurement`, `host_data`) are read from the signed
//!      report for the caller to match against its expected reference.
//!
//! Every check fails closed: a mismatch, a malformed field, or an absent
//! expected value is an error, never a pass. Field offsets follow the AMD
//! SEV-SNP ABI report layout and are cross-checked against
//! `evidence.quote_report_data` (which must equal the report's `report_data`).

use anyhow::{ensure, Context, Result};
use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine as _;
use sev::certs::snp::{builtin, Certificate, Chain, Verifiable};
use sev::firmware::guest::AttestationReport;
use sev::parser::ByteParser;

/// AMD SEV-SNP ABI report layout offsets (the fields this verifier reads).
///
/// The report is a 1184-byte little-endian structure. These offsets are the
/// canonical AMD ABI (`ATTESTATION_REPORT`); `report_data` is 64 bytes at
/// `0x0050`, the launch digest `measurement` 48 bytes at `0x0090`, and
/// `host_data` (the Kata init-data digest) 32 bytes at `0x00C0`.
const REPORT_LEN: usize = 1184;
const POLICY: std::ops::Range<usize> = 0x0008..0x0010;
const REPORT_DATA: std::ops::Range<usize> = 0x0050..0x0090;
const MEASUREMENT: std::ops::Range<usize> = 0x0090..0x00C0;
const HOST_DATA: std::ops::Range<usize> = 0x00C0..0x00E0;

/// `SNP_GUEST_POLICY` DEBUG bit — a debuggable guest is never trusted.
const POLICY_DEBUG_BIT: u64 = 1 << 3;

/// The measured registers of the SNP guest that produced a report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnpMeasurements {
    /// The 64-byte `report_data` the AMD report committed (the v2 binding).
    pub report_data: [u8; 64],
    /// The guest launch digest (`MEASUREMENT`, 48 bytes).
    pub measurement: [u8; 48],
    /// The Kata init-data digest (`HOST_DATA`, 32 bytes).
    pub host_data: [u8; 32],
    /// The raw `SNP_GUEST_POLICY` (debug + ABI flags).
    pub policy: u64,
}

/// One `evidence.snp.cert_chain[]` entry (`{cert_type, data:[bytes]}`, raw DER).
#[derive(Clone, Debug)]
pub struct CertEntry {
    pub cert_type: String,
    pub der: Vec<u8>,
}

/// The SNP evidence node of a `kubetee.attestation.v2` response.
#[derive(Clone, Debug)]
pub struct SnpEvidence {
    /// The exact 1184-byte AMD-signed report (`evidence.snp.raw_report`).
    pub raw_report: Vec<u8>,
    /// The `cert_chain` VCEK/ASK/ARK entries (raw DER).
    pub cert_chain: Vec<CertEntry>,
}

fn decode_b64(value: &str) -> Result<Vec<u8>> {
    // Live captures wrap long values with interior whitespace; strip it, then
    // accept padded/unpadded base64url or standard base64.
    let cleaned: String = value.chars().filter(|c| !c.is_whitespace()).collect();
    URL_SAFE_NO_PAD
        .decode(cleaned.trim_end_matches('='))
        .or_else(|_| URL_SAFE.decode(&cleaned))
        .or_else(|_| STANDARD.decode(&cleaned))
        .context("bad base64")
}

fn cert_entry(node: &serde_json::Value) -> Result<CertEntry> {
    let cert_type = node
        .get("cert_type")
        .and_then(|v| v.as_str())
        .context("snp cert_chain entry has no cert_type")?
        .to_string();
    let data = node
        .get("data")
        .and_then(|v| v.as_array())
        .context("snp cert_chain entry has no data bytes")?;
    let mut der = Vec::with_capacity(data.len());
    for (i, b) in data.iter().enumerate() {
        der.push(
            b.as_u64()
                .and_then(|n| u8::try_from(n).ok())
                .with_context(|| format!("snp cert_chain data[{i}] is not a byte"))?,
        );
    }
    ensure!(!der.is_empty(), "snp cert_chain entry {cert_type} is empty");
    Ok(CertEntry { cert_type, der })
}

/// Parse the `evidence.snp` node of a response into [`SnpEvidence`], failing
/// closed on a missing or malformed `raw_report` / `cert_chain`.
pub fn parse_snp(node: &serde_json::Value) -> Result<SnpEvidence> {
    let raw_report = node
        .get("raw_report")
        .and_then(|v| v.as_str())
        .context("evidence.snp.raw_report missing")?;
    let raw_report = decode_b64(raw_report).context("decode evidence.snp.raw_report")?;
    ensure!(
        raw_report.len() == REPORT_LEN,
        "evidence.snp.raw_report is {} bytes, expected {REPORT_LEN}",
        raw_report.len()
    );
    let chain_node = node
        .get("cert_chain")
        .and_then(|v| v.as_array())
        .context("evidence.snp.cert_chain missing")?;
    let cert_chain = chain_node
        .iter()
        .map(cert_entry)
        .collect::<Result<Vec<_>>>()
        .context("parse evidence.snp.cert_chain")?;
    Ok(SnpEvidence {
        raw_report,
        cert_chain,
    })
}

/// Build the ARK→ASK→VCEK chain from `cert_chain` (VCEK/ASK/ARK raw-DER
/// entries), and **pin the ARK to a known AMD root** before verifying the chain
/// signatures. Fails closed if any leg is absent or the root is not AMD's.
fn verify_anchored_chain(cert_chain: &[CertEntry]) -> Result<Chain> {
    let find = |kind: &str| -> Result<Certificate> {
        let mut matches = cert_chain
            .iter()
            .filter(|e| e.cert_type.trim().eq_ignore_ascii_case(kind));
        let entry = matches
            .next()
            .with_context(|| format!("snp cert_chain has no {kind}"))?;
        ensure!(
            matches.next().is_none(),
            "snp cert_chain has more than one {kind}"
        );
        Certificate::from_der(&entry.der).map_err(|e| anyhow::anyhow!("parse {kind}: {e}"))
    };
    let (ark, ask, vcek) = (find("ARK")?, find("ASK")?, find("VCEK")?);

    // Root pin: the served ARK must be a known AMD root (Milan/Genoa/Turin).
    // `Chain::verify` alone only proves self-consistency — a forged self-signed
    // ARK would pass it. This pin is the actual root of trust.
    let served_ark_der = ark
        .to_der()
        .map_err(|e| anyhow::anyhow!("served ARK DER: {e}"))?;
    let roots: [(&str, &[u8]); 3] = [
        ("Milan", builtin::milan::ARK),
        ("Genoa", builtin::genoa::ARK),
        ("Turin", builtin::turin::ARK),
    ];
    let anchored = roots.iter().any(|(_, pem)| {
        Certificate::from_pem(pem)
            .and_then(|root| root.to_der())
            .map(|root_der| root_der == served_ark_der)
            .unwrap_or(false)
    });
    ensure!(
        anchored,
        "SNP ARK is not a known AMD root (Milan/Genoa/Turin) — refusing to trust a foreign root"
    );

    let chain = Chain::from((&ask, &ark, &vcek));
    chain
        .verify()
        .map_err(|_| anyhow::anyhow!("SNP certificate chain does NOT verify (ARK->ASK->VCEK)"))?;
    Ok(chain)
}

/// Full SNP appraisal of `evidence`: parse the AMD-signed `raw_report`, verify
/// the root-anchored chain and report signature, reject a debug guest, and
/// cross-check the committed `report_data` against `quote_report_data`. Returns
/// the measured registers for the caller to match against its reference.
///
/// `quote_report_data` is the `evidence.quote_report_data` field (base64, 64
/// bytes) — when present it must equal the report's `report_data` (anti-swap).
pub fn verify_snp(
    evidence: &SnpEvidence,
    quote_report_data: Option<&str>,
) -> Result<SnpMeasurements> {
    let bytes = evidence.raw_report.as_slice();
    // Parse + verify the signed bytes directly (the report the AMD VCEK signed).
    let report: AttestationReport =
        ByteParser::from_bytes(bytes).map_err(|e| anyhow::anyhow!("parse SNP raw_report: {e}"))?;
    let chain = verify_anchored_chain(&evidence.cert_chain)?;
    // Report signature over to_bytes()[..0x2a0] via the root-anchored VCEK.
    (&chain, &report)
        .verify()
        .map_err(|_| anyhow::anyhow!("SNP report signature does NOT verify against the VCEK"))?;

    // Measured registers + policy straight from the signed ABI layout.
    let mut report_data = [0u8; 64];
    report_data.copy_from_slice(&bytes[REPORT_DATA]);
    let mut measurement = [0u8; 48];
    measurement.copy_from_slice(&bytes[MEASUREMENT]);
    let mut host_data = [0u8; 32];
    host_data.copy_from_slice(&bytes[HOST_DATA]);
    let policy = u64::from_le_bytes(
        bytes[POLICY]
            .try_into()
            .context("SNP policy field is not 8 bytes")?,
    );
    ensure!(
        policy & POLICY_DEBUG_BIT == 0,
        "SNP report has the DEBUG policy bit set (policy {policy:#x})"
    );

    // Cross-check: the committed report_data must equal evidence.quote_report_data.
    if let Some(qrd) = quote_report_data {
        let qrd = decode_b64(qrd).context("decode evidence.quote_report_data")?;
        ensure!(
            qrd.as_slice() == &report_data[..],
            "SNP report_data does not match evidence.quote_report_data"
        );
    }

    Ok(SnpMeasurements {
        report_data,
        measurement,
        host_data,
        policy,
    })
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "test fixtures intentionally fail hard on malformed local values"
    )]

    use super::*;

    #[test]
    fn the_policy_debug_bit_is_the_abi_bit_3() {
        assert_eq!(POLICY_DEBUG_BIT, 0b1000);
    }

    #[test]
    fn decode_b64_accepts_wrapped_urlsafe_and_standard() {
        let raw = [7u8; 32];
        for encode in [
            STANDARD.encode(raw),
            URL_SAFE_NO_PAD.encode(raw),
            format!(
                "{}\n{}\n",
                &STANDARD.encode(raw)[..16],
                &STANDARD.encode(raw)[16..]
            ),
        ] {
            assert_eq!(decode_b64(&encode).unwrap(), raw);
        }
    }

    #[test]
    fn a_malformed_snp_node_fails_closed() {
        let empty = serde_json::json!({});
        assert!(parse_snp(&empty).is_err());
        let short = serde_json::json!({"raw_report": STANDARD.encode([0u8; 10]), "cert_chain": []});
        assert!(parse_snp(&short).is_err(), "short raw_report must fail");
    }
}
