//! Evidence checks shared by the NEAR and Chutes upstream verifiers: fresh
//! nonces, TLS key hashing, Intel DCAP appraisal and NVIDIA NRAS verdicts.

pub mod nras;

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, ensure, Context, Result};
use dcap_qvl::collateral::CollateralClient;
use dcap_qvl::policy::{Policy as _, QuoteClaims};
use dcap_qvl::quote::{Report, TDReport10};
use dcap_qvl::tcb_info::TcbStatus;
use dcap_qvl::verify::QuoteVerifier;
use dcap_qvl::QuotePolicy;
use rand::Rng as _;
use sha2::{Digest as _, Sha256};
use x509_parser::parse_x509_certificate;

/// A fresh 32-byte attestation nonce from the thread-local CSPRNG.
#[must_use]
pub fn random_nonce() -> [u8; 32] {
    let mut nonce = [0_u8; 32];
    rand::rng().fill_bytes(&mut nonce);
    nonce
}

/// SHA-256 of a certificate's DER `SubjectPublicKeyInfo`.
///
/// # Errors
///
/// Returns an error when the certificate is not valid DER X.509.
pub fn spki_sha256(certificate_der: &[u8]) -> Result<[u8; 32]> {
    let (_, certificate) = parse_x509_certificate(certificate_der)
        .map_err(|error| anyhow::anyhow!("parse TLS certificate: {error}"))?;
    Ok(Sha256::digest(certificate.public_key().raw).into())
}

/// The Intel collateral client both verifiers fetch through: Phala's PCCS
/// unless `PCCS_URL` overrides it.
///
/// # Errors
///
/// Returns an error when the HTTP client cannot be built.
pub fn collateral_client() -> Result<CollateralClient> {
    CollateralClient::from_env().context("build DCAP collateral client")
}

/// The TD report body of a TDX quote.
///
/// # Errors
///
/// Returns an error for an SGX enclave report.
pub fn td_report(report: &Report) -> Result<&TDReport10> {
    match report {
        Report::TD10(td) => Ok(td),
        Report::TD15(td) => Ok(&td.base),
        Report::SgxEnclave(_) => bail!("attestation is SGX, expected TDX"),
    }
}

/// Fetch Intel collateral for `quote`, verify its signature chain and apply
/// [`appraise`].
///
/// # Errors
///
/// Returns an error when collateral cannot be fetched, the quote signature
/// chain fails, or the appraisal rejects the claims.
pub async fn verify_quote(collateral: &CollateralClient, quote: &[u8]) -> Result<QuoteClaims> {
    let bundle = collateral
        .fetch(quote)
        .await
        .context("fetch Intel DCAP collateral")?;
    let now = unix_now()?;
    let claims = QuoteVerifier::new_prod()
        .verify_with_policy(quote, bundle, now, &QuotePolicy::claims_only(now))
        .context("verify TDX quote signature chain")?;
    appraise(&claims, now)?;
    Ok(claims)
}

/// Appraise verified quote claims: merged, platform and QE TCB all
/// `UpToDate`, collateral unexpired, TDX rather than SGX, and the TD debug
/// attribute clear.
///
/// The PCK platform flags (dynamic platform, cached keys, SMT) are accepted:
/// multi-socket GPU servers are dynamic platforms, and so is the genuine
/// sample quote in the test fixtures.
///
/// # Errors
///
/// Returns an error naming the first check that fails.
pub fn appraise(claims: &QuoteClaims, now: u64) -> Result<&TDReport10> {
    QuotePolicy::strict(now)
        .allow_dynamic_platform(true)
        .allow_cached_keys(true)
        .allow_smt(true)
        .validate(claims)
        .context("TDX quote fails the UpToDate DCAP policy")?;
    ensure!(
        claims.platform.tcb_level.tcb_status == TcbStatus::UpToDate,
        "TDX platform TCB status is {:?}, expected UpToDate",
        claims.platform.tcb_level.tcb_status
    );
    ensure!(
        claims.qe.tcb_level.tcb_status == TcbStatus::UpToDate,
        "TDX QE TCB status is {:?}, expected UpToDate",
        claims.qe.tcb_level.tcb_status
    );
    let td = td_report(&claims.report)?;
    ensure!(
        td.td_attributes[0] & 1 == 0,
        "TDX quote has the debug attribute set"
    );
    Ok(td)
}

/// Seconds since the Unix epoch.
///
/// # Errors
///
/// Returns an error when the system clock predates the epoch.
pub fn unix_now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock predates the Unix epoch")?
        .as_secs())
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "fixture decoding fails the test")]
mod tests {
    use super::*;
    use dcap_qvl::policy::PckCertFlag;

    const FIXTURE_NOW: u64 = 1_751_000_000;

    fn fixture_claims() -> QuoteClaims {
        let quote = include_bytes!("../tests/fixtures/dcap/tdx_quote");
        let collateral: dcap_qvl::QuoteCollateralV3 = serde_json::from_slice(include_bytes!(
            "../tests/fixtures/dcap/tdx_quote_collateral.json"
        ))
        .unwrap();
        QuoteVerifier::new_prod()
            .verify_with_policy(
                quote,
                collateral,
                FIXTURE_NOW,
                &QuotePolicy::claims_only(FIXTURE_NOW),
            )
            .unwrap()
    }

    fn td_mut(claims: &mut QuoteClaims) -> &mut TDReport10 {
        match &mut claims.report {
            Report::TD10(td) => td,
            Report::TD15(td) => &mut td.base,
            Report::SgxEnclave(_) => unreachable!("fixture is a TDX quote"),
        }
    }

    #[test]
    fn genuine_up_to_date_quote_passes_the_appraisal() {
        let claims = fixture_claims();
        assert_eq!(claims.platform.pck.dynamic_platform, PckCertFlag::True);
        appraise(&claims, FIXTURE_NOW).unwrap();
    }

    #[test]
    fn tcb_below_up_to_date_fails_closed() {
        for status in [
            TcbStatus::SWHardeningNeeded,
            TcbStatus::OutOfDate,
            TcbStatus::Revoked,
        ] {
            let mut merged = fixture_claims();
            merged.tcb.status = status;
            assert!(appraise(&merged, FIXTURE_NOW).is_err(), "merged {status:?}");

            let mut platform = fixture_claims();
            platform.platform.tcb_level.tcb_status = status;
            let error = appraise(&platform, FIXTURE_NOW).unwrap_err();
            assert!(
                format!("{error:#}").contains("TCB"),
                "platform {status:?}: {error:#}"
            );

            let mut qe = fixture_claims();
            qe.qe.tcb_level.tcb_status = status;
            assert!(appraise(&qe, FIXTURE_NOW).is_err(), "QE {status:?}");
        }
    }

    #[test]
    fn debug_td_fails_closed() {
        let mut claims = fixture_claims();
        td_mut(&mut claims).td_attributes[0] |= 1;
        let error = appraise(&claims, FIXTURE_NOW).unwrap_err();
        assert!(error.to_string().contains("debug"), "{error:#}");
    }

    #[test]
    fn expired_collateral_fails_closed() {
        let claims = fixture_claims();
        let error = appraise(&claims, claims.earliest_expiration_date + 1).unwrap_err();
        assert!(format!("{error:#}").contains("expired"), "{error:#}");
    }

    #[test]
    fn tampered_signed_collateral_is_rejected_by_the_signature_chain() {
        let quote = include_bytes!("../tests/fixtures/dcap/tdx_quote");
        let mut collateral: dcap_qvl::QuoteCollateralV3 = serde_json::from_slice(include_bytes!(
            "../tests/fixtures/dcap/tdx_quote_collateral.json"
        ))
        .unwrap();
        collateral.tcb_info = collateral.tcb_info.replacen("\"TDX\"", "\"SGX\"", 1);
        let result = QuoteVerifier::new_prod().verify_with_policy(
            quote,
            collateral,
            FIXTURE_NOW,
            &QuotePolicy::claims_only(FIXTURE_NOW),
        );
        assert!(result.is_err());
    }

    #[test]
    fn spki_hash_rejects_non_certificates() {
        assert!(spki_sha256(b"not a certificate").is_err());
    }

    #[test]
    fn nonces_are_fresh() {
        assert_ne!(random_nonce(), random_nonce());
    }
}
