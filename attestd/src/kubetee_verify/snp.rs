//! Parse the gateway's native `CoCo` AMD evidence and verify its trust chain.
//! Intel DCAP parsing remains an entirely separate verifier arm.

use anyhow::{ensure, Context, Result};
use base64::Engine as _;
use serde_json::Value;
use sev::firmware::guest::AttestationReport;
use sev::firmware::host::CertTableEntry;
use sev::parser::ByteParser as _;

use super::policy::{self, AmdEndpoint, Kds};

/// The four supported wire states reduce to two standard `CoCo` objects:
/// a report-encoded hex/base64 string, or a `CoCo` structured report. The
/// gateway uses the latter; neither is ever a byte offset in an Intel quote.
pub(crate) fn report(evidence: &Value) -> Result<AttestationReport> {
    let report = evidence.get("attestation_report").unwrap_or(evidence);
    if let Some(report) = report.as_object() {
        if let Some(encoded) = report.get("attestation_report").and_then(Value::as_str) {
            let mut bytes = encoded.as_bytes();
            if bytes.starts_with(b"0x") {
                bytes = &bytes[2..];
            }
            let report = if encoded.len() == 2368 || encoded.starts_with("0x") {
                hex::decode(bytes).context("decode SNP report hex")?
            } else {
                base64::engine::general_purpose::STANDARD
                    .decode(bytes)
                    .context("decode SNP report base64")?
            };
            return AttestationReport::from_bytes(&report)
                .map_err(|error| anyhow::Error::from(error).context("decode raw SNP report"));
        }
        // CoCo serializes the combined CPU family as 25 (0x19) or 26 (0x1a),
        // exactly the wire byte the stock library expects. Deserialize its
        // JSON directly; never rewrite the evidence or its signed fields.
        return serde_json::from_value(Value::Object(report.clone()))
            .context("decode structured CoCo SNP report");
    }
    let raw = report
        .as_str()
        .context("SNP attestation_report must be CoCo structured JSON or raw hex/base64")?;
    let hex_string = raw.strip_prefix("0x").unwrap_or(raw);
    let bytes = if hex_string.len() == 2368 {
        hex::decode(hex_string).context("decode SNP report hex")?
    } else {
        base64::engine::general_purpose::STANDARD
            .decode(raw)
            .context("decode SNP report base64")?
    };
    AttestationReport::from_bytes(&bytes)
        .map_err(|error| anyhow::Error::from(error).context("decode raw SNP report"))
}

fn certificates(evidence: &Value) -> Result<Vec<CertTableEntry>> {
    match evidence.get("cert_chain") {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(certificates) => serde_json::from_value(certificates.clone())
            .context("parse native CoCo SNP certificate table"),
    }
}

async fn verify_with(
    endpoint: &impl AmdEndpoint,
    evidence: &Value,
    report_data: &[u8; 64],
) -> Result<AttestationReport> {
    verify_with_cache(endpoint, evidence, report_data, policy::shared_vcek_cache()).await
}

async fn verify_with_cache(
    endpoint: &impl AmdEndpoint,
    evidence: &Value,
    report_data: &[u8; 64],
    cache: &policy::VcekCache,
) -> Result<AttestationReport> {
    let report = report(evidence)?;
    ensure!(
        report.report_data == *report_data,
        "SNP signed report_data is not the v1 nonce/keyset binding"
    );
    ensure!(
        (3..=5).contains(&report.version),
        "unsupported SNP report version {}",
        report.version
    );
    let supplied_chain = policy::chain_from_table(&certificates(evidence)?)?;
    let signed_by = supplied_chain
        .as_ref()
        .map(super::policy::vek_kind)
        .transpose()?;
    if let Some(super::policy::VekKind::Vlek) = signed_by {
        anyhow::bail!(
            "VLEK requires AMD hashstick validation and is not accepted by this consumer"
        );
    }
    let vek = policy::verify_vek_with_cache(&report, endpoint, cache).await?;
    if let Some(chain) = supplied_chain {
        // Treat the whole CoCo table as supplied *data*. CoCo verifies its
        // path; this comparison prevents it substituting an endorsement key.
        ensure!(
            chain.to_der().map_err(anyhow::Error::from)?
                == vek.to_der().map_err(anyhow::Error::from)?,
            "supplied AMD endorsement key differs from the KDS binding for this report"
        );
    }
    Ok(report)
}

pub(crate) async fn verify(evidence: &Value, report_data: &[u8; 64]) -> Result<AttestationReport> {
    verify_with(&Kds, evidence, report_data).await
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::result_large_err,
        reason = "stock snp hardware verifier's API uses std::io::Error"
    )]
    #![expect(
        clippy::unwrap_used,
        reason = "CoCo fixture tests deliberately reject malformed local fixtures"
    )]
    use super::*;
    use sev::certs::snp::{builtin::milan, Certificate, Verifiable};
    use std::sync::atomic::{AtomicUsize, Ordering};

    const REPORT: &[u8] = include_bytes!("../../tests/fixtures/kubetee/snp/test-report.bin");
    const VCEK: &[u8] = include_bytes!("../../tests/fixtures/kubetee/snp/test-vcek.der");

    fn evidence() -> Value {
        let report = AttestationReport::from_bytes(REPORT).unwrap();
        serde_json::json!({ "schema": "kubetee.snp-evidence/1", "attestation_report": report, "cert_chain": [{"cert_type":"VCEK","data":VCEK}] })
    }
    #[test]
    fn native_structured_report_and_certificate_table_round_trip() {
        let report = report(&evidence()).unwrap();
        assert_eq!(
            report.measurement,
            AttestationReport::from_bytes(REPORT).unwrap().measurement
        );
        let certs = policy::chain_from_table(&certificates(&evidence()).unwrap())
            .unwrap()
            .unwrap();
        let ca = sev::certs::snp::ca::Chain {
            ark: Certificate::from_pem(milan::ARK).unwrap(),
            ask: Certificate::from_pem(milan::ASK).unwrap(),
        };
        let vek = sev::certs::snp::Chain { ca, vek: certs };
        (&vek).verify().unwrap();
        policy::verify_report_chain(&vek, &report).unwrap();
        let mut tampered = report;
        tampered.measurement[0] ^= 1;
        assert!(policy::verify_report_chain(&vek, &tampered).is_err());
    }
    #[test]
    fn a_signed_report_is_not_literal_trust_without_release_approval() {
        let raw = include_bytes!("../../tests/fixtures/kubetee/coco-snp-evidence.json");
        let value: Value = serde_json::from_slice(raw).unwrap();
        let report = report(&value).unwrap();
        let cert = policy::chain_from_table(&certificates(&value).unwrap())
            .unwrap()
            .unwrap();
        let ca = sev::certs::snp::ca::Chain {
            ark: Certificate::from_pem(sev::certs::snp::builtin::genoa::ARK).unwrap(),
            ask: Certificate::from_pem(sev::certs::snp::builtin::genoa::ASK).unwrap(),
        };
        (&ca).verify().unwrap();
        (&cert, &report).verify().unwrap();
        let chain = sev::certs::snp::Chain { ca, vek: cert };
        policy::verify_report_chain(&chain, &report).unwrap();
        assert!(policy::accept(&report).is_err());
        // Real authenticated evidence does not imply release admission.
        // A signature-relevant mutation must fail the stock cryptographic check.
        let mut tampered = report;
        tampered.measurement[0] ^= 1;
        assert!(policy::verify_report_chain(&chain, &tampered).is_err());
    }

    #[test]
    fn a_v2_fixture_never_gets_accepted_as_current_snp_hardware_proof() {
        let error = runtime()
            .block_on(verify_with(
                &RejectAnyRequest,
                &evidence(),
                &AttestationReport::from_bytes(REPORT).unwrap().report_data,
            ))
            .unwrap_err();
        assert!(format!("{error:#}").contains("unsupported SNP report version 2"));
    }
    #[test]
    fn vlek_is_rejected_before_unsupported_hardware_lookup() {
        let raw = include_bytes!("../../tests/fixtures/kubetee/snp/test-vlek-report.bin");
        let raw_vcek = include_bytes!("../../tests/fixtures/kubetee/snp/test-vlek.der");
        let report = AttestationReport::from_bytes(raw).unwrap();
        let evidence = serde_json::json!({"attestation_report":report, "cert_chain":[{"cert_type":"VLEK", "data":raw_vcek.as_slice()}]});
        let error = runtime()
            .block_on(verify_with(
                &RejectAnyRequest,
                &evidence,
                &report.report_data,
            ))
            .unwrap_err();
        assert!(format!("{error:#}").contains("VLEK"), "{error:#}");
    }
    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .unwrap()
    }
    #[test]
    fn a_different_signed_statement_fails_before_kds_access() {
        let error = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .unwrap()
            .block_on(verify_with(&RejectAnyRequest, &evidence(), &[0; 64]))
            .unwrap_err();
        assert!(format!("{error:#}").contains("nonce/keyset"));
    }
    #[test]
    fn native_kds_response_verify_report_and_pin_requested_cpu_tcb() {
        struct PinCpuTcb {
            report: AttestationReport,
            vcek: Vec<u8>,
        }
        impl AmdEndpoint for PinCpuTcb {
            fn fetch(
                &self,
                url: url::Url,
            ) -> impl std::future::Future<Output = Result<Vec<u8>>> + Send {
                let report = self.report;
                let tcb = report.reported_tcb;
                assert_eq!(url.scheme(), "https");
                assert_eq!(url.host_str(), Some("kdsintf.amd.com"));
                assert_eq!(
                    url.path(),
                    format!("/vcek/v1/Genoa/{}", hex::encode(report.chip_id))
                );
                let query: std::collections::HashMap<_, _> =
                    url.query_pairs().into_owned().collect();
                assert_eq!(query.len(), 4);
                assert_eq!(query["blSPL"], tcb.bootloader.to_string());
                assert_eq!(query["teeSPL"], tcb.tee.to_string());
                assert_eq!(query["snpSPL"], tcb.snp.to_string());
                assert_eq!(query["ucodeSPL"], tcb.microcode.to_string());
                std::future::ready(Ok(self.vcek.clone()))
            }
        }
        let evidence: Value = serde_json::from_slice(include_bytes!(
            "../../tests/fixtures/kubetee/coco-snp-evidence.json"
        ))
        .unwrap();
        let report = report(&evidence).unwrap();
        assert_eq!(report.version, 3);
        let vcek = certificates(&evidence).unwrap().remove(0).data;
        let endpoint = PinCpuTcb { report, vcek };
        let cache = policy::VcekCache::default();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .unwrap();
        let verified = runtime
            .block_on(verify_with_cache(
                &endpoint,
                &evidence,
                &report.report_data,
                &cache,
            ))
            .unwrap();
        assert_eq!(verified.version, 3);
        assert_eq!(verified.reported_tcb, report.reported_tcb);
    }

    #[test]
    fn a_cached_vcek_does_not_cache_report_signature_verification() {
        struct CountedVcek {
            calls: std::sync::Arc<AtomicUsize>,
            certificate: Vec<u8>,
        }
        impl AmdEndpoint for CountedVcek {
            fn fetch(
                &self,
                _url: url::Url,
            ) -> impl std::future::Future<Output = Result<Vec<u8>>> + Send {
                self.calls.fetch_add(1, Ordering::SeqCst);
                std::future::ready(Ok(self.certificate.clone()))
            }
        }

        let mut evidence: Value = serde_json::from_slice(include_bytes!(
            "../../tests/fixtures/kubetee/coco-snp-evidence.json"
        ))
        .unwrap();
        let original_report = report(&evidence).unwrap();
        let certificate = certificates(&evidence).unwrap().remove(0).data;
        let calls = std::sync::Arc::new(AtomicUsize::new(0));
        let endpoint = CountedVcek {
            calls: std::sync::Arc::clone(&calls),
            certificate,
        };
        let cache = policy::VcekCache::default();
        let runtime = runtime();
        runtime
            .block_on(verify_with_cache(
                &endpoint,
                &evidence,
                &original_report.report_data,
                &cache,
            ))
            .unwrap();

        let byte = u8::try_from(
            evidence["attestation_report"]["report_data"][0]
                .as_u64()
                .unwrap(),
        )
        .unwrap();
        evidence["attestation_report"]["report_data"][0] = Value::from(byte ^ 1);
        let tampered_report = report(&evidence).unwrap();
        let error = runtime
            .block_on(verify_with_cache(
                &endpoint,
                &evidence,
                &tampered_report.report_data,
                &cache,
            ))
            .unwrap_err();
        assert!(format!("{error:#}").contains("signature"), "{error:#}");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn coco_v3_fixture_cryptographic_chain_result_is_tested_not_assumed() {
        let mut evidence: Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/kubetee/coco-snp-evidence.json"
        ))
        .unwrap();
        if let Some(object) = evidence.as_object_mut() {
            object.insert(
                "schema".into(),
                Value::String("kubetee.snp-evidence/1".into()),
            );
        }
        let full = &evidence;
        let report = report(full).unwrap();
        assert_eq!(report.version, 3);
        assert_eq!(
            policy::Generation::of(&report).unwrap().to_string(),
            "Genoa"
        );
        let cert = policy::chain_from_table(&certificates(full).unwrap())
            .unwrap()
            .unwrap();
        let ca = sev::certs::snp::ca::Chain {
            ark: Certificate::from_pem(sev::certs::snp::builtin::genoa::ARK).unwrap(),
            ask: Certificate::from_pem(sev::certs::snp::builtin::genoa::ASK).unwrap(),
        };
        let report_result = (&cert, &report).verify();
        let chain = sev::certs::snp::Chain { ca, vek: cert };
        let chain_result = (&chain).verify();
        assert!(
            report_result.is_ok() && chain_result.is_ok(),
            "public CoCo fixture chain failed: {report_result:?} / {chain_result:?}"
        );
        assert!(
            policy::accept(&report).is_err(),
            "test evidence is not an approved release"
        );
    }
    #[test]
    fn snp_launch_digest_and_host_data_remain_distinct() {
        let report = AttestationReport::from_bytes(REPORT).unwrap();
        assert_eq!(report.measurement.len(), 48);
        assert_eq!(report.host_data.len(), 32);
    }
    #[test]
    fn a_malformed_legacy_recursive_encoding_is_not_guessed() {
        let malformed = serde_json::json!({ "attestation_report": {"to_python": {}} });
        assert!(report(&malformed).is_err());
    }
    #[test]
    fn an_unrelated_generation_uses_its_full_64_octet_genoa_lookup() {
        struct UnexpectedFetch {
            chip_id: String,
        }
        impl AmdEndpoint for UnexpectedFetch {
            fn fetch(
                &self,
                url: url::Url,
            ) -> impl std::future::Future<Output = Result<Vec<u8>>> + Send {
                std::future::ready((|| {
                    anyhow::ensure!(url.path() == format!("/vcek/v1/Genoa/{}", self.chip_id));
                    anyhow::bail!("test stops before the external KDS request")
                })())
            }
        }
        let raw = include_bytes!("../../tests/fixtures/kubetee/coco-snp-evidence.json");
        let value: Value = serde_json::from_slice(raw).unwrap();
        let report = report(&value).unwrap();
        assert_eq!(policy::Generation::Genoa.to_string(), "Genoa");
        assert!(matches!(
            policy::Generation::of(&report),
            Ok(policy::Generation::Genoa)
        ));
        let lookup = UnexpectedFetch {
            chip_id: hex::encode(report.chip_id),
        };
        let cache = policy::VcekCache::default();
        let error = runtime()
            .block_on(policy::verify_vek_with_cache(&report, &lookup, &cache))
            .unwrap_err();
        assert!(format!("{error:#}").contains("test stops"), "{error:#}");
    }

    struct RejectAnyRequest;
    impl AmdEndpoint for RejectAnyRequest {
        fn fetch(
            &self,
            url: url::Url,
        ) -> impl std::future::Future<Output = Result<Vec<u8>>> + Send {
            std::future::ready(Err(anyhow::anyhow!("unexpected AMD request {url}")))
        }
    }

    #[test]
    fn live_new_york_turin_release_chain_and_tcb_replay_offline() {
        use sha2::Digest as _;

        struct ActualTurinVcek;
        impl AmdEndpoint for ActualTurinVcek {
            fn fetch(
                &self,
                url: url::Url,
            ) -> impl std::future::Future<Output = Result<Vec<u8>>> + Send {
                assert_eq!(url.scheme(), "https");
                assert_eq!(url.host_str(), Some("kdsintf.amd.com"));
                assert_eq!(url.path(), "/vcek/v1/Turin/fb09b33adc81fc0c");
                let query: std::collections::HashMap<_, _> =
                    url.query_pairs().into_owned().collect();
                assert_eq!(query["blSPL"], "3");
                assert_eq!(query["teeSPL"], "2");
                assert_eq!(query["snpSPL"], "6");
                assert_eq!(query["ucodeSPL"], "98");
                assert_eq!(query["fmcSPL"], "1");
                std::future::ready(Ok(include_bytes!(
                    "../../tests/fixtures/kubetee/snp/production-turin-vcek.der"
                )
                .to_vec()))
            }
        }

        let raw = include_bytes!("../../tests/fixtures/kubetee/snp/production-turin-evidence.json");
        let payload: Value = serde_json::from_slice(raw).unwrap();
        let statement = payload["bindings"]["report_data_statement"]
            .as_str()
            .unwrap();
        let digest = sha2::Sha256::digest(statement.as_bytes());
        let mut bound = [0u8; 64];
        bound[..32].copy_from_slice(&digest);
        let report = runtime()
            .block_on(verify_with(
                &ActualTurinVcek,
                &payload["evidence"]["snp"],
                &bound,
            ))
            .unwrap();
        assert_eq!(
            hex::encode(report.measurement),
            "20f0e183b7844cc835118d804699ab8b6cdab297414d8f54d70331378ff0d7fdd8a7548a0253ba561bec21e13a0dcc67"
        );
        assert_eq!(
            hex::encode(report.host_data),
            "5bd1fe028a632b9efc6eceedcbf5a344b13ed1dab6c1b3a8295f0ff20aebe3aa"
        );
        assert_eq!(report.reported_tcb.bootloader, 3);
        assert_eq!(report.reported_tcb.snp, 6);
        assert_eq!(report.reported_tcb.microcode, 98);
        assert_eq!(report.reported_tcb.fmc, Some(1));
    }
}
