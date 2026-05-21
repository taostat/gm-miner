//! Attestation evidence provider.
//!
//! [`AttestationProvider`] is the seam between the `GET /attestation/info`
//! request handler and the dstack guest agent. The production
//! implementation, [`DstackAttestationProvider`], calls
//! `DstackClient::info()` once at startup to cache the static per-CVM
//! fields (`app_id`, `compose_hash`, `os_image_hash`, `instance_id`),
//! then asks the guest agent for a fresh quote bound to a caller nonce
//! on every request.
//!
//! The wire struct [`AttestationInfo`] matches the gm gateway's
//! `gateway/src/attestation/provider.rs` so the registry's single
//! attestation checker handles both services. In particular the pubkey
//! field is named `gateway_pubkey` on the wire: the registry's miner
//! checker reads `payload["gateway_pubkey"]` verbatim.

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use chrono::{DateTime, Utc};
use dstack_sdk::dstack_client::DstackClient;
use thiserror::Error;

use crate::keypair::SigningKeypair;
use crate::report_data::compute_report_data;

/// Wire-shaped attestation evidence. Serialized as the
/// `GET /attestation/info` response body. Field shape matches
/// `gm/docs/contracts/gateway-attestation-info.md`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AttestationInfo {
    pub schema_version: String,
    /// The miner's identity slug. Named `gateway_id` on the wire so the
    /// response shares the gateway's `AttestationInfo` shape.
    pub gateway_id: String,
    /// The miner attestation keypair's public key, base64. The registry
    /// reads this exact field name; it is the key bound into the
    /// quote's `report_data`.
    pub gateway_pubkey: String,
    pub tee_platform: String,
    pub app_id: String,
    pub compose_hash: String,
    pub os_image_hash: String,
    pub instance_id: String,
    pub tcb_info: TcbInfoWire,
    pub quote: String,
    pub report_data: String,
    pub nonce: String,
    pub issued_at: DateTime<Utc>,
}

/// Wire shape of the `tcb_info` object inside [`AttestationInfo`].
#[derive(Debug, Clone, serde::Serialize)]
pub struct TcbInfoWire {
    pub status: TcbStatus,
    pub tcb_date: DateTime<Utc>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub advisory_ids: Vec<String>,
}

/// TCB status enum. Only `UpToDate` is acceptable to the registry; the
/// other variants are surfaced so an operator can see a host needs
/// patching. The registry's `dcap-qvl` verification is what decides the
/// real TCB status from the quote's collateral — this field is
/// informational on the response.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub enum TcbStatus {
    UpToDate,
    #[serde(rename = "SWHardeningNeeded")]
    SwHardeningNeeded,
    ConfigurationNeeded,
    #[serde(rename = "ConfigurationAndSWHardeningNeeded")]
    ConfigurationAndSwHardeningNeeded,
    OutOfDate,
    OutOfDateConfigurationNeeded,
    Revoked,
}

/// Errors emitted by the attestation path.
#[derive(Debug, Error)]
pub enum AttestationError {
    #[error("dstack get_quote failed: {0}")]
    DstackQuote(String),
    #[error("dstack get_key failed: {0}")]
    DstackKey(String),
    #[error("dstack info failed: {0}")]
    DstackInfo(String),
}

/// The attestation provider trait. Implementations are `Send + Sync`
/// because the axum app state holds an `Arc<dyn AttestationProvider>`
/// shared across concurrent requests.
#[async_trait]
pub trait AttestationProvider: Send + Sync {
    /// Build the full [`AttestationInfo`] bound to `nonce`:
    ///
    /// 1. Compute `report_data = SHA-512(pubkey || nonce)`.
    /// 2. Ask dstack for a fresh quote with that `report_data`.
    /// 3. Stamp `issued_at = Utc::now()`.
    ///
    /// `nonce` is the raw bytes — the handler base64-decodes the wire
    /// `?nonce=...` first. The returned `nonce` field is the base64 echo.
    ///
    /// # Errors
    ///
    /// Returns an [`AttestationError`] when the dstack guest agent
    /// cannot produce a quote (unreachable, error response, or a quote
    /// that does not decode as hex).
    async fn build_info(&self, nonce: &[u8]) -> Result<AttestationInfo, AttestationError>;
}

/// Production provider: calls the dstack guest agent for each quote.
pub struct DstackAttestationProvider {
    miner_id: String,
    keypair: SigningKeypair,
    /// Cached per-CVM static fields, fetched once at startup via
    /// `DstackClient::info()`.
    static_info: StaticAttestationFields,
    /// Path to the dstack socket. `None` means the default
    /// `/var/run/dstack.sock`; tests inject a simulator endpoint.
    dstack_socket: Option<String>,
}

#[derive(Debug, Clone)]
struct StaticAttestationFields {
    app_id: String,
    compose_hash: String,
    os_image_hash: String,
    instance_id: String,
}

impl DstackAttestationProvider {
    /// Boot the provider by fetching the dstack `info()` snapshot once.
    /// Subsequent `build_info` calls reuse this snapshot and only hit
    /// the quote endpoint per request.
    ///
    /// # Errors
    ///
    /// Returns [`AttestationError::DstackInfo`] when the dstack guest
    /// agent is unreachable or its `info()` call fails.
    pub async fn bootstrap(
        miner_id: String,
        keypair: SigningKeypair,
        dstack_socket: Option<String>,
    ) -> Result<Self, AttestationError> {
        let client = DstackClient::new(dstack_socket.as_deref());
        let info = client
            .info()
            .await
            .map_err(|e| AttestationError::DstackInfo(e.to_string()))?;
        // os_image_hash is empty when the OS image is not measured by
        // the KMS; the InfoResponse carries it on the top level and the
        // tcb_info both — prefer the top-level field, fall back to
        // tcb_info so a non-empty value is always used when present.
        let os_image_hash = if info.os_image_hash.is_empty() {
            info.tcb_info.os_image_hash.clone()
        } else {
            info.os_image_hash.clone()
        };
        let static_info = StaticAttestationFields {
            app_id: info.app_id,
            compose_hash: info.compose_hash,
            os_image_hash,
            instance_id: info.instance_id,
        };
        Ok(Self {
            miner_id,
            keypair,
            static_info,
            dstack_socket,
        })
    }
}

#[async_trait]
impl AttestationProvider for DstackAttestationProvider {
    async fn build_info(&self, nonce: &[u8]) -> Result<AttestationInfo, AttestationError> {
        let pubkey_bytes = self.keypair.public_bytes();
        let report_data = compute_report_data(&pubkey_bytes, nonce);
        let client = DstackClient::new(self.dstack_socket.as_deref());
        let quote = client
            .get_quote(report_data.to_vec())
            .await
            .map_err(|e| AttestationError::DstackQuote(e.to_string()))?;
        let quote_bytes = quote
            .decode_quote()
            .map_err(|e| AttestationError::DstackQuote(format!("decode hex quote: {e}")))?;
        Ok(AttestationInfo {
            schema_version: "1".to_owned(),
            gateway_id: self.miner_id.clone(),
            gateway_pubkey: self.keypair.public_b64(),
            tee_platform: "intel-tdx".to_owned(),
            app_id: self.static_info.app_id.clone(),
            compose_hash: self.static_info.compose_hash.clone(),
            os_image_hash: self.static_info.os_image_hash.clone(),
            instance_id: self.static_info.instance_id.clone(),
            // The registry decides the real TCB status from the quote's
            // collateral via dcap-qvl; this field is an informational
            // echo. Report `UpToDate` — a stale host surfaces as a
            // verification failure on the registry side regardless.
            tcb_info: TcbInfoWire {
                status: TcbStatus::UpToDate,
                tcb_date: Utc::now(),
                advisory_ids: Vec::new(),
            },
            quote: BASE64_STANDARD.encode(&quote_bytes),
            report_data: BASE64_STANDARD.encode(report_data),
            nonce: BASE64_STANDARD.encode(nonce),
            issued_at: Utc::now(),
        })
    }
}

#[cfg(test)]
pub(crate) mod testing {
    //! A deterministic provider for handler tests. Returns a synthetic
    //! quote so the wire shape and the `report_data` binding can be
    //! exercised without a TDX socket. Never used on a deployed miner.
    use super::{
        async_trait, AttestationError, AttestationInfo, AttestationProvider, TcbInfoWire,
        TcbStatus, Utc, BASE64_STANDARD,
    };
    use crate::keypair::SigningKeypair;
    use crate::report_data::compute_report_data;
    use base64::Engine;

    pub(crate) struct DeterministicProvider {
        miner_id: String,
        keypair: SigningKeypair,
    }

    impl DeterministicProvider {
        pub(crate) fn new(miner_id: &str) -> Self {
            Self {
                miner_id: miner_id.to_owned(),
                keypair: SigningKeypair::deterministic(miner_id),
            }
        }
    }

    #[async_trait]
    impl AttestationProvider for DeterministicProvider {
        async fn build_info(&self, nonce: &[u8]) -> Result<AttestationInfo, AttestationError> {
            let pubkey_bytes = self.keypair.public_bytes();
            let report_data = compute_report_data(&pubkey_bytes, nonce);
            let mut quote_bytes = Vec::with_capacity(64 + 64);
            quote_bytes.extend_from_slice(
                b"GM-MINER-ATTESTD-TEST-QUOTE--not-a-real-tdx-quote--padding64bytes",
            );
            quote_bytes.extend_from_slice(&report_data);
            Ok(AttestationInfo {
                schema_version: "1".to_owned(),
                gateway_id: self.miner_id.clone(),
                gateway_pubkey: self.keypair.public_b64(),
                tee_platform: "intel-tdx".to_owned(),
                app_id: "0".repeat(40),
                compose_hash: "1".repeat(64),
                os_image_hash: "2".repeat(64),
                instance_id: "dstack-test-instance".to_owned(),
                tcb_info: TcbInfoWire {
                    status: TcbStatus::OutOfDate,
                    tcb_date: Utc::now(),
                    advisory_ids: vec!["GM-TEST-NOT-A-REAL-ATTESTATION".to_owned()],
                },
                quote: BASE64_STANDARD.encode(&quote_bytes),
                report_data: BASE64_STANDARD.encode(report_data),
                nonce: BASE64_STANDARD.encode(nonce),
                issued_at: Utc::now(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::testing::DeterministicProvider;
    use super::*;
    use crate::report_data::compute_report_data;

    #[tokio::test]
    async fn build_info_emits_contract_shape() {
        let provider = DeterministicProvider::new("miner-1");
        let nonce = b"test-nonce-32-bytes-padded--abcd";
        assert_eq!(nonce.len(), 32);
        let info = provider.build_info(nonce).await.unwrap();
        assert_eq!(info.schema_version, "1");
        assert_eq!(info.gateway_id, "miner-1");
        assert_eq!(info.tee_platform, "intel-tdx");
        assert_eq!(info.compose_hash.len(), 64);
        assert_eq!(info.os_image_hash.len(), 64);
        assert!(info.app_id.len() >= 40);
        // report_data is base64 of 64 bytes -> 88 chars.
        assert_eq!(info.report_data.len(), 88);
        let rd_bytes = BASE64_STANDARD.decode(&info.report_data).unwrap();
        assert_eq!(rd_bytes.len(), 64);
    }

    #[tokio::test]
    async fn report_data_binds_pubkey_and_nonce() {
        let provider = DeterministicProvider::new("miner-1");
        let nonce = b"another-32-byte-nonce-padding-ab";
        let info = provider.build_info(nonce).await.unwrap();
        let pubkey = BASE64_STANDARD.decode(&info.gateway_pubkey).unwrap();
        let expected = compute_report_data(&pubkey, nonce);
        let got = BASE64_STANDARD.decode(&info.report_data).unwrap();
        assert_eq!(got.as_slice(), &expected);
    }

    #[tokio::test]
    async fn quote_changes_with_nonce() {
        let provider = DeterministicProvider::new("miner-1");
        let a = provider
            .build_info(b"nonce-a-padding-to-16b")
            .await
            .unwrap();
        let b = provider
            .build_info(b"nonce-b-padding-to-16b")
            .await
            .unwrap();
        assert_ne!(a.quote, b.quote);
        assert_ne!(a.report_data, b.report_data);
        // Static fields stay constant across requests.
        assert_eq!(a.compose_hash, b.compose_hash);
        assert_eq!(a.app_id, b.app_id);
    }
}
