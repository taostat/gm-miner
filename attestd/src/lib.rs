//! gm miner attestation server library.
//!
//! Serves `GET /attestation/info` with a fresh Intel TDX quote fetched
//! from the dstack guest agent. Runs as a small HTTP server alongside
//! Envoy inside the miner's TEE container; Envoy routes the single
//! `/attestation/info` path to it.
//!
//! The wire contract is `gm/docs/contracts/gateway-attestation-info.md`
//! — the same one the gm gateway's attestation surface produces, so the
//! registry's single attestation checker verifies both services.

pub mod identity;
pub mod info;
pub mod keypair;
pub mod provider;
pub mod ratls;
pub mod report_data;

pub use identity::validate_miner_id;
pub use info::{attestation_info, AppState, AttestationInfoQuery};
pub use keypair::SigningKeypair;
pub use provider::{
    AttestationError, AttestationInfo, AttestationProvider, DstackAttestationProvider, TcbStatus,
};
pub use ratls::{provision as provision_ratls, RatlsError, RatlsPaths};
pub use report_data::compute_report_data;
