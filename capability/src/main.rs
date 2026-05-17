//! gm miner capability check service - Phase 0 scaffold.
//!
//! Phase 1 W4 implements the per-provider /capability/{provider}
//! endpoints described in
//! `taostat/gm/docs/contracts/miner-capability.md`.

#![forbid(unsafe_code)]

fn main() {
    tracing_subscriber::fmt().with_env_filter("info").init();
    tracing::info!("phase 0 gm-miner-capability scaffold compiles; ready for W4");
}
