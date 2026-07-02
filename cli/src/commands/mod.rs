//! gmcli command handlers and their private helpers.
//!
//! `main.rs` stays pure coordination (clap surface, `main`, `dispatch`,
//! `dispatch_worker`); each subcommand's logic lives in a focused submodule
//! here. Cross-module items are `pub(crate)` — these are binary-internal.

pub mod deploy;
pub mod doctor;
pub mod earnings;
pub mod fun;
pub mod hotkey;
pub mod keys;
pub mod persist;
pub mod products;
pub mod streaming_check;
pub mod wizard;

use gm_miner_cli::network::Network;

/// Extract a human-readable error detail from a registry JSON error body.
///
/// Returns the `detail` string field if present, otherwise the whole body
/// re-serialized. Avoids leaking a `'static str` on every error path.
fn error_detail(json: &serde_json::Value) -> String {
    json.get("detail")
        .and_then(serde_json::Value::as_str)
        .map_or_else(|| json.to_string(), str::to_owned)
}

pub(crate) fn status_error(op: &str, status: reqwest::StatusCode, body: &str) -> anyhow::Error {
    let detail = serde_json::from_str::<serde_json::Value>(body)
        .map_or_else(|_| body.to_owned(), |json| error_detail(&json));
    anyhow::anyhow!("{op} failed ({status}): {detail}")
}

/// Turn a failed `GET /miners/me` into an actionable error instead of dumping
/// the raw response body.
///
/// A 403/404 means the caller authenticated fine but the registry has no miner
/// for this hotkey — i.e. it isn't registered on the subnet. A 401 is handled
/// upstream by [`RegistryClient`], but together with 404 it can also mean the
/// command is pointed at the wrong network, so the hint names the active one.
///
/// [`RegistryClient`]: gm_miner_cli::client::RegistryClient
pub(crate) fn me_error(network: Network, status: reqwest::StatusCode) -> anyhow::Error {
    let netuid = network.netuid();
    if matches!(status.as_u16(), 401 | 403 | 404) {
        return anyhow::anyhow!(
            "your hotkey isn't registered on subnet {netuid} (registry returned {status}).\n\
             Run `gmcli register-hotkey` to record your hotkey, then `gmcli deploy` \
             to attach a worker.\n\
             Already registered? You're on the `{network}` network — pass \
             `--network mainnet` / `--network testnet` if that's not where your \
             hotkey lives."
        );
    }
    anyhow::anyhow!("registry request to {network} failed ({status})")
}
