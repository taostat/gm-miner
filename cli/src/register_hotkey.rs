//! Record a hotkey after a direct read-only chain registration check.

use anyhow::{bail, Context, Result};
use subxt::utils::AccountId32;

use crate::btcli::Registration;
use crate::config::HotkeyRecord;
use crate::network::Network;

/// The base58 alphabet (Bitcoin/substrate variant — no `0`, `O`, `I`, `l`).
const BASE58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Sanity-check an ss58 address before recording it.
///
/// This is a *format* check, not a registration check: it rejects obvious
/// fat-finger errors (empty, wrong length, non-base58 characters) without
/// claiming the address is registered. Substrate ss58 addresses are base58 of
/// a 35-byte payload (1-byte prefix + 32-byte key + 2-byte checksum), which
/// encodes to 47-48 characters; gm hotkeys carry the `5` network prefix.
///
/// # Errors
/// Returns a human-readable reason when the string can't be an ss58 address.
pub fn validate_ss58(addr: &str) -> Result<(), String> {
    let addr = addr.trim();
    if addr.is_empty() {
        return Err("hotkey ss58 address is empty".to_owned());
    }
    if !(46..=49).contains(&addr.len()) {
        return Err(format!(
            "{addr:?} is not a valid ss58 address (expected ~48 characters, got {})",
            addr.len()
        ));
    }
    if let Some(bad) = addr.bytes().find(|b| !BASE58.contains(b)) {
        return Err(format!(
            "{addr:?} contains {:?}, which is not a base58 character",
            bad as char
        ));
    }
    Ok(())
}

/// Outcome of recording a bring-your-own ss58: the record to persist plus a
/// human note about whether registration was verified locally.
#[derive(Debug, PartialEq, Eq)]
pub struct ByoOutcome {
    pub record: HotkeyRecord,
    pub note: String,
}

/// Record a supplied hotkey only after confirming its subnet membership.
///
/// # Errors
/// Returns an error for an invalid address or a hotkey absent from the subnet.
pub fn record_byo(registration: Registration, network: Network, ss58: &str) -> Result<ByoOutcome> {
    if let Err(reason) = validate_ss58(ss58) {
        bail!("invalid --hotkey-ss58: {reason}");
    }
    let ss58 = ss58
        .trim()
        .parse::<AccountId32>()
        .context("invalid --hotkey-ss58 address or checksum")?
        .to_string();

    match registration {
        Registration::Registered { uid } => Ok(ByoOutcome {
            record: HotkeyRecord {
                ss58,
                name: None,
                verified: true,
            },
            note: format!(
                "Verified on {network} (netuid {}) — uid {uid}.",
                network.netuid()
            ),
        }),
        Registration::Absent => bail!(
            "{ss58} is not registered on {network} (netuid {}). \
             Register it first, or pass the address you actually registered. \
             On the wrong network? Pass `--network mainnet`/`--network testnet`.",
            network.netuid()
        ),
    }
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test assertions intentionally panic on unexpected values"
)]
mod tests {
    use super::{record_byo, validate_ss58};
    use crate::btcli::Registration;
    use crate::network::Network;

    const VALID_SS58: &str = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY";

    #[test]
    fn validate_ss58_accepts_a_real_address() {
        assert!(validate_ss58(VALID_SS58).is_ok());
    }

    #[test]
    fn validate_ss58_rejects_empty_short_and_non_base58() {
        assert!(validate_ss58("").is_err());
        assert!(validate_ss58("5Grw").is_err());
        // '0', 'O', 'I', 'l' are not in the base58 alphabet.
        let with_zero = format!("0{}", &VALID_SS58[1..]);
        assert!(validate_ss58(&with_zero).is_err());
    }

    #[test]
    fn byo_with_bridge_verifies_and_captures_uid() {
        let registration = Registration::Registered { uid: 5 };
        let out = record_byo(registration, Network::Testnet, VALID_SS58).expect("record byo");
        assert!(out.record.verified);
        assert!(out.note.contains("uid 5"));
    }

    #[test]
    fn byo_records_canonical_prefix_42_address() {
        // The same public key encoded with prefix 0.
        let alternate = "15oF4uVJwmo4TdGW7VfQxNLavjCXviqxT9S1MgbjMNHr6Sp5";
        let out = record_byo(
            Registration::Registered { uid: 5 },
            Network::Testnet,
            alternate,
        )
        .expect("canonical address");
        assert_eq!(out.record.ss58, VALID_SS58);
    }

    #[test]
    fn byo_with_bridge_rejects_absent_hotkey() {
        let registration = Registration::Absent;
        let err = record_byo(registration, Network::Mainnet, VALID_SS58)
            .expect_err("absent hotkey must fail");
        assert!(format!("{err}").contains("not registered"));
    }

    #[test]
    fn byo_rejects_malformed_ss58_before_any_bridge_call() {
        let registration = Registration::Registered { uid: 1 };
        let err =
            record_byo(registration, Network::Testnet, "not-an-address").expect_err("must fail");
        assert!(format!("{err}").contains("invalid --hotkey-ss58"));
    }
}
