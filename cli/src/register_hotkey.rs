//! `gm-miner register-hotkey` — record (and optionally register) the hotkey
//! the miner serves under.
//!
//! Two flows, dispatched on whether the operator passed `--hotkey-ss58`:
//!
//! - **Bring-your-own** (`--hotkey-ss58 <addr>`): the operator already
//!   registered the hotkey elsewhere (a browser wallet, another machine).
//!   gm-miner just records the ss58. If `btcli` happens to be present we
//!   confirm the hotkey is on the subnet and capture its uid; if not, we
//!   accept the address and defer verification to the first deploy/login,
//!   which the registry/gateway probe anyway.
//! - **Assisted** (no `--hotkey-ss58`): gm-miner offers to register a fresh
//!   hotkey through `btcli`. This is the only flow that requires `btcli`.
//!
//! The pure decision logic lives here behind the [`BtcliBridge`] trait so it
//! is unit-testable with canned btcli output; main.rs owns the clap wiring,
//! the install prompt, and config persistence.

use anyhow::{bail, Result};

use crate::btcli::{BtcliBridge, Registration};
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

/// Build the [`HotkeyRecord`] for a bring-your-own ss58, verifying against the
/// subnet metagraph when a btcli bridge is available.
///
/// With `bridge: Some` we query the metagraph: a registered hotkey is recorded
/// `verified` with its uid in the note; an *absent* hotkey is an error (the
/// operator named an address that isn't on this subnet — better to refuse than
/// to record a hotkey that will never serve). With `bridge: None` we record
/// the address unverified and say so plainly.
///
/// # Errors
/// Returns an error if the ss58 fails format validation, the metagraph query
/// fails, or the hotkey is provably absent from the subnet.
pub fn record_byo(
    bridge: Option<&dyn BtcliBridge>,
    network: Network,
    ss58: &str,
) -> Result<ByoOutcome> {
    if let Err(reason) = validate_ss58(ss58) {
        bail!("invalid --hotkey-ss58: {reason}");
    }
    let ss58 = ss58.trim().to_owned();

    let Some(bridge) = bridge else {
        return Ok(ByoOutcome {
            record: HotkeyRecord {
                ss58,
                name: None,
                verified: false,
            },
            note: format!(
                "Recorded for {network} (netuid {}). Registration not yet verified \
                 locally — install btcli to verify, or it will be confirmed on your \
                 first deploy.",
                network.netuid()
            ),
        });
    };

    match bridge.registration_of(network, &ss58)? {
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

/// The record to persist after a successful `btcli subnet register`, plus
/// whether the metagraph already shows the new uid.
#[derive(Debug, PartialEq, Eq)]
pub struct PostRegister {
    pub record: HotkeyRecord,
    /// `Some(uid)` once the hotkey appears on the metagraph; `None` while
    /// registration is still settling (it can take a block).
    pub uid: Option<u64>,
}

/// Build the record to persist after `btcli subnet register` returns, re-reading
/// the metagraph for the new uid.
///
/// btcli has already reported success, so the hotkey *is* registered — we always
/// persist its known `ss58`. The metagraph can lag a block, so a uid that hasn't
/// appeared yet leaves the record `verified: false` with `uid: None` rather than
/// discarding a successful registration. The caller reports the settling state.
///
/// # Errors
/// Returns an error only if the metagraph query itself fails (btcli unreachable).
pub fn confirm_registered(
    bridge: &dyn BtcliBridge,
    network: Network,
    ss58: &str,
    hotkey_name: &str,
) -> Result<PostRegister> {
    let uid = match bridge.registration_of(network, ss58)? {
        Registration::Registered { uid } => Some(uid),
        Registration::Absent => None,
    };
    Ok(PostRegister {
        record: HotkeyRecord {
            ss58: ss58.to_owned(),
            name: Some(hotkey_name.to_owned()),
            verified: uid.is_some(),
        },
        uid,
    })
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test assertions intentionally panic on unexpected values"
)]
mod tests {
    use super::{confirm_registered, record_byo, validate_ss58};
    use crate::btcli::{BtcliBridge, Registration};
    use crate::config::HotkeyRecord;
    use crate::network::Network;
    use anyhow::Result;

    const VALID_SS58: &str = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY";

    struct StubBridge {
        result: Registration,
    }

    impl BtcliBridge for StubBridge {
        fn registration_of(&self, _network: Network, _ss58: &str) -> Result<Registration> {
            Ok(self.result.clone())
        }
        fn register(
            &self,
            _network: Network,
            _wallet: &str,
            _hotkey: &str,
            _assume_yes: bool,
        ) -> Result<()> {
            Ok(())
        }
        fn hotkey_ss58(&self, _wallet: &str, _hotkey: &str) -> Result<Option<String>> {
            Ok(None)
        }
        fn neuron_stats(
            &self,
            _network: Network,
            _ss58: &str,
        ) -> Result<Option<crate::btcli::NeuronStats>> {
            Ok(None)
        }
    }

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
    fn byo_without_bridge_records_unverified() {
        let out = record_byo(None, Network::Testnet, VALID_SS58).expect("record byo");
        assert_eq!(
            out.record,
            HotkeyRecord {
                ss58: VALID_SS58.to_owned(),
                name: None,
                verified: false,
            }
        );
        assert!(out.note.contains("not yet verified"));
    }

    #[test]
    fn byo_with_bridge_verifies_and_captures_uid() {
        let bridge = StubBridge {
            result: Registration::Registered { uid: 5 },
        };
        let out = record_byo(Some(&bridge), Network::Testnet, VALID_SS58).expect("record byo");
        assert!(out.record.verified);
        assert!(out.note.contains("uid 5"));
    }

    #[test]
    fn byo_with_bridge_rejects_absent_hotkey() {
        let bridge = StubBridge {
            result: Registration::Absent,
        };
        let err = record_byo(Some(&bridge), Network::Mainnet, VALID_SS58)
            .expect_err("absent hotkey must fail");
        assert!(format!("{err}").contains("not registered"));
    }

    #[test]
    fn byo_rejects_malformed_ss58_before_any_bridge_call() {
        let bridge = StubBridge {
            result: Registration::Registered { uid: 1 },
        };
        let err =
            record_byo(Some(&bridge), Network::Testnet, "not-an-address").expect_err("must fail");
        assert!(format!("{err}").contains("invalid --hotkey-ss58"));
    }

    #[test]
    fn confirm_registered_captures_uid_and_verifies() {
        let bridge = StubBridge {
            result: Registration::Registered { uid: 9 },
        };
        let out =
            confirm_registered(&bridge, Network::Testnet, VALID_SS58, "default").expect("confirm");
        assert_eq!(out.uid, Some(9));
        assert_eq!(
            out.record,
            HotkeyRecord {
                ss58: VALID_SS58.to_owned(),
                name: Some("default".to_owned()),
                verified: true,
            }
        );
    }

    #[test]
    fn confirm_registered_still_records_ss58_while_settling() {
        // btcli succeeded but the metagraph hasn't caught up: the ss58 is still
        // recorded (the registration happened), just unverified with no uid.
        let bridge = StubBridge {
            result: Registration::Absent,
        };
        let out =
            confirm_registered(&bridge, Network::Mainnet, VALID_SS58, "default").expect("confirm");
        assert_eq!(out.uid, None);
        assert_eq!(out.record.ss58, VALID_SS58);
        assert!(!out.record.verified);
    }
}
