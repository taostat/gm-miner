//! `gmcli earnings` — the miner's current standing on the subnet.
//!
//! v1 is the **chain-emission** view: it reads the miner's neuron row straight
//! from the subnet metagraph (via the [`BtcliBridge`]) and reports uid, stake,
//! and per-tempo emission in the subnet's own alpha token. It deliberately does
//! not touch gm-internal accounting — the USD-spread earnings a miner keeps from
//! the gateway are a future (v2) view, noted in the output so the distinction is
//! explicit.
//!
//! The pure pieces live here behind the trait so they unit-test against canned
//! btcli JSON: [`resolve_hotkey`] (flag > registered > error) and
//! [`render_earnings`] (the summary text). main.rs owns the clap wiring, the
//! btcli install prompt, and the bridge call.

use std::fmt::Write as _;

use anyhow::{bail, Result};

use crate::btcli::NeuronStats;
use crate::config::{Config, HotkeyRecord};
use crate::network::Network;

/// The hotkey `earnings` will report on, plus how it was chosen.
///
/// `name` is the local btcli wallet name when known (a recorded hotkey), absent
/// for a `--hotkey-ss58` override the operator typed in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedHotkey {
    pub ss58: String,
    pub name: Option<String>,
}

impl ResolvedHotkey {
    fn from_record(record: &HotkeyRecord) -> Self {
        Self {
            ss58: record.ss58.clone(),
            name: record.name.clone(),
        }
    }
}

/// The hotkey to report on — the operator's own, derived rather than asked for:
/// the login token's `sub` claim, else the recorded `register-hotkey` identity.
///
/// A single-hotkey operator never needs to type their ss58: logging in (or
/// registering) already tells gmcli who they are.
///
/// # Errors
/// Returns an error when neither a login token nor a recorded hotkey is
/// available, naming `login`/`register-hotkey` (and the network, in case the
/// operator is simply on the wrong one) so the next step is obvious.
pub fn resolve_hotkey(cfg: &Config, network: Network) -> Result<ResolvedHotkey> {
    if let Some(ss58) = cfg.token_hotkey() {
        return Ok(ResolvedHotkey { ss58, name: None });
    }
    if let Some(record) = cfg.registered_hotkey() {
        return Ok(ResolvedHotkey::from_record(record));
    }
    bail!(
        "no hotkey to report on for {network} (netuid {}).\n  \
         set up your miner first: `gmcli register-hotkey`, then `gmcli login`\n  \
         (already registered on the subnet? just `gmcli login`).\n  \
         on the wrong network? pass `--network mainnet`/`--network testnet`.",
        network.netuid()
    )
}

/// A rough per-day alpha emission estimate from a per-tempo value.
///
/// btcli reports a neuron's emission as alpha granted **per tempo** (epoch), NOT
/// per block — the raw chain value is nano-alpha/block but btcli converts it for
/// display (docs.taostats.io/docs/metagraph). A subnet emits ~1 alpha/block, so
/// a per-block-per-neuron figure of ~150 would be impossible; the ~150 value is
/// per-tempo. So: blocks are ~12s, a day holds `86400 / 12 = 7200` blocks, a
/// tempo of `tempo_blocks` blocks recurs `7200 / tempo_blocks` times a day. An
/// *estimate* — `None` when the metagraph didn't carry the tempo.
fn per_day_estimate(emission_alpha: f64, tempo_blocks: Option<u64>) -> Option<f64> {
    const BLOCKS_PER_DAY: f64 = 86_400.0 / 12.0;
    // A tempo is a small block count (hundreds); a value that won't fit a u32
    // is nonsense, so treat it as no-estimate rather than casting lossily.
    let tempo = tempo_blocks
        .filter(|t| *t > 0)
        .and_then(|t| u32::try_from(t).ok())?;
    Some(emission_alpha * (BLOCKS_PER_DAY / f64::from(tempo)))
}

/// Render the chain-emission summary for a resolved hotkey.
///
/// `stats: None` means the hotkey is not on this subnet's metagraph — rendered
/// as actionable guidance (wrong network? not registered yet?) rather than a
/// raw dump. `stats: Some` renders uid, stake, and per-tempo emission in alpha,
/// with a clearly-labelled per-day estimate when the tempo is known.
#[must_use]
pub fn render_earnings(
    network: Network,
    hotkey: &ResolvedHotkey,
    stats: Option<&NeuronStats>,
) -> String {
    let mut out = String::new();
    let name = hotkey.name.as_deref().unwrap_or("(no local name)");
    let netuid = network.netuid();
    let _ = writeln!(out, "gmcli earnings — {network} (netuid {netuid})\n");
    let _ = writeln!(out, "  Hotkey : {} ({name})", hotkey.ss58);

    let Some(stats) = stats else {
        let _ = write!(
            out,
            "\n  {} is not on the {network} subnet (netuid {netuid}).\n  \
             On the wrong network? Pass `--network mainnet`/`--network testnet`.\n  \
             Not registered yet? Run `gmcli register-hotkey`.\n",
            hotkey.ss58
        );
        return out;
    };

    let _ = writeln!(out, "  uid    : {}", stats.uid);
    out.push_str("\nChain emission (v1):\n");
    let _ = write!(out, "  Emission : {:.6} α / tempo", stats.emission_alpha);
    match per_day_estimate(stats.emission_alpha, stats.tempo_blocks) {
        Some(per_day) => {
            let _ = writeln!(out, "  (~{per_day:.4} α/day estimate)");
        }
        None => out.push('\n'),
    }
    let _ = writeln!(out, "  Stake    : {:.6} α", stats.stake_alpha);
    let _ = writeln!(
        out,
        "  Incentive: {:.4}   Dividends: {:.4}",
        stats.incentive, stats.dividends
    );
    out.push_str(
        "\nNote: this is on-chain emission in the subnet's alpha token. \
         Your gm USD-spread earnings are a future (v2) view.\n",
    );
    out
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test assertions intentionally panic on unexpected values"
)]
mod tests {
    use super::{render_earnings, resolve_hotkey, ResolvedHotkey};
    use crate::btcli::NeuronStats;
    use crate::config::{Config, HotkeyRecord, TokenEntry};
    use crate::network::Network;
    use base64::Engine as _;

    const SS58: &str = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY";
    const TOKEN_SS58: &str = "5FFCSZsDr38iPJtZED3ze4EjVsQNsufauYHpqpcKtfYt8ikz";

    fn cfg_with_hotkey(network: Network, record: Option<HotkeyRecord>) -> Config {
        let mut cfg = Config::default();
        cfg.set_network(network);
        if let Some(record) = record {
            cfg.active_entry_mut().set_registered_hotkey(record);
        }
        cfg
    }

    /// A JWT whose `sub` claim is `ss58` (unsigned — only the payload matters).
    fn jwt_with_sub(ss58: &str) -> String {
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(format!(r#"{{"sub":"{ss58}"}}"#));
        format!("h.{payload}.s")
    }

    fn cfg_with_token(network: Network, sub: &str) -> Config {
        let mut cfg = Config::default();
        cfg.set_network(network);
        cfg.active_entry_mut().tokens = Some(TokenEntry {
            access_token: Some(jwt_with_sub(sub)),
            token_expires_at: None,
            refresh_token: None,
        });
        cfg
    }

    fn stats() -> NeuronStats {
        NeuronStats {
            uid: 0,
            emission_alpha: 148.01,
            stake_alpha: 56_788.59,
            incentive: 1.0,
            dividends: 0.0,
            tempo_blocks: Some(360),
        }
    }

    #[test]
    fn token_sub_is_the_default_hotkey() {
        let cfg = cfg_with_token(Network::Testnet, TOKEN_SS58);
        let resolved = resolve_hotkey(&cfg, Network::Testnet).expect("token resolves");
        assert_eq!(
            resolved,
            ResolvedHotkey {
                ss58: TOKEN_SS58.to_owned(),
                name: None,
            }
        );
    }

    #[test]
    fn token_hotkey_wins_over_registered() {
        // Both present: the login token is authoritative (it's who the registry
        // says you are), so it wins over the locally recorded register-hotkey.
        let mut cfg = cfg_with_token(Network::Testnet, TOKEN_SS58);
        cfg.active_entry_mut().set_registered_hotkey(HotkeyRecord {
            ss58: SS58.to_owned(),
            name: Some("miner".to_owned()),
            verified: true,
        });
        let resolved = resolve_hotkey(&cfg, Network::Testnet).expect("token resolves");
        assert_eq!(resolved.ss58, TOKEN_SS58);
    }

    #[test]
    fn falls_back_to_registered_hotkey() {
        let cfg = cfg_with_hotkey(
            Network::Testnet,
            Some(HotkeyRecord {
                ss58: SS58.to_owned(),
                name: Some("miner".to_owned()),
                verified: true,
            }),
        );
        let resolved = resolve_hotkey(&cfg, Network::Testnet).expect("registered resolves");
        assert_eq!(resolved.ss58, SS58);
        assert_eq!(resolved.name.as_deref(), Some("miner"));
    }

    #[test]
    fn no_hotkey_errors_with_register_hint() {
        let cfg = cfg_with_hotkey(Network::Mainnet, None);
        let err = resolve_hotkey(&cfg, Network::Mainnet).expect_err("must fail");
        let msg = format!("{err}");
        assert!(msg.contains("register-hotkey"), "got: {msg}");
        assert!(msg.contains("mainnet"), "got: {msg}");
    }

    #[test]
    fn registered_hotkey_is_network_scoped() {
        // A hotkey recorded on testnet is invisible when resolving on mainnet.
        let mut cfg = cfg_with_hotkey(
            Network::Testnet,
            Some(HotkeyRecord {
                ss58: SS58.to_owned(),
                name: Some("miner".to_owned()),
                verified: true,
            }),
        );
        cfg.set_network(Network::Mainnet);
        assert!(resolve_hotkey(&cfg, Network::Mainnet).is_err());
    }

    #[test]
    fn renders_emission_stake_and_per_day_estimate() {
        let hotkey = ResolvedHotkey {
            ss58: SS58.to_owned(),
            name: Some("miner".to_owned()),
        };
        let rendered = render_earnings(Network::Testnet, &hotkey, Some(&stats()));
        assert!(rendered.contains("netuid 482"), "{rendered}");
        assert!(rendered.contains("uid    : 0"), "{rendered}");
        assert!(rendered.contains("Chain emission (v1)"), "{rendered}");
        assert!(rendered.contains("148.010000 α / tempo"), "{rendered}");
        assert!(rendered.contains("α/day estimate"), "{rendered}");
        assert!(rendered.contains("56788.590000 α"), "{rendered}");
        // The chain standing is alpha, never mislabelled USD; the only USD
        // mention is the v2-future note.
        assert!(rendered.contains("future (v2) view"), "{rendered}");
        assert!(!rendered.contains('$'), "{rendered}");
    }

    #[test]
    fn renders_no_per_day_when_tempo_missing() {
        let hotkey = ResolvedHotkey {
            ss58: SS58.to_owned(),
            name: None,
        };
        let mut s = stats();
        s.tempo_blocks = None;
        let rendered = render_earnings(Network::Mainnet, &hotkey, Some(&s));
        assert!(!rendered.contains("α/day estimate"), "{rendered}");
        assert!(rendered.contains("(no local name)"), "{rendered}");
    }

    #[test]
    fn renders_actionable_message_when_not_on_subnet() {
        let hotkey = ResolvedHotkey {
            ss58: SS58.to_owned(),
            name: Some("miner".to_owned()),
        };
        let rendered = render_earnings(Network::Mainnet, &hotkey, None);
        assert!(
            rendered.contains("is not on the mainnet subnet"),
            "{rendered}"
        );
        assert!(rendered.contains("register-hotkey"), "{rendered}");
        assert!(rendered.contains("--network"), "{rendered}");
        // No raw chain dump in the not-found path.
        assert!(!rendered.contains("Emission"), "{rendered}");
    }
}
