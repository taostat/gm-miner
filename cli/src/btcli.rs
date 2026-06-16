//! Bridge to `btcli` (bittensor-cli) for on-chain hotkey work.
//!
//! `gm-miner` never handles wallet private keys — `btcli` owns the wallet and
//! signs the registration extrinsic. This module shells out to `btcli` and
//! parses its `--json-output`, keeping every parse isolated behind the
//! [`BtcliBridge`] trait so tests inject canned output instead of running a
//! real chain query.
//!
//! Network mapping is fixed: the gm [`Network`](crate::network::Network)
//! resolves to btcli's `--network` value (`test` for testnet / netuid 482,
//! `finney` for mainnet / netuid 28) — see [`btcli_network`].

use anyhow::{bail, Context, Result};
use serde::Deserialize;

use crate::network::Network;

/// The `btcli --network` value for a gm [`Network`].
///
/// btcli names the chains `test` and `finney`; gm names them `testnet` and
/// `mainnet`. Verified against `btcli subnet metagraph --netuid 482 --network
/// test` (testnet) and the btcli reference (`--network finney` for mainnet).
#[must_use]
pub fn btcli_network(network: Network) -> &'static str {
    match network {
        Network::Testnet => "test",
        Network::Mainnet => "finney",
    }
}

/// A hotkey's registration state on a subnet, as read from the metagraph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Registration {
    /// The hotkey holds `uid` on the subnet.
    Registered { uid: u64 },
    /// The hotkey is absent from the subnet metagraph.
    Absent,
}

/// A miner's chain-side standing on a subnet, read from one metagraph row.
///
/// Every field is what `btcli subnet metagraph --json-output` emits verbatim
/// (bittensor-cli 9.20.x): `emission`/`stake` are in the subnet's own alpha
/// token (not TAO, not USD); `incentive`/`dividends` are the normalised
/// `[0, 1]` shares. `earnings` renders these as the v1 chain-emission view.
#[derive(Debug, Clone, PartialEq)]
pub struct NeuronStats {
    /// The neuron's uid on the subnet.
    pub uid: u64,
    /// Per-tempo emission to this neuron, in alpha.
    pub emission_alpha: f64,
    /// Total stake on this neuron, in alpha.
    pub stake_alpha: f64,
    /// Normalised incentive share `[0, 1]` — the mining component.
    pub incentive: f64,
    /// Normalised dividend share `[0, 1]` — the validating component.
    pub dividends: f64,
    /// Blocks per tempo, used to turn per-tempo emission into a per-day
    /// estimate. `None` when the metagraph omits it.
    pub tempo_blocks: Option<u64>,
}

/// The on-chain primitives `register-hotkey` needs. Real impl shells out to
/// `btcli`; tests inject a stub returning canned values.
pub trait BtcliBridge {
    /// The hotkey's registration on `network`'s subnet, by ss58 address.
    ///
    /// # Errors
    /// Returns an error if btcli can't be run or its output can't be parsed.
    fn registration_of(&self, network: Network, ss58: &str) -> Result<Registration>;

    /// The neuron's chain standing on `network`'s subnet, by ss58 address, or
    /// `None` when the hotkey is absent from the metagraph (not registered, or
    /// the wrong network). Reads the same `subnet metagraph` JSON as
    /// [`registration_of`](Self::registration_of), surfacing the full row.
    ///
    /// # Errors
    /// Returns an error if btcli can't be run or its output can't be parsed.
    fn neuron_stats(&self, network: Network, ss58: &str) -> Result<Option<NeuronStats>>;

    /// Register `wallet`/`hotkey` on `network`'s subnet, streaming btcli's
    /// output (including its own cost confirmation) through. `assume_yes`
    /// passes btcli's non-interactive `--no-prompt`.
    ///
    /// # Errors
    /// Returns an error if btcli exits non-zero.
    fn register(
        &self,
        network: Network,
        wallet: &str,
        hotkey: &str,
        assume_yes: bool,
    ) -> Result<()>;

    /// Resolve a `wallet`/`hotkey` name to its ss58 address via the local
    /// wallet store. Returns `None` when the pair isn't in the store (a typoed
    /// name) or the output can't be parsed, so callers can refuse to spend
    /// rather than register blind.
    ///
    /// # Errors
    /// Returns an error only when btcli itself can't be run.
    fn hotkey_ss58(&self, wallet: &str, hotkey: &str) -> Result<Option<String>>;
}

/// One neuron row from `btcli subnet metagraph --json-output --no-prompt`.
/// Only the fields gm-miner reads are modelled; btcli emits many more.
/// Verified against bittensor-cli 9.20.x, which keys the row's address `hotkey`,
/// its per-tempo emission `emissions` (plural), and `stake` in alpha.
#[derive(Debug, Deserialize)]
struct MetagraphNeuron {
    #[serde(alias = "hotkey_ss58")]
    hotkey: String,
    uid: u64,
    #[serde(default)]
    emissions: f64,
    #[serde(default)]
    stake: f64,
    #[serde(default)]
    incentive: f64,
    #[serde(default)]
    dividends: f64,
}

/// The subnet `tempo` block from `btcli subnet metagraph --json-output`:
/// bittensor-cli 9.20.x nests `tempo` (blocks per epoch) under a `tempo` object.
#[derive(Debug, Deserialize)]
struct MetagraphTempo {
    tempo: u64,
}

/// The slice of `btcli subnet metagraph --json-output --no-prompt` we parse:
/// the neuron rows (under the `uids` key in bittensor-cli 9.20.x) plus the
/// subnet `tempo`, used to turn per-tempo emission into a per-day estimate.
#[derive(Debug, Deserialize)]
struct MetagraphOutput {
    #[serde(alias = "neurons", default)]
    uids: Vec<MetagraphNeuron>,
    #[serde(default)]
    tempo: Option<MetagraphTempo>,
}

/// Find a hotkey's uid in `btcli subnet metagraph --json-output --no-prompt`.
///
/// Isolated so the brittle shape-matching against btcli's JSON lives in one
/// place: bittensor-cli 9.20.x nests the neuron rows under `uids`, each row
/// keying its address `hotkey` and its index `uid`.
fn parse_registration(json: &[u8], ss58: &str) -> Result<Registration> {
    let parsed: MetagraphOutput = serde_json::from_slice(json)
        .context("parse `btcli subnet metagraph --json-output --no-prompt`")?;
    match parsed.uids.iter().find(|n| n.hotkey == ss58) {
        Some(neuron) => Ok(Registration::Registered { uid: neuron.uid }),
        None => Ok(Registration::Absent),
    }
}

/// Read a hotkey's [`NeuronStats`] from `btcli subnet metagraph --json-output
/// --no-prompt`, or `None` when the row is absent. Same `uids`/`tempo` shape as
/// [`parse_registration`]; isolated here so the JSON contract lives in one place.
fn parse_neuron_stats(json: &[u8], ss58: &str) -> Result<Option<NeuronStats>> {
    let parsed: MetagraphOutput = serde_json::from_slice(json)
        .context("parse `btcli subnet metagraph --json-output --no-prompt`")?;
    let tempo_blocks = parsed.tempo.map(|t| t.tempo);
    Ok(parsed
        .uids
        .into_iter()
        .find(|n| n.hotkey == ss58)
        .map(|n| NeuronStats {
            uid: n.uid,
            emission_alpha: n.emissions,
            stake_alpha: n.stake,
            incentive: n.incentive,
            dividends: n.dividends,
            tempo_blocks,
        }))
}

/// One hotkey row under a wallet in `btcli wallet list --json-output`.
#[derive(Debug, Deserialize)]
struct WalletHotkey {
    name: String,
    #[serde(alias = "ss58", alias = "hotkey_ss58")]
    ss58_address: String,
}

/// One wallet (coldkey) in `btcli wallet list --json-output`.
#[derive(Debug, Deserialize)]
struct WalletEntry {
    name: String,
    #[serde(default)]
    hotkeys: Vec<WalletHotkey>,
}

/// The slice of `btcli wallet list --json-output` we parse.
#[derive(Debug, Deserialize)]
struct WalletList {
    #[serde(default)]
    wallets: Vec<WalletEntry>,
}

/// Resolve a `wallet`/`hotkey` name to its ss58 from `btcli wallet list
/// --json-output`. Returns `None` when the output doesn't contain the pair,
/// can't be parsed, or the row carries a non-ss58 placeholder.
///
/// The placeholder guard matters: for a locked or password-protected hotkey,
/// bittensor-cli emits a row with a stand-in like `?` or `<ENCRYPTED>` in place
/// of the address. Validating the shape here turns that into an unresolved
/// `None`, so the caller refuses to register rather than persisting garbage as
/// the miner hotkey. Verified shape against 9.20.x:
/// `{"wallets":[{"name","ss58_address","hotkeys":[{"name","ss58_address"}]}]}`.
fn parse_hotkey_ss58(json: &[u8], wallet: &str, hotkey: &str) -> Option<String> {
    let parsed: WalletList = serde_json::from_slice(json).ok()?;
    parsed
        .wallets
        .into_iter()
        .find(|w| w.name == wallet)?
        .hotkeys
        .into_iter()
        .find(|h| h.name == hotkey)
        .map(|h| h.ss58_address)
        .filter(|addr| crate::register_hotkey::validate_ss58(addr).is_ok())
}

/// Shells out to a real `btcli` on PATH.
pub struct RealBtcli;

impl RealBtcli {
    /// Run `btcli` with `args`, returning stdout on success. Surfaces btcli's
    /// own stderr on failure so the operator sees its message, not a generic one.
    fn run(args: &[&str]) -> Result<Vec<u8>> {
        let out = std::process::Command::new("btcli")
            .args(args)
            .output()
            .with_context(|| format!("run `btcli {}`", args.join(" ")))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            bail!("btcli failed: {}", stderr.trim());
        }
        Ok(out.stdout)
    }

    /// The metagraph JSON for `network`'s subnet. `--json-output` requires
    /// `--no-prompt`; without it bittensor-cli 9.20.x errors instead of emitting
    /// JSON. Shared by [`registration_of`](Self::registration_of) and
    /// [`neuron_stats`](Self::neuron_stats) so the args live in one place.
    fn metagraph_json(network: Network) -> Result<Vec<u8>> {
        let netuid = network.netuid().to_string();
        let chain = btcli_network(network);
        Self::run(&[
            "subnet",
            "metagraph",
            "--netuid",
            &netuid,
            "--network",
            chain,
            "--json-output",
            "--no-prompt",
        ])
    }
}

impl BtcliBridge for RealBtcli {
    fn registration_of(&self, network: Network, ss58: &str) -> Result<Registration> {
        parse_registration(&Self::metagraph_json(network)?, ss58)
    }

    fn neuron_stats(&self, network: Network, ss58: &str) -> Result<Option<NeuronStats>> {
        parse_neuron_stats(&Self::metagraph_json(network)?, ss58)
    }

    fn register(
        &self,
        network: Network,
        wallet: &str,
        hotkey: &str,
        assume_yes: bool,
    ) -> Result<()> {
        let netuid = network.netuid().to_string();
        let chain = btcli_network(network);
        let mut args = vec![
            "subnet",
            "register",
            "--netuid",
            &netuid,
            "--network",
            chain,
            "--wallet.name",
            wallet,
            "--wallet.hotkey",
            hotkey,
        ];
        if assume_yes {
            args.push("--no-prompt");
        }
        // Inherit stdio: btcli prompts for the wallet password and shows the
        // burn-cost confirmation itself — gm-miner must not capture that.
        let status = std::process::Command::new("btcli")
            .args(&args)
            .status()
            .context("run `btcli subnet register`")?;
        if !status.success() {
            bail!(
                "btcli registration failed. Wrong network, insufficient balance, \
                 or a missing/locked wallet are the usual causes — check the btcli \
                 output above."
            );
        }
        Ok(())
    }

    fn hotkey_ss58(&self, wallet: &str, hotkey: &str) -> Result<Option<String>> {
        let stdout = Self::run(&["wallet", "list", "--json-output"])?;
        Ok(parse_hotkey_ss58(&stdout, wallet, hotkey))
    }
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test assertions intentionally panic on unexpected values"
)]
mod tests {
    use super::{
        btcli_network, parse_hotkey_ss58, parse_neuron_stats, parse_registration, Registration,
    };
    use crate::network::Network;

    #[test]
    fn network_maps_to_btcli_chain() {
        assert_eq!(btcli_network(Network::Testnet), "test");
        assert_eq!(btcli_network(Network::Mainnet), "finney");
    }

    // Trimmed real output of `btcli subnet metagraph --netuid 482 --network
    // test --json-output --no-prompt` (bittensor-cli 9.20.x): neuron rows under
    // `uids`, each keyed `uid`/`hotkey`/`emissions`/`stake`/`incentive`/
    // `dividends`, plus the nested `tempo` object.
    const METAGRAPH_JSON: &[u8] = br#"{"netuid":482,"registration_cost":0.0005,
        "tempo":{"block_since_last_step":50,"tempo":360},
        "uids":[
          {"uid":0,"hotkey":"5AAA","coldkey":"5CK","stake":56788.59,
           "incentive":1.0,"dividends":0.0,"emissions":148.01},
          {"uid":7,"hotkey":"5BBB","coldkey":"5CK","stake":0.0,
           "incentive":0.0,"dividends":0.5,"emissions":12.5}]}"#;

    #[test]
    fn parses_registered_hotkey_uid_from_real_shape() {
        let reg = parse_registration(METAGRAPH_JSON, "5BBB").expect("parse metagraph");
        assert_eq!(reg, Registration::Registered { uid: 7 });
    }

    #[test]
    fn parses_absent_hotkey() {
        let reg = parse_registration(METAGRAPH_JSON, "5ZZZ").expect("parse metagraph");
        assert_eq!(reg, Registration::Absent);
    }

    #[test]
    fn empty_metagraph_has_no_registration() {
        let reg = parse_registration(br#"{"netuid":482,"uids":[]}"#, "5AAA")
            .expect("parse empty metagraph");
        assert_eq!(reg, Registration::Absent);
    }

    #[test]
    fn rejects_unparseable_output() {
        let err = parse_registration(b"not json", "5AAA").expect_err("must fail");
        assert!(format!("{err}").contains("btcli subnet metagraph"));
    }

    #[test]
    fn parses_neuron_stats_from_real_shape() {
        let stats = parse_neuron_stats(METAGRAPH_JSON, "5AAA")
            .expect("parse stats")
            .expect("hotkey present");
        assert_eq!(stats.uid, 0);
        assert!((stats.emission_alpha - 148.01).abs() < 1e-9);
        assert!((stats.stake_alpha - 56788.59).abs() < 1e-9);
        assert!((stats.incentive - 1.0).abs() < 1e-9);
        assert!((stats.dividends - 0.0).abs() < 1e-9);
        assert_eq!(stats.tempo_blocks, Some(360));
    }

    #[test]
    fn neuron_stats_absent_hotkey_is_none() {
        let stats = parse_neuron_stats(METAGRAPH_JSON, "5ZZZ").expect("parse stats");
        assert!(stats.is_none());
    }

    #[test]
    fn neuron_stats_tolerate_missing_tempo() {
        // A metagraph without the tempo object still parses; the per-day
        // estimate is simply unavailable.
        let json = br#"{"netuid":482,"uids":[{"uid":3,"hotkey":"5CCC","emissions":1.0}]}"#;
        let stats = parse_neuron_stats(json, "5CCC")
            .expect("parse stats")
            .expect("hotkey present");
        assert_eq!(stats.uid, 3);
        assert_eq!(stats.tempo_blocks, None);
        assert!((stats.stake_alpha - 0.0).abs() < 1e-9);
    }

    #[test]
    fn neuron_stats_rejects_unparseable_output() {
        let err = parse_neuron_stats(b"not json", "5AAA").expect_err("must fail");
        assert!(format!("{err}").contains("btcli subnet metagraph"));
    }

    // Trimmed real output of `btcli wallet list --json-output` (9.20.x) with
    // real-length ss58 addresses so the validity filter is exercised.
    const COLDKEY: &str = "5CdHHdHMSbBW3Qs1REQhNq69ej1QTtVUfAHhPRuT14hyL3WA";
    const HK_DEFAULT: &str = "5FFCSZsDr38iPJtZED3ze4EjVsQNsufauYHpqpcKtfYt8ikz";
    const HK_BACKUP: &str = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY";

    fn wallet_list_json() -> Vec<u8> {
        format!(
            r#"{{"wallets":[{{"name":"miner","ss58_address":"{COLDKEY}","hotkeys":[
              {{"name":"default","ss58_address":"{HK_DEFAULT}"}},
              {{"name":"backup","ss58_address":"{HK_BACKUP}"}}]}}]}}"#
        )
        .into_bytes()
    }

    #[test]
    fn resolves_hotkey_ss58_by_wallet_and_name() {
        assert_eq!(
            parse_hotkey_ss58(&wallet_list_json(), "miner", "backup"),
            Some(HK_BACKUP.to_owned())
        );
    }

    #[test]
    fn unresolvable_hotkey_ss58_is_none_not_error() {
        // Empty wallet list, unknown wallet, and unparseable output all return
        // None so the caller refuses to spend rather than panicking.
        let json = wallet_list_json();
        assert_eq!(
            parse_hotkey_ss58(br#"{"wallets":[]}"#, "miner", "default"),
            None
        );
        assert_eq!(parse_hotkey_ss58(&json, "other", "default"), None);
        assert_eq!(parse_hotkey_ss58(b"garbage", "miner", "default"), None);
    }

    #[test]
    fn placeholder_address_for_locked_hotkey_is_unresolved() {
        // A locked/encrypted hotkey reports a stand-in instead of an ss58. It
        // must not be returned as a real address — the caller would otherwise
        // register and persist the placeholder as the miner hotkey.
        for placeholder in ["?", "<ENCRYPTED>", ""] {
            let json = format!(
                r#"{{"wallets":[{{"name":"miner","ss58_address":"{COLDKEY}",
                   "hotkeys":[{{"name":"default","ss58_address":"{placeholder}"}}]}}]}}"#
            );
            assert_eq!(
                parse_hotkey_ss58(json.as_bytes(), "miner", "default"),
                None,
                "placeholder {placeholder:?} must not resolve"
            );
        }
    }
}
