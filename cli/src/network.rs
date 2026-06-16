//! The network profile every command resolves against.
//!
//! A miner targets exactly one Bittensor network per invocation — `testnet`
//! or `mainnet`. Each carries a fixed set of coordinates: the subnet
//! `netuid`, the chain websocket entrypoint, and the default registry URL.
//! Centralising them here means the scattered `--testnet`-bool branches
//! collapse to one enum, and later work (`register-hotkey`, `earnings`) can
//! read the chain/subnet coordinates straight off the resolved profile
//! instead of re-deriving them.
//!
//! The registry URL is a *default*: a stored `api_url` (or `--api-url` /
//! `GM_REGISTRY_URL`) still overrides it per network — see
//! [`Config::api_url`](crate::config::Config::api_url).

use std::fmt;
use std::str::FromStr;

/// A Bittensor network the miner can target.
///
/// `Mainnet` is the default so a bare command (no `--network`, no `--testnet`,
/// no stored selection) targets production.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    /// gm testnet — subnet 482 on `test.finney`.
    Testnet,
    /// gm mainnet — subnet 28 on `finney`.
    #[default]
    Mainnet,
}

impl Network {
    /// The subnet `netuid` the miner registers and serves on.
    #[must_use]
    pub fn netuid(self) -> u16 {
        match self {
            Self::Testnet => 482,
            Self::Mainnet => 28,
        }
    }

    /// The Bittensor chain websocket entrypoint for this network. Consumed by
    /// the future wallet/subtensor client (`register-hotkey`, `earnings`).
    #[must_use]
    pub fn chain_ws(self) -> &'static str {
        match self {
            Self::Testnet => "wss://test.finney.opentensor.ai",
            Self::Mainnet => "wss://entrypoint-finney.opentensor.ai",
        }
    }

    /// The registry URL used when no `api_url` is stored and no override is
    /// given. A stored value or `--api-url` / `GM_REGISTRY_URL` still wins.
    #[must_use]
    pub fn default_registry_url(self) -> &'static str {
        match self {
            Self::Testnet => "https://test-registry.saygm.com",
            Self::Mainnet => "https://gm-registry.taostats.io",
        }
    }

    /// The config key this network is stored under (`active_network`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Testnet => "testnet",
            Self::Mainnet => "mainnet",
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Network {
    type Err = String;

    /// Parse a `--network` value. Unknown names list the valid options so the
    /// clap error is actionable.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "testnet" | "test" => Ok(Self::Testnet),
            "mainnet" | "main" | "finney" => Ok(Self::Mainnet),
            other => Err(format!(
                "unknown network {other:?}: use `testnet` or `mainnet`"
            )),
        }
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "tests intentionally panic on unexpected values"
)]
mod tests {
    use super::Network;

    #[test]
    fn default_is_mainnet() {
        assert_eq!(Network::default(), Network::Mainnet);
    }

    #[test]
    fn coordinates_are_pinned() {
        assert_eq!(Network::Testnet.netuid(), 482);
        assert_eq!(Network::Mainnet.netuid(), 28);
        assert_eq!(
            Network::Testnet.chain_ws(),
            "wss://test.finney.opentensor.ai"
        );
        assert_eq!(
            Network::Mainnet.chain_ws(),
            "wss://entrypoint-finney.opentensor.ai"
        );
        assert_eq!(
            Network::Testnet.default_registry_url(),
            "https://test-registry.saygm.com"
        );
        assert_eq!(
            Network::Mainnet.default_registry_url(),
            "https://gm-registry.taostats.io"
        );
    }

    #[test]
    fn parse_accepts_aliases() {
        assert_eq!("testnet".parse::<Network>().unwrap(), Network::Testnet);
        assert_eq!("TEST".parse::<Network>().unwrap(), Network::Testnet);
        assert_eq!("mainnet".parse::<Network>().unwrap(), Network::Mainnet);
        assert_eq!("finney".parse::<Network>().unwrap(), Network::Mainnet);
    }

    #[test]
    fn parse_rejects_unknown() {
        let err = "devnet".parse::<Network>().unwrap_err();
        assert!(
            err.contains("testnet") && err.contains("mainnet"),
            "got: {err}"
        );
    }

    #[test]
    fn round_trips_through_as_str() {
        for net in [Network::Testnet, Network::Mainnet] {
            assert_eq!(net.as_str().parse::<Network>().unwrap(), net);
        }
    }
}
