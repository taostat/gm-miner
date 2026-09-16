//! Read-only Substrate registration lookup. No wallet, signer or CLI process.

use anyhow::{Context, Result};
use subxt::{dynamic, utils::AccountId32, OnlineClient, SubstrateConfig};

use crate::{btcli::Registration, network::Network};

/// Read the hotkey's UID from `SubtensorModule.Uids` at a finalized block.
/// Metadata supplies key encoding and storage hashers; no metagraph is fetched.
///
/// # Errors
/// Rejects invalid SS58 checksums, RPC failures, timeouts and incompatible metadata.
pub async fn registration_of(network: Network, ss58: &str) -> Result<Registration> {
    let account: AccountId32 = ss58
        .parse()
        .context("invalid hotkey SS58 address or checksum")?;
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let api = OnlineClient::<SubstrateConfig>::from_url(network.chain_ws()).await?;
        let address = dynamic::storage("SubtensorModule", "Uids", vec![
            dynamic::Value::u128(u128::from(network.netuid())),
            dynamic::Value::from_bytes(account.0),
        ]);
        let uid = api.storage().at_latest().await?.fetch(&address).await?;
        Ok::<_, anyhow::Error>(match uid {
            Some(value) => Registration::Registered { uid: u64::from(value.as_type::<u16>()?) },
            None => Registration::Absent,
        })
    }).await.context("chain registration lookup timed out after 30 seconds")?
        .with_context(|| format!("read hotkey registration on {network} (netuid {}) from {}; retry when the chain RPC is available", network.netuid(), network.chain_ws()))
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "test assertions")]
mod tests {
    #[tokio::test]
    async fn invalid_checksum_is_rejected_before_connecting() {
        let error = super::registration_of(
            crate::network::Network::Mainnet,
            "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQZ",
        )
        .await
        .expect_err("invalid checksum");
        assert!(error.to_string().contains("checksum"));
    }

    #[tokio::test]
    #[ignore = "read-only live RPC check; set GMCLI_TEST_HOTKEY"]
    async fn live_registration_lookup() {
        let hotkey = std::env::var("GMCLI_TEST_HOTKEY").expect("set GMCLI_TEST_HOTKEY");
        let network = std::env::var("GMCLI_TEST_NETWORK")
            .unwrap_or_else(|_| "mainnet".to_owned())
            .parse()
            .expect("network");
        let registration = super::registration_of(network, &hotkey)
            .await
            .expect("live lookup");
        println!("{network}: {registration:?}");
    }
}
