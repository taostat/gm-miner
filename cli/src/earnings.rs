//! Registry-served earnings, preserving integer nano-dollar precision.

use std::fmt::Write as _;

use anyhow::{bail, Context, Result};
use serde::Deserialize;

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

/// Public `GET /miners/{hotkey}/earnings` response. The total spans all history.
#[derive(Debug, Deserialize)]
pub struct MinerEarnings {
    pub miner_hotkey: String,
    pub total_earnings_ndollars: String,
    pub epochs: Vec<EpochEarnings>,
}

#[derive(Debug, Deserialize)]
pub struct EpochEarnings {
    pub epoch_id: u64,
    pub finalized_at: chrono::DateTime<chrono::Utc>,
    pub earnings_ndollars: String,
    pub successful_requests: u64,
    pub failed_requests: u64,
}

/// Fetch recent finalized earnings without requiring registry authentication.
///
/// # Errors
/// Returns an error for invalid addresses, failed requests or malformed responses.
pub async fn fetch_earnings(registry_url: &str, hotkey: &str) -> Result<MinerEarnings> {
    crate::register_hotkey::validate_ss58(hotkey).map_err(anyhow::Error::msg)?;
    let url = format!(
        "{}/miners/{hotkey}/earnings?limit=10",
        registry_url.trim_end_matches('/')
    );
    let response = crate::client::build_http_client()?
        .get(&url)
        .send()
        .await
        .with_context(|| format!("fetch earnings from {url}"))?;
    if !response.status().is_success() {
        bail!(
            "registry earnings request failed ({}); retry or check the selected registry/network",
            response.status()
        );
    }
    let earnings: MinerEarnings = response
        .json()
        .await
        .context("parse registry earnings response")?;
    if earnings.miner_hotkey != hotkey {
        bail!("registry returned earnings for a different hotkey");
    }
    Ok(earnings)
}

fn dollars(value: &str) -> Result<String> {
    let amount: u128 = value
        .parse()
        .context("invalid registry nano-dollar amount")?;
    let whole = amount / 1_000_000_000;
    let mut fraction = format!("{:09}", amount % 1_000_000_000);
    while fraction.len() > 3 && fraction.ends_with('0') {
        fraction.pop();
    }
    Ok(format!("${whole}.{fraction}"))
}

/// Render lifetime served value and recent history, not chain payments or profit.
///
/// # Errors
/// Returns an error if a registry monetary amount is not an unsigned integer.
pub fn render_earnings(
    network: Network,
    hotkey: &ResolvedHotkey,
    earnings: &MinerEarnings,
) -> Result<String> {
    let mut out = String::new();
    let name = hotkey.name.as_deref().unwrap_or("no local name");
    let netuid = network.netuid();
    let _ = writeln!(out, "gmcli earnings — {network} (netuid {netuid})\n");
    let _ = writeln!(out, "  Hotkey : {} ({name})", hotkey.ss58);

    let _ = writeln!(
        out,
        "\nRegistry served earnings (USD)\n  Lifetime total: {}",
        dollars(&earnings.total_earnings_ndollars)?
    );
    if earnings.epochs.is_empty() {
        out.push_str("\nNo finalized earnings history returned. This does not establish subnet registration.\n");
    } else {
        let _ = writeln!(
            out,
            "\nRecent finalized epochs ({} shown, newest first):",
            earnings.epochs.len()
        );
        for epoch in &earnings.epochs {
            let _ = writeln!(
                out,
                "  Epoch {} | {} | {} successful / {} failed requests | finalized {}",
                epoch.epoch_id,
                dollars(&epoch.earnings_ndollars)?,
                epoch.successful_requests,
                epoch.failed_requests,
                epoch.finalized_at.to_rfc3339()
            );
        }
    }
    out.push_str("\nServed value is not on-chain payments or profit. Unfinalized activity is not included.\n");
    Ok(out)
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test assertions intentionally panic on unexpected values"
)]
mod tests {
    use super::{render_earnings, resolve_hotkey, ResolvedHotkey};
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

    fn response() -> super::MinerEarnings {
        serde_json::from_value(serde_json::json!({
            "miner_hotkey": SS58,
            "total_earnings_ndollars": "9007199254740993001",
            "epochs": [{"epoch_id": 42, "finalized_at": "2026-09-16T12:00:00Z",
                "earnings_ndollars": "1", "successful_requests": 3, "failed_requests": 1}]
        }))
        .expect("fixture")
    }

    #[test]
    fn renders_exact_lifetime_total_independent_of_recent_page() {
        let hotkey = ResolvedHotkey {
            ss58: SS58.to_owned(),
            name: None,
        };
        let rendered = render_earnings(Network::Mainnet, &hotkey, &response()).expect("render");
        assert!(rendered.contains("$9007199254.740993001"), "{rendered}");
        assert!(rendered.contains("$0.000000001"), "{rendered}");
        assert!(rendered.contains("3 successful / 1 failed"));
        assert!(rendered.contains("2026-09-16T12:00:00+00:00"));
        assert!(rendered.contains("not on-chain payments or profit"));
    }

    #[test]
    fn empty_history_does_not_claim_hotkey_is_absent() {
        let mut earnings = response();
        earnings.epochs.clear();
        earnings.total_earnings_ndollars = "0".to_owned();
        let hotkey = ResolvedHotkey {
            ss58: SS58.to_owned(),
            name: None,
        };
        let rendered = render_earnings(Network::Testnet, &hotkey, &earnings).expect("render");
        assert!(rendered.contains("$0.000"));
        assert!(rendered.contains("does not establish subnet registration"));
        assert!(rendered.contains("netuid 482"));
    }

    #[test]
    fn invalid_money_is_never_rendered_as_zero() {
        for amount in ["NaN", "1.5", "-1", ""] {
            assert!(super::dollars(amount).is_err());
        }
    }

    #[tokio::test]
    async fn fetches_public_registry_earnings_without_auth() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/miners/{SS58}/earnings")))
            .and(query_param("limit", "10"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "miner_hotkey": SS58, "total_earnings_ndollars": "0", "epochs": []
            })))
            .expect(1)
            .mount(&server)
            .await;
        let earnings = super::fetch_earnings(&server.uri(), SS58)
            .await
            .expect("fetch");
        assert!(earnings.epochs.is_empty());
        let requests = server.received_requests().await.expect("requests");
        assert!(!requests[0].headers.contains_key("authorization"));
    }

    #[tokio::test]
    async fn failed_or_wrong_hotkey_responses_are_not_zero_earnings() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        for response in [
            ResponseTemplate::new(503),
            ResponseTemplate::new(200).set_body_string(""),
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "miner_hotkey": TOKEN_SS58, "total_earnings_ndollars": "0", "epochs": []
            })),
        ] {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .respond_with(response)
                .mount(&server)
                .await;
            assert!(super::fetch_earnings(&server.uri(), SS58).await.is_err());
        }
    }
}
