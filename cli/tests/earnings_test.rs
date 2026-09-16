//! Drive the shipped command with no external executables on PATH.
#![expect(clippy::unwrap_used, reason = "test assertions")]

use gm_miner_cli::{
    config::{Config, HotkeyRecord},
    network::Network,
};
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

const HOTKEY: &str = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY";

#[tokio::test]
async fn earnings_uses_registry_with_no_btcli_or_login() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/miners/{HOTKEY}/earnings")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "miner_hotkey": HOTKEY, "total_earnings_ndollars": "1234567890", "epochs": []
        })))
        .expect(1)
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.set_network(Network::Mainnet);
    cfg.active_entry_mut().set_registered_hotkey(HotkeyRecord {
        ss58: HOTKEY.to_owned(),
        name: None,
        verified: true,
    });
    std::fs::write(
        dir.path().join("config.json"),
        serde_json::to_vec(&cfg).unwrap(),
    )
    .unwrap();
    let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_gmcli"))
        .args(["earnings", "--yes"])
        .env("GMCLI_CONFIG_DIR", dir.path())
        .env("GM_REGISTRY_URL", server.uri())
        .env("PATH", "")
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("$1.23456789"), "{text}");
    assert!(text.contains("Registry served earnings"), "{text}");
    assert!(!server.received_requests().await.unwrap()[0]
        .headers
        .contains_key("authorization"));
}

#[test]
fn supplied_hotkey_checksum_is_checked_without_btcli() {
    let dir = tempfile::tempdir().unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_gmcli"))
        .args([
            "register-hotkey",
            "--hotkey-ss58",
            "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQZ",
        ])
        .env("GMCLI_CONFIG_DIR", dir.path())
        .env("PATH", "")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("checksum"), "{error}");
    assert!(!dir.path().join("config.json").exists());
}
