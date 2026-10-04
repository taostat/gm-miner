//! Exercise declaration messages and exit codes through the actual CLI binary.

#![expect(
    clippy::expect_used,
    reason = "test assertions panic on unexpected values"
)]

use wiremock::{
    matchers::{header, method, path},
    Mock, MockServer, ResponseTemplate,
};

#[tokio::test]
async fn declaration_statuses_produce_correct_output_and_exit_codes() {
    for (status, bulk) in [(202, false), (409, false), (200, false), (202, true)] {
        let server = MockServer::start().await;
        let retail = serde_json::json!({"dimensions": {
            "input_per_mtok_ndollars": 3_000_000_000_u64,
            "output_per_mtok_ndollars": 15_000_000_000_u64,
        }});
        Mock::given(method("GET"))
            .and(path("/products"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "products": [{"provider": "anthropic", "model": "claude-sonnet-4-6",
                    "status": "active", "retail_price": retail}],
                "generated_at": "2026-10-04T11:00:00Z",
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/miners/products/routes"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "routes": [{"route_id": 1, "provider": "anthropic", "model": "claude-sonnet-4-6",
                    "buyer_provider": "anthropic", "buyer_model": "claude-sonnet-4-6",
                    "retail_price": retail, "capable_worker_count": 1, "already_offered": true}],
                "generated_at": "2026-10-04T11:00:00Z",
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/miners/products"))
            .and(header(gm_miner_cli::client::PRICE_INCREASE_SCHEDULING_HEADER, "1"))
            .respond_with(ResponseTemplate::new(status).set_body_json(serde_json::json!({
                "code": "price_increase_scheduled",
                "detail": "Price increase scheduled for 2026-10-04T12:00:00+00:00. Current price remains active.",
                "active_discount_bp": 5000, "pending_discount_bp": 0,
                "effective_at": "2026-10-04T12:00:00+00:00",
            })))
            .expect(1)
            .mount(&server)
            .await;
        let config_dir = tempfile::tempdir().expect("temporary CLI configuration");
        std::fs::write(
            config_dir.path().join("config.json"),
            serde_json::to_vec(&serde_json::json!({
                "active_network": "testnet",
                "networks": {"testnet": {"api_url": server.uri(), "tokens": {
                    "access_token": "local-test-token", "token_expires_at": "2999-01-01T00:00:00Z"
                }}}
            }))
            .expect("serialize test config"),
        )
        .expect("write test config");
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_gmcli"));
        command
            .env("GMCLI_CONFIG_DIR", config_dir.path())
            .env_remove("GM_REGISTRY_URL")
            .arg(if bulk {
                "declare-products"
            } else {
                "declare-product"
            })
            .args(["--provider", "anthropic", "--discount-pct", "0", "--yes"]);
        if !bulk {
            command.args(["--model", "claude-sonnet-4-6"]);
        }
        let output = command.output().await.expect("run CLI binary");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            output.status.success(),
            status != 409,
            "status={status} bulk={bulk}\n{stdout}\n{stderr}"
        );
        if status == 202 {
            assert!(
                stdout.contains("Price increase scheduled for 2026-10-04T12:00:00+00:00"),
                "{stdout}"
            );
            assert!(stdout.contains("Current price remains active"), "{stdout}");
            if bulk {
                assert!(stdout.contains("1 price increase(s) scheduled"), "{stdout}");
                assert!(stdout.contains("1 ok, 0 failed"), "{stdout}");
            }
        } else if status == 409 {
            assert!(stderr.contains("409 Conflict"), "{stderr}");
            assert!(stderr.contains("Price increase scheduled"), "{stderr}");
        } else {
            assert!(stdout.contains("→ ok"), "{stdout}");
        }
    }
}
