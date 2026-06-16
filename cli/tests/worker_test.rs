//! Tests for the `gmcli worker add/list/remove` wire shapes and the
//! `RegistryClient` paths they use.
//!
//! Covers:
//!   * `WorkerCreateRequest` serialises to the exact
//!     `{endpoint, attestation_endpoint, compose_hash, os_image_hash,
//!     node_secret}` body `POST /miners/{hotkey}/workers` expects.
//!   * A wiremock-backed round-trip proves the body actually put on the
//!     wire for `worker add` matches that shape and carries the per-worker
//!     node secret.
//!   * `WorkerListResponse` / `WorkerCreateResponse` deserialise the
//!     registry's response shapes.
//!   * `RegistryClient::delete` issues the `worker remove` call and a 204
//!     is treated as success.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test assertions intentionally panic on unexpected values"
)]

use gm_miner_cli::{
    client::RegistryClient,
    config::{Config, NetworkEntry, TokenEntry},
    types::{WorkerCreateRequest, WorkerCreateResponse, WorkerListResponse},
};
use wiremock::{
    matchers::{body_json, header, method, path},
    Mock, MockServer, ResponseTemplate,
};

// ── Pure serialization tests ─────────────────────────────────────────────────

#[test]
fn worker_create_request_serialises_to_registry_shape() {
    let body = serde_json::to_value(WorkerCreateRequest {
        endpoint: "https://app_x-8080s.dstack-prod5.phala.network",
        attestation_endpoint: "https://app_x-8080s.dstack-prod5.phala.network",
        compose_hash: "a".repeat(64).as_str(),
        os_image_hash: "b".repeat(64).as_str(),
        node_secret: Some("deadbeef"),
    })
    .unwrap();

    assert_eq!(
        body,
        serde_json::json!({
            "endpoint": "https://app_x-8080s.dstack-prod5.phala.network",
            "attestation_endpoint": "https://app_x-8080s.dstack-prod5.phala.network",
            "compose_hash": "a".repeat(64),
            "os_image_hash": "b".repeat(64),
            "node_secret": "deadbeef",
        }),
        "worker-add body must match POST /miners/{{hotkey}}/workers exactly"
    );
}

#[test]
fn worker_list_response_deserialises() {
    let json = serde_json::json!({
        "workers": [
            {
                "worker_id": "01J0A",
                "endpoint": "https://w1",
                "attestation_endpoint": "https://w1",
                "status": "active",
                "image_compose_hash": null,
                "last_attestation_at": "2026-06-12T00:00:00Z",
                "supported_models": {},
                "created_at": "2026-06-11T00:00:00Z"
            },
            {
                "worker_id": "01J0B",
                "endpoint": "https://w2",
                "attestation_endpoint": "https://w2",
                "status": "pending",
                "last_attestation_at": null,
                "created_at": "2026-06-11T00:00:00Z"
            }
        ]
    });
    let list: WorkerListResponse = serde_json::from_value(json).unwrap();
    assert_eq!(list.workers.len(), 2);
    assert_eq!(list.workers[0].worker_id, "01J0A");
    assert_eq!(list.workers[0].status, "active");
    assert_eq!(
        list.workers[0].last_attestation_at.as_deref(),
        Some("2026-06-12T00:00:00Z")
    );
    assert_eq!(list.workers[1].last_attestation_at, None);
}

#[test]
fn worker_create_response_deserialises() {
    let json = serde_json::json!({
        "worker_id": "01J0C",
        "miner_hotkey": "5HK",
        "status": "pending",
        "created_at": "2026-06-12T00:00:00Z"
    });
    let created: WorkerCreateResponse = serde_json::from_value(json).unwrap();
    assert_eq!(created.worker_id, "01J0C");
    assert_eq!(created.miner_hotkey, "5HK");
    assert_eq!(created.status, "pending");
}

// ── Wire round-trip with wiremock ────────────────────────────────────────────

fn config_for(server: &MockServer) -> Config {
    let mut networks = std::collections::HashMap::new();
    networks.insert(
        "testnet".to_owned(),
        NetworkEntry {
            api_url: Some(server.uri()),
            tokens: Some(TokenEntry {
                access_token: Some("test-token".to_owned()),
                refresh_token: None,
                token_expires_at: None,
            }),
            workers: Vec::new(),
            legacy_node_secret: None,
            registered_hotkey: None,
        },
    );
    Config {
        active_network: Some("testnet".to_owned()),
        provider_keys: None,
        phala_api_key: None,
        api_url_override: None,
        accepted_terms: None,
        networks,
    }
}

#[tokio::test]
async fn worker_add_puts_exact_body_with_per_worker_secret_on_the_wire() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/miners/5HK/workers"))
        .and(header("authorization", "Bearer test-token"))
        .and(body_json(serde_json::json!({
            "endpoint": "https://app_x-8080s.dstack-prod5.phala.network",
            "attestation_endpoint": "https://app_x-8080s.dstack-prod5.phala.network",
            "compose_hash": "a".repeat(64),
            "os_image_hash": "b".repeat(64),
            "node_secret": "per-worker-secret",
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "worker_id": "01J0C",
            "miner_hotkey": "5HK",
            "status": "pending",
            "created_at": "2026-06-12T00:00:00Z"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let body = serde_json::to_value(WorkerCreateRequest {
        endpoint: "https://app_x-8080s.dstack-prod5.phala.network",
        attestation_endpoint: "https://app_x-8080s.dstack-prod5.phala.network",
        compose_hash: "a".repeat(64).as_str(),
        os_image_hash: "b".repeat(64).as_str(),
        node_secret: Some("per-worker-secret"),
    })
    .unwrap();

    let mut client = RegistryClient::new(config_for(&server));
    let resp = client
        .post("/miners/5HK/workers", &body)
        .await
        .expect("POST must reach the mock");
    assert_eq!(resp.status().as_u16(), 201);

    let created: WorkerCreateResponse = resp.json().await.expect("parse response");
    assert_eq!(created.worker_id, "01J0C");
}

#[tokio::test]
async fn worker_remove_issues_delete_and_treats_204_as_success() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/miners/5HK/workers/01J0C"))
        .and(header("authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let mut client = RegistryClient::new(config_for(&server));
    let resp = client
        .delete("/miners/5HK/workers/01J0C")
        .await
        .expect("DELETE must reach the mock");
    assert_eq!(resp.status().as_u16(), 204);
}
