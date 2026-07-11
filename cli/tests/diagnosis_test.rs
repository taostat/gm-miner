//! Wire-shape tests for the miner diagnosis surface.
//!
//! Covers the three registry responses `gmcli status`, `gmcli pricing`, and
//! `gmcli worker list` read to answer "why am I not getting traffic":
//!
//!   * `GET /miners/me` — the per-offer ineligible reason + hint.
//!   * `GET /miners/me/pricing-competitiveness` — rank against the field.
//!   * `GET /miners/{hotkey}/workers` — suspension + key-slot state.
//!
//! Each field is additive on the registry side, so every shape is also
//! asserted to decode against a registry build that does not emit it yet.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test assertions intentionally panic on unexpected values"
)]

use gm_miner_cli::types::{MinerStatus, PricingCompetitiveness, WorkerListResponse};

#[test]
fn miner_status_decodes_the_ineligible_reason_and_hint() {
    let miner: MinerStatus = serde_json::from_value(serde_json::json!({
        "hotkey": "5Hk",
        "status": "active",
        "last_attestation_at": null,
        "image_compose_hash": null,
        "products": [{
            "provider": "anthropic",
            "model": "claude-sonnet-4-6",
            "is_offered": true,
            "is_eligible": false,
            "discount_bp": 500,
            "ineligible_reason": "capability_probe_failed: upstream rejected key (401)",
            "ineligible_hint": "Your upstream provider key was rejected (401).",
            "capability_check_passed_at": null,
        }],
    }))
    .unwrap();

    let offer = &miner.products[0];
    assert_eq!(
        offer.ineligible_reason.as_deref(),
        Some("capability_probe_failed: upstream rejected key (401)")
    );
    assert!(offer.ineligible_hint.as_deref().unwrap().contains("401"));
}

#[test]
fn miner_status_decodes_without_the_diagnosis_fields() {
    let miner: MinerStatus = serde_json::from_value(serde_json::json!({
        "hotkey": "5Hk",
        "status": "active",
        "last_attestation_at": null,
        "image_compose_hash": null,
        "products": [{
            "provider": "anthropic",
            "model": "claude-sonnet-4-6",
            "is_offered": true,
            "is_eligible": true,
            "discount_bp": 500,
        }],
    }))
    .expect("a registry that predates the diagnosis fields must still decode");

    assert!(miner.products[0].ineligible_reason.is_none());
    assert!(miner.products[0].capability_check_passed_at.is_none());
}

#[test]
fn pricing_competitiveness_decodes_rank_and_the_unsold_nudge() {
    let body: PricingCompetitiveness = serde_json::from_value(serde_json::json!({
        "hotkey": "5Hk",
        "products": [
            {
                "provider": "anthropic",
                "model": "claude-sonnet-4-6",
                "competitor_count": 5,
                "best_cost_ndollars": 16_200_000_000_u64,
                "median_cost_ndollars": 18_000_000_000_u64,
                "offered_by_you": true,
                "your_cost_ndollars": 18_000_000_000_u64,
                "your_discount_bp": 500,
                "your_rank": 3,
            },
            {
                "provider": "openai",
                "model": "gpt-5.6",
                "competitor_count": 2,
                "best_cost_ndollars": 12_000_000_000_u64,
                "median_cost_ndollars": 13_500_000_000_u64,
                "offered_by_you": false,
                "your_cost_ndollars": null,
                "your_discount_bp": null,
                "your_rank": null,
            },
        ],
    }))
    .unwrap();

    let mine = &body.products[0];
    assert_eq!(mine.your_rank, Some(3));
    assert_eq!(mine.competitor_count, 5);
    assert_eq!(mine.best_cost_ndollars, 16_200_000_000);

    let unsold = &body.products[1];
    assert!(!unsold.offered_by_you);
    assert!(unsold.your_cost_ndollars.is_none());
}

#[test]
fn worker_list_decodes_suspension_and_slot_state() {
    let list: WorkerListResponse = serde_json::from_value(serde_json::json!({
        "workers": [{
            "worker_id": "01J0A",
            "endpoint": "https://w1.example.org:8443",
            "status": "suspended",
            "last_attestation_at": "2026-07-11T08:00:00+00:00",
            "last_seen_at": "2026-07-11T08:29:00+00:00",
            "suspended_at": "2026-07-11T08:30:00+00:00",
            "next_probe_at": "2026-07-11T09:02:00+00:00",
            "suspended_reprobe_attempt": 3,
            "consecutive_ok": 1,
            "consecutive_ok_required": 2,
            "supported_models": {"openai": ["gpt-5.6"]},
            "provider_slot_status": {
                "openai": {"BBBBBBBBBBBB": {"status": "unverified", "models": []}}
            },
        }],
    }))
    .unwrap();

    let worker = &list.workers[0];
    assert_eq!(
        worker.suspended_at.as_deref(),
        Some("2026-07-11T08:30:00+00:00")
    );
    assert_eq!(
        worker.next_probe_at.as_deref(),
        Some("2026-07-11T09:02:00+00:00")
    );
    assert_eq!(worker.consecutive_ok, 1);
    assert_eq!(worker.consecutive_ok_required, 2);
    assert_eq!(worker.suspended_reprobe_attempt, 3);
    assert_eq!(
        worker.provider_slot_status["openai"]["BBBBBBBBBBBB"]
            .status
            .as_deref(),
        Some("unverified")
    );
    assert_eq!(worker.supported_models["openai"], vec!["gpt-5.6"]);
}

#[test]
fn worker_list_decodes_without_the_suspension_fields() {
    let list: WorkerListResponse = serde_json::from_value(serde_json::json!({
        "workers": [{
            "worker_id": "01J0A",
            "endpoint": "https://w1.example.org:8443",
            "status": "active",
            "last_attestation_at": null,
        }],
    }))
    .expect("a registry that predates the suspension fields must still decode");

    let worker = &list.workers[0];
    assert!(worker.suspended_at.is_none());
    assert_eq!(worker.consecutive_ok, 0);
    assert!(worker.provider_slot_status.is_empty());
}
