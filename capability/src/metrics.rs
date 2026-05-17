//! Prometheus metrics for the miner capability service.
//!
//! Exposes the health and capacity signals the registry scrapes on
//! its control-loop cadence (spec §11.2):
//!
//! - `gm_miner_inflight_requests` — current in-flight Envoy requests
//! - `gm_miner_capacity_max` — configured max concurrent capacity
//!
//! The inflight counter is updated by Envoy's stats sink (out of scope
//! for this service); `capacity_max` is a static gauge set from env vars.
//! In v1 these are stubs: the registry uses them for `capacity_ok`
//! detection; Envoy's own `/stats` endpoint surfaces the real inflight.

use prometheus::{Encoder, Gauge, Registry, TextEncoder};

/// Metrics exported by this service.
pub struct MinerMetrics {
    pub inflight: Gauge,
    pub capacity_max: Gauge,
    pub registry: Registry,
}

/// Build the Prometheus registry with miner metrics pre-registered.
///
/// # Panics
/// Panics if Prometheus rejects a hardcoded metric name or rejects
/// registering a metric (neither can happen at runtime with valid
/// constant names and a fresh registry).
#[must_use]
pub fn build_registry() -> std::sync::Arc<MinerMetrics> {
    let registry = Registry::new();

    #[expect(
        clippy::expect_used,
        reason = "infallible: constant metric name + fresh registry"
    )]
    let inflight = Gauge::new(
        "gm_miner_inflight_requests",
        "Current number of in-flight upstream requests being proxied by Envoy. \
         Updated by Envoy stats; this gauge is a read-through stub in v1.",
    )
    .expect("inflight gauge");
    #[expect(
        clippy::expect_used,
        reason = "infallible: fresh registry, no duplicate names"
    )]
    registry
        .register(Box::new(inflight.clone()))
        .expect("register inflight");

    let capacity_max_val: f64 = std::env::var("GM_CAPACITY_MAX")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100.0);

    #[expect(
        clippy::expect_used,
        reason = "infallible: constant metric name + fresh registry"
    )]
    let capacity_max = Gauge::new(
        "gm_miner_capacity_max",
        "Maximum concurrent requests this miner is configured to serve.",
    )
    .expect("capacity_max gauge");
    capacity_max.set(capacity_max_val);
    #[expect(
        clippy::expect_used,
        reason = "infallible: fresh registry, no duplicate names"
    )]
    registry
        .register(Box::new(capacity_max.clone()))
        .expect("register capacity_max");

    std::sync::Arc::new(MinerMetrics {
        inflight,
        capacity_max,
        registry,
    })
}

/// Render all metrics in Prometheus text exposition format.
///
/// # Panics
/// Panics if the encoder fails or the output is not valid UTF-8 — neither
/// can occur for the Prometheus text format with ASCII metric names.
#[must_use]
pub fn render(metrics: &MinerMetrics) -> String {
    let encoder = TextEncoder::new();
    let mut buf = Vec::new();
    #[expect(clippy::expect_used, reason = "infallible: TextEncoder never fails")]
    encoder
        .encode(&metrics.registry.gather(), &mut buf)
        .expect("encode metrics");
    #[expect(
        clippy::expect_used,
        reason = "infallible: Prometheus text output is always valid UTF-8"
    )]
    String::from_utf8(buf).expect("valid utf8")
}
