//! gm miner OAuth-subscription token-refresh sidecar.
//!
//! Runs alongside Envoy inside the miner's TEE container. Reads sealed
//! `GM_<PROVIDER>_OAUTH_*` env vars at startup, periodically refreshes
//! provider access tokens against the upstream OAuth endpoints
//! (`auth.openai.com` / `console.anthropic.com`), and exposes the
//! current Bearer token plus expiry on a loopback HTTP endpoint Envoy
//! pulls from via its `lua` filter.
//!
//! The wire shapes here follow `docs/research/oauth-subscription-
//! prior-art.md` (Hermes / `OpenClaw` research) — 120-second refresh
//! skew before access-token expiry, exponential backoff with jitter on
//! failure, mark the provider down after the configured retry budget
//! is exhausted so Envoy's per-provider route returns 503 (which the
//! gateway's capacity-aware router already treats as zero capacity for
//! that provider on this miner).
//!
//! Module layout:
//!
//! * [`config`]  — read sealed env vars into a per-provider config struct
//! * [`provider`] — provider-specific OAuth refresh-endpoint shape
//! * [`refresh`] — single-shot token refresh against the upstream
//! * [`state`]   — shared in-memory token cache the HTTP server reads
//! * [`metrics`] — Prometheus counter / gauge bundle
//! * [`server`]  — axum routes (`/token/{provider}`, `/healthz`, `/metrics`)
//! * [`worker`]  — per-provider tokio task that drives `refresh`
//!   against `state` on the skew-before-expiry schedule

#![forbid(unsafe_code)]

pub mod config;
pub mod metrics;
pub mod provider;
pub mod refresh;
pub mod server;
pub mod state;
pub mod worker;

pub use config::{ProviderConfig, SidecarConfig};
pub use metrics::Metrics;
pub use provider::{OauthProvider, ProviderEndpoints};
pub use refresh::{refresh_once, RefreshError, RefreshOutcome};
pub use state::{ProviderState, TokenSnapshot};
pub use worker::{run_provider_worker, RetryPolicy};
