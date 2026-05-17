# W4 Handoff — Miner Package

Branch: `phase1/miner`

## What was built

### Miner Docker image (`image/`)

- `image/Dockerfile` — multi-stage build: `rust:1.83-slim-bookworm` builder → `envoyproxy/envoy:v1.32-latest` runtime. Both base images are digest-pinned. Determinism flags set: `SOURCE_DATE_EPOCH=1700000000`, `RUSTFLAGS="-C codegen-units=1 -C debuginfo=0"`, `CARGO_INCREMENTAL=0`. Exposes 8080 (Envoy), 8443 (capability), 9090 (metrics). Runs as `envoy` user (uid 100).
- `image/envoy.yaml` — static Envoy config with three provider clusters (Anthropic, OpenAI, Gemini). Routes on `x-gm-provider` header injected by the gateway. Each route strips gm-internal headers and injects the upstream API key from the corresponding env var. Fallback route returns 501 JSON when provider is unrecognized. All clusters use TLS with SAN verification and HTTP/2.
- `image/start.sh` — container entrypoint. Validates at least one provider key is set, starts the capability service, waits for `/health` readiness, then starts Envoy.

### Capability service (`capability/`)

Axum 0.7 HTTP server; binary `gm-miner-capability`.

Endpoints:
- `GET /capability/anthropic` — bearer-authenticated; checks `ANTHROPIC_API_KEY` presence then calls `api.anthropic.com/v1/models`
- `GET /capability/openai` — bearer-authenticated; checks `OPENAI_API_KEY` then calls `api.openai.com/v1/models`
- `GET /capability/gemini` — bearer-authenticated; checks `GOOGLE_API_KEY` then calls `generativelanguage.googleapis.com/v1beta/models`
- `GET /health` — unauthenticated liveness probe; used by `start.sh` readiness check
- `GET /metrics` — Prometheus text format on separate port; exposes `gm_miner_inflight_requests` and `gm_miner_capacity_max`

Response shape (all endpoints): `{ schema_version: "1", provider, checked_at, env_var_present, upstream_ok, models[], rate_limit_headers, error? }`

Status codes: 200 when `upstream_ok || !env_var_present`; 503 when env var present but upstream unreachable.

Config via env vars: `CAPABILITY_PORT` (default 8443), `METRICS_PORT` (default 9090), `CAPABILITY_BEARER_TOKEN` (required; all requests rejected with 401 if absent), `GM_CAPACITY_MAX` (default 100).

Tests: 8 integration tests in `capability/tests/capability_integration.rs` using `tower::ServiceExt::oneshot`.

### CLI (`cli/`)

Clap 4.5 binary `gm-miner` with six subcommands:

| Subcommand | Action |
|---|---|
| `login` | OAuth 2.0 device-code flow via Taostats auth; saves tokens to `~/.gm-miner/config.json` |
| `register-image` | `POST /miners/register` with compose_hash + os_image_hash |
| `list-products` | `GET /products`; prints provider/model/status table |
| `declare-product` | `POST /miners/products` with provider, model, price block |
| `update-prices` | `PATCH /miners/products/{provider}/{model}/prices` |
| `status` | `GET /miners/me`; prints miner and per-product eligibility |

All price flags (`--price-input`, `--price-output`, `--price-cache-read`, `--price-cache-write-5m`, `--price-cache-write-1h`) accept USD/Mtok strings and convert to picodollars/Mtok (×10¹²) before sending to the registry.

Config persisted to `~/.gm-miner/config.json` (chmod 600 on Unix). Supports `--testnet` flag and `--api-url` override. Network-keyed config allows separate mainnet/testnet credentials.

Tests: 12 tests in `cli/tests/picodollar_test.rs` covering conversion, boundary conditions, and display formatting. 7 unit tests inline in `cli/src/picodollar.rs`.

### dstack compose template (`dstack/`)

- `dstack/docker-compose.yaml` — template with `${GM_IMAGE_REF:?...}` substituted by `deploy.sh`; passes all provider keys and capability config as env vars.
- `dstack/deploy.sh` — full deploy pipeline: builds/pushes multi-arch image to GCR, resolves digest, creates or updates the dstack-cloud project, writes `.env` (encrypted by dstack KMS at deploy time), runs `dstack-cloud deploy`.

### Docs (`docs/`)

- `docs/reproducibility.md` — partial reproducibility analysis: Rust binaries are deterministic; Docker layers are not (timestamps, layer ordering). Table of determinism sources. Instructions for re-pinning base images.

## Key decisions

**Trailing usage events** — v1 events are emitted as a stub Lua filter comment in `envoy.yaml`. The event is unsigned (no miner pubkey in v1 contracts). Full implementation is W3/W5 scope.

**Provider route discrimination** — The gateway adds `x-gm-provider: anthropic|openai|gemini` to every proxied request. Envoy dispatches on this header. Path-based routing would not work reliably across providers (all use similar `/v1/chat/completions` paths).

**Picodollar ceiling** — `u64::MAX as f64` rounds up, making a naive overflow check wrong. Used a practical constant `18.4 USD/Mtok` (safely below the true ceiling of ~18.446 USD/Mtok) to avoid ambiguity.

**Capability testability** — Added a `[lib]` target to `capability/Cargo.toml` so integration tests can import `gm_miner_capability::routes` and `gm_miner_capability::metrics` without needing to compile the binary.

## Build verification

```
cargo clippy --all-targets --all-features -- -D warnings   # clean
cargo test                                                  # 27 tests pass
shellcheck image/start.sh dstack/deploy.sh                 # clean
shfmt -d image/start.sh dstack/deploy.sh                   # clean
```

## What W5 needs from W4

1. **Capability bearer token** — generated by `deploy.sh` and printed to stdout. W5 (registry) must store this and send it as `Authorization: Bearer <token>` when calling `GET /capability/{provider}`.
2. **Capability endpoint URL** — `https://<miner-ip>:8443/capability/{provider}`. The IP/hostname comes from `dstack-cloud status` after deploy.
3. **`compose_hash`** — SHA-256 of `docker-compose.yaml` printed by `deploy.sh`. Pass to `gm-miner register-image --compose-hash <hash>`.

## What is NOT done (Phase 2 scope)

- Real token refresh (CLI calls `login` again when access token expires; no silent refresh).
- Trailing usage event signing (reserved in `envoy.yaml` Lua stub; requires miner pubkey from W5/W6).
- `gm-miner update-prices` diff display (sends patch but does not show before/after).
- Prometheus inflight gauge is read-only stub; Envoy stats integration is out of scope for v1.
