# W4 Handoff — Miner Package

Branch: `phase1/miner`

## What was built

### Miner Docker image (`image/`)

- `image/Dockerfile` — multi-stage build: `rust:1.83-slim-bookworm` builder → `envoyproxy/envoy:v1.32-latest` runtime. Both base images are digest-pinned. Determinism flags set: `SOURCE_DATE_EPOCH=1700000000`, `RUSTFLAGS="-C codegen-units=1 -C debuginfo=0"`, `CARGO_INCREMENTAL=0`. Exposes 8080 (envoy data plane) and 9901 (envoy admin / `/stats/prometheus`, bound to localhost). Runs as `envoy` user (uid 100).
- `image/envoy.yaml` — static Envoy config with three provider clusters (Anthropic, OpenAI, Gemini) plus an `admin:` block on `127.0.0.1:9901` exposing `/stats/prometheus`. Routes on `x-gm-provider` header injected by the gateway. Each route strips gm-internal headers and injects the upstream API key from the corresponding env var. Fallback route returns 501 JSON when provider is unrecognized. All clusters use TLS with SAN verification and HTTP/2.
- `image/start.sh` — container entrypoint. Validates at least one provider key is set, then `exec`s envoy as PID 1.

### Capability model

The miner runtime is **envoy + native prometheus exposure only** — no sidecar service. The registry validates a miner's capability by probing envoy's data plane directly:

| Provider | Probe |
|---|---|
| Anthropic | `GET https://<miner>:8080/v1/models` with `x-gm-provider: anthropic` |
| OpenAI | `GET https://<miner>:8080/v1/models` with `x-gm-provider: openai` |
| Gemini | `GET https://<miner>:8080/v1beta/models` with `x-gm-provider: gemini` |

A `200` means the provider's key is configured and the upstream is reachable; a `401` means the key is missing or revoked; a `5xx` or timeout means the upstream is unreachable. The registry parses the upstream's native model-list response shape per provider rather than the canonical wrapper the old capability sidecar exposed.

### CLI (`cli/`)

Clap 4.5 binary `gm-miner` with eight subcommands:

| Subcommand | Action |
|---|---|
| `set-api-keys` | persists provider API keys to `~/.gm-miner/config.json` (mode 0600) |
| `deploy` | full trust-correct deploy: provisions GCP, builds/pushes the image, scaffolds/validates the dstack-cloud project, deploys, verifies hashes against the registry, registers the image |
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

- `dstack/docker-compose.yaml` — template with `${GM_IMAGE_REF:?...}` substituted by `gm-miner deploy`; passes the three optional provider API keys as env vars.
- `dstack/app.json.template` — reference shape for the trust-correct `app.json` (`key_provider: kms`, `gateway_enabled: true`, the trusted `kms_url`).

The full deploy pipeline lives in the `gm-miner deploy` subcommand (`cli/src/deploy.rs` + `cli/src/gcp.rs`): it preflights host tools, provisions the GCP project / service APIs / GCS bucket / Artifact Registry repo, builds and pushes the image, resolves the digest, scaffolds or validates the dstack-cloud project, pulls the OS image, writes `.env` (encrypted by dstack KMS at deploy time), runs `dstack-cloud deploy`, verifies the resulting hashes against the registry approval, and registers the image. It replaces the former `dstack/deploy.sh`.

### Docs (`docs/`)

- `docs/reproducibility.md` — partial reproducibility analysis: Rust binaries are deterministic; Docker layers are not (timestamps, layer ordering). Table of determinism sources. Instructions for re-pinning base images.

## Key decisions

**Envoy-only TEE runtime** — Updates to images that run inside TDX are operationally expensive (rebuild + re-attest + re-register). Keeping the miner's TEE workload as just envoy minimises the surface that has to change for any future feature. The capability sidecar that originally lived here was deleted in favour of the registry probing envoy's data plane directly — a 200 from `GET /v1/models` proves the upstream key works and lists the models, which is the only signal the old sidecar produced.

**Provider route discrimination** — The gateway adds `x-gm-provider: anthropic|openai|gemini` to every proxied request. Envoy dispatches on this header. Path-based routing would not work reliably across providers (all use similar `/v1/chat/completions` paths).

**Picodollar ceiling** — `u64::MAX as f64` rounds up, making a naive overflow check wrong. Used a practical constant `18.4 USD/Mtok` (safely below the true ceiling of ~18.446 USD/Mtok) to avoid ambiguity.

## Build verification

```
cargo clippy --all-targets --all-features -- -D warnings   # clean
cargo test                                                  # all tests pass
shellcheck image/start.sh                                   # clean
shfmt -d image/start.sh                                     # clean
```

## What W5 needs from W4

1. **Miner endpoint URL** — `https://<miner-ip>:8080`. The IP/hostname comes from `dstack-cloud status` after deploy. The registry probes upstream availability + key validity by issuing `GET /v1/models` (anthropic / openai) or `GET /v1beta/models` (gemini) with the `x-gm-provider` header.
2. **`compose_hash`** — SHA-256 of `docker-compose.yaml`, verified against the registry approval and registered automatically by `gm-miner deploy` (or read from `dstack-cloud status` for a manual `gm-miner register-image`).

## What is NOT done (Phase 2 scope)

- Real token refresh (CLI calls `login` again when access token expires; no silent refresh).
- `gm-miner update-prices` diff display (sends patch but does not show before/after).
- Per-miner prometheus enrichment beyond envoy's native stats: the registry-emitted `gm_miner_*` capacity/inflight gauges from the old capability sidecar are gone. Envoy's `envoy_http_*` and `envoy_cluster_*` series cover requests/latency/errors; capacity tagging can be reintroduced via prometheus `relabel_configs` rather than in-TEE code.
