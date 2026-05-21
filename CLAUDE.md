# gm-miner

A Rust CLI (`gm-miner`) that operators use to deploy and manage a gm subnet
miner. The miner itself is a containerized workload running inside an Intel TDX
TEE managed by Phala Cloud. This CLI handles the full operator lifecycle:
authentication, miner image build/push, Phala Cloud deployment, hash
verification against the registry's approval list, image registration, product
declaration, and price management.

## Layout

- `cli/src/main.rs` — all CLI subcommand dispatch; pure coordination, no logic
- `cli/src/lib.rs` — module declarations; re-exports for binary and tests
- `cli/src/auth.rs` — Taostats device-code OAuth2 flow
- `cli/src/client.rs` — `RegistryClient`: typed HTTP wrappers for registry endpoints
- `cli/src/config.rs` — `Config` loaded from `~/.gm-miner/config.json` (mode 0600); supports `mainnet`/`testnet` networks
- `cli/src/deploy.rs` — `PhalaClient` trait + `RealPhalaClient`; deploy orchestration: compose rendering, `phala deploy`, `phala cvms get` hash polling, hash verification
- `cli/src/image.rs` — miner image build/push: `docker buildx --push` to a public registry, digest resolution
- `cli/src/node_secret.rs` — per-network node secret: generated once, persisted in config, embedded in compose env so envoy enforces it
- `cli/src/picodollar.rs` — USD/Mtok string → picodollars (u64) conversion; integer-only, no floats
- `cli/src/types.rs` — shared types: `MinerPriceBlock`, `MinerStatus`, `Product`, `Provider`
- `image/` — the miner container image (Dockerfile, envoy config)
- `dstack/` — the compose template `gm-miner deploy` renders and submits to Phala Cloud

## Build / lint / test

```bash
cd cli   # or from repo root

# build
cargo build --release -p gm-miner-cli

# lint
cargo clippy --all-targets --all-features -- -D warnings

# format check
cargo fmt --check

# tests (wiremock for registry HTTP; no real Phala Cloud / docker required)
cargo test -p gm-miner-cli
```

## Subcommands

| Command | Purpose |
|---|---|
| `set-api-keys` | Persist provider API keys (Anthropic, OpenAI, Google) to `~/.gm-miner/config.json` |
| `deploy` | Full trust-correct deploy: build/push image + Phala Cloud deploy + hash verification + image registration |
| `login` | Device-code OAuth flow; stores access token in config |
| `register-image` | Re-register an already-deployed image (debugging / registry resync) |
| `list-products` | Show the registry product catalog |
| `declare-product` | Register a miner-product offer with prices in USD/Mtok |
| `update-prices` | Update prices on an existing offer |
| `status` | Show current registration state and per-product eligibility |

## Key conventions

- All prices are accepted by the CLI as USD per million tokens (e.g. `"3.00"`) and converted to picodollars/Mtok (u64) before being sent to the registry. Conversion is decimal-string-only — no floats — so every picodollar of a sub-cent price is preserved exactly.
- The node secret is generated once per network (`mainnet`/`testnet`) and persisted to `~/.gm-miner/config.json`. It is embedded in the container's compose env, enforced by envoy, and stored in the registry — all three must stay in lockstep across re-deploys.
- `--testnet` / `--api-url` are resolved on every invocation and never sticky-overwrite the stored config's `active_network`. A prior `--testnet` run does not silently affect the next command.
- `deploy` is the happy path: it verifies that the deployed compose hash and OS image hash exactly match the registry's approved version before registering the image. `register-image` exists only for re-registration without redeploying.
- Config file is at `~/.gm-miner/config.json` (mode 0600). The `GM_REGISTRY_URL` env var can override the API URL for a single run without persisting.
- `deploy` and `register-image` shell out to the `phala` CLI (npm package `phala`, install with `npm i -g phala`). Phala Cloud auth is a Phala Cloud API key — set `PHALA_CLOUD_API_KEY` or run `phala login` before deploying. The `phala` CLI is preflighted at the start of `deploy` with an install hint.
- Supply-chain: workspace `deny.toml` governs advisory/license/ban checks (`cargo deny check`).
