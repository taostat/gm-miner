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
- `cli/src/network.rs` — `Network` enum (testnet/mainnet) carrying `netuid`, chain websocket, and default registry URL; the seam later work (register-hotkey, earnings) reads coordinates from
- `cli/src/btcli.rs` — `BtcliBridge` trait + `RealBtcli`: bridge to `btcli` (bittensor-cli) for hotkey registration/metagraph queries; `gm-miner` never touches wallet keys. `btcli_network()` maps `Network`→`test`/`finney`
- `cli/src/dependency.rs` — `ensure_dependency(&Dependency, assume_yes)`: reusable PATH-detect-and-offer-to-install primitive (e.g. `BTCLI`); `register-hotkey`'s assisted flow uses it, `deploy`/future init-wizard can adopt it
- `cli/src/register_hotkey.rs` — pure decision logic for `register-hotkey` (ss58 validation, bring-your-own vs assisted), testable against a stubbed `BtcliBridge`
- `cli/src/deploy.rs` — `PhalaClient` trait + `RealPhalaClient`; deploy orchestration: compose rendering, `phala deploy`, `phala cvms get` hash polling, hash verification
- `cli/src/image.rs` — miner image build/push: `docker buildx --push` to a public registry, digest resolution
- `cli/src/node_secret.rs` — per-worker node secret: a fresh secret per worker (CVM), reused across re-deploys of the same `--app-name`, persisted in the worker's config record, embedded in compose env so envoy enforces it
- discount/price conversion lives in `cli/src/main.rs` (`parse_discount_pct`, `format_per_mtok_usd`) — decimal-string → nano-dollars (u64), integer-only, no floats
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
| `register-hotkey` | Record the serving hotkey: `--hotkey-ss58` records one registered elsewhere; otherwise registers a fresh hotkey via the `btcli` bridge (`--wallet`/`--hotkey`) |
| `doctor` | Preflight checklist (network, login, provider keys, `phala` CLI + API key, hotkey registration) with actionable fixes |
| `register-image` | Re-register an already-deployed image (debugging / registry resync; hidden from default help) |
| `declare-product` | Register a single miner-product offer with a pct discount |
| `declare-products` | Fan one discount across the catalog (or one provider) |
| `status` | Show current registration state, per-product eligibility, and the per-Mtok rate received (`list-products` is a hidden alias) |
| `worker add/list/remove` | Manage the data-plane workers (Phala CVMs) attached to the hotkey |

Network selection is a sticky `--network testnet|mainnet` (mainnet by default);
`--testnet` is the shorthand. The `Network` profile (`cli/src/network.rs`)
carries each network's `netuid`, chain websocket, and default registry URL.

## Key conventions

- All prices are accepted by the CLI as USD per million tokens (e.g. `"3.00"`) and converted to nano-dollars/Mtok (u64) before being sent to the registry. Conversion is decimal-string-only — no floats — so every nano-dollar of a sub-cent price is preserved exactly.
- The node secret is generated once per network (`mainnet`/`testnet`) and persisted to `~/.gm-miner/config.json`. It is embedded in the container's compose env, enforced by envoy, and stored in the registry — all three must stay in lockstep across re-deploys.
- `--network` / `--testnet` are sticky: an explicit choice is persisted as `active_network`, so later commands target it until a different one is passed. `--api-url` is *not* sticky — it overrides the registry URL for a single run only (as does `GM_REGISTRY_URL`).
- `deploy` is the happy path: it verifies that the deployed compose hash and OS image hash exactly match the registry's approved version before registering the image. `register-image` exists only for re-registration without redeploying.
- Config file is at `~/.gm-miner/config.json` (mode 0600). The `GM_REGISTRY_URL` env var can override the API URL for a single run without persisting.
- `deploy` and `register-image` shell out to the `phala` CLI (npm package `phala`, install with `npm i -g phala`). Phala Cloud auth is a Phala Cloud API key — set `PHALA_CLOUD_API_KEY` or run `phala login` before deploying. The `phala` CLI is preflighted at the start of `deploy` with an install hint.
- Supply-chain: workspace `deny.toml` governs advisory/license/ban checks (`cargo deny check`).
