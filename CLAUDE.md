# gmcli

A Rust CLI (`gmcli`) that operators use to deploy and manage a gm subnet
miner. The miner itself is a containerized workload running inside an Intel TDX
TEE managed by Phala Cloud. This CLI handles the full operator lifecycle:
authentication, miner image build/push, Phala Cloud deployment, hash
verification against the registry's approval list, image registration, product
declaration, and price management.

## Layout

- `cli/src/main.rs` — clap surface plus the `dispatch` / `dispatch_worker` routers; pure coordination, no logic
- `cli/src/commands/` — one module per subcommand handler (`deploy`, `products`, `pricing`, `hotkey`, `doctor`, `wizard`, `keys`, `earnings`, `fun`) plus `persist` (config/token persistence) and the shared `status_error`/`me_error` helpers in `commands/mod.rs`
- `cli/src/lib.rs` — module declarations; re-exports for binary and tests
- `cli/src/auth.rs` — Taostats device-code OAuth2 flow
- `cli/src/client.rs` — `RegistryClient`: typed HTTP wrappers for registry endpoints
- `cli/src/config.rs` — `Config` loaded from `~/.gmcli/config.json` (mode 0600); supports `mainnet`/`testnet` networks
- `cli/src/network.rs` — `Network` enum (testnet/mainnet) carrying `netuid`, chain websocket, and default registry URL; the seam later work (register-hotkey, earnings) reads coordinates from
- `cli/src/btcli.rs` — `BtcliBridge` trait + `RealBtcli`: bridge to `btcli` (bittensor-cli) for read-only wallet-list and metagraph queries; `gmcli` never signs an extrinsic or touches wallet keys — the operator runs any wallet-signing command themselves. `btcli_network()` maps `Network`→`test`/`finney`
- `cli/src/dependency.rs` — `ensure_dependency(&Dependency, assume_yes)`: reusable PATH-detect-and-offer-to-install primitive (e.g. `BTCLI`); `register-hotkey`'s assisted flow uses it, `deploy`/future init-wizard can adopt it
- `cli/src/register_hotkey.rs` — pure decision logic for `register-hotkey` (ss58 validation, bring-your-own vs assisted), testable against a stubbed `BtcliBridge`
- `cli/src/deploy/` — deploy orchestration split by responsibility: `mod.rs` (`prepare_deploy_target`, `ImageProvisioner`), `cvm.rs` (`PhalaClient` trait + `RealPhalaClient`, `phala deploy` / `phala cvms get`), `registry_auth.rs` (private-registry pull-credential probing), `compose.rs` (env/compose rendering), `version.rs` (image-version fetch/select), `hashes.rs` (hash normalize/verify)
- `cli/src/image.rs` — miner image build/push: `docker buildx --push` to a public registry, digest resolution
- `cli/src/node_secret.rs` — per-worker node secret: a fresh secret per worker (CVM), reused across re-deploys of the same `--app-name`, persisted in the worker's config record, embedded in compose env so envoy enforces it
- `cli/src/pricing.rs` — discount/price conversion (`parse_discount_pct`, `format_per_mtok_usd`, `effective_per_mtok_ndollars`) — decimal-string → nano-dollars (u64), integer-only, no floats
- `cli/src/types.rs` — shared types: `Provider`, `Product`, `MinerStatus`, and the worker request/response shapes (`WorkerCreateRequest`, `WorkerEntry`, `WorkerListResponse`)
- `azure-verify/` — `gm-azure-verify`: the Azure owner-capture checks, shared by `attestd` (fail-closed boot gate + periodic re-verification) and `gmcli doctor` (preflight). One crate on purpose: a doctor that promised a PASS the boot gate then refused would be worse than no preflight. `AzureVerifier::verify_target` is the gate's pass/fail; `audit_target` is the same sweep collecting every finding for doctor to print
- `image/` — the miner container image (Dockerfile, envoy config)
- `dstack/` — the compose template `gmcli deploy` renders and submits to Phala Cloud

## Build / lint / test

```bash
cd cli   # or from repo root

# build
cargo build --release -p gmcli

# lint
cargo clippy --all-targets --all-features -- -D warnings

# format check
cargo fmt --check

# tests (wiremock for registry HTTP; no real Phala Cloud / docker required)
cargo test -p gmcli
```

## Subcommands

| Command | Purpose |
|---|---|
| `init` | Guided onboarding wizard: register hotkey → login → set keys → deploy → declare products, skipping steps already done |
| `set-api-keys` | Persist provider API keys (Anthropic, OpenAI, Google, Chutes, Z.ai, Moonshot) and cloud-upstream selectors (Bedrock, Microsoft Foundry, Azure OpenAI) to `~/.gmcli/config.json` |
| `deploy` | Full trust-correct deploy: build/push image + Phala Cloud deploy + hash verification + image registration |
| `login` | Device-code OAuth flow; stores access token in config |
| `register-hotkey` | Record the serving hotkey: `--hotkey-ss58` records one registered elsewhere; otherwise (`--wallet`/`--hotkey`) resolves the local btcli hotkey, checks the metagraph, and prints the `btcli subnet register` command for the operator to run — gmcli never signs |
| `doctor` | Preflight checklist (network, login, provider keys, `phala` CLI + API key, Azure owner-capture controls, hotkey registration) with actionable fixes |
| `register-image` | Re-register an already-deployed image (debugging / registry resync; hidden from default help) |
| `declare-product` | Register a single miner-product offer with a pct discount |
| `declare-products` | Fan one discount across the catalog (or one provider) |
| `status` | Show current registration state, per-product eligibility, and the per-Mtok rate received; every ineligible offer is explained beneath the table with the registry's reason and the fix (`list-products` is a hidden alias) |
| `pricing` | Rank each offer against the eligible field on the scalar the gateway routes on — your rank, the field's size, its best/median cost, and the products others serve and you do not |
| `earnings` | Read the hotkey's neuron row from the subnet metagraph (via btcli) and report UID, stake, and per-tempo emission |
| `worker add/list/remove` | Manage the data-plane workers (Phala CVMs) attached to the hotkey |
| `publish-image-version` | Compute the release image's `compose_hash`/`os_image_hash` offline and upsert the approved `ImageVersion` to the registry (release pipeline; needs the registry admin key) |

Network selection is a sticky `--network testnet|mainnet` (mainnet by default);
`--testnet` is the shorthand. The `Network` profile (`cli/src/network.rs`)
carries each network's `netuid`, chain websocket, and default registry URL.

## Key conventions

- Anthropic offers can be served from three upstreams: `direct` (api.anthropic.com), `bedrock`, or `foundry` (Claude on Microsoft Foundry — an Anthropic-native passthrough at `https://<resource>.services.ai.azure.com/anthropic/v1/messages`, so envoy needs only the same host/path/header rewrite Bedrock uses). Cloud upstreams are single-slot and carry a registry `backend` marker; Foundry routes on the *deployment* name, declared per-offer with `--upstream-model`. `attestd` verifies each configured Azure account's owner-capture controls at boot and periodically, and `gmcli doctor` runs the same `gm-azure-verify` code as a preflight so the failure is caught before a CVM is paid for — see `AZURE_VERIFY_NOTES.md`, including what that verification does *not* cover. Azure attaches an Application Insights connection to a portal-created Foundry resource by default, and the gate refuses to boot while it exists: that is the single commonest Azure deploy failure.
- Prices are declared as a `--discount-pct` in `[0, 99.90]` with up to two decimal places. The CLI converts to integer basis-points (no floats) before sending to the registry. The miner receives `(100 - pct)%` of retail per Mtok.
- Each worker (Phala CVM) carries its own node secret, generated fresh on first deploy and reused on re-deploys of the same `--app-name`. The secret is embedded in the compose env, enforced by envoy, and stored in the registry — all three must stay in lockstep across re-deploys.
- Worker #1 (the worker `deploy` / `register-image` refresh via `POST /miners/register`) is the **oldest live worker in the registry**, read from `GET /miners/{hotkey}/workers` — never a local record's position. Local `WorkerRecord`s are not pruned when the registry deregisters a worker, so a dead CVM can sit at local position 1 forever. `workers::is_secondary_live` is the one place that decision is made.
- `phala deploy` cannot reuse a CVM name, so `deploy` / `worker add` probe for an existing CVM under `--app-name` before any image build and stop with the `phala cvms delete <app_id>` to run. gmcli never deletes a CVM: that destroys a running worker and stays the operator's explicit act.
- `--network` / `--testnet` are sticky: an explicit choice is persisted as `active_network`, so later commands target it until a different one is passed. `--api-url` is *not* sticky — it overrides the registry URL for a single run only (as does `GM_REGISTRY_URL`).
- `deploy` is the happy path: it verifies that the deployed compose hash and OS image hash exactly match the registry's approved version before registering the image. `register-image` exists only for re-registration without redeploying.
- Config file is at `~/.gmcli/config.json` (mode 0600). The `GM_REGISTRY_URL` env var can override the API URL for a single run without persisting.
- `deploy` and `register-image` shell out to the `phala` CLI (npm package `phala`, install with `npm i -g phala`). Phala Cloud auth uses a Phala Cloud API key: pass `--phala-api-key`, set `PHALA_API_KEY` / `PHALA_CLOUD_API_KEY`, or `phala auth login` for a CLI session. The `phala` CLI is preflighted at the start of `deploy` with an install hint.
- Supply-chain: workspace `deny.toml` governs advisory/license/ban checks (`cargo deny check`).
