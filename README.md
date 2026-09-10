# gm-miner

Miner image and CLI for the [gm](https://saygm.com) Bittensor subnet (netuid 28 mainnet, 482
testnet). Buyers point an existing OpenAI / Anthropic / Gemini SDK at the gm gateway and get
identical behavior; miners supply upstream API capacity and earn the spread. The gateway runs
inside an Intel TDX TEE so neither operators nor host machines see buyer content or miners'
upstream keys.

You bring your own provider API keys (Anthropic, OpenAI, Google, Chutes, Z.ai, Moonshot,
DeepInfra, KubeTEE, Engy, Moonmath, NEAR AI Cloud, or Bedrock/Foundry/Azure transport backends
behind the existing Anthropic/OpenAI routes) and your own funded
[Phala Cloud](https://cloud.phala.network) account. Transport capability is not registry
admission: Azure OpenAI chat completions and Foundry Messages are qualified only when the
image's `upstream-model-hop` feature and the registry's `upstream-model-echo` capability are
both present. Azure Responses is unqualified because its echo is the deployment name, and
Bedrock inference is disabled: requests return 421 with a slot header and 400 without one. Direct
Anthropic/OpenAI routes use verified key slots enforced by the miner runtime. The `gmcli` tool
handles the full operator lifecycle from your laptop.

| Path | Description |
|---|---|
| `image/` | Miner container image with eleven provider routes (Anthropic / OpenAI / Gemini / Chutes / Z.ai / Moonshot / DeepInfra / KubeTEE / Engy / Moonmath / NEAR) and an optional `benchmark` route to a synthetic upstream. Anthropic can target direct Anthropic, AWS Bedrock, or Microsoft Foundry; OpenAI can target direct OpenAI or Azure OpenAI. NEAR requests pass through an in-image verifier which attests the exact upstream TLS connection before forwarding. Pinned to digest. At startup the entrypoint mints the data-plane RA-TLS certificate (one-shot), then runs the attestation server, optional NEAR verifier, and Envoy data plane. |
| `cli/` | `gmcli` CLI (Rust + clap). Operator commands handle login, image registration, products, and prices. The image also uses its hidden `slot-env` command to derive upstream key slots inside the TEE. |
| `dstack/` | Docker Compose template for the miner workload; `gmcli deploy` renders it and submits it to Phala Cloud. |
| `docs/` | Operator-facing docs including reproducibility caveats. |

## Quick start

Three steps to a running miner.

1. **Install the Phala CLI** (the miner deploys to Phala Cloud) and have a funded account:

   ```sh
   npm i -g phala
   phala auth login          # or set PHALA_API_KEY
   ```

   A new miner needs a funded Phala Cloud account — sign up at <https://cloud.phala.network> and
   create an API key (Dashboard → API Keys).

2. **Install gmcli:**

   ```sh
   curl --proto '=https' --tlsv1.2 -LsSf \
     https://github.com/taostat/gm-miner/releases/latest/download/gmcli-installer.sh | sh
   ```

   The installer places the binary in `~/.cargo/bin` (or `CARGO_HOME`) and ensures that
   directory is on your `PATH`. To install a specific version, replace `latest/download` with
   `download/<tag>`, e.g. `https://github.com/taostat/gm-miner/releases/download/v0.1.0/gmcli-installer.sh`.

   To upgrade later:

   ```sh
   gmcli update
   ```

   That replaces the binary in place with the latest release and needs no login. Nothing warns
   you when your CLI is behind, so a documented command that reports `unrecognized subcommand`
   usually means an upgrade is due rather than a missing feature; `gmcli --version` confirms
   what you are on.

3. **Run the guided onboarding:**

   ```sh
   gmcli --network testnet init   # testnet (netuid 482)
   gmcli init                     # mainnet (netuid 28, default)
   ```

   `gmcli init` walks you through hotkey → login → provider keys → deploy → declare products,
   detecting and skipping anything already done. That's it.

## Manual setup (advanced)

Prefer to run each step yourself? `gmcli init` just orchestrates these:

### 1. Register your hotkey

Your miner earns emissions under a Bittensor hotkey. Record it with `gmcli register-hotkey`.

**Bring-your-own (no btcli needed):** if you already registered the hotkey elsewhere (a browser
wallet, Bittensor explorer, or another machine), pass the ss58 address directly:

```sh
gmcli register-hotkey --hotkey-ss58 5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY
```

**Assisted flow (requires btcli):** if you have not registered yet, omit `--hotkey-ss58` and
pass the btcli wallet and hotkey name. gmcli resolves the hotkey's ss58 from your local btcli
wallet, checks the subnet metagraph, and — when the hotkey isn't registered yet — prints the
exact `btcli subnet register` command for you to run. gmcli never signs an on-chain extrinsic
or touches your wallet keys; you run any wallet-signing command yourself:

```sh
gmcli register-hotkey --wallet miner --hotkey default
```

btcli is only needed for these read-only wallet/metagraph lookups in the assisted flow. The
bring-your-own path (`--hotkey-ss58`) has no btcli dependency.

### 2. Log in

Authenticate with Taostats (device-code OAuth). The browser opens automatically; pass
`--no-browser` to print the URL instead:

```sh
gmcli login
gmcli --network testnet login   # testnet
```

Credentials are stored in `~/.gmcli/config.json`.

### 3. Set your provider API keys

Your provider API keys (Anthropic, OpenAI, Google, Chutes, Z.ai, Moonshot, DeepInfra, KubeTEE,
Engy, Moonmath, NEAR) are baked into the miner container at
deploy time and stay inside the TEE — gm never sees them. Set the keys for whichever providers you
intend to serve:

```sh
gmcli set-api-keys --anthropic sk-ant-...
gmcli set-api-keys --openai sk-... --google AIza...
gmcli set-api-keys --chutes cpk-...
gmcli set-api-keys --zai zai-...
gmcli set-api-keys --moonshot sk-...
gmcli set-api-keys --deepinfra ...
gmcli set-api-keys --kubetee sk-...
gmcli set-api-keys --engy sk-...
gmcli set-api-keys --moonmath sk-...
gmcli set-api-keys --near near-...
```

Each flag replaces the stored value; omitted flags leave existing values intact.
See [the miner model sourcing matrix](docs/provider-model-support.md) to choose
where to source each model you want to provide.
For direct upstreams, each existing key flag also accepts up to 8 semicolon-separated keys. The
miner advertises opaque slot ids for those keys so the gateway can pick one per request:

```sh
gmcli set-api-keys --anthropic "sk-ant-a;sk-ant-b;sk-ant-c"
```

See [multi-key slots](docs/multi-key-slots.md) for the slot behavior and limits.

DeepInfra, Engy's GLM/Kimi routes, Moonmath, NEAR, and KubeTEE's GLM/Kimi routes are *sourcing*
upstreams: they serve buyer products under existing names rather than appearing
in the catalog under their own names. Engy's Qwen3.6 35B-A3B and Qwen3.8 27B,
plus KubeTEE's
`deepseek/deepseek-v4-flash-0731` and `ornith/ornith-1.5-397b` are instead
buyer-visible products. KubeTEE's `deepseek/deepseek-v4.1-flash` is a source
route for the canonical `deepseek-v4.1-flash` buyer product. The precise model
ids are listed in the
[miner model sourcing matrix](docs/provider-model-support.md). One model can have several such
routes and none of them is canonical. Setting one of those keys is what makes the matching route
available to you. A single worker can serve only one route per model, so run two workers to use
two upstreams for the same model. Run `gmcli sources` to see the routes your registry currently
publishes, and read [sourcing routes](docs/sourcing.md) for setup and settlement details.

The Gemini image-generation products `gemini-3.1-flash-lite-image` and
`gemini-3.1-flash-image` use Google's native
`POST /v1beta/models/{model}:generateContent` API. They are not OpenAI-compatible
chat routes. Their definitions are available on both networks, so pricing,
status, and catalog payloads can decode every image dimension. Select the
network whose offer you intend to change:

```sh
gmcli --network testnet declare-product \
  --provider gemini --model gemini-3.1-flash-image --discount-pct 5

gmcli --network mainnet declare-product \
  --provider gemini --model gemini-3.1-flash-image --discount-pct 5
```

Capability and health checks use a text-only Gemini request and do not generate
a paid image. When you intentionally want to spend one small native image
request per SKU on testnet, use the [Gemini image canary](docs/image-canary.md);
it preflights both live eligible offers and prints only safe response/balance
reconciliation evidence. Downstream validator, finalizer, and dashboard
evidence is a separate GM runbook check. See the [provider support
matrix](docs/provider-model-support.md) for the provider-side setup.

Azure OpenAI chat completions and Microsoft Foundry Messages forward the request body
unchanged through Envoy's existing TLS clusters. **Name each Azure or Foundry deployment
exactly the canonical gm model id**, such as `gpt-5.4` or `claude-opus-4-6`.
The image verifies through ARM that a catalog-named deployment X serves model X, with
format `OpenAI` for Azure OpenAI or `Anthropic` for Foundry, using exact ASCII comparison.
A mismatch blocks boot or takes the worker offline at the next 60-second deployment poll.
Non-catalog names are ignored by this binding check; a missing deployment is handled by
the registry's per-offer probe and the gateway's upstream 404 handling.

Cloud registration, recovery and declaration require registry capability
`upstream-model-echo`; deployment also requires the approved image feature
`upstream-model-hop`. These contract names are unchanged. The gateway checks each response's
model echo. Azure Responses still returns a typed JSON 400 because its echo identifies the
deployment name. Bedrock inference remains disabled: 421 with a slot header, typed 400 without.
Azure OpenAI and Foundry each accept exactly one HMAC slot derived from their single cloud key;
all other slot ids return 421. Cloud keys cannot contain semicolons.

Configure Azure OpenAI with its endpoint, API key and account-scoped Reader credentials:

```sh
gmcli set-api-keys \
  --openai-upstream azure \
  --azure-openai-endpoint https://<resource>.openai.azure.com \
  --azure-openai-api-key <azure-api-key> \
  --azure-tenant-id <tenant> \
  --azure-subscription-id <subscription> \
  --azure-resource-group <rg> \
  --azure-client-id <appId> \
  --azure-client-secret <password>
```

For Foundry, use its Anthropic endpoint and separate Reader credentials:

```sh
gmcli set-api-keys \
  --anthropic-upstream foundry \
  --azure-foundry-endpoint https://<resource>.services.ai.azure.com \
  --azure-foundry-api-key <foundry-api-key> \
  --azure-foundry-tenant-id <tenant> \
  --azure-foundry-subscription-id <subscription> \
  --azure-foundry-resource-group <rg> \
  --azure-foundry-client-id <appId> \
  --azure-foundry-client-secret <password>
```

See [Foundry setup](docs/foundry-setup.md) for deployment creation prerequisites,
the creation API version, replacement procedure, and capture controls to clear.
The verifier reads ARM identities; it does not create or replace deployments.

Run `gmcli doctor` before deploying. It lists the bound account's ARM deployments
(name, format, model, version), flags every catalog-named mismatch, and sends one
1-token request per honestly named catalog deployment, printing the echoed model beside
the deployment name. Worker `backends` remain transport provenance; offers use the same
canonical `provider/model` as direct supply.


### 4. Deploy your miner

Deploy creates a Phala Cloud CVM, verifies the deployed image hashes against the registry's
approved versions, and registers the worker — all in one step.

**You need a funded Phala Cloud account.** Sign up at <https://cloud.phala.network> and create
an API key (Dashboard → API Keys). gmcli will prompt for it on the first deploy and save it for
later runs. Pass `--phala-api-key <key>` or set `PHALA_API_KEY` to skip the prompt.

Most miners deploy the gm-published image (no Docker build required):

```sh
gmcli deploy
```

For testnet:

```sh
gmcli --network testnet deploy
```

Deploy takes a few minutes. When it finishes it prints the `worker_id` and `app_id` and
suggests the next step.

To check everything is in order before deploying, run the preflight checklist:

```sh
gmcli doctor
```

### 5. Declare your products and prices

Tell the registry which models you serve and at what discount off retail. The discount sets your
payout: a 10% discount means you keep 90% of each per-Mtok dollar.

Fan one discount across the whole catalog. Bulk declaration checks the registry's
`upstream-model-echo` capability, retains direct/API-key providers, and explicitly skips
cloud-backed entries because the bulk wire request has no per-deployment binding. A single cloud
declaration requires that capability check. `gmcli deploy` separately checks the approved
image for `upstream-model-hop`; per-worker offer admission belongs to the registry.
The canonical model id also names the deployment; the
registry contract has no separate deployment-name field:

```sh
gmcli declare-products --discount-pct 5
```

Or filter to one provider:

```sh
gmcli declare-products --provider anthropic --discount-pct 5
gmcli declare-products --provider openai --discount-pct 10
```

If the selected provider uses Bedrock, Foundry or Azure, bulk declaration skips those offers and
explains that a binding is not sent by the bulk request. To declare a
single direct/API-key offer:

```sh
gmcli declare-product --provider anthropic --model claude-sonnet-4-6 --discount-pct 5
```

`--discount-pct` accepts a value in `[0, 99.90]` with up to two decimal places (e.g. `10.5`).
`0` means at retail; `99.90` is the cap (keeps per-request revenue strictly positive).
Use the registry-owned source model for every admitted route; do not override it with a deployment
name. After the capability check, a cloud offer is declared exactly like its direct
counterpart; the registry decides whether each worker is eligible. Azure Responses and Bedrock remain unqualified; legacy Bedrock ids remain
representable for audit and transport diagnostics.

Before anything is sent, both commands resolve the percentage into the absolute per-Mtok price
you would receive on **every dimension the product prices** — input and output, plus prompt
cache, audio, image and long-context rates where the model has them — print those figures, and ask you
to confirm. Dimensions a model does not price are not listed. Pass `--yes` to skip the prompt;
a non-interactive stdin skips it too, so scripted declarations keep working unchanged.

What is sent is the percentage, not those figures: the registry resolves them against its own
retail when it records the offer, so the printed numbers are "at current retail" and a retail
change in between moves what you are paid. The output says so, and `gmcli status` shows the
rate each standing offer is actually on.

To see the buyer products and the explicit capability/admission status for each route:

```sh
gmcli sources
```

These settle on the *buyer* product's retail less your discount, so the gap between that and what
the upstream charges you is your spread. See [sourcing routes](docs/sourcing.md).

### 6. Check your status

```sh
gmcli status
```

Shows your registration state and, for each declared product, whether it is offered and
eligible, plus the per-Mtok rate you will actually receive.

### 7. Monitor your earnings

```sh
gmcli earnings
```

Reads your hotkey's neuron row from the subnet metagraph (via btcli) and reports UID, stake,
and per-tempo emission. btcli is required for this command; gmcli offers to install it if
missing.

## Managing multiple workers

The first `gmcli deploy` creates worker #1. To attach further capacity under the same hotkey,
use `gmcli worker add` with a distinct `--app-name`:

```sh
gmcli worker add --app-name gm-miner-2
```

List all workers:

```sh
gmcli worker list
```

Deregister a worker (does not tear down the Phala CVM — run `phala cvms delete <app_id>`
separately):

```sh
gmcli worker remove <worker_id>
```

## Command reference

| Command | Description |
|---|---|
| `gmcli init` | Guided onboarding wizard: register hotkey → login → set keys → deploy → declare products |
| `gmcli login` | Device-code OAuth login; stores credentials in `~/.gmcli/config.json` |
| `gmcli register-hotkey` | Record the serving hotkey (`--hotkey-ss58` or assisted via btcli) |
| `gmcli deploy` | Full deploy: fetch approved image, launch Phala CVM, verify hashes, register worker |
| `gmcli set-api-keys` | Persist provider API keys (Anthropic, OpenAI, Google, Chutes, Z.ai, Moonshot, DeepInfra, KubeTEE, Engy, Moonmath, NEAR) |
| `gmcli declare-product` | Declare a single model offer with a discount |
| `gmcli declare-products` | Fan one discount across the catalog or one provider's slice |
| `gmcli undeclare-product` | Withdraw a single offer; re-declaring re-offers it |
| `gmcli undeclare-products` | Withdraw every standing offer (`--all`) or one provider's slice |
| `gmcli status` | Registration state + per-product eligibility and rates |
| `gmcli pricing` | Rank each offer against the eligible field on the scalar the gateway routes on |
| `gmcli sources` | List [sourcing routes](docs/sourcing.md), separating transport capability from current registry admission |
| `gmcli earnings` | On-chain hotkey emission from the subnet metagraph (requires btcli) |
| `gmcli doctor` | Preflight checklist (network, login, keys, Phala CLI + key, hotkey) |
| `gmcli check-streaming` | Probe streaming through one selected worker: its verified provider/model coverage, including each offered sourcing route and upstream key slot |
| `gmcli image-canary` | Testnet-only, funded native Gemini image preflight and two-SKU settlement reconciliation (paid; never part of health checks) |
| `gmcli update` | Upgrade gmcli in place to the latest release (no login required) |
| `gmcli worker add` | Attach a new Phala CVM as an additional worker |
| `gmcli worker list` | List workers with per-worker status and last attestation |
| `gmcli worker remove` | Deregister a worker from the registry |

All commands accept `--network testnet|mainnet` (default: mainnet). The selection is sticky:
pass it once and every later command targets it until you pass a different one. `--testnet` is
shorthand for `--network testnet`.

## Configuration

Config is stored in `~/.gmcli/config.json` (mode 0600). To use a different directory:

```sh
GMCLI_CONFIG_DIR=/path/to/dir gmcli login
```

The `GM_REGISTRY_URL` env var overrides the registry API URL for a single run without
persisting it.

The paid image canary uses a buyer key, not a provider key. Set `GM_API_KEY` (or
pass `--buyer-api-key`) and run it with `--network testnet`. It defaults to the
testnet gateway; `GM_GATEWAY_URL` is available only as a per-run override for
local/mock verification. See [docs/image-canary.md](docs/image-canary.md).

## Troubleshooting

**`gmcli doctor` is the first diagnostic step.** It prints a green/red checklist of everything
deploy needs and names the command that fixes each red item.

| Symptom | Fix |
|---|---|
| "no provider keys" on deploy | `gmcli set-api-keys --anthropic <key>` |
| "no Phala credential" | Set `PHALA_API_KEY` or run `gmcli deploy` and paste the key at the prompt |
| "no credit balance" from Phala | Top up at <https://cloud.phala.network> (Dashboard → Deposit) |
| "hotkey isn't registered" | Run `gmcli register-hotkey`, then re-deploy |
| Foundry miner restart-loops right after deploy | Azure attached an Application Insights connection to the resource; delete it — see [Foundry setup](docs/foundry-setup.md) |
| Token expired prompt on every command | Run `gmcli login` to refresh |
| Wrong network (testnet vs mainnet) | Pass `--network mainnet` or `--network testnet` |

## Releasing

The release pipeline is driven by [`dist`](https://opensource.axo.dev/cargo-dist/) and lives
in `.github/workflows/release.yml`. Configuration is in `dist-workspace.toml`.

A release is triggered by pushing a **version tag** matching `v<major>.<minor>.<patch>` (e.g.
`v0.1.0`). The tag's version must match the workspace `version` in `Cargo.toml`. On a tag push,
the workflow cross-builds `gmcli` for all configured targets, generates the shell installer, and
publishes a GitHub Release with the artifacts and checksums.

To cut a release:

```sh
# 1. Bump `version` under [workspace.package] in Cargo.toml, in a PR. Merge it.
# 2. From an up-to-date main:
./scripts/release.sh              # or --dry-run to see what it would tag
```

`release.sh` reads the version out of `Cargo.toml` and tags that — you never type it. It
refuses to run off `main`, on a dirty tree, when `main` is behind `origin`, or when the tag
already exists, and asks before pushing.

Do not hand-tag. `dist` rejects a tag that does not match the workspace version, and every
failed release in this repo has been exactly that: `v0.3.11-dev`, `v0.3.12-dev`, `v0.3.13-dev`,
`v0.3.14` and `v0.3.14-dev` were all pushed against a stale `Cargo.toml`, published nothing, and
went unnoticed because a failed release looks the same as no release. A burned tag cannot be
reused either, since deleting a published tag rewrites a public ref — bump to the next version
instead.

The `release` workflow also runs in dry-run mode on pull requests, so changes to the pipeline
are validated before merge without publishing.

`release.yml` is autogenerated by `dist`. Its `uses:` actions are hand-pinned to commit SHAs
to satisfy the repo's `zizmor`/`actionlint` checks. Re-running `dist init` or `dist generate`
overwrites the file and resets those pins — re-pin every `uses:` line afterwards (see the note
at the top of `release.yml`).

## License

Apache-2.0.
