# gm-miner

Miner image and CLI for the [gm](https://saygm.com) Bittensor subnet (netuid 28 mainnet, 482
testnet). Buyers point an existing OpenAI / Anthropic / Gemini SDK at the gm gateway and get
identical behavior; miners supply upstream API capacity and earn the spread. The gateway runs
inside an Intel TDX TEE so neither operators nor host machines see buyer content or miners'
upstream keys.

You bring your own provider API keys (Anthropic, OpenAI, Google) and your own funded
[Phala Cloud](https://cloud.phala.network) account. The `gmcli` tool handles the full operator
lifecycle from your laptop.

| Path | Description |
|---|---|
| `image/` | Envoy-only miner image with three provider routes (Anthropic / OpenAI / Gemini) and an optional `benchmark` route to a synthetic upstream. Pinned to digest. The runtime is `envoy` plus its native `/stats/prometheus` exposure — no sidecar service. |
| `cli/` | `gmcli` CLI (Rust + clap). Login via Taostats device-code OAuth; register image; declare products + prices; check status. Runs operator-side from a laptop, not inside the TEE. |
| `dstack/` | Docker Compose template for the miner workload; `gmcli deploy` renders it and submits it to Phala Cloud. |
| `docs/` | Operator-facing docs including reproducibility caveats. |

## Install

`gmcli` runs operator-side from a laptop. Prebuilt binaries for macOS (Apple Silicon + Intel),
Linux (x86-64 + aarch64), and Windows (x86-64) are published on the
[GitHub Releases page](https://github.com/taostat/gm-miner/releases).

Install the latest release with the one-line installer (macOS / Linux):

```sh
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/taostat/gm-miner/releases/latest/download/gmcli-installer.sh | sh
```

On Windows, use the PowerShell installer:

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://github.com/taostat/gm-miner/releases/latest/download/gmcli-installer.ps1 | iex"
```

On macOS / Linux with Homebrew:

```sh
brew install taostat/gmcli/gmcli
```

The installer places the binary in `~/.cargo/bin` (or `CARGO_HOME`) and ensures that directory
is on your `PATH`. To install a specific version, replace `latest` with a tag, e.g.
`download/v0.1.0/`.

Verify:

```sh
gmcli --version
```

## Onboarding walkthrough

The `gmcli init` wizard walks you through the entire setup in order. Run it first:

```sh
gmcli --network testnet init   # start on testnet (netuid 482)
gmcli init                     # or mainnet (netuid 28, the default)
```

The wizard detects steps already done (hotkey recorded, login valid, worker deployed, keys set)
and skips them, so a returning miner breezes through. Each step shows the exact command it will
run and asks before executing. Run `gmcli --yes init` to accept every step without prompting.

You can also run each step individually:

### 1. Register your hotkey

Your miner earns emissions under a Bittensor hotkey. Record it with `gmcli register-hotkey`.

**Bring-your-own (no btcli needed):** if you already registered the hotkey elsewhere (a browser
wallet, Bittensor explorer, or another machine), pass the ss58 address directly:

```sh
gmcli register-hotkey --hotkey-ss58 5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY
```

**Assisted flow (requires btcli):** if you have not registered yet, omit `--hotkey-ss58` and
pass the btcli wallet and hotkey name. gmcli offers to register a fresh hotkey through btcli
(btcli holds your wallet keys — gmcli never sees them):

```sh
gmcli register-hotkey --wallet miner --hotkey default
```

btcli is only needed for the assisted registration flow. The bring-your-own path (`--hotkey-ss58`)
has no btcli dependency.

### 2. Log in

Authenticate with Taostats (device-code OAuth). The browser opens automatically; pass
`--no-browser` to print the URL instead:

```sh
gmcli login
gmcli --network testnet login   # testnet
```

Credentials are stored in `~/.gmcli/config.json`.

### 3. Set your provider API keys

Your provider API keys (Anthropic, OpenAI, Google) are baked into the miner container at deploy
time and stay inside the TEE — gm never sees them. Set the keys for whichever providers you
intend to serve:

```sh
gmcli set-api-keys --anthropic sk-ant-...
gmcli set-api-keys --openai sk-... --google AIza...
```

Each flag replaces the stored value; omitted flags leave existing values intact.

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

Fan one discount across the whole catalog:

```sh
gmcli declare-products --discount-pct 5
```

Or filter to one provider:

```sh
gmcli declare-products --provider anthropic --discount-pct 5
gmcli declare-products --provider openai --discount-pct 10
```

Or declare a single offer:

```sh
gmcli declare-product --provider anthropic --model claude-sonnet-4-6 --discount-pct 5
```

`--discount-pct` accepts a value in `[0, 99.90]` with up to two decimal places (e.g. `10.5`).
`0` means at retail; `99.90` is the cap (keeps per-request revenue strictly positive).

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
| `gmcli init` | Guided onboarding wizard: register hotkey → login → deploy → set keys → declare products |
| `gmcli login` | Device-code OAuth login; stores credentials in `~/.gmcli/config.json` |
| `gmcli register-hotkey` | Record the serving hotkey (`--hotkey-ss58` or assisted via btcli) |
| `gmcli deploy` | Full deploy: fetch approved image, launch Phala CVM, verify hashes, register worker |
| `gmcli set-api-keys` | Persist provider API keys (Anthropic, OpenAI, Google) |
| `gmcli declare-product` | Declare a single model offer with a discount |
| `gmcli declare-products` | Fan one discount across the catalog or one provider's slice |
| `gmcli status` | Registration state + per-product eligibility and rates |
| `gmcli earnings` | On-chain hotkey emission from the subnet metagraph (requires btcli) |
| `gmcli doctor` | Preflight checklist (network, login, keys, Phala CLI + key, hotkey) |
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

## Troubleshooting

**`gmcli doctor` is the first diagnostic step.** It prints a green/red checklist of everything
deploy needs and names the command that fixes each red item.

| Symptom | Fix |
|---|---|
| "no provider keys" on deploy | `gmcli set-api-keys --anthropic <key>` |
| "no Phala credential" | Set `PHALA_API_KEY` or run `gmcli deploy` and paste the key at the prompt |
| "no credit balance" from Phala | Top up at <https://cloud.phala.network> (Dashboard → Deposit) |
| "hotkey isn't registered" | Run `gmcli register-hotkey`, then re-deploy |
| Token expired prompt on every command | Run `gmcli login` to refresh |
| Wrong network (testnet vs mainnet) | Pass `--network mainnet` or `--network testnet` |

## Releasing

The release pipeline is driven by [`dist`](https://opensource.axo.dev/cargo-dist/) and lives
in `.github/workflows/release.yml`. Configuration is in `dist-workspace.toml`.

A release is triggered by pushing a **version tag** matching `v<major>.<minor>.<patch>` (e.g.
`v0.1.0`). The tag's version must match the workspace `version` in `Cargo.toml`. On a tag push,
the workflow cross-builds `gmcli` for all configured targets, generates the shell installer, and
publishes a GitHub Release with the artifacts and checksums.

To cut `v0.1.0`:

```sh
# 1. Ensure Cargo.toml `version` is 0.1.0 and main is green.
# 2. Tag and push.
git tag v0.1.0
git push origin v0.1.0
```

The `release` workflow also runs in dry-run mode on pull requests, so changes to the pipeline
are validated before merge without publishing.

`release.yml` is autogenerated by `dist`. Its `uses:` actions are hand-pinned to commit SHAs
to satisfy the repo's `zizmor`/`actionlint` checks. Re-running `dist init` or `dist generate`
overwrites the file and resets those pins — re-pin every `uses:` line afterwards (see the note
at the top of `release.yml`).

## License

Apache-2.0.
