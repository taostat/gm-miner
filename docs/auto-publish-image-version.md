# Auto-publishing the release `ImageVersion`

The registry enforces miner attestation against an allow-list of approved
`ImageVersion` rows: a CVM whose measured `compose_hash` / `os_image_hash`
is absent from the list is rejected. That allow-list used to be
hand-published, so it drifted from what the released CLI actually deploys —
surfacing at deploy time as a `HASH MISMATCH`. The release pipeline now
publishes the matching version automatically, computing both hashes offline
from source.

## How the hashes are computed offline

A dstack CVM's `compose_hash` is `sha256` over the canonical serialization of
its `app_compose` object — the wrapper dstack measures into RTMR3 and exposes
in the attestation TCB info. The VMM hashes the exact UTF-8 bytes of the
submitted `app-compose.json` string and the guest re-hashes the same file, so
the value is **re-derivable offline** — that re-derivability is the whole
point of dstack attestation.

- **The serialization** mirrors dstack's `get_compose_hash`: JSON with
  **lexicographically sorted keys** and **compact separators** (`,` and `:`,
  no spaces), non-ASCII left as UTF-8, lowercase-hex digest. In Rust a
  `BTreeMap` plus `serde_json::to_string` reproduces it.
- **The hashed object is the wrapper**, not the raw `docker-compose.yaml`. Its
  `docker_compose_file` field carries the rendered compose YAML as one JSON
  string and `pre_launch_script` carries the bundled pre-launch script. The
  rest are the Phala-Cloud-set security/runtime flags (`kms_enabled`,
  `gateway_enabled`, `tproxy_enabled`, `public_logs`, `public_sysinfo`,
  `public_tcbinfo`, `local_key_provider_enabled`, …), `allowed_envs` (the
  env-var names the deploy declares), and the runner/storage fields. The
  earlier deploy-and-read approach searched only the serialization space and
  missed these flag fields — the gap was content, not formatting.
- **`os_image_hash`** is the pinned dstack OS image's published reproducible
  measurement (`PINNED_OS_IMAGE_HASH`, tied to `DEFAULT_OS_IMAGE`).

`cli/src/compose_hash.rs` implements this. Its gate test reproduces a real,
registry-approved testnet `compose_hash` byte-for-byte, anchoring the field
set, the flag values, and the serialization to ground truth so any drift is
caught in CI rather than at a miner's deploy.

### The canonical `allowed_envs`

`allowed_envs` is the list of env-var names the deploy declares. The `phala`
CLI derives it from the `.env` line keys, keeping a name whenever its line is
non-blank regardless of the value. `gmcli deploy` therefore writes every
provider key name on its own line unconditionally — a configured key as
`NAME=<value>`, an unset key as a bare `NAME=` — so the measured `allowed_envs`
is the same fixed set for every miner no matter which providers they
configured. That set is `compose_hash::CANONICAL_ALLOWED_ENVS`: the direct
provider keys, the Anthropic/OpenAI cloud upstream selectors and cloud
settings, plus the node secret (`ANTHROPIC_API_KEY`, `ANTHROPIC_UPSTREAM`,
`BEDROCK_REGION`, `BEDROCK_API_KEY`, `BEDROCK_MODEL_MAP`, `OPENAI_API_KEY`,
`OPENAI_UPSTREAM`, `AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_API_KEY`,
`GOOGLE_API_KEY`, `CHUTES_API_KEY`, `GM_NODE_SECRET`), with no private-registry
pull credentials. The registry's approved baseline is keyed on it.

## Interface

`gmcli publish-image-version`:

- `--network testnet|mainnet` — the network whose registry to publish to.
  The `GM_NETWORK` literal in the rendered compose makes the `compose_hash`
  network-specific, so each network gets its own row.
- `--image-ref <repo@sha256:…>` — the digest-pinned released image.
- `--registry-admin-key <key>` / `REGISTRY_ADMIN_KEY` — the registry admin
  `X-API-Key`. This is the only secret the publish needs — no `PHALA_API_KEY`.
- `--api-url <url>` overrides the network's default registry URL.
- `--git-tag`, `--git-commit`, `--git-repo` — provenance stamped onto the
  row; the auto-generated notes reference the tag + commit.

The registry endpoint (`POST /admin/image-versions`) is an upsert keyed on
`(compose_hash, os_image_hash)`, so re-publishing the same release is a no-op
update — the command is idempotent by construction.

## Release CI

`.github/workflows/publish-image-version.yml` builds and pushes the miner
image at the release commit (digest-pinned), then runs
`publish-image-version` once per target network. Each network's registry admin
key is the only secret; there is no Phala account or CVM in the loop.
