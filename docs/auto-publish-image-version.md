# Auto-publishing the release `ImageVersion`

The registry enforces miner attestation against an allow-list of approved
`ImageVersion` rows: a CVM whose measured `compose_hash` / `os_image_hash`
is absent from the list is rejected. That allow-list used to be
hand-published, so it drifted from what the released CLI actually deploys —
surfacing at deploy time as a `HASH MISMATCH`. The release pipeline now
publishes the matching version automatically.

## Why we deploy-and-read instead of computing the hash offline

dstack's `compose_hash` is `sha256` over the **app-compose.json** manifest
that Phala Cloud's backend assembles — *not* over the `docker-compose.yaml`
the CLI renders. The backend owns that manifest:

- the field set and its defaults (`manifest_version`, `runner`,
  `kms_enabled`, `gateway_enabled`, `key_provider`, the node's
  `default_gateway_domain`, …), set server-side, not by the `phala` CLI;
- the exact JSON serialization (there are at least three incompatible
  serializers in the dstack / phala-cloud ecosystem: compact+sorted,
  4-space-indent+sorted, and insertion-order+indent — each yields a
  different digest for the same logical object).

None of that is derivable from the CLI's inputs. An empirical search over
~720k field/serializer permutations against the live testnet oracle
(`compose_hash=e47562cd…`) reproduced **no** match. Offline computation is
therefore both infeasible to get right and brittle to any backend change —
and unverifiable for mainnet, where there is no oracle. The only trustworthy
source of the hash a release produces is the platform that measures it.

So the release does a real throwaway deploy per target network, reads the
measured hashes back from `phala cvms get`, publishes them, and tears the
CVM down.

## Interface

`gmcli publish-image-version`:

- `--network testnet|mainnet` — the network whose registry to publish to.
  The `GM_NETWORK` literal in the rendered compose makes the `compose_hash`
  network-specific, so each network gets its own deploy + row.
- `--image-ref <repo@sha256:…>` — the digest-pinned released image.
- `--registry-admin-key <key>` / `REGISTRY_ADMIN_KEY` — the registry admin
  `X-API-Key`.
- `--api-url <url>` overrides the network's default registry URL.
- `--git-tag`, `--git-commit`, `--git-repo` — provenance stamped onto the
  row; the auto-generated notes reference the tag + commit.
- Phala deploy knobs reuse `deploy`'s defaults (`--instance-type`,
  `--disk-size`, `--os-image`, `--boot-timeout-secs`, `--phala-api-key`).
- `--keep-cvm` leaves the throwaway CVM running (debugging); the default
  tears it down.

The registry endpoint (`POST /admin/image-versions`) is an upsert keyed on
`(compose_hash, os_image_hash)`, so re-publishing the same release is a
no-op update — the command is idempotent by construction.

## Release CI

`.github/workflows/release.yml` runs `publish-image-version` once per target
network after the host job, using the gm-funded Phala test account and each
network's registry admin key. See the workflow's `publish-image-versions`
job.
