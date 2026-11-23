# Publishing release `ImageVersion` rows

The release workflow publishes an image measurement for each non-expiring KMS
root returned by `GET /kms-roots`. Each row contains the compose hash for that
root's CA public key and the pinned OS image hash. The registry upsert key is
`(compose_hash, os_image_hash)`.

## Measured compose shape

New deployments use OS image `dstack-0.6.5` and the Phala manifest v3 shape.
The measured `app_compose` includes:

- `manifest_version: "3"` and `init_script: []`;
- `key_provider: "kms"` and `key_provider_id` set to the selected root's
  `ca_pubkey` from `GET /kms-roots`;
- `requirements: {"ephemeral_data_disk": true}`;
- `secure_time: false` and `storage_fs: "zfs"`;
- the rendered Docker Compose bytes, pre-launch script bytes, declared
  environment names, and the remaining Phala runtime fields.

The compose hash serializes the normalized object as compact UTF-8 JSON with
lexicographically sorted keys, then computes lowercase SHA-256. Phala removes
the runner-inapplicable script field and omits its null and empty optional
fields before hashing. `cli/src/compose_hash.rs` implements the same
normalization and serialization.

The live v3 fixture records the exact Docker Compose and pre-launch script
bytes from a 0.6.5 deployment. Its test reproduces compose hash
`0d75dcd1311506ec717f9bac9628e4edfed8023115ea7e78aa0a1086a8b67a79`. A
separate frozen v2 JSON fixture preserves the historical hash check. The
candidate test uses the current bundled template and does not change that
historical fixture.

`PINNED_OS_IMAGE_HASH` is
`4771a29e03e93f0e2d5e37174cd8bb1112942c9689deb36b16c5df9e183d8623`, paired
with `DEFAULT_OS_IMAGE = "dstack-0.6.5"`.

## Publishing

`gmcli publish-image-version` accepts:

- `--network testnet|mainnet` to select the registry;
- `--image-ref <repo@sha256:…>` for the released image;
- `--registry-admin-key <key>` or `REGISTRY_ADMIN_KEY` for the registry
  admin API;
- `--api-url <url>` to override the network's registry URL;
- `--git-tag`, `--git-commit`, and `--git-repo` for release metadata.

The command reads the approved KMS roots from the selected network, computes
one root-specific compose hash per root, and upserts the corresponding rows.
It does not create a Phala CVM.

## Release CI

`.github/workflows/publish-image-version.yml` builds and pushes the miner image
at the release commit, then runs `publish-image-version` once for each target
network. Each network's registry admin key is used only for its publication
step.
