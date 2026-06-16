# gm miner image — build reproducibility

## Status

**Partially reproducible.** The Rust binaries inside the image are
deterministic given the same toolchain and dependency lock. The Docker
layer structure is *not* bit-for-bit reproducible due to filesystem
timestamp embedding — a known gap in Docker's build toolchain that is
post-v1 (see Phala's own documentation on this topic).

What matters for attestation: the **compose-hash** (SHA256 of
`docker-compose.yaml`) is the primary measurement that changes when the
workload definition changes. The image digest is a secondary anchor that
changes whenever the source changes. Neither requires bit-for-bit layer
reproducibility to be useful for attestation; the TEE measures the
compose-hash at boot and binds it to the attestation quote.

## Sources of determinism (what we control)

| Layer | Deterministic? | How |
|---|---|---|
| Envoy base image | Yes | Pinned by `@sha256:…` digest |
| Rust builder base | Yes | Pinned by `@sha256:…` digest |
| Rust binary: `gmcli` (CLI) | Yes, given same toolchain | `RUSTFLAGS="-C codegen-units=1 -C debuginfo=0"`, `CARGO_INCREMENTAL=0`, `SOURCE_DATE_EPOCH` set |
| `envoy.yaml` | Yes | Static config, version-controlled |
| `start.sh` | Yes | Static script, version-controlled |

## Sources of remaining non-determinism

| Source | Impact | Mitigation |
|---|---|---|
| Docker layer timestamps | Image digest changes across rebuilds from identical source | None in v1. Accepted: the compose-hash (not the image digest) is the primary attestation anchor |
| Rust toolchain version | Different `rustc` versions produce different binaries | Pinned via `rust-version` in `Cargo.toml`; build pipeline must use the exact `rustc` version |
| System library versions in the Envoy base image | If the base image tag is updated (not the digest), binaries change | Always pin `@sha256:…` — never use a mutable tag in production |
| LLVM code layout (ASLR/entropy in LLVM) | Negligible; eliminated by `codegen-units=1` | Already done |

## Re-pinning base images

When updating the Envoy or Rust builder base:

```bash
# Get the current digest for the envoy image:
docker manifest inspect envoyproxy/envoy:v1.32-latest \
  | jq -r '.manifests[] | select(.platform.architecture=="amd64") | .digest'

# Get the current digest for the Rust builder:
docker manifest inspect rust:1.83-slim-bookworm \
  | jq -r '.manifests[] | select(.platform.architecture=="amd64") | .digest'
```

Update both `FROM` lines in `image/Dockerfile` with the new digest.
Commit the change; the CI pipeline will rebuild and produce a new image
digest that the registry operator must add to the supported image
versions list.

## Fully reproducible builds (post-v1)

For truly bit-for-bit reproducible Docker images, the path forward is:

1. **Nix-based builds** — Nix can produce identical layer tarballs given
   the same Nix expression and pinned nixpkgs.
2. **`--source-date-epoch` in Docker BuildKit** — Docker BuildKit 0.12+
   supports `SOURCE_DATE_EPOCH` to strip timestamps from layers; not yet
   reliable for all base image combinations as of May 2026.

Neither is required for v1. The registry's image versioning tracks
compose-hash + os-image-hash (per `registry.proto`), not a binary hash
of the Docker image layers. Operators can verify the measurement by
re-running the build and comparing compose-hashes.
