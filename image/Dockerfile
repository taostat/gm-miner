## gm miner image — multi-stage, digest-pinned, reproducible build.
##
## Reproducibility status (see docs/reproducibility.md):
##   - Base image is pinned by SHA256 digest: fully reproducible given
##     the same Rust toolchain and dependency lock.
##   - Rust binaries are built with RUSTFLAGS="-C codegen-units=1
##     -C debuginfo=0" which eliminates the most common sources of
##     non-determinism (parallel codegen, DWARF timestamps).
##   - SOURCE_DATE_EPOCH is set to a fixed epoch so embedded build
##     timestamps are constant.
##   - Remaining non-determinism: Docker layer timestamps (not part of
##     the Envoy attestation measurement; the compose-hash covers only
##     docker-compose.yaml) and any platform-dependent entropy in LLVM's
##     code layout. Fully reproducible Docker is post-v1 per Phala docs.

## ── Stage 1: Rust builder ──────────────────────────────────────────────
## Pinned to the rust:1.92-slim-bookworm multi-arch index digest. 1.92
## matches the gm gateway image's toolchain; the locked dependency tree
## (dstack-sdk -> alloy, pulled in by the attestd crate) needs rustc
## 1.88+, so the previous 1.87 base no longer builds.
## Update the pin via: docker buildx imagetools inspect rust:1.92-slim-bookworm
FROM rust:1.92-slim-bookworm@sha256:f1f73538ebe623fd3673a35aff3df358ae1084c64c55646516e5b17b321b6c9b AS builder

## Reproducibility: fixed build timestamp, single codegen unit.
ENV SOURCE_DATE_EPOCH=1700000000
ENV RUSTFLAGS="-C codegen-units=1 -C debuginfo=0"
ENV CARGO_INCREMENTAL=0

WORKDIR /build

## Copy workspace manifests first for layer caching.
COPY Cargo.toml Cargo.lock ./
COPY cli/Cargo.toml ./cli/
COPY attestd/Cargo.toml ./attestd/
COPY auth-sidecar/Cargo.toml ./auth-sidecar/

## Copy dstack assets required by include_str! at compile time.
COPY dstack/ ./dstack/

## Pre-build a dummy workspace to cache dependencies. The attestd crate
## ships a lib and two bins (gm-miner-attestd, gm-miner-ratls); the
## auth-sidecar crate ships a lib + one bin (gm-miner-auth-sidecar).
## The dummy tree needs an entry file for each declared target.
RUN mkdir -p cli/src attestd/src/bin auth-sidecar/src \
  && echo "fn main() {}" > cli/src/main.rs \
  && echo "fn main() {}" > attestd/src/main.rs \
  && echo "fn main() {}" > attestd/src/bin/ratls.rs \
  && echo "" > attestd/src/lib.rs \
  && echo "fn main() {}" > auth-sidecar/src/main.rs \
  && echo "" > auth-sidecar/src/lib.rs \
  && cargo build --release --workspace 2>/dev/null || true \
  && rm -rf cli/src attestd/src auth-sidecar/src

## Copy real sources.
COPY cli/ ./cli/
COPY attestd/ ./attestd/
COPY auth-sidecar/ ./auth-sidecar/

## Build the workspace. Touch the entry points to invalidate the dummy
## build cache so the real sources compile.
RUN touch cli/src/main.rs attestd/src/main.rs attestd/src/lib.rs \
    attestd/src/bin/ratls.rs \
    auth-sidecar/src/main.rs auth-sidecar/src/lib.rs \
  && cargo build --release --workspace \
  && strip target/release/gm-miner target/release/gm-miner-attestd \
    target/release/gm-miner-ratls target/release/gm-miner-auth-sidecar

## ── Stage 2: Runtime image ────────────────────────────────────────────
## Envoy 1.32.x pinned by digest.
## Update the pin via: docker manifest inspect envoyproxy/envoy:v1.32-latest
## Current digest as of 2026-05-17:
FROM envoyproxy/envoy:v1.38-latest@sha256:8146b97ee61a42cd216514709e4e3198af75f014974e3d9f310aef9c901fcbdf

## ca-certificates is already present in the envoy base image; nothing
## else needs to be installed — the attestation server talks to the
## dstack guest agent over a unix socket and is reached by envoy over
## loopback, so no extra runtime packages are required.

## Image version — set at build time by the build pipeline.
ARG GM_IMAGE_VERSION=dev
ENV GM_IMAGE_VERSION=${GM_IMAGE_VERSION}

## Copy the operator-side CLI binary. The CLI is included in the image
## for one-shot ops tasks (config dump, key rotation) executed via
## `docker run --entrypoint gm-miner ...`.
COPY --from=builder /build/target/release/gm-miner /usr/local/bin/gm-miner

## Copy the attestation server. start.sh launches it alongside envoy;
## envoy routes GET /attestation/info to it on loopback.
COPY --from=builder /build/target/release/gm-miner-attestd /usr/local/bin/gm-miner-attestd

## Copy the RA-TLS provisioner. start.sh runs it once before envoy to
## mint the data-plane TLS cert via the dstack guest agent.
COPY --from=builder /build/target/release/gm-miner-ratls /usr/local/bin/gm-miner-ratls

## Copy the OAuth-subscription refresh sidecar. start.sh launches it
## alongside envoy when at least one provider is configured in
## oauth_subscription mode; envoy's per-route Lua filter fetches the
## current bearer token from it via the loopback `auth_sidecar`
## cluster on every data-plane request. Skipped on api-key-only
## deployments — see start.sh for the launch condition.
COPY --from=builder /build/target/release/gm-miner-auth-sidecar /usr/local/bin/gm-miner-auth-sidecar

## Copy Envoy config.
COPY image/envoy.yaml /etc/envoy/envoy.yaml

## Copy startup script.
COPY image/start.sh /usr/local/bin/start.sh
RUN chmod +x /usr/local/bin/start.sh

## Envoy data-plane port: RA-TLS-terminated upstream request proxying
## AND the registry's GET /attestation/info probes (envoy routes that
## path to the loopback-bound attestation server). TLS is terminated
## with the dstack-minted RA-TLS certificate (see start.sh / envoy.yaml).
EXPOSE 8080
## Envoy admin port — runtime config introspection, `/quitquitquit`, and
## the raw `/stats/prometheus`. Bound to localhost via the admin block
## in envoy.yaml; the EXPOSE is informational only and the port is never
## published to the host.
EXPOSE 9901
## Envoy Prometheus metrics port. The `metrics` listener in envoy.yaml
## serves ONLY `/stats/prometheus` (gated on x-gm-node-key) and proxies
## it to the loopback admin port; the rest of the admin surface stays
## unreachable. Published by dstack/docker-compose.yaml so scrapers can
## reach it; the EXPOSE itself is informational.
EXPOSE 9902

## Drop to non-root. The envoy base image has the envoy user (uid 100).
## The RA-TLS provisioner and the attestation server run as the same
## user; they need read access to the bind-mounted /var/run/dstack.sock
## and write access to /tmp (world-writable) for the RA-TLS PEM files.
USER envoy

## start.sh provisions the RA-TLS cert, launches the attestation server
## in the background, then runs envoy.
ENTRYPOINT ["/usr/local/bin/start.sh"]
