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
## Pinned to rust:1.87-slim-bookworm digest at time of writing.
## Update the pin via: docker buildx imagetools inspect rust:1.87-slim-bookworm
FROM rust:1.87-slim-bookworm@sha256:437507c3e719e4f968033b88d851ffa9f5aceeb2dcc2482cc6cb7647811a55eb AS builder

## Reproducibility: fixed build timestamp, single codegen unit.
ENV SOURCE_DATE_EPOCH=1700000000
ENV RUSTFLAGS="-C codegen-units=1 -C debuginfo=0"
ENV CARGO_INCREMENTAL=0

WORKDIR /build

## Copy workspace manifests first for layer caching.
COPY Cargo.toml Cargo.lock ./
COPY cli/Cargo.toml ./cli/

## Copy dstack assets required by include_str! at compile time.
COPY dstack/ ./dstack/

## Pre-build a dummy workspace to cache dependencies.
RUN mkdir -p cli/src \
  && echo "fn main() {}" > cli/src/main.rs \
  && cargo build --release --workspace 2>/dev/null || true \
  && rm -rf cli/src

## Copy real sources.
COPY cli/ ./cli/

## Build the CLI. Touch src to invalidate the dummy build cache.
RUN touch cli/src/main.rs \
  && cargo build --release --workspace \
  && strip target/release/gm-miner

## ── Stage 2: Runtime image ────────────────────────────────────────────
## Envoy 1.32.x pinned by digest.
## Update the pin via: docker manifest inspect envoyproxy/envoy:v1.32-latest
## Current digest as of 2026-05-17:
FROM envoyproxy/envoy:v1.32-latest@sha256:6bf0d37dd5e8eac4b37effe89a1aec4760f7f2ce860d1fd6af22147eb87a5058

## ca-certificates is already present in the envoy base image; nothing
## else needs to be installed now that the capability sidecar is gone.

## Image version — set at build time by the build pipeline.
ARG GM_IMAGE_VERSION=dev
ENV GM_IMAGE_VERSION=${GM_IMAGE_VERSION}

## Copy the operator-side CLI binary. The CLI is included in the image
## for one-shot ops tasks (config dump, key rotation) executed via
## `docker run --entrypoint gm-miner ...`; the runtime entrypoint
## itself is envoy alone.
COPY --from=builder /build/target/release/gm-miner /usr/local/bin/gm-miner

## Copy Envoy config.
COPY image/envoy.yaml /etc/envoy/envoy.yaml

## Copy startup script.
COPY image/start.sh /usr/local/bin/start.sh
RUN chmod +x /usr/local/bin/start.sh

## Envoy data-plane port (upstream request proxying).
EXPOSE 8080
## Envoy admin port (Prometheus `/stats/prometheus` and runtime config
## introspection — bound to localhost via admin block in envoy.yaml,
## the EXPOSE is informational only).
EXPOSE 9901

## Drop to non-root. The envoy base image has the envoy user (uid 100).
USER envoy

ENTRYPOINT ["/usr/local/bin/start.sh"]
