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
FROM rust:1.96-slim-bookworm@sha256:b5f842fac1e3b4ff718a652a8e0173b62d9403ec826ef4998880b9347db30684 AS builder

## Reproducibility: fixed build timestamp, single codegen unit.
ENV SOURCE_DATE_EPOCH=1700000000
ENV RUSTFLAGS="-C codegen-units=1 -C debuginfo=0"
ENV CARGO_INCREMENTAL=0

WORKDIR /build

## Copy workspace manifests first for layer caching.
COPY Cargo.toml Cargo.lock ./
COPY cli/Cargo.toml ./cli/
COPY attestd/Cargo.toml ./attestd/
COPY azure-verify/Cargo.toml ./azure-verify/

## Copy dstack assets required by include_str! at compile time.
COPY dstack/ ./dstack/

## Pre-build a dummy workspace to cache dependencies. The attestd crate
## ships a lib and six bins (gm-miner-attestd, gm-miner-ratls, and the
## NEAR, Chutes, KubeTEE and Bedrock Mantle proxies), so the dummy tree
## needs an entry file for each declared target.
RUN mkdir -p cli/src attestd/src/bin azure-verify/src \
  && echo "fn main() {}" > cli/src/main.rs \
  && echo "fn main() {}" > attestd/src/main.rs \
  && echo "fn main() {}" > attestd/src/bin/ratls.rs \
  && echo "fn main() {}" > attestd/src/bin/near_verify_proxy.rs \
  && echo "fn main() {}" > attestd/src/bin/chutes_verify_proxy.rs \
  && echo "fn main() {}" > attestd/src/bin/kubetee_verify_proxy.rs \
  && echo "fn main() {}" > attestd/src/bin/bedrock_mantle_proxy.rs \
  && echo "" > attestd/src/lib.rs \
  && echo "" > azure-verify/src/lib.rs \
  && cargo build --release --workspace 2>/dev/null || true \
  && rm -rf cli/src attestd/src azure-verify/src

## Copy real sources.
COPY cli/ ./cli/
COPY attestd/ ./attestd/
COPY azure-verify/ ./azure-verify/

## Build the workspace. Touch the entry points to invalidate the dummy
## build cache so the real sources compile.
RUN touch cli/src/main.rs attestd/src/main.rs attestd/src/lib.rs \
    attestd/src/bin/ratls.rs attestd/src/bin/near_verify_proxy.rs \
    attestd/src/bin/chutes_verify_proxy.rs attestd/src/bin/kubetee_verify_proxy.rs \
    attestd/src/bin/bedrock_mantle_proxy.rs \
    azure-verify/src/lib.rs \
  && cargo build --release --workspace \
  && strip target/release/gmcli target/release/gm-miner-attestd \
    target/release/gm-miner-ratls target/release/gm-near-verify-proxy \
    target/release/gm-chutes-verify-proxy target/release/gm-kubetee-verify-proxy \
    target/release/gm-bedrock-mantle-proxy

## ── Stage 2: Runtime image ────────────────────────────────────────────
## Pin the base by digest so a mutable tag cannot change the attested runtime.
FROM envoyproxy/envoy:v1.38-latest@sha256:b1f389c3a6148e85e9de364cb867aa2e5802153abb37ad80f1f2241d693da32a

## Every Envoy upstream cluster validates against the system bundle
## /etc/ssl/certs/ca-certificates.crt. The base image ships
## ca-certificates 20240203~22.04.1; pin the jammy-security release that
## carries Mozilla's 2.90 root store. Its postinst drops the roots that
## release removed, including AAA Certificate Services and emSign ECC
## Root CA - G3. The check after it fails the build if either root is
## still in the bundle Envoy reads, by SHA-256 fingerprint (AAA
## Certificate Services D7:A7:A0:FB..., emSign ECC Root CA - G3
## 86:A1:EC:BA...), whatever a later package does.
## Nothing else needs to be installed — the attestation server talks to
## the dstack guest agent over a unix socket and is reached by envoy
## over loopback.
## Update the pin via: apt-cache policy ca-certificates (in this base image)
RUN apt-get update \
  && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ca-certificates=20260816ubuntu0.22.04.1 \
  && rm -rf /var/lib/apt/lists/* \
  && bundle=/etc/ssl/certs/ca-certificates.crt \
  && awk -v fp='openssl x509 -noout -fingerprint -sha256' \
    '/BEGIN CERT/ { pem = "" } { pem = pem $0 "\n" } /END CERT/ { printf "%s", pem | fp; close(fp) }' \
    "${bundle}" > /tmp/ca-fingerprints \
  && test "$(wc -l < /tmp/ca-fingerprints)" -eq "$(grep -c 'BEGIN CERT' "${bundle}")" \
  && ! grep -i \
    -e 'D7:A7:A0:FB:5D:7E:27:31:D7:71:E9:48:4E:BC:DE:F7:1D:5F:0C:3E:0A:29:48:78:2B:C8:3E:E0:EA:69:9E:F4' \
    -e '86:A1:EC:BA:08:9C:4A:8D:3B:BE:27:34:C6:12:BA:34:1D:81:3E:04:3C:F9:E8:A8:62:CD:5C:57:A3:6B:BE:6B' \
    /tmp/ca-fingerprints \
  && rm /tmp/ca-fingerprints

## Image version — set at build time by the build pipeline.
ARG GM_IMAGE_VERSION=dev
ENV GM_IMAGE_VERSION=${GM_IMAGE_VERSION}

## start.sh depends on gmcli slot-env to derive key slots inside the TEE.
COPY --from=builder /build/target/release/gmcli /usr/local/bin/gmcli

## Copy the attestation server. start.sh launches it alongside envoy;
## envoy routes GET /attestation/info to it on loopback.
COPY --from=builder /build/target/release/gm-miner-attestd /usr/local/bin/gm-miner-attestd

## Copy the RA-TLS provisioner. start.sh runs it once before envoy to
## mint the data-plane TLS cert via the dstack guest agent.
COPY --from=builder /build/target/release/gm-miner-ratls /usr/local/bin/gm-miner-ratls

## Copy the NEAR verifier. It attests and forwards each NEAR inference over
## one exact TLS connection; Envoy never has a direct NEAR origin route.
COPY --from=builder /build/target/release/gm-near-verify-proxy /usr/local/bin/gm-near-verify-proxy

## Copy the Chutes verifier. It admits Chutes instances on verified evidence
## and carries confidential requests end to end encrypted to them.
COPY --from=builder /build/target/release/gm-chutes-verify-proxy /usr/local/bin/gm-chutes-verify-proxy

## Copy the KubeTEE verifier. It attests each connection to llm.kubetee.ai
## before sending chat requests on it.
COPY --from=builder /build/target/release/gm-kubetee-verify-proxy /usr/local/bin/gm-kubetee-verify-proxy

## Copy the fixed Bedrock Mantle adapter; start.sh runs it only for the
## registry-authorized dynamic model bindings.
COPY --from=builder /build/target/release/gm-bedrock-mantle-proxy /usr/local/bin/gm-bedrock-mantle-proxy

## Copy the Envoy config templates; start.sh renders them with gmcli render-envoy.
COPY image/envoy/ /etc/envoy/

## Copy startup script.
COPY image/start.sh /usr/local/bin/start.sh
RUN chmod +x /usr/local/bin/start.sh

## Envoy data-plane port: RA-TLS-terminated upstream request proxying
## AND the registry's GET /attestation/info probes (envoy routes that
## path to the loopback-bound attestation server). TLS is terminated
## with the dstack-minted RA-TLS certificate (see start.sh / image/envoy/).
EXPOSE 8080
## Envoy admin port — runtime config introspection, `/quitquitquit`, and
## the raw `/stats/prometheus`. Bound to localhost via the admin block
## in image/envoy/base.yaml; the EXPOSE is informational only and the port is never
## published to the host.
EXPOSE 9901
## Envoy Prometheus metrics port. The `metrics` listener in image/envoy/base.yaml
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
