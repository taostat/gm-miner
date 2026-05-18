#!/usr/bin/env bash
# gm miner container entrypoint.
#
# The miner runtime is just envoy + its native /stats/prometheus
# exposure. No capability sidecar: the registry probes the upstream
# directly through this envoy with the `x-gm-provider` header to
# validate that the API key works and to list available models.
#
# Disabled-route handling: envoy's static config carries all three
# provider clusters. Routes match on `x-gm-provider`. When the
# corresponding env var is absent envoy injects an empty key and the
# upstream returns 401; the registry's probe surfaces that as a
# capability failure for the affected provider. The 501 fallback in
# envoy.yaml fires only when no provider header arrives.

set -euo pipefail

log() { printf '[start] %s\n' "$*" >&2; }

# ── Require at least one provider key ─────────────────────────────────
HAS_KEY=0
if [[ -n "${ANTHROPIC_API_KEY:-}" ]]; then
  HAS_KEY=1
  log "ANTHROPIC_API_KEY set"
fi
if [[ -n "${OPENAI_API_KEY:-}" ]]; then
  HAS_KEY=1
  log "OPENAI_API_KEY set"
fi
if [[ -n "${GOOGLE_API_KEY:-}" ]]; then
  HAS_KEY=1
  log "GOOGLE_API_KEY set"
fi

if [[ "${HAS_KEY}" -eq 0 ]]; then
  log "error: at least one of ANTHROPIC_API_KEY / OPENAI_API_KEY / GOOGLE_API_KEY must be set"
  exit 1
fi

GM_IMAGE_VERSION="${GM_IMAGE_VERSION:-unknown}"
log "image version: ${GM_IMAGE_VERSION}"

# ── Exec envoy as PID 1 ───────────────────────────────────────────────
# `exec` so envoy receives signals (SIGTERM from the container runtime)
# directly and the container exits when envoy does.
log "starting envoy"
exec envoy \
  -c /etc/envoy/envoy.yaml \
  --log-level warn \
  --drain-time-s 10
