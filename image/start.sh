#!/usr/bin/env bash
# gm miner container entrypoint.
#
# Validates that at least one upstream provider key is set, then starts
# the capability service and Envoy in parallel.
#
# Disabled-route handling: Envoy's static config carries all three
# provider clusters. Routes match on the x-gm-provider header injected
# by the gateway. When an env var is absent, the gateway should not
# route to this miner for that provider — enforcement is at the registry
# level (capability check returns env_var_present=false). The 501
# fallback in envoy.yaml fires only as a last defence.

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

# ── Required runtime config ────────────────────────────────────────────
GM_IMAGE_VERSION="${GM_IMAGE_VERSION:-unknown}"
CAPABILITY_PORT="${CAPABILITY_PORT:-8443}"
ENVOY_PORT="${ENVOY_PORT:-8080}"
METRICS_PORT="${METRICS_PORT:-9090}"

log "image version: ${GM_IMAGE_VERSION}"

# ── Expose image version for the registry's version check ─────────────
# Written to a well-known path so the capability service can read it.
mkdir -p /run/gm
printf '%s\n' "${GM_IMAGE_VERSION}" >/run/gm/image-version
log "image version written to /run/gm/image-version"

# ── Start capability service ───────────────────────────────────────────
log "starting capability service on port ${CAPABILITY_PORT}"
/usr/local/bin/gm-miner-capability \
  --port "${CAPABILITY_PORT}" \
  --metrics-port "${METRICS_PORT}" \
  &
CAPABILITY_PID=$!

# ── Wait for capability service to be ready ────────────────────────────
TRIES=0
until curl -sf "http://127.0.0.1:${CAPABILITY_PORT}/health" >/dev/null 2>&1 || [[ "${TRIES}" -ge 20 ]]; do
  TRIES=$((TRIES + 1))
  sleep 0.5
done
if [[ "${TRIES}" -ge 20 ]]; then
  log "error: capability service did not start in 10s"
  kill "${CAPABILITY_PID}" 2>/dev/null || true
  exit 1
fi
log "capability service ready"

# ── Start Envoy ────────────────────────────────────────────────────────
log "starting Envoy on port ${ENVOY_PORT}"
envoy \
  -c /etc/envoy/envoy.yaml \
  --log-level warn \
  --drain-time-s 10 \
  &
ENVOY_PID=$!

# ── Wait for termination signal, clean up children ─────────────────────
trap 'log "shutting down"; kill "${CAPABILITY_PID}" "${ENVOY_PID}" 2>/dev/null || true; wait' TERM INT

wait
