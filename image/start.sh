#!/usr/bin/env bash
# gm miner container entrypoint.
#
# The miner runtime is two co-located processes:
#
#   1. gm-miner-attestd — serves GET /attestation/info with a fresh
#      Intel TDX quote from the dstack guest agent. Bound to loopback;
#      envoy routes the single /attestation/info path to it.
#   2. envoy — the data plane on :8080. Proxies provider inference
#      traffic and the registry's x-gm-provider capability probes, and
#      forwards /attestation/info to the attestation server.
#
# Disabled-route handling: envoy's static config carries all three
# provider clusters. Routes match on `x-gm-provider`. When the
# corresponding env var is absent envoy injects an empty key and the
# upstream returns 401; the registry's probe surfaces that as a
# capability failure for the affected provider. The 501 fallback in
# envoy.yaml fires only when no provider header arrives.
#
# Process supervision: attestd runs in the background. If it exits the
# whole container exits non-zero so the runtime's `restart:
# unless-stopped` policy recreates it — a miner with a dead attestation
# server fails the registry's attestation check and gets suspended, so
# crashing fast and recovering is the correct behaviour.

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

# ── Render the node secret into the envoy config ──────────────────────
# Envoy's inbound Lua filter enforces x-gm-node-key against a config
# literal — Envoy's Lua sandbox does not document os.getenv support, so
# the secret is substituted in here rather than read at Lua runtime. An
# unset GM_NODE_SECRET renders an empty literal, which the filter treats
# as "skip the check" (a miner predating node-secret auth).
#
# The substitution is a literal token replace (awk index/substr, not
# gsub) so a secret containing regex- or replacement-special characters
# is handled verbatim. The rendered config goes to a writable path; the
# baked-in /etc/envoy/envoy.yaml stays untouched.
RENDERED_CONFIG=/tmp/envoy.rendered.yaml
GM_NODE_SECRET="${GM_NODE_SECRET:-}" awk '
  BEGIN { token = "__GM_NODE_SECRET__"; secret = ENVIRON["GM_NODE_SECRET"] }
  {
    out = ""
    rest = $0
    while ((pos = index(rest, token)) > 0) {
      out = out substr(rest, 1, pos - 1) secret
      rest = substr(rest, pos + length(token))
    }
    print out rest
  }
' /etc/envoy/envoy.yaml >"${RENDERED_CONFIG}"

if [[ -n "${GM_NODE_SECRET:-}" ]]; then
  log "GM_NODE_SECRET set — envoy enforces x-gm-node-key on inbound requests"
else
  log "warning: GM_NODE_SECRET unset — inbound data plane is unauthenticated"
fi

GM_IMAGE_VERSION="${GM_IMAGE_VERSION:-unknown}"
log "image version: ${GM_IMAGE_VERSION}"

# ── Launch the attestation server ─────────────────────────────────────
# gm-miner-attestd binds 127.0.0.1:8081 (envoy's `attestd` cluster
# target) and fetches TDX quotes over /var/run/dstack.sock. The socket
# is bind-mounted by the dstack compose; without it attestd exits at
# startup and the supervision block below brings the container down.
ATTESTD_BIND_ADDR="127.0.0.1:8081"
export GM_ATTESTD_BIND_ADDR="${ATTESTD_BIND_ADDR}"
log "starting attestation server on ${ATTESTD_BIND_ADDR}"
gm-miner-attestd &
ATTESTD_PID=$!

# If attestd dies, terminate envoy so the container exits and the
# runtime restarts the whole stack.
monitor_attestd() {
  wait "${ATTESTD_PID}" 2>/dev/null || true
  log "error: attestation server exited — stopping container"
  kill -TERM "${ENVOY_PID}" 2>/dev/null || true
}

# ── Launch envoy ──────────────────────────────────────────────────────
# Not `exec`d: the script stays PID 1 so it can supervise both
# processes. SIGTERM from the container runtime is forwarded to both.
log "starting envoy"
envoy \
  -c "${RENDERED_CONFIG}" \
  --log-level warn \
  --drain-time-s 10 &
ENVOY_PID=$!

# shellcheck disable=SC2317,SC2329  # invoked indirectly via the trap below.
shutdown() {
  log "received signal — shutting down"
  kill -TERM "${ENVOY_PID}" "${ATTESTD_PID}" 2>/dev/null || true
}
trap shutdown TERM INT

monitor_attestd &

# Exit with envoy's status. `wait` on a specific PID returns that
# process's exit code; a non-zero code propagates so the runtime's
# restart policy fires.
wait "${ENVOY_PID}"
ENVOY_STATUS=$?
kill -TERM "${ATTESTD_PID}" 2>/dev/null || true
log "envoy exited with status ${ENVOY_STATUS}"
exit "${ENVOY_STATUS}"
