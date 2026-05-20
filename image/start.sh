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

# ── Exec envoy as PID 1 ───────────────────────────────────────────────
# `exec` so envoy receives signals (SIGTERM from the container runtime)
# directly and the container exits when envoy does.
log "starting envoy"
exec envoy \
  -c "${RENDERED_CONFIG}" \
  --log-level warn \
  --drain-time-s 10
