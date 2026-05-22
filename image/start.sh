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
# Benchmark route: the optional `x-gm-provider: benchmark` route proxies
# to a synthetic upstream named by GM_BENCHMARK_UPSTREAM_URL. Its
# cluster cannot be baked in statically (the upstream is a runtime URL),
# so the route + cluster live between `## gm:benchmark-begin` and
# `## gm:benchmark-end` sentinel lines in envoy.yaml. The rendering step
# below substitutes the URL's host/port into that block, or drops the
# whole block when GM_BENCHMARK_UPSTREAM_URL is unset — the route then
# disappears and a `benchmark` request falls through to the 501
# catch-all (the same "route disabled" outcome as an unset provider
# key).
#
# Process supervision: attestd and envoy both run in the background;
# this script stays PID 1 and `wait -n`s on both. When either exits the
# whole container exits non-zero so the runtime's `restart:
# unless-stopped` policy recreates the stack — a miner missing either
# process cannot serve the registry, so crashing fast and recovering is
# the correct behaviour. The exit log names which process died and its
# status, so a genuine crash is diagnosable from `phala cvms logs`.

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

# ── Resolve the benchmark upstream ────────────────────────────────────
# GM_BENCHMARK_UPSTREAM_URL, when set, names the synthetic upstream the
# `x-gm-provider: benchmark` route proxies to. Envoy clusters take a
# host and a port, not a URL, so the URL is split here. Only the host
# (or host:port) authority is consumed — scheme and path are ignored:
# the benchmark cluster is plain HTTP/1.1 and the route forwards the
# request path unchanged. An explicit port is used as given; with none,
# port 80 is the default.
#
# The host and port are validated here rather than at envoy startup: an
# unvalidated value renders into envoy.yaml verbatim, and a malformed
# one (non-numeric port, empty host) makes envoy reject the config and
# crash-loop with an opaque JSON parse error. Catching it here fails
# fast with a message that names the offending env var. Bracketed IPv6
# literals are not supported — the benchmark upstream is a named
# internal service.
BENCHMARK_HOST=""
BENCHMARK_PORT=""
if [[ -n "${GM_BENCHMARK_UPSTREAM_URL:-}" ]]; then
  benchmark_authority="${GM_BENCHMARK_UPSTREAM_URL#*://}"
  benchmark_authority="${benchmark_authority%%/*}"
  if [[ "${benchmark_authority}" == *:* ]]; then
    BENCHMARK_HOST="${benchmark_authority%:*}"
    BENCHMARK_PORT="${benchmark_authority##*:}"
  else
    BENCHMARK_HOST="${benchmark_authority}"
    BENCHMARK_PORT="80"
  fi
  if [[ -z "${BENCHMARK_HOST}" || "${BENCHMARK_HOST}" == *:* ]]; then
    log "error: GM_BENCHMARK_UPSTREAM_URL has no usable host (bracketed IPv6 is unsupported): ${GM_BENCHMARK_UPSTREAM_URL}"
    exit 1
  fi
  if [[ ! "${BENCHMARK_PORT}" =~ ^[0-9]+$ ]] || ((BENCHMARK_PORT < 1 || BENCHMARK_PORT > 65535)); then
    log "error: GM_BENCHMARK_UPSTREAM_URL has an invalid port (want 1-65535): ${GM_BENCHMARK_UPSTREAM_URL}"
    exit 1
  fi
fi

# ── Render the envoy config ───────────────────────────────────────────
# Two substitutions happen here, both literal token replaces (awk
# index/substr, not gsub) so values with regex- or replacement-special
# characters are handled verbatim. The rendered config goes to a
# writable path; the baked-in /etc/envoy/envoy.yaml stays untouched.
#
#   1. The node secret. Envoy's inbound Lua filter enforces x-gm-node-key
#      against a config literal — Envoy's Lua sandbox does not document
#      os.getenv support, so the secret is substituted in rather than
#      read at Lua runtime. An unset GM_NODE_SECRET renders an empty
#      literal, which the filter treats as "skip the check" (a miner
#      predating node-secret auth).
#   2. The benchmark route + cluster, delimited by `## gm:benchmark-begin`
#      / `## gm:benchmark-end` sentinel lines (matched as whole lines so a
#      mention of the word in a comment never triggers them). When
#      GM_BENCHMARK_UPSTREAM_URL is set, the host/port placeholders are
#      filled and the sentinel lines dropped; when it is unset, every line
#      between the sentinels (sentinels included) is dropped, so the route
#      and cluster vanish from the rendered config.
RENDERED_CONFIG=/tmp/envoy.rendered.yaml
GM_NODE_SECRET="${GM_NODE_SECRET:-}" \
  GM_BENCHMARK_ENABLED="${GM_BENCHMARK_UPSTREAM_URL:+1}" \
  GM_BENCHMARK_HOST="${BENCHMARK_HOST}" \
  GM_BENCHMARK_PORT="${BENCHMARK_PORT}" \
  awk '
  function subst(line, token, value,    out, rest, pos) {
    out = ""
    rest = line
    while ((pos = index(rest, token)) > 0) {
      out = out substr(rest, 1, pos - 1) value
      rest = substr(rest, pos + length(token))
    }
    return out rest
  }
  BEGIN {
    secret = ENVIRON["GM_NODE_SECRET"]
    bench_enabled = (ENVIRON["GM_BENCHMARK_ENABLED"] == "1")
    bench_host = ENVIRON["GM_BENCHMARK_HOST"]
    bench_port = ENVIRON["GM_BENCHMARK_PORT"]
  }
  /^[[:space:]]*## gm:benchmark-begin[[:space:]]*$/ { in_benchmark = 1; next }
  /^[[:space:]]*## gm:benchmark-end[[:space:]]*$/   { in_benchmark = 0; next }
  in_benchmark && !bench_enabled { next }
  {
    line = subst($0, "__GM_NODE_SECRET__", secret)
    line = subst(line, "__GM_BENCHMARK_HOST__", bench_host)
    line = subst(line, "__GM_BENCHMARK_PORT__", bench_port)
    print line
  }
' /etc/envoy/envoy.yaml >"${RENDERED_CONFIG}"

if [[ -n "${GM_NODE_SECRET:-}" ]]; then
  log "GM_NODE_SECRET set — envoy enforces x-gm-node-key on inbound requests"
else
  log "warning: GM_NODE_SECRET unset — inbound data plane is unauthenticated"
fi

if [[ -n "${GM_BENCHMARK_UPSTREAM_URL:-}" ]]; then
  log "GM_BENCHMARK_UPSTREAM_URL set — benchmark route proxies to ${BENCHMARK_HOST}:${BENCHMARK_PORT}"
else
  log "GM_BENCHMARK_UPSTREAM_URL unset — benchmark route disabled"
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

# ── Supervise both processes ──────────────────────────────────────────
# `wait -n` blocks until *either* child exits, then returns that child's
# status. It must run in this (the main) shell: `wait` can only reap a
# shell's own children, so a backgrounded `( wait "$PID" )` subshell
# sees neither attestd nor envoy as its child and returns 127
# immediately — falsely reporting the process dead. Whichever process
# exits first, the container must come down so the runtime's
# `restart: unless-stopped` policy recreates the whole stack: a miner
# missing either envoy or attestd cannot serve the registry.
#
# `|| FIRST_EXIT_STATUS=$?` captures the exited child's status AND keeps
# `set -e` from aborting the script the instant a process exits
# non-zero — without it the diagnostic block below never runs and the
# exit cause is never logged.
FIRST_EXIT_STATUS=0
wait -n "${ATTESTD_PID}" "${ENVOY_PID}" || FIRST_EXIT_STATUS=$?

# Name the process that exited so the log states the real cause. `kill
# -0` succeeds only while a pid is still alive; the dead one is the one
# that triggered the `wait -n` return.
if ! kill -0 "${ATTESTD_PID}" 2>/dev/null; then
  log "error: attestation server exited (status ${FIRST_EXIT_STATUS}) — stopping container"
elif ! kill -0 "${ENVOY_PID}" 2>/dev/null; then
  log "error: envoy exited (status ${FIRST_EXIT_STATUS}) — stopping container"
else
  log "error: a supervised process exited (status ${FIRST_EXIT_STATUS}) — stopping container"
fi

# Stop the survivor and reap it before exiting.
kill -TERM "${ATTESTD_PID}" "${ENVOY_PID}" 2>/dev/null || true
wait 2>/dev/null || true

# Always exit non-zero so the container runtime's `restart:
# unless-stopped` policy recreates the stack. A supervised process
# exiting *at all* — even with a clean status 0 (a graceful or
# self-initiated shutdown) — leaves the miner missing one of its two
# required services, which is a failure. The exit code is only a
# diagnostic detail: surface it when it is non-zero, otherwise exit 1
# so a status-0 child exit is still treated as a container failure.
if [[ "${FIRST_EXIT_STATUS}" -ne 0 ]]; then
  exit "${FIRST_EXIT_STATUS}"
fi
exit 1
