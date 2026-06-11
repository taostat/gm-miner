#!/usr/bin/env bash
# gm miner container entrypoint.
#
# Startup runs one one-shot provisioning step, then launches up to
# three co-located long-running processes:
#
#   0. gm-miner-ratls (one-shot) — mints the data-plane RA-TLS
#      certificate via dstack's GetTlsKey RPC and writes the key/cert
#      PEM files envoy's :8080 DownstreamTlsContext references. Runs to
#      completion before envoy starts; a failure aborts the container.
#   1. gm-miner-attestd — serves GET /attestation/info with a fresh
#      Intel TDX quote from the dstack guest agent. Bound to loopback;
#      envoy routes the single /attestation/info path to it.
#   2. gm-miner-auth-sidecar (conditional) — refreshes provider OAuth
#      subscription tokens and exposes them to envoy via a loopback
#      HTTP endpoint. Only launched when at least one provider is
#      configured in oauth_subscription mode (`GM_<PROVIDER>_OAUTH_
#      REFRESH_TOKEN` set); api-key-only deployments skip this step
#      and the envoy config drops the oauth route blocks at render
#      time, so the loopback cluster is never referenced.
#   3. envoy — the data plane on :8080. Terminates RA-TLS with the
#      minted certificate, proxies provider inference traffic and the
#      registry's x-gm-provider capability probes, and forwards
#      /attestation/info to the attestation server.
#
# Disabled-route handling: envoy's static config carries all three
# provider clusters. Routes match on `x-gm-provider`. When the
# corresponding env var is absent envoy injects an empty key and the
# upstream returns 401; the registry's probe surfaces that as a
# capability failure for the affected provider. The 501 fallback in
# envoy.yaml fires only when no provider header arrives.
#
# Benchmark route: the `x-gm-provider: benchmark` route proxies to the
# benchmark upstream URL keyed off GM_NETWORK below. Both the testnet
# and mainnet URLs are hardcoded in this script, so the upstream cannot
# be redirected by editing an env var — only by editing this script,
# which moves the compose_hash and is rejected by the registry's
# attestation enforcement. The rendering step substitutes the resolved
# URL's host/port into envoy.yaml.
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

# ── Resolve per-provider auth mode (api_key vs oauth_subscription) ────
# A provider is in oauth_subscription mode iff its
# GM_<PROVIDER>_OAUTH_REFRESH_TOKEN env var is set. Otherwise it is in
# api_key mode (the default). The two modes are mutually exclusive on
# any given provider — the envoy config keeps exactly one route block
# per provider (see the gm:<provider>-{apikey,oauth} sentinel pairs in
# envoy.yaml). When a provider has BOTH an api key and an OAuth refresh
# token set, oauth_subscription wins — the operator explicitly opted
# in to OAuth via `gm-miner deploy --paste-{codex,claude}-auth` and the
# api-key fallback would silently mask that intent.
ANTHROPIC_OAUTH=0
OPENAI_OAUTH=0
if [[ -n "${GM_ANTHROPIC_OAUTH_REFRESH_TOKEN:-}" ]]; then
  ANTHROPIC_OAUTH=1
fi
if [[ -n "${GM_OPENAI_OAUTH_REFRESH_TOKEN:-}" ]]; then
  OPENAI_OAUTH=1
fi

# ── Require at least one provider credential ──────────────────────────
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
if [[ "${ANTHROPIC_OAUTH}" -eq 1 ]]; then
  HAS_KEY=1
  log "GM_ANTHROPIC_OAUTH_REFRESH_TOKEN set — anthropic in oauth_subscription mode"
fi
if [[ "${OPENAI_OAUTH}" -eq 1 ]]; then
  HAS_KEY=1
  log "GM_OPENAI_OAUTH_REFRESH_TOKEN set — openai in oauth_subscription mode"
fi

if [[ "${HAS_KEY}" -eq 0 ]]; then
  log "error: at least one provider credential must be set — ANTHROPIC_API_KEY / OPENAI_API_KEY / GOOGLE_API_KEY or GM_{ANTHROPIC,OPENAI}_OAUTH_REFRESH_TOKEN"
  exit 1
fi

# ── Resolve the benchmark upstream ────────────────────────────────────
# The benchmark URL is hardcoded per network in this script, NOT taken
# from a runtime env var: a miner cannot redirect the `x-gm-provider:
# benchmark` route to a colluding service without editing this file,
# which moves the compose_hash and is rejected by the registry's
# attestation enforcement. GM_NETWORK is set by `gm-miner deploy` as a
# rendered literal in dstack/docker-compose.yaml — part of the
# attestation-measured compose source — so its value is fixed at deploy
# time and equally tamper-evident.
#
# Envoy clusters take a host and a port, not a URL: the literal URL
# below is split into BENCHMARK_HOST / BENCHMARK_PORT / BENCHMARK_TLS,
# then substituted into envoy.yaml's benchmark cluster. The scheme
# decides both the default port (443 for https, 80 for http) and
# whether the cluster carries an upstream TLS context — envoy.yaml's
# `gm:benchmark-tls` sentinel block is kept when the URL is https and
# dropped when it is http.
case "${GM_NETWORK:?GM_NETWORK must be set (rendered into dstack/docker-compose.yaml by gm-miner deploy)}" in
  testnet) BENCHMARK_URL="https://test-benchmark.saygm.com" ;;
  mainnet) BENCHMARK_URL="https://benchmark.saygm.com" ;;
  *)
    log "error: unknown GM_NETWORK '${GM_NETWORK}' (want testnet or mainnet)"
    exit 1
    ;;
esac

case "${BENCHMARK_URL}" in
  https://*)
    BENCHMARK_TLS=1
    benchmark_default_port=443
    ;;
  http://*)
    BENCHMARK_TLS=0
    benchmark_default_port=80
    ;;
  *)
    log "error: BENCHMARK_URL must start with http:// or https:// (got '${BENCHMARK_URL}')"
    exit 1
    ;;
esac

benchmark_authority="${BENCHMARK_URL#*://}"
benchmark_authority="${benchmark_authority%%/*}"
if [[ "${benchmark_authority}" == *:* ]]; then
  BENCHMARK_HOST="${benchmark_authority%:*}"
  BENCHMARK_PORT="${benchmark_authority##*:}"
else
  BENCHMARK_HOST="${benchmark_authority}"
  BENCHMARK_PORT="${benchmark_default_port}"
fi

# ── Render the envoy config ───────────────────────────────────────────
# Literal token replaces (awk index/substr, not gsub) so values with
# regex- or replacement-special characters are handled verbatim. The
# rendered config goes to a writable path; the baked-in
# /etc/envoy/envoy.yaml stays untouched.
#
#   1. The node secret. Envoy's inbound Lua filter enforces x-gm-node-key
#      against a config literal — Envoy's Lua sandbox does not document
#      os.getenv support, so the secret is substituted in rather than
#      read at Lua runtime. An unset GM_NODE_SECRET renders an empty
#      literal, which the filter treats as "skip the check" (a miner
#      predating node-secret auth).
#   2. The benchmark cluster's host and port — resolved above from the
#      hardcoded per-network URL.
#   3. The benchmark cluster's upstream TLS block, delimited by
#      `## gm:benchmark-tls-begin` / `-end` whole-line sentinels. Kept
#      when the URL is https; dropped (the cluster stays plain HTTP/1.1)
#      when it is http.
#   4. Per-provider auth-mode route blocks. For each of anthropic and
#      openai the config carries TWO route blocks side by side, wrapped
#      in `gm:<provider>-apikey-begin/end` and `gm:<provider>-oauth-
#      begin/end` whole-line sentinels. Exactly ONE block per provider
#      survives: the api-key block when the provider is in api-key mode
#      (default), the oauth block when GM_<PROVIDER>_OAUTH_REFRESH_TOKEN
#      is set. Mode resolution happens above; the awk below just keeps
#      or drops each block per the resolved `*_OAUTH` flag.
RENDERED_CONFIG=/tmp/envoy.rendered.yaml
GM_NODE_SECRET="${GM_NODE_SECRET:-}" \
  GM_BENCHMARK_HOST="${BENCHMARK_HOST}" \
  GM_BENCHMARK_PORT="${BENCHMARK_PORT}" \
  GM_BENCHMARK_TLS="${BENCHMARK_TLS}" \
  GM_ANTHROPIC_OAUTH="${ANTHROPIC_OAUTH}" \
  GM_OPENAI_OAUTH="${OPENAI_OAUTH}" \
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
    bench_host = ENVIRON["GM_BENCHMARK_HOST"]
    bench_port = ENVIRON["GM_BENCHMARK_PORT"]
    bench_tls = (ENVIRON["GM_BENCHMARK_TLS"] == "1")
    anth_oauth = (ENVIRON["GM_ANTHROPIC_OAUTH"] == "1")
    oai_oauth = (ENVIRON["GM_OPENAI_OAUTH"] == "1")
  }
  /^[[:space:]]*## gm:benchmark-tls-begin[[:space:]]*$/   { in_bench_tls = 1; next }
  /^[[:space:]]*## gm:benchmark-tls-end[[:space:]]*$/     { in_bench_tls = 0; next }
  /^[[:space:]]*## gm:anthropic-apikey-begin[[:space:]]*$/ { in_anth_apikey = 1; next }
  /^[[:space:]]*## gm:anthropic-apikey-end[[:space:]]*$/   { in_anth_apikey = 0; next }
  /^[[:space:]]*## gm:anthropic-oauth-begin[[:space:]]*$/  { in_anth_oauth = 1; next }
  /^[[:space:]]*## gm:anthropic-oauth-end[[:space:]]*$/    { in_anth_oauth = 0; next }
  /^[[:space:]]*## gm:openai-apikey-begin[[:space:]]*$/    { in_oai_apikey = 1; next }
  /^[[:space:]]*## gm:openai-apikey-end[[:space:]]*$/      { in_oai_apikey = 0; next }
  /^[[:space:]]*## gm:openai-oauth-begin[[:space:]]*$/     { in_oai_oauth = 1; next }
  /^[[:space:]]*## gm:openai-oauth-end[[:space:]]*$/       { in_oai_oauth = 0; next }
  in_bench_tls    && !bench_tls  { next }
  in_anth_apikey  && anth_oauth  { next }
  in_anth_oauth   && !anth_oauth { next }
  in_oai_apikey   && oai_oauth   { next }
  in_oai_oauth    && !oai_oauth  { next }
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

if [[ "${BENCHMARK_TLS}" -eq 1 ]]; then
  log "benchmark route proxies to https://${BENCHMARK_HOST}:${BENCHMARK_PORT} (GM_NETWORK=${GM_NETWORK})"
else
  log "benchmark route proxies to http://${BENCHMARK_HOST}:${BENCHMARK_PORT} (GM_NETWORK=${GM_NETWORK})"
fi

GM_IMAGE_VERSION="${GM_IMAGE_VERSION:-unknown}"
log "image version: ${GM_IMAGE_VERSION}"

# ── Provision the data-plane RA-TLS certificate ───────────────────────
# Mechanism 2 of attestation-and-identity.md. gm-miner-ratls calls the
# dstack guest agent's GetTlsKey RPC (over /var/run/dstack.sock) with
# usage_ra_tls=true: the guest agent mints a fresh TLS key, takes a TDX
# quote bound to that key, and issues an X.509 cert carrying the quote.
# It writes the PEM key/cert to /tmp/gm-ratls/; envoy's :8080
# DownstreamTlsContext references those exact paths (the paths are a
# build-time contract baked into both gm-miner-ratls and envoy.yaml).
#
# This is a one-shot step that must finish before envoy starts — envoy
# fails to bind a TLS listener if the cert files are absent. A dstack
# failure here is fatal: gm-miner-ratls exits non-zero, `set -e` aborts
# the container, and the runtime's `restart: unless-stopped` policy
# retries the whole startup — the same fail-fast posture attestd uses
# for its own dstack calls.
log "minting data-plane RA-TLS certificate via dstack get_tls_key"
gm-miner-ratls
log "RA-TLS certificate ready"

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

# ── Launch the OAuth refresh sidecar (if any provider needs it) ───────
# gm-miner-auth-sidecar binds 127.0.0.1:7100 (the `auth_sidecar` envoy
# cluster target) and 127.0.0.1:7101 (the sidecar's `/metrics` scrape
# surface). It is only required when at least one provider is in
# oauth_subscription mode — running it in api-key-only deployments
# would add a second supervised process that has no work to do, so
# start.sh skips it. The envoy config's OAuth route blocks are also
# dropped on those deployments (the awk sentinel handling above), so
# `auth_sidecar` is never referenced from a live route.
AUTH_SIDECAR_PID=""
if [[ "${ANTHROPIC_OAUTH}" -eq 1 || "${OPENAI_OAUTH}" -eq 1 ]]; then
  export GM_AUTH_SIDECAR_TOKEN_BIND_ADDR="127.0.0.1:7100"
  export GM_AUTH_SIDECAR_METRICS_BIND_ADDR="127.0.0.1:7101"
  log "starting auth sidecar on ${GM_AUTH_SIDECAR_TOKEN_BIND_ADDR} (metrics ${GM_AUTH_SIDECAR_METRICS_BIND_ADDR})"
  gm-miner-auth-sidecar &
  AUTH_SIDECAR_PID=$!
fi

# ── Launch envoy ──────────────────────────────────────────────────────
# Not `exec`d: the script stays PID 1 so it can supervise the child
# processes. SIGTERM from the container runtime is forwarded to every
# supervised process via the trap below.
log "starting envoy"
envoy \
  -c "${RENDERED_CONFIG}" \
  --log-level warn \
  --drain-time-s 10 &
ENVOY_PID=$!

# shellcheck disable=SC2317,SC2329  # invoked indirectly via the trap below.
shutdown() {
  log "received signal — shutting down"
  kill -TERM "${ENVOY_PID}" "${ATTESTD_PID}" ${AUTH_SIDECAR_PID:+"${AUTH_SIDECAR_PID}"} 2>/dev/null || true
}
trap shutdown TERM INT

# ── Supervise every long-running child ────────────────────────────────
# `wait -n` blocks until *any* child exits, then returns that child's
# status. It must run in this (the main) shell: `wait` can only reap a
# shell's own children, so a backgrounded `( wait "$PID" )` subshell
# sees neither attestd nor envoy nor the sidecar as its child and
# returns 127 immediately — falsely reporting the process dead.
# Whichever process exits first, the container must come down so the
# runtime's `restart: unless-stopped` policy recreates the whole stack:
# a miner missing any of envoy / attestd / (when enabled) the auth
# sidecar cannot serve the registry.
#
# `|| FIRST_EXIT_STATUS=$?` captures the exited child's status AND keeps
# `set -e` from aborting the script the instant a process exits
# non-zero — without it the diagnostic block below never runs and the
# exit cause is never logged.
FIRST_EXIT_STATUS=0
wait -n "${ATTESTD_PID}" "${ENVOY_PID}" \
  ${AUTH_SIDECAR_PID:+"${AUTH_SIDECAR_PID}"} ||
  FIRST_EXIT_STATUS=$?

# Name the process that exited so the log states the real cause. `kill
# -0` succeeds only while a pid is still alive; the dead one is the one
# that triggered the `wait -n` return.
if ! kill -0 "${ATTESTD_PID}" 2>/dev/null; then
  log "error: attestation server exited (status ${FIRST_EXIT_STATUS}) — stopping container"
elif ! kill -0 "${ENVOY_PID}" 2>/dev/null; then
  log "error: envoy exited (status ${FIRST_EXIT_STATUS}) — stopping container"
elif [[ -n "${AUTH_SIDECAR_PID}" ]] && ! kill -0 "${AUTH_SIDECAR_PID}" 2>/dev/null; then
  log "error: auth sidecar exited (status ${FIRST_EXIT_STATUS}) — stopping container"
else
  log "error: a supervised process exited (status ${FIRST_EXIT_STATUS}) — stopping container"
fi

# Stop the survivors and reap them before exiting.
kill -TERM "${ATTESTD_PID}" "${ENVOY_PID}" \
  ${AUTH_SIDECAR_PID:+"${AUTH_SIDECAR_PID}"} 2>/dev/null || true
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
