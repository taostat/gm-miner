#!/usr/bin/env bash
# gm miner container entrypoint.
#
# Startup runs the required one-shot gates, then launches the required
# co-located long-running processes:
#
#   0. gm-miner-attestd --verify-azure-once (one-shot, Azure only) —
#      verifies the configured Azure OpenAI account owner-capture
#      controls before Envoy can serve Azure traffic. A failure aborts
#      the container.
#   1. gm-miner-ratls (one-shot) — mints the data-plane RA-TLS
#      certificate via dstack's GetTlsKey RPC and writes the key/cert
#      PEM files envoy's :8080 DownstreamTlsContext references. Runs to
#      completion before envoy starts; a failure aborts the container.
#   2. gm-miner-attestd — serves GET /attestation/info with a fresh
#      Intel TDX quote from the dstack guest agent. Bound to loopback;
#      envoy routes the single /attestation/info path to it.
#   3. gm-near-verify-proxy (when NEAR_API_KEY is configured) — verifies
#      nonce-bound TDX, GPU, model and live TLS-key evidence on the exact
#      upstream connection used for each NEAR inference request.
#   4. gm-chutes-verify-proxy (when CHUTES_API_KEY is configured) — admits
#      Chutes instances on verified TDX, GPU and measurement evidence and
#      carries confidential Chutes requests end to end encrypted to the
#      admitted instance key.
#   5. envoy — the data plane on :8080. Terminates RA-TLS with the
#      minted certificate, proxies provider inference traffic and the
#      registry's x-gm-provider capability probes, and forwards
#      /attestation/info to the attestation server.
#
# Disabled-route handling: envoy's static config carries all direct
# provider clusters. Routes match on `x-gm-provider`. When the
# corresponding env var is absent envoy injects an empty key and the
# upstream returns 401; the registry's probe surfaces that as a
# capability failure for the affected provider. The 501 fallback in
# image/envoy/base.yaml fires only when no provider header arrives.
#
# Benchmark route: the `x-gm-provider: benchmark` route proxies to the
# benchmark upstream URL keyed off GM_NETWORK below. Both the testnet
# and mainnet URLs are hardcoded in this script, so the upstream cannot
# be redirected by editing an env var — only by editing this script,
# which moves the compose_hash and is rejected by the registry's
# attestation enforcement. The rendering step substitutes the resolved
# host into the benchmark upstream file.
#
# Process supervision: required servers run in the background; this script
# stays PID 1 and watches all of them. When any exits the
# whole container exits non-zero so the runtime's `restart:
# unless-stopped` policy recreates the stack — a miner missing Envoy,
# attestd, or a configured NEAR or Chutes verifier cannot serve the registry, so crashing fast and recovering is
# the correct behaviour. The exit log names which process died and its
# status, so a genuine crash is diagnosable from `phala cvms logs`.

set -euo pipefail

log() { printf '[start] %s\n' "$*" >&2; }

lowercase() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

fan_out_slots() {
  local provider="$1"
  local env_var="$2"
  # Legacy/no-node-secret deployments cannot derive slot ids (the HMAC key
  # is the node secret). A single key keeps working through the direct env
  # fallback in the Lua filter; multiple keys have nothing to select them
  # by, so that combination is a configuration error.
  if [[ -z "${GM_NODE_SECRET:-}" ]]; then
    if [[ "${!env_var:-}" == *";"* ]]; then
      log "error: ${env_var} holds multiple keys but GM_NODE_SECRET is unset; upstream key slots require a node secret"
      exit 1
    fi
    return 0
  fi
  local exports
  if ! exports="$("${GMCLI_BIN:-gmcli}" slot-env --provider "${provider}" --env-var "${env_var}")"; then
    log "error: failed to derive upstream key slots for ${env_var}"
    exit 1
  fi
  # shellcheck disable=SC2090 # gmcli emits shell-quoted export lines only.
  eval "${exports}"
}

ANTHROPIC_UPSTREAM="${ANTHROPIC_UPSTREAM:-direct}"
OPENAI_UPSTREAM="${OPENAI_UPSTREAM:-direct}"

# The node secret is substituted raw into the Envoy Lua filter as a bare
# string literal (`local expected = "<secret>"`); a value carrying a quote,
# backslash, or newline would close that literal and inject attacker Lua onto
# the buyer data path. The registry constrains the secret it registers to
# `^[A-Za-z0-9_-]{16,128}$`, but the CVM env is supplied independently and is
# not covered by the attestation compose_hash — so re-check it here before it
# reaches the render. Empty stays allowed: that selects the unauthenticated
# legacy path the Lua already handles.
validate_node_secret() {
  local secret="${GM_NODE_SECRET:-}"
  # C locale so the character class is ASCII, not a locale-widened range.
  local LC_ALL=C
  if [[ -n "${secret}" && ! "${secret}" =~ ^[A-Za-z0-9_-]{16,128}$ ]]; then
    log "error: GM_NODE_SECRET must match ^[A-Za-z0-9_-]{16,128}\$ (16-128 URL-safe chars); refusing to render the data plane"
    exit 1
  fi
}

validate_hostname() {
  local name="$1"
  local host="$2"
  if [[ -z "${host}" || "${host}" == *[!A-Za-z0-9.-]* || "${host}" == .* || "${host}" == *. || "${host}" == *..* ]]; then
    log "error: ${name} must be a DNS host (got '${host}')"
    exit 1
  fi
}

require_host_suffix() {
  local name="$1"
  local host="$2"
  shift 2
  local suffix
  for suffix in "$@"; do
    if [[ "${host}" == *".${suffix}" ]]; then
      return
    fi
  done
  log "error: ${name} host '${host}' is not in the allowed suffix set: $*"
  exit 1
}

## Cloud backend keys are single-slot: a ';'-separated value
## would advertise slots the registry never probes.
require_single_slot() {
  local name="$1"
  local value="$2"
  local upstream="$3"
  if [[ "${value}" == *";"* ]]; then
    log "error: ${name} cannot contain ';' when ${upstream}; cloud backends are single-slot"
    exit 1
  fi
}

matched_host_suffix() {
  local host="$1"
  shift
  local suffix
  for suffix in "$@"; do
    if [[ "${host}" == *".${suffix}" ]]; then
      printf '%s' "${suffix}"
      return 0
    fi
  done
  return 1
}

## Extract the host from an Azure endpoint URL. `name` is the env var the
## endpoint came from, so the error names what the operator must fix.
parse_azure_host() {
  local name="$1"
  local endpoint="$2"
  local rest="${endpoint}"
  case "${endpoint}" in
    https://*) rest="${endpoint#https://}" ;;
    http://*)
      log "error: ${name} must use https when a scheme is provided"
      exit 1
      ;;
    *://*)
      log "error: ${name} has unsupported URL scheme"
      exit 1
      ;;
    *)
      log "error: ${name} must use https"
      exit 1
      ;;
  esac
  rest="${rest%%/*}"
  rest="${rest%%\?*}"
  rest="${rest%%#*}"
  if [[ "${rest}" == *"@"* ]]; then
    log "error: ${name} must not contain userinfo"
    exit 1
  fi
  if [[ "${rest}" == *:* ]]; then
    rest="${rest%%:*}"
  fi
  lowercase "${rest}"
}

# ── Resolve provider upstream selectors ───────────────────────────────
ANTHROPIC_HOST=api.anthropic.com
AZURE_ENABLED=0

case "${ANTHROPIC_UPSTREAM}" in
  direct) ;;
  bedrock)
    if [[ -z "${BEDROCK_REGION:-}" ]]; then
      log "error: BEDROCK_REGION must be set when ANTHROPIC_UPSTREAM=bedrock"
      exit 1
    fi
    if [[ -z "${BEDROCK_API_KEY:-}" ]]; then
      log "error: BEDROCK_API_KEY must be set when ANTHROPIC_UPSTREAM=bedrock"
      exit 1
    fi
    require_single_slot BEDROCK_API_KEY "${BEDROCK_API_KEY}" "ANTHROPIC_UPSTREAM=bedrock"
    if [[ ! "${BEDROCK_REGION}" =~ ^[A-Za-z0-9-]+$ ]]; then
      log "error: BEDROCK_REGION must contain only letters, numbers, and hyphens"
      exit 1
    fi
    ANTHROPIC_HOST="bedrock-mantle.$(lowercase "${BEDROCK_REGION}").api.aws"
    validate_hostname "Bedrock" "${ANTHROPIC_HOST}"
    case "${ANTHROPIC_HOST}" in
      bedrock-mantle.*.api.aws) ;;
      *)
        log "error: Bedrock host '${ANTHROPIC_HOST}' is not allowed"
        exit 1
        ;;
    esac
    # anthropic.bedrock.yaml matches this exact Mantle host's SAN; a suffix
    # match would also admit unrelated *.api.aws certs. Inference is refused
    # inside the image because Bedrock has no qualified model echo.
    ;;
  foundry)
    ## Microsoft Foundry serves Claude on an Anthropic-native passthrough:
    ## POST https://<resource>.services.ai.azure.com/anthropic/v1/messages,
    ## same Messages body, same `anthropic-version` header, `x-api-key` auth.
    ## `services.ai.azure.com` is the only host
    ## Microsoft and Anthropic document for this endpoint — do not widen it.
    if [[ -z "${AZURE_FOUNDRY_ENDPOINT:-}" ]]; then
      log "error: AZURE_FOUNDRY_ENDPOINT must be set when ANTHROPIC_UPSTREAM=foundry"
      exit 1
    fi
    if [[ -z "${AZURE_FOUNDRY_API_KEY:-}" ]]; then
      log "error: AZURE_FOUNDRY_API_KEY must be set when ANTHROPIC_UPSTREAM=foundry"
      exit 1
    fi
    require_single_slot AZURE_FOUNDRY_API_KEY "${AZURE_FOUNDRY_API_KEY}" "ANTHROPIC_UPSTREAM=foundry"
    ANTHROPIC_HOST="$(parse_azure_host AZURE_FOUNDRY_ENDPOINT "${AZURE_FOUNDRY_ENDPOINT}")"
    validate_hostname "Microsoft Foundry" "${ANTHROPIC_HOST}"
    require_host_suffix "Microsoft Foundry" "${ANTHROPIC_HOST}" services.ai.azure.com
    AZURE_ENABLED=1
    ;;
  *)
    log "error: ANTHROPIC_UPSTREAM must be 'direct', 'bedrock', or 'foundry' (got '${ANTHROPIC_UPSTREAM}')"
    exit 1
    ;;
esac

OPENAI_HOST=api.openai.com
OPENAI_SAN_SUFFIX=

case "${OPENAI_UPSTREAM}" in
  direct) ;;
  azure)
    if [[ -z "${AZURE_OPENAI_ENDPOINT:-}" ]]; then
      log "error: AZURE_OPENAI_ENDPOINT must be set when OPENAI_UPSTREAM=azure"
      exit 1
    fi
    if [[ -z "${AZURE_OPENAI_API_KEY:-}" ]]; then
      log "error: AZURE_OPENAI_API_KEY must be set when OPENAI_UPSTREAM=azure"
      exit 1
    fi
    require_single_slot AZURE_OPENAI_API_KEY "${AZURE_OPENAI_API_KEY}" "OPENAI_UPSTREAM=azure"
    OPENAI_HOST="$(parse_azure_host AZURE_OPENAI_ENDPOINT "${AZURE_OPENAI_ENDPOINT}")"
    validate_hostname "Azure OpenAI" "${OPENAI_HOST}"
    require_host_suffix "Azure OpenAI" "${OPENAI_HOST}" \
      openai.azure.com \
      services.ai.azure.com \
      cognitiveservices.azure.com
    AZURE_OPENAI_SUFFIX="$(matched_host_suffix "${OPENAI_HOST}" \
      openai.azure.com \
      services.ai.azure.com \
      cognitiveservices.azure.com)"
    OPENAI_SAN_SUFFIX=".${AZURE_OPENAI_SUFFIX}"
    AZURE_ENABLED=1
    ;;
  *)
    log "error: OPENAI_UPSTREAM must be 'direct' or 'azure' (got '${OPENAI_UPSTREAM}')"
    exit 1
    ;;
esac

# ── Require at least one provider key ─────────────────────────────────
HAS_KEY=0
if [[ "${ANTHROPIC_UPSTREAM}" == "direct" && -n "${ANTHROPIC_API_KEY:-}" ]]; then
  HAS_KEY=1
  log "ANTHROPIC_API_KEY set"
fi
if [[ "${ANTHROPIC_UPSTREAM}" == "bedrock" && -n "${BEDROCK_API_KEY:-}" ]]; then
  HAS_KEY=1
  log "BEDROCK_API_KEY set"
fi
if [[ "${ANTHROPIC_UPSTREAM}" == "foundry" && -n "${AZURE_FOUNDRY_API_KEY:-}" ]]; then
  HAS_KEY=1
  log "AZURE_FOUNDRY_API_KEY set"
fi
if [[ "${OPENAI_UPSTREAM}" == "direct" && -n "${OPENAI_API_KEY:-}" ]]; then
  HAS_KEY=1
  log "OPENAI_API_KEY set"
fi
if [[ "${OPENAI_UPSTREAM}" == "azure" && -n "${AZURE_OPENAI_API_KEY:-}" ]]; then
  HAS_KEY=1
  log "AZURE_OPENAI_API_KEY set"
fi
if [[ -n "${GOOGLE_API_KEY:-}" ]]; then
  HAS_KEY=1
  log "GOOGLE_API_KEY set"
fi
if [[ -n "${CHUTES_API_KEY:-}" ]]; then
  HAS_KEY=1
  log "CHUTES_API_KEY set"
fi
if [[ -n "${ZAI_API_KEY:-}" ]]; then
  HAS_KEY=1
  log "ZAI_API_KEY set"
fi
if [[ -n "${MOONSHOT_API_KEY:-}" ]]; then
  HAS_KEY=1
  log "MOONSHOT_API_KEY set"
fi
if [[ -n "${DEEPINFRA_API_KEY:-}" ]]; then
  HAS_KEY=1
  log "DEEPINFRA_API_KEY set"
fi
if [[ -n "${KUBETEE_API_KEY:-}" ]]; then
  HAS_KEY=1
  log "KUBETEE_API_KEY set"
fi
if [[ -n "${ENGY_API_KEY:-}" ]]; then
  HAS_KEY=1
  log "ENGY_API_KEY set"
fi
if [[ -n "${MOONMATH_API_KEY:-}" ]]; then
  HAS_KEY=1
  log "MOONMATH_API_KEY set"
fi
if [[ -n "${NEAR_API_KEY:-}" ]]; then
  HAS_KEY=1
  log "NEAR_API_KEY set (NEAR requests require the local attestation proxy)"
fi

if [[ "${HAS_KEY}" -eq 0 ]]; then
  if [[ "${ANTHROPIC_UPSTREAM}" == "direct" && "${OPENAI_UPSTREAM}" == "direct" ]]; then
    log "error: at least one of ANTHROPIC_API_KEY / OPENAI_API_KEY / GOOGLE_API_KEY / CHUTES_API_KEY / ZAI_API_KEY / MOONSHOT_API_KEY / DEEPINFRA_API_KEY / KUBETEE_API_KEY / ENGY_API_KEY / MOONMATH_API_KEY / NEAR_API_KEY must be set"
  else
    log "error: at least one usable provider key must be set"
  fi
  exit 1
fi

# ── Fan direct provider keys out into per-slot process env ────────────
validate_node_secret
if [[ "${AZURE_ENABLED}" -eq 1 && -z "${GM_NODE_SECRET:-}" ]]; then
  log "error: GM_NODE_SECRET must be set when Azure OpenAI or Foundry cloud slot routing is enabled"
  exit 1
fi
if [[ "${ANTHROPIC_UPSTREAM}" == "direct" && -n "${ANTHROPIC_API_KEY:-}" ]]; then
  fan_out_slots anthropic ANTHROPIC_API_KEY
fi
if [[ "${OPENAI_UPSTREAM}" == "direct" && -n "${OPENAI_API_KEY:-}" ]]; then
  fan_out_slots openai OPENAI_API_KEY
fi
if [[ -n "${GOOGLE_API_KEY:-}" ]]; then
  fan_out_slots gemini GOOGLE_API_KEY
fi
if [[ -n "${CHUTES_API_KEY:-}" ]]; then
  fan_out_slots chutes CHUTES_API_KEY
fi
if [[ -n "${ZAI_API_KEY:-}" ]]; then
  fan_out_slots zai ZAI_API_KEY
fi
if [[ -n "${MOONSHOT_API_KEY:-}" ]]; then
  fan_out_slots moonshot MOONSHOT_API_KEY
fi
if [[ -n "${DEEPINFRA_API_KEY:-}" ]]; then
  fan_out_slots deepinfra DEEPINFRA_API_KEY
fi
if [[ -n "${KUBETEE_API_KEY:-}" ]]; then
  fan_out_slots kubetee KUBETEE_API_KEY
fi
if [[ -n "${ENGY_API_KEY:-}" ]]; then
  fan_out_slots engy ENGY_API_KEY
fi
if [[ -n "${MOONMATH_API_KEY:-}" ]]; then
  fan_out_slots moonmath MOONMATH_API_KEY
fi
if [[ -n "${NEAR_API_KEY:-}" ]]; then
  fan_out_slots near NEAR_API_KEY
fi
if [[ "${ANTHROPIC_UPSTREAM}" == "foundry" && -n "${AZURE_FOUNDRY_API_KEY:-}" ]]; then
  fan_out_slots anthropic AZURE_FOUNDRY_API_KEY
fi
if [[ "${OPENAI_UPSTREAM}" == "azure" && -n "${AZURE_OPENAI_API_KEY:-}" ]]; then
  fan_out_slots openai AZURE_OPENAI_API_KEY
fi

# ── Resolve the benchmark upstream ────────────────────────────────────
# The benchmark host is hardcoded per network in this script, NOT taken
# from a runtime env var: a miner cannot redirect the `x-gm-provider:
# benchmark` route to a colluding service without editing this file,
# which moves the compose_hash and is rejected by the registry's
# attestation enforcement. GM_NETWORK is set by `gmcli deploy` as a
# rendered literal in dstack/docker-compose.yaml — part of the
# attestation-measured compose source — so its value is fixed at deploy
# time and equally tamper-evident. image/envoy/upstreams/benchmark.yaml
# reaches it over TLS on 443.
case "${GM_NETWORK:?GM_NETWORK must be set (rendered into dstack/docker-compose.yaml by gmcli deploy)}" in
  testnet) BENCHMARK_HOST=test-benchmark.saygm.com ;;
  mainnet) BENCHMARK_HOST=benchmark.saygm.com ;;
  *)
    log "error: unknown GM_NETWORK '${GM_NETWORK}' (want testnet or mainnet)"
    exit 1
    ;;
esac

# ── Gate Azure data-plane startup ─────────────────────────────────────
# Render-only mode is an offline config check and never starts Envoy. On
# real Azure startup, fail closed before rendering/provisioning/launching
# any serving process: a failed owner-capture check must restart the
# container rather than allowing Envoy to proxy Azure traffic.
if [[ "${GM_START_RENDER_ONLY:-}" != "1" ]] &&
  [[ "${OPENAI_UPSTREAM}" == "azure" || "${ANTHROPIC_UPSTREAM}" == "foundry" ]]; then
  log "verifying Azure owner-capture controls before starting data plane"
  gm-miner-attestd --verify-azure-once
  log "Azure owner-capture verification passed"
fi

# ── Render the envoy config ───────────────────────────────────────────
# gmcli render-envoy assembles image/envoy/base.yaml and the selected
# upstream files (see image/envoy/README.md). It reads the GM_* variables
# below plus the GM_<PROVIDER>_SLOT_IDS that fan_out_slots exported, and
# fails on any token it cannot fill. The node secret is rendered raw into
# a Lua string literal; that is injection-safe only because
# validate_node_secret already rejected any quote, backslash or newline.
# The rendered config goes to a writable path; the baked-in templates
# stay untouched.
RENDERED_CONFIG="${GM_RENDERED_CONFIG:-/tmp/envoy.rendered.yaml}"
GM_NODE_SECRET="${GM_NODE_SECRET:-}" \
  GM_BENCHMARK_HOST="${BENCHMARK_HOST}" \
  GM_ANTHROPIC_HOST="${ANTHROPIC_HOST}" \
  GM_OPENAI_HOST="${OPENAI_HOST}" \
  GM_OPENAI_SAN_SUFFIX="${OPENAI_SAN_SUFFIX}" \
  "${GMCLI_BIN:-gmcli}" render-envoy \
  --template-dir "${GM_ENVOY_TEMPLATE_DIR:-/etc/envoy}" \
  --out "${RENDERED_CONFIG}" \
  --select "anthropic=${ANTHROPIC_UPSTREAM}" \
  --select "openai=${OPENAI_UPSTREAM}"

if [[ -n "${GM_NODE_SECRET:-}" ]]; then
  log "GM_NODE_SECRET set — envoy enforces x-gm-node-key on inbound requests"
else
  log "warning: GM_NODE_SECRET unset — inbound data plane is unauthenticated"
fi

log "benchmark route proxies to https://${BENCHMARK_HOST} (GM_NETWORK=${GM_NETWORK})"

if [[ "${ANTHROPIC_UPSTREAM}" == "bedrock" ]]; then
  log "anthropic Bedrock inference is rejected as unqualified (configured host https://${ANTHROPIC_HOST} is retained only for non-inference checks)"
fi
if [[ "${OPENAI_UPSTREAM}" == "azure" ]]; then
  log "openai route proxies to Azure OpenAI at https://${OPENAI_HOST}"
fi

GM_IMAGE_VERSION="${GM_IMAGE_VERSION:-unknown}"
log "image version: ${GM_IMAGE_VERSION}"

if [[ "${GM_START_RENDER_ONLY:-}" == "1" ]]; then
  log "render-only mode complete: ${RENDERED_CONFIG}"
  exit 0
fi

# ── Provision the data-plane RA-TLS certificate ───────────────────────
# Mechanism 2 of attestation-and-identity.md. gm-miner-ratls calls the
# dstack guest agent's GetTlsKey RPC (over /var/run/dstack.sock) with
# usage_ra_tls=true: the guest agent mints a fresh TLS key, takes a TDX
# quote bound to that key, and issues an X.509 cert carrying the quote.
# It writes the PEM key/cert to /tmp/gm-ratls/; envoy's :8080
# DownstreamTlsContext references those exact paths (the paths are a
# build-time contract baked into both gm-miner-ratls and image/envoy/base.yaml).
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

# Install the trap before starting children: Azure readiness can take time,
# and PID 1 must forward termination even while the data plane is disabled.
NEAR_PROXY_PID=""
CHUTES_PROXY_PID=""
ATTESTD_PID=""
ENVOY_PID=""
# shellcheck disable=SC2317,SC2329  # invoked indirectly via the trap below.
shutdown() {
  log "received signal — shutting down"
  local -a pids=()
  local pid
  for pid in "${ENVOY_PID}" "${ATTESTD_PID}" "${NEAR_PROXY_PID}" "${CHUTES_PROXY_PID}"; do
    if [[ -n "${pid}" ]]; then
      pids+=("${pid}")
    fi
  done
  if [[ "${#pids[@]}" -gt 0 ]]; then
    kill -TERM "${pids[@]}" 2>/dev/null || true
    wait "${pids[@]}" 2>/dev/null || true
  fi
  exit 1
}
trap shutdown TERM INT

# ── Launch the NEAR attestation proxy ─────────────────────────────────
# NEAR routes exist only when a key is configured. The long-running proxy
# verifies each inference over the exact TLS connection it forwards on and
# fails that request closed. Do not make every closed-list origin a global
# startup dependency: one unavailable model must not take unrelated models
# or providers out of service. Process supervision below remains the proxy
# readiness gate; if the proxy itself exits, the whole container exits.
if [[ -n "${NEAR_API_KEY:-}" ]]; then
  log "starting NEAR verification proxy on 127.0.0.1:8082"
  gm-near-verify-proxy &
  NEAR_PROXY_PID=$!
fi

# ── Launch the Chutes verification proxy ──────────────────────────────
# Envoy sends Chutes requests with a `-TEE` selector to this proxy on
# 127.0.0.1:8083. It admits instances
# per request credential on demand, so it has no startup dependency on
# Chutes; supervision below brings the container down if it exits.
if [[ -n "${CHUTES_API_KEY:-}" ]]; then
  log "starting Chutes verification proxy on 127.0.0.1:8083"
  gm-chutes-verify-proxy &
  CHUTES_PROXY_PID=$!
fi

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

# The one-shot check predates certificate provisioning. Wait for the serving
# verifier to refresh that evidence and start its success-anchored pollers.
if [[ "${AZURE_ENABLED}" -eq 1 ]]; then
  until gm-miner-attestd --check-ready >/dev/null 2>&1; do
    if ! kill -0 "${ATTESTD_PID}" 2>/dev/null; then
      wait "${ATTESTD_PID}" || true
      log "error: attestation server exited before Azure readiness"
      for pid in "${NEAR_PROXY_PID}" "${CHUTES_PROXY_PID}"; do
        if [[ -n "${pid}" ]]; then
          kill -TERM "${pid}" 2>/dev/null || true
        fi
      done
      exit 1
    fi
    sleep 0.1
  done
fi

# ── Launch envoy ──────────────────────────────────────────────────────
# Not `exec`d: the script stays PID 1 so it can supervise the attestation
# server, optional NEAR and Chutes verifiers, and Envoy. SIGTERM from the container runtime is
# forwarded to every child.
log "starting envoy"
envoy \
  -c "${RENDERED_CONFIG}" \
  --log-level warn \
  --drain-time-s 10 &
ENVOY_PID=$!

# ── Supervise all serving processes ───────────────────────────────────
# `jobs -pr` lists only children still running. Poll it from this main shell
# so the first stopped child can be reaped here with `wait`, preserving its
# real status. This is portable to the older Bash shipped on macOS too, which
# keeps the startup/supervision integration tests honest. Whichever process
# exits first, the container must come down so the runtime's
# `restart: unless-stopped` policy recreates the whole stack: a miner
# missing Envoy, attestd, or a configured NEAR or Chutes verifier cannot serve
# the registry.
#
# `|| FIRST_EXIT_STATUS=$?` captures the exited child's status AND keeps
# `set -e` from aborting the script the instant a process exits
# non-zero — without it the diagnostic block below never runs and the
# exit cause is never logged.
FIRST_EXIT_STATUS=0
FIRST_EXIT_PID=""
SUPERVISED_PIDS=("${ATTESTD_PID}" "${ENVOY_PID}")
if [[ -n "${NEAR_PROXY_PID}" ]]; then
  SUPERVISED_PIDS+=("${NEAR_PROXY_PID}")
fi
if [[ -n "${CHUTES_PROXY_PID}" ]]; then
  SUPERVISED_PIDS+=("${CHUTES_PROXY_PID}")
fi
while [[ -z "${FIRST_EXIT_PID}" ]]; do
  RUNNING_PIDS=" $(jobs -pr | tr '\n' ' ') "
  for pid in "${SUPERVISED_PIDS[@]}"; do
    if [[ "${RUNNING_PIDS}" != *" ${pid} "* ]]; then
      FIRST_EXIT_PID="${pid}"
      wait "${pid}" || FIRST_EXIT_STATUS=$?
      break
    fi
  done
  if [[ -z "${FIRST_EXIT_PID}" ]]; then
    sleep 0.1
  fi
done

# Name the process that exited so the log states the real cause.
if [[ "${FIRST_EXIT_PID}" == "${ATTESTD_PID}" ]]; then
  log "error: attestation server exited (status ${FIRST_EXIT_STATUS}) — stopping container"
elif [[ -n "${NEAR_PROXY_PID}" && "${FIRST_EXIT_PID}" == "${NEAR_PROXY_PID}" ]]; then
  log "error: NEAR verification proxy exited (status ${FIRST_EXIT_STATUS}) — stopping container"
elif [[ -n "${CHUTES_PROXY_PID}" && "${FIRST_EXIT_PID}" == "${CHUTES_PROXY_PID}" ]]; then
  log "error: Chutes verification proxy exited (status ${FIRST_EXIT_STATUS}) — stopping container"
elif [[ "${FIRST_EXIT_PID}" == "${ENVOY_PID}" ]]; then
  log "error: envoy exited (status ${FIRST_EXIT_STATUS}) — stopping container"
else
  log "error: a supervised process exited (status ${FIRST_EXIT_STATUS}) — stopping container"
fi

# Stop the survivor and reap it before exiting.
kill -TERM "${SUPERVISED_PIDS[@]}" 2>/dev/null || true
wait 2>/dev/null || true

# Always exit non-zero so the container runtime's `restart:
# unless-stopped` policy recreates the stack. A supervised process
# exiting *at all* — even with a clean status 0 (a graceful or
# self-initiated shutdown) — leaves the miner missing one of its required
# services, which is a failure. The exit code is only a
# diagnostic detail: surface it when it is non-zero, otherwise exit 1
# so a status-0 child exit is still treated as a container failure.
if [[ "${FIRST_EXIT_STATUS}" -ne 0 ]]; then
  exit "${FIRST_EXIT_STATUS}"
fi
exit 1
