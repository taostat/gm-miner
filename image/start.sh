#!/usr/bin/env bash
# gm miner container entrypoint.
#
# Startup runs the required one-shot gates, then launches two co-located
# long-running processes:
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

lowercase() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

lua_string() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  printf '"%s"' "${value}"
}

lua_bool() {
  if [[ "$1" == "1" ]]; then
    printf 'true'
  else
    printf 'false'
  fi
}

lua_slot_map() {
  local ids="$1"
  local prefix="$2"
  if [[ -z "${ids}" ]]; then
    printf '{}'
    return
  fi

  local -a slot_ids
  local IFS=';'
  read -r -a slot_ids <<<"${ids}"

  local out="{"
  local idx=1
  local slot_id
  for slot_id in "${slot_ids[@]}"; do
    if [[ "${idx}" -gt 1 ]]; then
      out+=", "
    fi
    out+="[$(lua_string "${slot_id}")]=$(lua_string "${prefix}_KEY_SLOT_${idx}")"
    idx=$((idx + 1))
  done
  out+="}"
  printf '%s' "${out}"
}

lua_default_slot_env() {
  local ids="$1"
  local prefix="$2"
  if [[ -z "${ids}" ]]; then
    printf 'nil'
  else
    lua_string "${prefix}_KEY_SLOT_1"
  fi
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

## Cloud backend keys are single-slot in this release: a ';'-separated value
## would advertise slots the registry never probes.
require_single_slot() {
  local name="$1"
  local value="$2"
  local upstream="$3"
  if [[ "${value}" == *";"* ]]; then
    log "error: ${name} cannot contain ';' when ${upstream}; cloud backends are single-slot in this release"
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
ANTHROPIC_PORT=443
ANTHROPIC_PATH_REWRITE=0
ANTHROPIC_AUTH_HEADER=x-api-key
ANTHROPIC_AUTH_VALUE="%ENVIRONMENT(ANTHROPIC_API_KEY)%"
ANTHROPIC_VERSION_APPEND_ACTION=ADD_IF_ABSENT
ANTHROPIC_SAN_MATCH=exact
ANTHROPIC_SAN_VALUE="${ANTHROPIC_HOST}"
ANTHROPIC_STATIC_AUTH=0
ANTHROPIC_CLOUD=0

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
    ANTHROPIC_PATH_REWRITE=1
    ANTHROPIC_AUTH_HEADER=x-api-key
    ANTHROPIC_AUTH_VALUE="%ENVIRONMENT(BEDROCK_API_KEY)%"
    ANTHROPIC_VERSION_APPEND_ACTION=OVERWRITE_IF_EXISTS_OR_ADD
    ANTHROPIC_SAN_MATCH=suffix
    ANTHROPIC_SAN_VALUE=.api.aws
    ANTHROPIC_STATIC_AUTH=1
    ANTHROPIC_CLOUD=1
    ;;
  foundry)
    ## Microsoft Foundry serves Claude on an Anthropic-native passthrough:
    ## POST https://<resource>.services.ai.azure.com/anthropic/v1/messages,
    ## same Messages body, same `anthropic-version` header, `x-api-key` auth.
    ## The path rewrite is identical to Bedrock's, so the envoy route needs no
    ## Foundry-specific block. `services.ai.azure.com` is the only host
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
    ANTHROPIC_PATH_REWRITE=1
    ANTHROPIC_AUTH_HEADER=x-api-key
    ANTHROPIC_AUTH_VALUE="%ENVIRONMENT(AZURE_FOUNDRY_API_KEY)%"
    ANTHROPIC_VERSION_APPEND_ACTION=OVERWRITE_IF_EXISTS_OR_ADD
    ANTHROPIC_SAN_MATCH=suffix
    ANTHROPIC_SAN_VALUE=.services.ai.azure.com
    ANTHROPIC_STATIC_AUTH=1
    ANTHROPIC_CLOUD=1
    ;;
  *)
    log "error: ANTHROPIC_UPSTREAM must be 'direct', 'bedrock', or 'foundry' (got '${ANTHROPIC_UPSTREAM}')"
    exit 1
    ;;
esac

OPENAI_HOST=api.openai.com
OPENAI_PORT=443
OPENAI_PATH_REWRITE=0
OPENAI_AUTH_HEADER=authorization
OPENAI_AUTH_VALUE="Bearer %ENVIRONMENT(OPENAI_API_KEY)%"
OPENAI_SAN_MATCH=exact
OPENAI_SAN_VALUE="${OPENAI_HOST}"
OPENAI_AZURE_TLS=0
OPENAI_STATIC_AUTH=0
OPENAI_CLOUD=0

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
    OPENAI_SAN_MATCH=suffix
    OPENAI_SAN_VALUE=".${AZURE_OPENAI_SUFFIX}"
    OPENAI_AZURE_TLS=1
    OPENAI_PATH_REWRITE=1
    OPENAI_AUTH_HEADER=api-key
    OPENAI_AUTH_VALUE="%ENVIRONMENT(AZURE_OPENAI_API_KEY)%"
    OPENAI_STATIC_AUTH=1
    OPENAI_CLOUD=1
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

if [[ "${HAS_KEY}" -eq 0 ]]; then
  if [[ "${ANTHROPIC_UPSTREAM}" == "direct" && "${OPENAI_UPSTREAM}" == "direct" ]]; then
    log "error: at least one of ANTHROPIC_API_KEY / OPENAI_API_KEY / GOOGLE_API_KEY / CHUTES_API_KEY / ZAI_API_KEY must be set"
  else
    log "error: at least one usable provider key must be set"
  fi
  exit 1
fi

# ── Fan direct provider keys out into per-slot process env ────────────
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

GM_ANTHROPIC_SLOT_MAP="$(lua_slot_map "${GM_ANTHROPIC_SLOT_IDS:-}" "GM_ANTHROPIC")"
GM_ANTHROPIC_DEFAULT_SLOT_ENV="$(lua_default_slot_env "${GM_ANTHROPIC_SLOT_IDS:-}" "GM_ANTHROPIC")"
GM_OPENAI_SLOT_MAP="$(lua_slot_map "${GM_OPENAI_SLOT_IDS:-}" "GM_OPENAI")"
GM_OPENAI_DEFAULT_SLOT_ENV="$(lua_default_slot_env "${GM_OPENAI_SLOT_IDS:-}" "GM_OPENAI")"
GM_GEMINI_SLOT_MAP="$(lua_slot_map "${GM_GEMINI_SLOT_IDS:-}" "GM_GEMINI")"
GM_GEMINI_DEFAULT_SLOT_ENV="$(lua_default_slot_env "${GM_GEMINI_SLOT_IDS:-}" "GM_GEMINI")"
GM_CHUTES_SLOT_MAP="$(lua_slot_map "${GM_CHUTES_SLOT_IDS:-}" "GM_CHUTES")"
GM_CHUTES_DEFAULT_SLOT_ENV="$(lua_default_slot_env "${GM_CHUTES_SLOT_IDS:-}" "GM_CHUTES")"
GM_ZAI_SLOT_MAP="$(lua_slot_map "${GM_ZAI_SLOT_IDS:-}" "GM_ZAI")"
GM_ZAI_DEFAULT_SLOT_ENV="$(lua_default_slot_env "${GM_ZAI_SLOT_IDS:-}" "GM_ZAI")"

# ── Resolve the benchmark upstream ────────────────────────────────────
# The benchmark URL is hardcoded per network in this script, NOT taken
# from a runtime env var: a miner cannot redirect the `x-gm-provider:
# benchmark` route to a colluding service without editing this file,
# which moves the compose_hash and is rejected by the registry's
# attestation enforcement. GM_NETWORK is set by `gmcli deploy` as a
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
case "${GM_NETWORK:?GM_NETWORK must be set (rendered into dstack/docker-compose.yaml by gmcli deploy)}" in
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
# Literal token replaces (awk index/substr, not gsub) so values with
# regex- or replacement-special characters are handled verbatim. The
# rendered config goes to a writable path; the baked-in
# /etc/envoy/envoy.yaml stays untouched.
#
#   1. The node secret. Envoy's inbound Lua filter enforces x-gm-node-key
#      against a config literal. Provider slot maps render as slot ids and
#      per-slot env var names only; key values stay in the Envoy process
#      environment and Lua reads them with os.getenv at request time.
#   2. The benchmark cluster's host and port — resolved above from the
#      hardcoded per-network URL.
#   3. The benchmark cluster's upstream TLS block, delimited by
#      `## gm:benchmark-tls-begin` / `-end` whole-line sentinels. Kept
#      when the URL is https; dropped (the cluster stays plain HTTP/1.1)
#      when it is http.
RENDERED_CONFIG="${GM_RENDERED_CONFIG:-/tmp/envoy.rendered.yaml}"
GM_NODE_SECRET="${GM_NODE_SECRET:-}" \
  GM_BENCHMARK_HOST="${BENCHMARK_HOST}" \
  GM_BENCHMARK_PORT="${BENCHMARK_PORT}" \
  GM_BENCHMARK_TLS="${BENCHMARK_TLS}" \
  GM_ANTHROPIC_HOST="${ANTHROPIC_HOST}" \
  GM_ANTHROPIC_PORT="${ANTHROPIC_PORT}" \
  GM_ANTHROPIC_PATH_REWRITE="${ANTHROPIC_PATH_REWRITE}" \
  GM_ANTHROPIC_AUTH_HEADER="${ANTHROPIC_AUTH_HEADER}" \
  GM_ANTHROPIC_AUTH_VALUE="${ANTHROPIC_AUTH_VALUE}" \
  GM_ANTHROPIC_VERSION_APPEND_ACTION="${ANTHROPIC_VERSION_APPEND_ACTION}" \
  GM_ANTHROPIC_STATIC_AUTH="${ANTHROPIC_STATIC_AUTH}" \
  GM_ANTHROPIC_CLOUD="$(lua_bool "${ANTHROPIC_CLOUD}")" \
  GM_ANTHROPIC_SLOT_MAP="${GM_ANTHROPIC_SLOT_MAP}" \
  GM_ANTHROPIC_DEFAULT_SLOT_ENV="${GM_ANTHROPIC_DEFAULT_SLOT_ENV}" \
  GM_ANTHROPIC_SAN_MATCH="${ANTHROPIC_SAN_MATCH}" \
  GM_ANTHROPIC_SAN_VALUE="${ANTHROPIC_SAN_VALUE}" \
  GM_OPENAI_HOST="${OPENAI_HOST}" \
  GM_OPENAI_PORT="${OPENAI_PORT}" \
  GM_OPENAI_PATH_REWRITE="${OPENAI_PATH_REWRITE}" \
  GM_OPENAI_AUTH_HEADER="${OPENAI_AUTH_HEADER}" \
  GM_OPENAI_AUTH_VALUE="${OPENAI_AUTH_VALUE}" \
  GM_OPENAI_STATIC_AUTH="${OPENAI_STATIC_AUTH}" \
  GM_OPENAI_CLOUD="$(lua_bool "${OPENAI_CLOUD}")" \
  GM_OPENAI_SLOT_MAP="${GM_OPENAI_SLOT_MAP}" \
  GM_OPENAI_DEFAULT_SLOT_ENV="${GM_OPENAI_DEFAULT_SLOT_ENV}" \
  GM_GEMINI_SLOT_MAP="${GM_GEMINI_SLOT_MAP}" \
  GM_GEMINI_DEFAULT_SLOT_ENV="${GM_GEMINI_DEFAULT_SLOT_ENV}" \
  GM_CHUTES_SLOT_MAP="${GM_CHUTES_SLOT_MAP}" \
  GM_CHUTES_DEFAULT_SLOT_ENV="${GM_CHUTES_DEFAULT_SLOT_ENV}" \
  GM_ZAI_SLOT_MAP="${GM_ZAI_SLOT_MAP}" \
  GM_ZAI_DEFAULT_SLOT_ENV="${GM_ZAI_DEFAULT_SLOT_ENV}" \
  GM_OPENAI_SAN_MATCH="${OPENAI_SAN_MATCH}" \
  GM_OPENAI_SAN_VALUE="${OPENAI_SAN_VALUE}" \
  GM_OPENAI_AZURE_TLS="${OPENAI_AZURE_TLS}" \
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
    anthropic_host = ENVIRON["GM_ANTHROPIC_HOST"]
    anthropic_port = ENVIRON["GM_ANTHROPIC_PORT"]
    anthropic_path_rewrite = (ENVIRON["GM_ANTHROPIC_PATH_REWRITE"] == "1")
    anthropic_auth_header = ENVIRON["GM_ANTHROPIC_AUTH_HEADER"]
    anthropic_auth_value = ENVIRON["GM_ANTHROPIC_AUTH_VALUE"]
    anthropic_version_append_action = ENVIRON["GM_ANTHROPIC_VERSION_APPEND_ACTION"]
    anthropic_static_auth = (ENVIRON["GM_ANTHROPIC_STATIC_AUTH"] == "1")
    anthropic_cloud = ENVIRON["GM_ANTHROPIC_CLOUD"]
    anthropic_slot_map = ENVIRON["GM_ANTHROPIC_SLOT_MAP"]
    anthropic_default_slot_env = ENVIRON["GM_ANTHROPIC_DEFAULT_SLOT_ENV"]
    anthropic_san_match = ENVIRON["GM_ANTHROPIC_SAN_MATCH"]
    anthropic_san_value = ENVIRON["GM_ANTHROPIC_SAN_VALUE"]
    openai_host = ENVIRON["GM_OPENAI_HOST"]
    openai_port = ENVIRON["GM_OPENAI_PORT"]
    openai_path_rewrite = (ENVIRON["GM_OPENAI_PATH_REWRITE"] == "1")
    openai_auth_header = ENVIRON["GM_OPENAI_AUTH_HEADER"]
    openai_auth_value = ENVIRON["GM_OPENAI_AUTH_VALUE"]
    openai_static_auth = (ENVIRON["GM_OPENAI_STATIC_AUTH"] == "1")
    openai_cloud = ENVIRON["GM_OPENAI_CLOUD"]
    openai_slot_map = ENVIRON["GM_OPENAI_SLOT_MAP"]
    openai_default_slot_env = ENVIRON["GM_OPENAI_DEFAULT_SLOT_ENV"]
    gemini_slot_map = ENVIRON["GM_GEMINI_SLOT_MAP"]
    gemini_default_slot_env = ENVIRON["GM_GEMINI_DEFAULT_SLOT_ENV"]
    chutes_slot_map = ENVIRON["GM_CHUTES_SLOT_MAP"]
    chutes_default_slot_env = ENVIRON["GM_CHUTES_DEFAULT_SLOT_ENV"]
    zai_slot_map = ENVIRON["GM_ZAI_SLOT_MAP"]
    zai_default_slot_env = ENVIRON["GM_ZAI_DEFAULT_SLOT_ENV"]
    openai_san_match = ENVIRON["GM_OPENAI_SAN_MATCH"]
    openai_san_value = ENVIRON["GM_OPENAI_SAN_VALUE"]
    openai_azure_tls = (ENVIRON["GM_OPENAI_AZURE_TLS"] == "1")
  }
  /^[[:space:]]*## gm:benchmark-tls-begin[[:space:]]*$/ { in_tls = 1; next }
  /^[[:space:]]*## gm:benchmark-tls-end[[:space:]]*$/   { in_tls = 0; next }
  in_tls && !bench_tls { next }
  /^[[:space:]]*## gm:anthropic-path-rewrite-begin[[:space:]]*$/ { in_anthropic_path_rewrite = 1; next }
  /^[[:space:]]*## gm:anthropic-path-rewrite-end[[:space:]]*$/   { in_anthropic_path_rewrite = 0; next }
  in_anthropic_path_rewrite && !anthropic_path_rewrite { next }
  /^[[:space:]]*## gm:anthropic-static-auth-begin[[:space:]]*$/ { in_anthropic_static_auth = 1; next }
  /^[[:space:]]*## gm:anthropic-static-auth-end[[:space:]]*$/   { in_anthropic_static_auth = 0; next }
  in_anthropic_static_auth && !anthropic_static_auth { next }
  /^[[:space:]]*## gm:openai-path-rewrite-begin[[:space:]]*$/ { in_openai_path_rewrite = 1; next }
  /^[[:space:]]*## gm:openai-path-rewrite-end[[:space:]]*$/   { in_openai_path_rewrite = 0; next }
  in_openai_path_rewrite && !openai_path_rewrite { next }
  /^[[:space:]]*## gm:openai-system-tls-begin[[:space:]]*$/ { in_openai_system_tls = 1; next }
  /^[[:space:]]*## gm:openai-system-tls-end[[:space:]]*$/   { in_openai_system_tls = 0; next }
  in_openai_system_tls && openai_azure_tls { next }
  /^[[:space:]]*## gm:openai-azure-tls-begin[[:space:]]*$/ { in_openai_azure_tls = 1; next }
  /^[[:space:]]*## gm:openai-azure-tls-end[[:space:]]*$/   { in_openai_azure_tls = 0; next }
  in_openai_azure_tls && !openai_azure_tls { next }
  /^[[:space:]]*## gm:openai-static-auth-begin[[:space:]]*$/ { in_openai_static_auth = 1; next }
  /^[[:space:]]*## gm:openai-static-auth-end[[:space:]]*$/   { in_openai_static_auth = 0; next }
  in_openai_static_auth && !openai_static_auth { next }
  {
    line = subst($0, "__GM_NODE_SECRET__", secret)
    line = subst(line, "__GM_BENCHMARK_HOST__", bench_host)
    line = subst(line, "__GM_BENCHMARK_PORT__", bench_port)
    line = subst(line, "__GM_ANTHROPIC_HOST__", anthropic_host)
    line = subst(line, "__GM_ANTHROPIC_PORT__", anthropic_port)
    line = subst(line, "__GM_ANTHROPIC_AUTH_HEADER__", anthropic_auth_header)
    line = subst(line, "__GM_ANTHROPIC_AUTH_VALUE__", anthropic_auth_value)
    line = subst(line, "__GM_ANTHROPIC_VERSION_APPEND_ACTION__", anthropic_version_append_action)
    line = subst(line, "__GM_ANTHROPIC_CLOUD__", anthropic_cloud)
    line = subst(line, "__GM_ANTHROPIC_SLOT_MAP__", anthropic_slot_map)
    line = subst(line, "__GM_ANTHROPIC_DEFAULT_SLOT_ENV__", anthropic_default_slot_env)
    line = subst(line, "__GM_ANTHROPIC_SAN_MATCH__", anthropic_san_match)
    line = subst(line, "__GM_ANTHROPIC_SAN_VALUE__", anthropic_san_value)
    line = subst(line, "__GM_OPENAI_HOST__", openai_host)
    line = subst(line, "__GM_OPENAI_PORT__", openai_port)
    line = subst(line, "__GM_OPENAI_AUTH_HEADER__", openai_auth_header)
    line = subst(line, "__GM_OPENAI_AUTH_VALUE__", openai_auth_value)
    line = subst(line, "__GM_OPENAI_CLOUD__", openai_cloud)
    line = subst(line, "__GM_OPENAI_SLOT_MAP__", openai_slot_map)
    line = subst(line, "__GM_OPENAI_DEFAULT_SLOT_ENV__", openai_default_slot_env)
    line = subst(line, "__GM_GEMINI_SLOT_MAP__", gemini_slot_map)
    line = subst(line, "__GM_GEMINI_DEFAULT_SLOT_ENV__", gemini_default_slot_env)
    line = subst(line, "__GM_CHUTES_SLOT_MAP__", chutes_slot_map)
    line = subst(line, "__GM_CHUTES_DEFAULT_SLOT_ENV__", chutes_default_slot_env)
    line = subst(line, "__GM_ZAI_SLOT_MAP__", zai_slot_map)
    line = subst(line, "__GM_ZAI_DEFAULT_SLOT_ENV__", zai_default_slot_env)
    line = subst(line, "__GM_OPENAI_SAN_MATCH__", openai_san_match)
    line = subst(line, "__GM_OPENAI_SAN_VALUE__", openai_san_value)
    print line
  }
' "${GM_ENVOY_TEMPLATE_PATH:-/etc/envoy/envoy.yaml}" >"${RENDERED_CONFIG}"

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

if [[ "${ANTHROPIC_UPSTREAM}" == "bedrock" ]]; then
  log "anthropic route proxies to AWS Bedrock at https://${ANTHROPIC_HOST}:${ANTHROPIC_PORT}"
fi
if [[ "${OPENAI_UPSTREAM}" == "azure" ]]; then
  log "openai route proxies to Azure OpenAI at https://${OPENAI_HOST}:${OPENAI_PORT}"
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
