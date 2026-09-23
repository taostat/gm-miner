#!/usr/bin/env bash
# Load every rendered Envoy config variant into the image's own Envoy.
#
# The render tests parse start.sh's output as YAML and assert on its shape, but
# nothing else hands it to Envoy before a CVM boots. A misspelt field, a wrong
# `@type`, or a Lua syntax error passes those tests and only fails at container
# start. `envoy --mode validate` builds the full server config (listeners, TLS
# contexts, Lua filters, clusters) without binding ports or resolving DNS.
#
# The Envoy image is read from image/Dockerfile's runtime stage, so this checks
# against exactly the pinned digest the miner ships.
#
#   scripts/validate-envoy.sh                  # uses target/release/gmcli
#   GMCLI_BIN=path/to/gmcli scripts/validate-envoy.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GMCLI_BIN="${GMCLI_BIN:-${ROOT}/target/release/gmcli}"

die() {
  echo "error: $*" >&2
  exit 1
}

[[ -x "${GMCLI_BIN}" ]] || die "gmcli not found at ${GMCLI_BIN}; build it or set GMCLI_BIN"
GMCLI_BIN="$(realpath "${GMCLI_BIN}")"

ENVOY_IMAGE="$(awk '$1 == "FROM" && $2 ~ /^envoyproxy\/envoy:/ { print $2 }' "${ROOT}/image/Dockerfile")"
[[ -n "${ENVOY_IMAGE}" ]] || die "no envoyproxy/envoy FROM line in image/Dockerfile"

WORK="$(mktemp -d)"
trap 'rm -r "${WORK}"' EXIT
mkdir "${WORK}/configs" "${WORK}/ratls"

# The ingress listener loads /tmp/gm-ratls/{cert,key}.pem, which gm-miner-ratls
# mints from the dstack guest agent at container start. Validation only needs
# a loadable P-256 pair at that path.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
  -subj "/CN=validate-envoy" \
  -keyout "${WORK}/ratls/key.pem" -out "${WORK}/ratls/cert.pem" 2>/dev/null

SECRET=validate-node-secret-0001

render() {
  local name="$1"
  shift
  env -i PATH="${PATH}" \
    GM_START_RENDER_ONLY=1 \
    GMCLI_BIN="${GMCLI_BIN}" \
    GM_ENVOY_TEMPLATE_DIR="${ROOT}/image/envoy" \
    GM_RENDERED_CONFIG="${WORK}/configs/${name}.yaml" \
    "$@" \
    bash "${ROOT}/image/start.sh" >"${WORK}/${name}.render.log" 2>&1 || {
    cat "${WORK}/${name}.render.log" >&2
    die "start.sh failed to render the ${name} variant"
  }
}

# One variant per sentinel-block combination start.sh can produce.
render direct-all GM_NETWORK=testnet GM_NODE_SECRET="${SECRET}" \
  ANTHROPIC_API_KEY=a OPENAI_API_KEY="o1;o2" GOOGLE_API_KEY=g CHUTES_API_KEY=c \
  ZAI_API_KEY=z MOONSHOT_API_KEY=m DEEPINFRA_API_KEY=d KUBETEE_API_KEY=k \
  ENGY_API_KEY=e MOONMATH_API_KEY=mm NEAR_API_KEY=n
render chutes-slots GM_NETWORK=testnet GM_NODE_SECRET="${SECRET}" CHUTES_API_KEY="c1;c2"
render mainnet GM_NETWORK=mainnet GM_NODE_SECRET="${SECRET}" ANTHROPIC_API_KEY=a
render no-node-secret GM_NETWORK=testnet OPENAI_API_KEY=o
render azure-clouds GM_NETWORK=testnet GM_NODE_SECRET="${SECRET}" \
  ANTHROPIC_UPSTREAM=foundry \
  AZURE_FOUNDRY_ENDPOINT=https://gm-resource.services.ai.azure.com/ \
  AZURE_FOUNDRY_API_KEY=f \
  OPENAI_UPSTREAM=azure \
  AZURE_OPENAI_ENDPOINT=https://gm-resource.openai.azure.com/ \
  AZURE_OPENAI_API_KEY=az
render bedrock GM_NETWORK=testnet GM_NODE_SECRET="${SECRET}" \
  ANTHROPIC_UPSTREAM=bedrock BEDROCK_REGION=us-west-2 BEDROCK_API_KEY=b

# The rendered files are 0600 under a 0700 temp dir; ENVOY_UID=0 stops the
# image entrypoint dropping to the unprivileged envoy user, which could not
# read them.
failed=0
for config in "${WORK}"/configs/*.yaml; do
  name="$(basename "${config}" .yaml)"
  if docker run --rm -e ENVOY_UID=0 \
    -v "${WORK}/configs:/configs:ro" \
    -v "${WORK}/ratls:/tmp/gm-ratls:ro" \
    "${ENVOY_IMAGE}" --mode validate -c "/configs/${name}.yaml" >"${WORK}/${name}.log" 2>&1; then
    echo "ok: ${name}"
  else
    echo "FAIL: ${name}" >&2
    cat "${WORK}/${name}.log" >&2
    failed=1
  fi
done
exit "${failed}"
