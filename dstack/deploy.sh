#!/usr/bin/env bash
# gm miner deployment script — generalizes the PoC's deploy.sh to three
# upstream providers (Anthropic / OpenAI / Gemini).
#
# Usage: export the API keys you own, then run:
#
#   export GCP_PROJECT_ID=<project>
#   export ANTHROPIC_API_KEY=sk-ant-...   # optional — omit if you don't have one
#   export OPENAI_API_KEY=sk-...          # optional
#   export GOOGLE_API_KEY=...             # optional
#   ./dstack/deploy.sh
#
# At least one provider key must be set. The image will gracefully
# disable routes for providers whose keys are absent.
#
# To register the deployed miner after the first boot:
#   1. Note the compose_sha256 printed below.
#   2. Retrieve the OS image hash from `dstack-cloud status`.
#   3. Run:
#        gm-miner login
#        gm-miner register-image \
#          --compose-hash <compose_sha256> \
#          --os-image-hash <os_image_hash>
#        gm-miner declare-product anthropic claude-sonnet-4-6 \
#          --price-input 2.80 --price-output 14.00

set -euo pipefail

# ── Configuration ──────────────────────────────────────────────────────────
APP_NAME="${APP_NAME:-gm-miner-1}"
MACHINE_TYPE="${MACHINE_TYPE:-c3-standard-4}"
GCP_REGION="${GCP_REGION:-us-central1}"
GCP_ZONE="${GCP_ZONE:-${GCP_REGION}-a}"
AR_REPO="${AR_REPO:-gm-miner}"
IMAGE_TAG="${IMAGE_TAG:-v0.1.0}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="${REPO_ROOT}/dist"
PROJECT_DIR="${DIST_DIR}/${APP_NAME}"

# ── Helpers ────────────────────────────────────────────────────────────────
die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}
log() { printf '[deploy] %s\n' "$*" >&2; }

require_tool() {
  local tool="$1" hint="$2"
  command -v "$tool" >/dev/null 2>&1 || die "missing ${tool}. ${hint}"
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

ensure_dstack_cloud() {
  if command -v dstack-cloud >/dev/null 2>&1; then return; fi
  log "dstack-cloud not found; installing to ~/.local/bin"
  mkdir -p "${HOME}/.local/bin"
  curl -fsSL -o "${HOME}/.local/bin/dstack-cloud" \
    https://raw.githubusercontent.com/Phala-Network/meta-dstack-cloud/main/scripts/bin/dstack-cloud
  chmod +x "${HOME}/.local/bin/dstack-cloud"
  case ":${PATH}:" in
    *":${HOME}/.local/bin:"*) ;;
    *) export PATH="${HOME}/.local/bin:${PATH}" ;;
  esac
  command -v dstack-cloud >/dev/null 2>&1 || die "dstack-cloud install failed"
}

ensure_dstack_cloud_global_config() {
  local cfg="${HOME}/.config/dstack-cloud/config.json"
  [[ -f "${cfg}" ]] && return
  log "creating ${cfg}"
  mkdir -p "$(dirname "${cfg}")"
  cat >"${cfg}" <<'JSON'
{
  "services": {
    "kms_urls": ["https://kms.tdxlab.dstack.org:12001"],
    "gateway_urls": ["https://gateway.tdxlab.dstack.org:12002"],
    "pccs_url": ""
  },
  "image_search_paths": ["~/.dstack/images"],
  "gcp": {
    "project": "",
    "zone": "us-central1-a",
    "bucket": ""
  }
}
JSON
}

# ── Pre-flight checks ──────────────────────────────────────────────────────

# At least one provider key must be set.
HAS_KEY=0
[[ -n "${ANTHROPIC_API_KEY:-}" ]] && {
  HAS_KEY=1
  log "ANTHROPIC_API_KEY present"
}
[[ -n "${OPENAI_API_KEY:-}" ]] && {
  HAS_KEY=1
  log "OPENAI_API_KEY present"
}
[[ -n "${GOOGLE_API_KEY:-}" ]] && {
  HAS_KEY=1
  log "GOOGLE_API_KEY present"
}
[[ "${HAS_KEY}" -eq 1 ]] || die "at least one of ANTHROPIC_API_KEY / OPENAI_API_KEY / GOOGLE_API_KEY must be set"

[[ -n "${GCP_PROJECT_ID:-}" ]] || die "GCP_PROJECT_ID not set"

require_tool gcloud "install: https://cloud.google.com/sdk/docs/install"
require_tool docker "install: https://docs.docker.com/get-docker/"
require_tool python3 "install python 3.8+"
require_tool mcopy "install mtools: brew install mtools"

# GNU tar is required by gcloud compute images create.
if [[ -x /opt/homebrew/opt/gnu-tar/libexec/gnubin/tar ]]; then
  export PATH="/opt/homebrew/opt/gnu-tar/libexec/gnubin:${PATH}"
fi
if ! tar --version 2>&1 | grep -qi 'gnu tar'; then
  die "GNU tar required. install: brew install gnu-tar"
fi

ensure_dstack_cloud
ensure_dstack_cloud_global_config

log "GCP project: ${GCP_PROJECT_ID} (zone ${GCP_ZONE})"
gcloud config set project "${GCP_PROJECT_ID}" >/dev/null

log "ensuring required GCP services are enabled"
gcloud services enable \
  compute.googleapis.com \
  artifactregistry.googleapis.com \
  confidentialcomputing.googleapis.com \
  storage.googleapis.com \
  --quiet

GCS_BUCKET="gs://${GCP_PROJECT_ID}-dstack"
if ! gcloud storage buckets describe "${GCS_BUCKET}" >/dev/null 2>&1; then
  log "creating GCS bucket ${GCS_BUCKET}"
  gcloud storage buckets create "${GCS_BUCKET}" \
    --location="${GCP_REGION}" \
    --uniform-bucket-level-access \
    --quiet
fi

AR_HOST="${GCP_REGION}-docker.pkg.dev"
AR_PATH="${AR_HOST}/${GCP_PROJECT_ID}/${AR_REPO}"
IMAGE_REF="${AR_PATH}/${APP_NAME}:${IMAGE_TAG}"

if ! gcloud artifacts repositories describe "${AR_REPO}" \
  --location="${GCP_REGION}" >/dev/null 2>&1; then
  log "creating Artifact Registry repo ${AR_REPO}"
  gcloud artifacts repositories create "${AR_REPO}" \
    --repository-format=docker \
    --location="${GCP_REGION}" \
    --description="gm miner images" \
    --quiet
fi

log "configuring Docker auth for ${AR_HOST}"
gcloud auth configure-docker "${AR_HOST}" --quiet

# ── Build and push ────────────────────────────────────────────────────────

# Pass the git commit SHA as the image version baked into the binary.
GM_IMAGE_VERSION="${GM_IMAGE_VERSION:-$(git -C "${REPO_ROOT}" rev-parse --short HEAD 2>/dev/null || echo "unknown")}"

log "building ${IMAGE_REF} (linux/amd64 for TDX C3 host, version ${GM_IMAGE_VERSION})"
docker buildx build \
  --platform linux/amd64 \
  --build-arg "GM_IMAGE_VERSION=${GM_IMAGE_VERSION}" \
  --file "${REPO_ROOT}/image/Dockerfile" \
  --tag "${IMAGE_REF}" \
  --push \
  "${REPO_ROOT}"

log "resolving pushed image digest"
IMAGE_DIGEST="$(gcloud artifacts docker images describe "${IMAGE_REF}" \
  --format='value(image_summary.digest)')"
PINNED_REF="${AR_PATH}/${APP_NAME}@${IMAGE_DIGEST}"
log "pinned image: ${PINNED_REF}"

# ── Render compose ────────────────────────────────────────────────────────

mkdir -p "${DIST_DIR}"
if [[ ! -f "${PROJECT_DIR}/app.json" ]]; then
  log "scaffolding dstack-cloud project at ${PROJECT_DIR}"
  (cd "${DIST_DIR}" && dstack-cloud new "${APP_NAME}" \
    --project "${GCP_PROJECT_ID}" \
    --zone "${GCP_ZONE}" \
    --machine-type "${MACHINE_TYPE}" \
    --instance-name "${APP_NAME}" \
    --key-provider kms \
    --gw)
else
  log "updating gcp_config in existing app.json (preserves app_id/instance_id_seed)"
  GCP_PROJECT_ID="${GCP_PROJECT_ID}" GCP_ZONE="${GCP_ZONE}" \
    MACHINE_TYPE="${MACHINE_TYPE}" APP_NAME="${APP_NAME}" \
    python3 - "${PROJECT_DIR}/app.json" <<'PY'
import json, os, sys
path = sys.argv[1]
with open(path) as f: app = json.load(f)
gcp = app.setdefault("gcp_config", {})
gcp["project"] = os.environ["GCP_PROJECT_ID"]
gcp["zone"] = os.environ["GCP_ZONE"]
gcp["machine_type"] = os.environ["MACHINE_TYPE"]
gcp["instance_name"] = os.environ["APP_NAME"]
with open(path, "w") as f: json.dump(app, f, indent=2)
PY
fi

log "rendering ${PROJECT_DIR}/docker-compose.yaml with pinned digest"
# Substitute only GM_IMAGE_REF. Provider keys in the .env file are NOT
# substituted here — dstack-KMS encrypts them from the .env at deploy time.
sed "s|\${GM_IMAGE_REF[^}]*}|${PINNED_REF}|g" \
  "${REPO_ROOT}/dstack/docker-compose.yaml" >"${PROJECT_DIR}/docker-compose.yaml"
grep -q "${PINNED_REF}" "${PROJECT_DIR}/docker-compose.yaml" ||
  die "image-ref substitution failed"

# ── Write .env (encrypted by dstack-cloud deploy) ─────────────────────────
log "writing ${PROJECT_DIR}/.env"
(
  umask 077
  {
    [[ -n "${ANTHROPIC_API_KEY:-}" ]] && printf 'ANTHROPIC_API_KEY=%s\n' "${ANTHROPIC_API_KEY}"
    [[ -n "${OPENAI_API_KEY:-}" ]] && printf 'OPENAI_API_KEY=%s\n' "${OPENAI_API_KEY}"
    [[ -n "${GOOGLE_API_KEY:-}" ]] && printf 'GOOGLE_API_KEY=%s\n' "${GOOGLE_API_KEY}"
    # Capability bearer token — generate a random 32-byte hex token if not set.
    CAPABILITY_BEARER_TOKEN="${CAPABILITY_BEARER_TOKEN:-$(python3 -c 'import secrets; print(secrets.token_hex(32))')}"
    printf 'CAPABILITY_BEARER_TOKEN=%s\n' "${CAPABILITY_BEARER_TOKEN}"
    log "CAPABILITY_BEARER_TOKEN generated (save this for registry configuration):"
    log "  ${CAPABILITY_BEARER_TOKEN}"
  } >"${PROJECT_DIR}/.env"
)

COMPOSE_HASH="$(sha256_of "${PROJECT_DIR}/docker-compose.yaml")"
log "compose sha256 = ${COMPOSE_HASH}"

# ── Pull dstack OS image ──────────────────────────────────────────────────
log "ensuring dstack-cloud OS image is downloaded locally"
DSTACK_OS_IMAGE_URL="${DSTACK_OS_IMAGE_URL:-https://github.com/Phala-Network/meta-dstack-cloud/releases/download/v0.6.0-test/dstack-cloud-0.6.0-uki.tar.gz}"
if [[ ! -f "${HOME}/.dstack/images/dstack-cloud-0.6.0-uki.tar.gz" ]]; then
  (cd "${PROJECT_DIR}" && dstack-cloud pull "${DSTACK_OS_IMAGE_URL}")
fi

# ── Deploy ────────────────────────────────────────────────────────────────
log "deploying ${APP_NAME} to ${MACHINE_TYPE} in ${GCP_ZONE}"
(cd "${PROJECT_DIR}" && dstack-cloud deploy)

log "fetching deployment status"
(cd "${PROJECT_DIR}" && dstack-cloud status) || true

cat <<EOF

Deployment complete.

  App name          ${APP_NAME}
  Image             ${PINNED_REF}
  Project dir       ${PROJECT_DIR}
  Compose sha256    ${COMPOSE_HASH}
  Image version     ${GM_IMAGE_VERSION}

Next steps:
  1. Run 'gm-miner login' to authenticate with Taostats.

  2. Register the image with the registry:
       gm-miner register-image \\
         --compose-hash ${COMPOSE_HASH} \\
         --os-image-hash <from dstack-cloud status>

  3. Declare products (adjust prices to your cost basis):
       gm-miner declare-product anthropic claude-sonnet-4-6 \\
         --price-input 2.80 --price-output 14.00
       gm-miner declare-product openai gpt-5.5 \\
         --price-input 1.20 --price-output 9.50

  4. Check status:
       gm-miner status

  5. The registry will run its control loop within ~10 minutes and
     mark eligible products as active if attestation passes.

NOTE: The CAPABILITY_BEARER_TOKEN has been printed above. You must
provide it to the registry operator so the registry can authenticate
its capability check calls to this miner.
EOF
