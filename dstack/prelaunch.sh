# shellcheck shell=bash
# Phala Cloud pre-launch script for gm miner deployments.
# Handles optional registry login, image access checks, and housekeeping.

echo "----------------------------------------------"
echo "Running Phala Cloud Pre-Launch Script"
echo "----------------------------------------------"
set -e

DOCKER_REGISTRY_TARGET=""

notify_host() {
  if command -v dstack-util >/dev/null 2>&1; then
    dstack-util notify-host -e "$1" -d "$2" || true
  elif command -v tdxctl >/dev/null 2>&1; then
    tdxctl notify-host -e "$1" -d "$2" || true
  fi
}

notify_host_hoot_info() {
  notify_host "boot.progress" "$1"
}

notify_host_hoot_error() {
  notify_host "boot.error" "$1"
}

perform_cleanup() {
  echo "Pruning unused images"
  docker image prune -af || true
  echo "Pruning unused volumes"
  docker volume prune -f || true
  notify_host_hoot_info "docker cleanup completed"
}

check_docker_login() {
  local registry="$1"
  local docker_config_path="${DOCKER_CONFIG:-${HOME:-}/.docker}/config.json"

  if [[ -n "$registry" ]]; then
    if [[ -f "$docker_config_path" ]] && grep -Fq -- "$registry" "$docker_config_path"; then
      return 0
    fi
    return 1
  fi

  if docker info 2>/dev/null | grep -q "Username"; then
    return 0
  fi
  return 1
}

echo "Starting login process..."

if [[ -n "${DSTACK_DOCKER_USERNAME:-}" && -n "${DSTACK_DOCKER_PASSWORD:-}" ]]; then
  echo "Docker credentials found"
  DOCKER_REGISTRY_TARGET="${DSTACK_DOCKER_REGISTRY:-docker.io}"
  echo "Target Docker registry: $DOCKER_REGISTRY_TARGET"

  if check_docker_login "${DSTACK_DOCKER_REGISTRY:-}"; then
    echo "Already logged in to Docker registry: $DOCKER_REGISTRY_TARGET"
  else
    echo "Logging in to Docker registry: $DOCKER_REGISTRY_TARGET"
    if [[ -n "${DSTACK_DOCKER_REGISTRY:-}" ]]; then
      if printf '%s\n' "${DSTACK_DOCKER_PASSWORD:-}" |
        docker login -u "${DSTACK_DOCKER_USERNAME:-}" --password-stdin "${DSTACK_DOCKER_REGISTRY:-}"; then
        echo "Docker login successful: $DOCKER_REGISTRY_TARGET"
      else
        echo "Docker login failed: $DOCKER_REGISTRY_TARGET"
        notify_host_hoot_error "docker login failed"
        exit 1
      fi
    else
      if printf '%s\n' "${DSTACK_DOCKER_PASSWORD:-}" |
        docker login -u "${DSTACK_DOCKER_USERNAME:-}" --password-stdin; then
        echo "Docker login successful: $DOCKER_REGISTRY_TARGET"
      else
        echo "Docker login failed: $DOCKER_REGISTRY_TARGET"
        notify_host_hoot_error "docker login failed"
        exit 1
      fi
    fi
  fi
elif [[ -n "${DSTACK_AWS_ACCESS_KEY_ID:-}" &&
  -n "${DSTACK_AWS_SECRET_ACCESS_KEY:-}" &&
  -n "${DSTACK_AWS_REGION:-}" &&
  -n "${DSTACK_AWS_ECR_REGISTRY:-}" ]]; then
  echo "AWS ECR credentials found"

  if [[ ! -f "./aws/dist/aws" ]]; then
    notify_host_hoot_info "awscli not installed, installing..."
    echo "AWS CLI not installed, installing..."
    if ! curl -fsS "https://awscli.amazonaws.com/awscli-exe-linux-x86_64-2.24.14.zip" -o "awscliv2.zip"; then
      notify_host_hoot_error "awscli download failed"
      exit 1
    fi
    if ! echo "6ff031a26df7daebbfa3ccddc9af1450 awscliv2.zip" | md5sum -c; then
      echo "MD5 checksum failed"
      notify_host_hoot_error "awscli install failed"
      exit 1
    fi
    if ! unzip awscliv2.zip &>/dev/null; then
      notify_host_hoot_error "awscli install failed"
      exit 1
    fi
  else
    echo "AWS CLI is already installed: ./aws/dist/aws"
  fi

  export AWS_ACCESS_KEY_ID="${DSTACK_AWS_ACCESS_KEY_ID:-}"
  export AWS_SECRET_ACCESS_KEY="${DSTACK_AWS_SECRET_ACCESS_KEY:-}"
  export AWS_DEFAULT_REGION="${DSTACK_AWS_REGION:-}"

  if [[ -n "${DSTACK_AWS_SESSION_TOKEN:-}" ]]; then
    echo "AWS session token found, using temporary credentials"
    export AWS_SESSION_TOKEN="${DSTACK_AWS_SESSION_TOKEN:-}"
  fi

  echo "Testing AWS credentials..."
  if ! ./aws/dist/aws sts get-caller-identity &>/dev/null; then
    echo "AWS credentials test failed"
    if [[ -n "${DSTACK_AWS_SESSION_TOKEN:-}" ]]; then
      echo "AWS temporary credentials may have expired; continuing startup"
      notify_host_hoot_info "AWS temporary credentials may have expired"
    else
      notify_host_hoot_error "Invalid AWS credentials"
      exit 1
    fi
  else
    echo "Logging in to AWS ECR..."
    if ./aws/dist/aws ecr get-login-password --region "${DSTACK_AWS_REGION:-}" |
      docker login --username AWS --password-stdin "${DSTACK_AWS_ECR_REGISTRY:-}"; then
      echo "AWS ECR login successful"
      notify_host_hoot_info "AWS ECR login successful"
    elif [[ -n "${DSTACK_AWS_SESSION_TOKEN:-}" ]]; then
      echo "AWS ECR login with temporary credentials did not complete; continuing startup"
      notify_host_hoot_info "AWS ECR login with temporary credentials did not complete"
    else
      notify_host_hoot_error "AWS ECR login failed"
      exit 1
    fi
  fi
fi

perform_cleanup

if [[ "$DOCKER_REGISTRY_TARGET" == "ghcr.io" &&
  -n "${DSTACK_DOCKER_USERNAME:-}" &&
  -n "${DSTACK_DOCKER_PASSWORD:-}" ]]; then
  compose_images=$(grep 'image:' /dstack/docker-compose.yaml 2>/dev/null |
    awk '{print $2}' |
    tr -d "\"'" || true)
  while IFS= read -r image; do
    [[ "$image" != ghcr.io/* ]] && continue
    reference="${image#ghcr.io/}"
    if [[ "$reference" == *@* ]]; then
      repository="${reference%%@*}"
      tag="${reference#*@}"
    else
      repository="${reference%%:*}"
      tag="${reference##*:}"
      [[ "$tag" == "$reference" || "$tag" == "$repository" ]] && tag="latest"
    fi

    echo "Checking image access: $image"
    token=$(curl -sf -u "${DSTACK_DOCKER_USERNAME:-}:${DSTACK_DOCKER_PASSWORD:-}" \
      "https://ghcr.io/token?service=ghcr.io&scope=repository:${repository}:pull" |
      jq -r '.token // empty' || true)
    if [[ -z "$token" ]]; then
      echo "ERROR: GHCR token exchange failed for $image"
      notify_host_hoot_error "GHCR token exchange failed: $image"
      exit 1
    fi

    http_code=$(curl -s -o /dev/null -w "%{http_code}" \
      -H "Authorization: Bearer $token" \
      -H "Accept: application/vnd.oci.image.index.v1+json,application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.list.v2+json,application/vnd.docker.distribution.manifest.v2+json" \
      "https://ghcr.io/v2/${repository}/manifests/${tag}" || true)
    if [[ "$http_code" != "200" ]]; then
      echo "ERROR: GHCR image access did not complete for $image (HTTP $http_code)"
      notify_host_hoot_error "GHCR image access did not complete: $image (HTTP $http_code)"
      exit 1
    fi
    echo "GHCR image access confirmed: $image"
  done <<<"$compose_images"
fi

echo "----------------------------------------------"
echo "Script execution completed"
echo "----------------------------------------------"
