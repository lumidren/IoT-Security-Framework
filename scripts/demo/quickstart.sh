#!/usr/bin/env bash
# IronMesh 5-minute quickstart (README): local stack, 500-device virtual fleet, staged OTA
# campaign and an automatic quarantine of the misbehaving device.
#
#   scripts/demo/quickstart.sh            # build + start + demo
#   IRONMESH_NO_BUILD=1 scripts/demo/quickstart.sh     # use already built / pulled images
#   IRONMESH_STACK_ONLY=1 scripts/demo/quickstart.sh   # stop once the stack is healthy (CI, HIL)
#
# Requires Docker Engine 24+ with the Compose v2 plugin. Everything else runs in containers.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DOCKER_DIR="${ROOT}/deploy/docker"
ENV_FILE="${DOCKER_DIR}/.env"
COMPOSE=(docker compose --project-directory "${DOCKER_DIR}" -f "${DOCKER_DIR}/docker-compose.yml" --env-file "${ENV_FILE}")
TIMEOUT_S="${IRONMESH_QUICKSTART_TIMEOUT_S:-900}"

log() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || die "docker is not installed"
docker compose version >/dev/null 2>&1 || die "the Docker Compose v2 plugin is required (docker compose)"

random_hex() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32
  else
    od -An -v -tx1 -N32 /dev/urandom | tr -d ' \n'
  fi
}

# 1. Secrets -----------------------------------------------------------------------------------
if [[ ! -f "${ENV_FILE}" ]]; then
  log "generating ${ENV_FILE} with random secrets"
  umask 077
  while IFS= read -r line || [[ -n "${line}" ]]; do
    line="${line%$'\r'}"
    if [[ "${line}" == *=__GENERATE__ ]]; then
      printf '%s=%s\n' "${line%%=*}" "$(random_hex)"
    else
      printf '%s\n' "${line}"
    fi
  done < "${DOCKER_DIR}/.env.example" > "${ENV_FILE}"
  umask 022
else
  log "using existing ${ENV_FILE}"
  if grep -q '=__GENERATE__' "${ENV_FILE}"; then
    die "${ENV_FILE} still contains __GENERATE__ placeholders"
  fi
  # Top up variables added to .env.example since this .env was generated (e.g. OTA_REGISTRY_TOKEN);
  # existing values are never touched, obsolete ones (OTA_TENANT_KEYS_PASSPHRASE) are ignored.
  added=()
  while IFS= read -r line || [[ -n "${line}" ]]; do
    line="${line%$'\r'}"
    [[ "${line}" =~ ^([A-Z0-9_]+)=(.*)$ ]] || continue
    name="${BASH_REMATCH[1]}" value="${BASH_REMATCH[2]}"
    grep -qE "^${name}=" "${ENV_FILE}" && continue
    [[ "${value}" == "__GENERATE__" ]] && value="$(random_hex)"
    printf '%s=%s\n' "${name}" "${value}" >> "${ENV_FILE}"
    added+=("${name}")
  done < "${DOCKER_DIR}/.env.example"
  if (( ${#added[@]} )); then log "added to ${ENV_FILE}: ${added[*]}"; fi
fi

env_value() { grep -E "^$1=" "${ENV_FILE}" | tail -n1 | cut -d= -f2-; }
FLEET_COUNT="$(env_value IRONMESH_FLEET_COUNT)"
FLEET_COUNT="${FLEET_COUNT:-500}"

# 2. Stack -------------------------------------------------------------------------------------
build_flag=(--build)
[[ "${IRONMESH_NO_BUILD:-0}" == "1" ]] && build_flag=()
log "starting the stack (first run builds every image; this takes a few minutes)"
# `up -d` returns once every depends_on condition is met: migrations, PKI bootstrap, topic
# creation (bridge), registry seed and the fleet registration (service `seed`, which also waits
# until the registry and the OTA service have pushed their keys to the PKI tenant policy).
if ! "${COMPOSE[@]}" up -d ${build_flag[@]+"${build_flag[@]}"}; then
  "${COMPOSE[@]}" ps -a || true
  die "docker compose up failed; inspect with: docker compose -f deploy/docker/docker-compose.yml logs <service>"
fi

wait_healthy() {
  local svc="$1" deadline=$((SECONDS + TIMEOUT_S)) cid state
  while :; do
    cid="$("${COMPOSE[@]}" ps -q "${svc}" 2>/dev/null || true)"
    if [[ -n "${cid}" ]]; then
      state="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "${cid}")"
      [[ "${state}" == "healthy" ]] && return 0
      [[ "${state}" == "unhealthy" || "${state}" == "exited" ]] && { "${COMPOSE[@]}" logs --tail 50 "${svc}"; die "${svc} is ${state}"; }
    fi
    (( SECONDS > deadline )) && die "timed out waiting for ${svc}"
    sleep 3
  done
}
for svc in pki policy emqx bridge registry ota anomaly console keycloak grafana; do
  wait_healthy "${svc}"
done
log "stack healthy"
if [[ "${IRONMESH_STACK_ONLY:-0}" == "1" ]]; then
  exit 0
fi

# 3. Demo ---------------------------------------------------------------------------------------
tools() { "${COMPOSE[@]}" --profile tools run --rm --no-deps demo-tools "$@"; }
log "waiting for ${FLEET_COUNT} simulated devices to enroll (EST + attestation)"
tools wait-active "${FLEET_COUNT}" --timeout-s "${TIMEOUT_S}"
log "uploading signed demo firmware and starting the staged campaign (1% -> 10% -> 100%)"
tools campaign
log "waiting for the anomaly engine to auto-quarantine the misbehaving device"
tools wait-quarantine --timeout-s "${TIMEOUT_S}"
tools status || true

cat <<EOF

IronMesh is running.

  Console     http://localhost:3000
              user     $(env_value IRONMESH_DEMO_USER)
              password $(env_value IRONMESH_DEMO_PASSWORD)
  Grafana     http://localhost:3001   (admin / $(env_value GRAFANA_ADMIN_PASSWORD))
  Prometheus  http://localhost:9090
  Registry    http://localhost:8000/openapi.json
  Broker      mqtts://localhost:8883  (mTLS, Device CA)

  Credentials live in deploy/docker/.env (git-ignored).
  Stop: docker compose -f deploy/docker/docker-compose.yml down   (add -v to wipe all state)
EOF
