#!/usr/bin/env bash
# Post-deploy smoke test: health endpoints + one synthetic software-key device enrolling (EST +
# attestation), connecting over mTLS and publishing telemetry against a deployed environment.
#
# The synthetic device is a factory-provisioned `ironmesh-fleet` identity (one device), created
# once per environment by the factory operator:
#
#   ironmesh-fleet provision --out smoke --count 1 --tenant <smoke tenant> --prefix 5303e000
#   pkictl issue-bootstrap ... --csr smoke/<id>/bootstrap.csr.pem   -> smoke/<id>/bootstrap.crt
#   POST /v1/devices {id, product, hw_revision, se_type: "software", bootstrap_serial_hex}
#   tar -czf - smoke | base64 -w0      -> environment secret SMOKE_FLEET_IDENTITY_TGZ_B64
#
# Each run unpacks a fresh copy, so only the bootstrap identity persists between runs and the
# device re-enrolls with a new operational key every time.
#
# Environment:
#   SMOKE_FLEET_IDENTITY_TGZ_B64  base64 tar.gz of the fleet directory (secret)
#   SMOKE_FLEET_TOML              fleet.toml for the environment (pki/mqtt hosts, pins, bundle key)
#   SMOKE_HEALTH_URLS             space separated URLs that must answer 2xx
#   FLEET_BIN                     path to ironmesh-fleet (default: ironmesh-fleet on PATH)
#   SMOKE_DURATION_S              run time (default 90)
set -euo pipefail

: "${SMOKE_FLEET_IDENTITY_TGZ_B64:?SMOKE_FLEET_IDENTITY_TGZ_B64 is required}"
: "${SMOKE_FLEET_TOML:?SMOKE_FLEET_TOML is required}"
FLEET_BIN="${FLEET_BIN:-ironmesh-fleet}"
DURATION="${SMOKE_DURATION_S:-90}"

for url in ${SMOKE_HEALTH_URLS:-}; do
  if curl --silent --show-error --fail --max-time 10 --retry 5 --retry-delay 5 --retry-all-errors -o /dev/null "${url}"; then
    echo "ok   ${url}"
  else
    echo "FAIL ${url}"
    exit 1
  fi
done

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
umask 077
printf '%s' "${SMOKE_FLEET_IDENTITY_TGZ_B64}" | base64 -d | tar -xzf - -C "${work}"
fleet_dir="$(dirname "$(find "${work}" -name fleet.json -print -quit)")"
[[ -f "${fleet_dir}/fleet.json" ]] || { echo "fleet.json not found in the identity archive"; exit 1; }
printf '%s\n' "${SMOKE_FLEET_TOML}" > "${work}/fleet.toml"

summary="$("${FLEET_BIN}" run --dir "${fleet_dir}" --config "${work}/fleet.toml" --count 1 \
  --duration-s "${DURATION}" | tail -n 1)"
echo "fleet summary: ${summary}"
python3 - "${summary}" <<'PY'
import json, sys
s = json.loads(sys.argv[1])
ok = s.get("enrolled", 0) >= 1 and s.get("published", 0) >= 1
print("synthetic enrollment", "ok" if ok else "FAILED", s)
sys.exit(0 if ok else 1)
PY
