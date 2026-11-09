#!/bin/sh
# pki-init: one-shot development PKI bootstrap for the local compose stack.
#
# Creates (idempotently) with `pkictl`, in the layout services/pki/README.md documents:
#   /pki-data   root-ca, factory-ca, device-ca, services-ca (+ .key.json, file KMS), bundle key
#   /tls/<svc>  tls.crt (leaf + Services CA), tls.key, ca.crt (Root + Services CA) for
#               pki, policy, bridge, registry, ota, anomaly (CN svc-<name>; pki uses CN "pki")
#   /tls/emqx   broker.pem / broker.key (Services CA, SAN emqx), ca-chain.pem (Device CA +
#               Services CA + Root, client verification), api-keys.txt (EMQX bootstrap API keys)
#   /trust      public material shared read-only with every service (CA certificates, the
#               bundle public key, SPKI pins, service public keys for ES256 service JWTs)
#   /fleet      bootstrap certificates for every identity created by `ironmesh-fleet provision`
#               (factory flow, HARDWARE_SETUP.md section 3) and the shared fleet.toml
#
# The OCSP responder key is not created here: the pki service derives its delegated OCSP signer
# from the Device CA at start-up (services/pki/internal/ocsp).
#
# Secrets arrive through the environment (PKI_FILE_KMS_PASSPHRASE is read by pkictl itself and
# never appears on a command line). Development hierarchy only: production roots are created
# offline with a Shamir quorum (`pkictl init-root --quorum-shares 5 --quorum-threshold 3`).
set -eu
umask 077

: "${PKI_FILE_KMS_PASSPHRASE:?PKI_FILE_KMS_PASSPHRASE is required}"
: "${IRONMESH_TENANT_ID:?IRONMESH_TENANT_ID is required}"
: "${EMQX_POLICY_API_SECRET:?EMQX_POLICY_API_SECRET is required}"
: "${EMQX_REGISTRY_API_SECRET:?EMQX_REGISTRY_API_SECRET is required}"
: "${EMQX_OTA_API_SECRET:?EMQX_OTA_API_SECRET is required}"

CA_DIR="${PKI_CA_DIR:-/pki-data}"
TLS_DIR="${IRONMESH_TLS_DIR:-/tls}"
TRUST_DIR="${IRONMESH_TRUST_DIR:-/trust}"
FLEET_DIR="${IRONMESH_FLEET_DIR:-/fleet}"
PUBLIC_URL="${PKI_PUBLIC_BASE_URL:-http://pki:8444}"
EMQX_EXTRA_SANS="${IRONMESH_EMQX_EXTRA_SANS:-}"
PKI_EXTRA_SANS="${IRONMESH_PKI_EXTRA_SANS:-}"
# Re-issue service certificates that expire within this many seconds (90-day certificates).
RENEW_BEFORE_S="${IRONMESH_RENEW_BEFORE_S:-1209600}"

log() { printf '%s pki-init: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }

# --- CA hierarchy ---------------------------------------------------------------------------
mkdir -p "${CA_DIR}"
if [ ! -f "${CA_DIR}/root-ca.crt" ]; then
  log "creating development root CA"
  pkictl init-root --dir "${CA_DIR}"
fi
for kind in factory device services; do
  if [ ! -f "${CA_DIR}/${kind}-ca.crt" ]; then
    log "creating ${kind} CA"
    pkictl init-intermediate --dir "${CA_DIR}" --kind "${kind}"
  fi
done
if [ ! -f "${CA_DIR}/bundle.key.json" ]; then
  log "creating Ed25519 bundle signing key"
  pkictl init-bundle-key --dir "${CA_DIR}"
fi

# --- public trust material ------------------------------------------------------------------
umask 022
mkdir -p "${TRUST_DIR}/service-pubkeys"
for f in root-ca.crt factory-ca.crt device-ca.crt services-ca.crt chain.pem bundle.pub.pem; do
  cp "${CA_DIR}/${f}" "${TRUST_DIR}/${f}"
done
cat "${CA_DIR}/root-ca.crt" "${CA_DIR}/services-ca.crt" > "${TRUST_DIR}/ca-bundle.pem"
# Hex Ed25519 bundle public key (last 32 bytes of the SubjectPublicKeyInfo DER).
openssl pkey -pubin -in "${CA_DIR}/bundle.pub.pem" -outform DER | tail -c 32 | od -An -v -tx1 | tr -d ' \n' > "${TRUST_DIR}/bundle-pubkey.hex"
# SHA-256 SPKI pin of the Services CA (EST server pin before a bundle is received).
openssl x509 -in "${CA_DIR}/services-ca.crt" -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum | cut -d' ' -f1 > "${TRUST_DIR}/services-ca-spki.sha256"

# --- service certificates -------------------------------------------------------------------
# issue <dir name> <common name> <comma separated SANs>
issue() {
  name="$1"; cn="$2"; sans="$3"
  out="${TLS_DIR}/${name}"
  mkdir -p "${out}"
  if [ -f "${out}/tls.crt" ] && openssl x509 -in "${out}/tls.crt" -noout -checkend "${RENEW_BEFORE_S}" >/dev/null 2>&1; then
    return 0
  fi
  log "issuing ${cn} (${sans})"
  work="$(mktemp -d)"
  umask 077
  pkictl issue-server --dir "${CA_DIR}" --cn "${cn}" --san "${sans}" --out "${work}"
  cp "${work}/${cn}.key.pem" "${out}/tls.key"
  umask 022
  cp "${work}/${cn}.crt" "${out}/tls.crt"
  cp "${TRUST_DIR}/ca-bundle.pem" "${out}/ca.crt"
  rm -rf "${work}"
  chmod 0600 "${out}/tls.key"
  # Public key for ES256 service-JWT verification (OTA_SERVICE_PUBLIC_KEYS_DIR, PKI JWT allow list).
  openssl x509 -in "${out}/tls.crt" -pubkey -noout > "${TRUST_DIR}/service-pubkeys/${name}.pem"
  cp "${TRUST_DIR}/service-pubkeys/${name}.pem" "${TRUST_DIR}/service-pubkeys/${cn}.pem"
}

issue pki pki "pki,localhost,127.0.0.1${PKI_EXTRA_SANS:+,${PKI_EXTRA_SANS}}"
issue policy svc-policy "policy"
issue bridge svc-bridge "bridge"
issue registry svc-registry "registry"
issue ota svc-ota "ota"
issue anomaly svc-anomaly "anomaly"
issue emqx emqx "emqx,localhost,127.0.0.1,mqtt.ironmesh.local${EMQX_EXTRA_SANS:+,${EMQX_EXTRA_SANS}}"

# ES256 keys trusted by the PKI management API (aud=pki): registry, ota and anomaly.
cat "${TRUST_DIR}/service-pubkeys/registry.pem" "${TRUST_DIR}/service-pubkeys/ota.pem" \
    "${TRUST_DIR}/service-pubkeys/anomaly.pem" > "${TRUST_DIR}/service-pubkeys/jwt-signers.pem"

# EMQX layout: the broker (uid 1000, member of gid 10001) reads these files.
cp "${TLS_DIR}/emqx/tls.crt" "${TLS_DIR}/emqx/broker.pem"
cp "${TLS_DIR}/emqx/tls.key" "${TLS_DIR}/emqx/broker.key"
cat "${CA_DIR}/device-ca.crt" "${CA_DIR}/services-ca.crt" "${CA_DIR}/root-ca.crt" > "${TLS_DIR}/emqx/ca-chain.pem"
umask 027
{
  printf 'policy:%s:administrator\n' "${EMQX_POLICY_API_SECRET}"
  printf 'registry:%s:administrator\n' "${EMQX_REGISTRY_API_SECRET}"
  printf 'ota:%s:administrator\n' "${EMQX_OTA_API_SECRET}"
} > "${TLS_DIR}/emqx/api-keys.txt"
chmod 0640 "${TLS_DIR}/emqx/broker.key" "${TLS_DIR}/emqx/api-keys.txt"
umask 022

# --- virtual fleet: factory bootstrap certificates ------------------------------------------
if [ -f "${FLEET_DIR}/fleet.json" ]; then
  issued=0
  for dir in "${FLEET_DIR}"/dev-*; do
    [ -d "${dir}" ] || continue
    id="$(basename "${dir}")"
    [ -f "${dir}/bootstrap.csr.pem" ] || continue
    [ -f "${dir}/bootstrap.crt" ] && continue
    pkictl issue-bootstrap --dir "${CA_DIR}" --tenant "${IRONMESH_TENANT_ID}" --device "${id}" \
      --csr "${dir}/bootstrap.csr.pem" --out "${dir}/factory" --public-url "${PUBLIC_URL}" >/dev/null
    cp "${dir}/factory/${id}.crt" "${dir}/bootstrap.crt"
    issued=$((issued + 1))
  done
  log "issued ${issued} bootstrap certificates"

  mkdir -p "${FLEET_DIR}/trust"
  cp "${TRUST_DIR}/ca-bundle.pem" "${FLEET_DIR}/trust/ca-bundle.pem"
  cat > "${FLEET_DIR}/fleet.toml" <<EOF
# Generated by pki-init; shared by every simulated device (device/agent-rs settings).
[pki]
est_host = "pki"
est_port = 8443
ca_bundle = "${FLEET_DIR}/trust/ca-bundle.pem"
est_pins = ["$(cat "${TRUST_DIR}/services-ca-spki.sha256")"]
bundle_pubkey = "$(cat "${TRUST_DIR}/bundle-pubkey.hex")"

[mqtt]
host = "emqx"
port = 8883

[telemetry]
interval_s = ${IRONMESH_FLEET_TELEMETRY_INTERVAL_S:-10}

[ota]
product = "${IRONMESH_FLEET_PRODUCT:-fleet-sim}"
allowed_hosts = ["ota"]

[agent]
fw_version = "1.0.0"
fw_version_code = 1
EOF
else
  log "no ${FLEET_DIR}/fleet.json: skipping fleet bootstrap certificates"
fi

log "done"
