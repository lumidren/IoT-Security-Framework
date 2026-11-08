#!/usr/bin/env bash
# pki_backup.sh - export of IronMesh PKI *metadata* to the backups bucket.
#
# Exports, for every CA key alias (root, factory, device, services, bundle signing and the
# firmware KEK): KMS DescribeKey, key policy, rotation status, grants and the public key (PEM);
# the CA chain and current CRL served by the PKI; the root-CA quorum inventory kept in Secrets
# Manager; and the replication status of the firmware signing secret. Everything is uploaded
# with SSE-KMS and a SHA-256 manifest.
#
# Private keys never leave KMS: asymmetric CMKs are not exportable by design, and this script
# only calls read-only KMS/Secrets Manager metadata APIs plus GetSecretValue on the inventory.
# The `pki` database itself is dumped by pg_backup.sh.
#
# Environment (defaults in parentheses):
#   AWS_REGION                   (eu-west-1)
#   BACKUP_BUCKET                destination bucket                                (required)
#   BACKUP_PREFIX                (pki)
#   BACKUP_KMS_KEY_ID            SSE-KMS key                                       (alias/ironmesh-prod-s3)
#   KMS_ALIAS_PREFIX             alias prefix of the CMKs                           (alias/ironmesh-prod)
#   KMS_KEY_PURPOSES             purposes to export                                (root-ca factory-ca device-ca services-ca bundle-signing firmware-kek)
#   PKI_BASE_URL                 public PKI base URL                               (https://pki.ironmesh.dev)
#   PKI_CRL_PATH                 (/crl/device-ca.crl)
#   PKI_CACERTS_PATH             (/.well-known/est/cacerts)
#   QUORUM_INVENTORY_SECRET      Secrets Manager name                              (ironmesh/prod/pki/root-ca-quorum-inventory)
#   FIRMWARE_SIGNING_SECRET      Secrets Manager name                              (ironmesh/prod/ota/firmware-signing-key)
#   REQUIRE_REPLICATION          fail if the firmware secret is not replicated     (true)
set -euo pipefail

AWS_REGION="${AWS_REGION:-eu-west-1}"
BACKUP_BUCKET="${BACKUP_BUCKET:?BACKUP_BUCKET is required}"
BACKUP_PREFIX="${BACKUP_PREFIX:-pki}"
BACKUP_KMS_KEY_ID="${BACKUP_KMS_KEY_ID:-alias/ironmesh-prod-s3}"
KMS_ALIAS_PREFIX="${KMS_ALIAS_PREFIX:-alias/ironmesh-prod}"
KMS_KEY_PURPOSES="${KMS_KEY_PURPOSES:-root-ca factory-ca device-ca services-ca bundle-signing firmware-kek}"
PKI_BASE_URL="${PKI_BASE_URL:-https://pki.ironmesh.dev}"
PKI_CRL_PATH="${PKI_CRL_PATH:-/crl/device-ca.crl}"
PKI_CACERTS_PATH="${PKI_CACERTS_PATH:-/.well-known/est/cacerts}"
QUORUM_INVENTORY_SECRET="${QUORUM_INVENTORY_SECRET:-ironmesh/prod/pki/root-ca-quorum-inventory}"
FIRMWARE_SIGNING_SECRET="${FIRMWARE_SIGNING_SECRET:-ironmesh/prod/ota/firmware-signing-key}"
REQUIRE_REPLICATION="${REQUIRE_REPLICATION:-true}"
export AWS_REGION

log() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

for tool in aws jq openssl curl sha256sum base64; do
  command -v "${tool}" >/dev/null 2>&1 || die "missing dependency: ${tool}"
done

WORK_DIR="$(mktemp -d)"
cleanup() { rm -rf "${WORK_DIR}"; }
trap cleanup EXIT

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
export_dir="${WORK_DIR}/${timestamp}"
mkdir -p "${export_dir}/kms" "${export_dir}/pki"
warnings=0

export_key() {
  local purpose="$1"
  local alias="${KMS_ALIAS_PREFIX}-${purpose}"
  local dir="${export_dir}/kms/${purpose}"
  mkdir -p "${dir}"

  local key_id
  if ! key_id="$(aws kms describe-key --key-id "${alias}" --query 'KeyMetadata.KeyId' --output text 2>/dev/null)"; then
    log "kms: alias ${alias} not found (skipping)"
    warnings=$((warnings + 1))
    return 0
  fi
  aws kms describe-key --key-id "${key_id}" > "${dir}/describe-key.json"
  aws kms get-key-policy --key-id "${key_id}" --policy-name default --query Policy --output text | jq . > "${dir}/key-policy.json"
  aws kms list-grants --key-id "${key_id}" > "${dir}/grants.json"
  aws kms list-aliases --key-id "${key_id}" > "${dir}/aliases.json"
  aws kms list-resource-tags --key-id "${key_id}" > "${dir}/tags.json"

  local usage spec
  usage="$(jq -r '.KeyMetadata.KeyUsage' "${dir}/describe-key.json")"
  spec="$(jq -r '.KeyMetadata.KeySpec' "${dir}/describe-key.json")"
  if [[ "${usage}" == "SIGN_VERIFY" ]]; then
    aws kms get-public-key --key-id "${key_id}" --query PublicKey --output text | base64 -d > "${dir}/public-key.der"
    openssl pkey -pubin -inform DER -in "${dir}/public-key.der" -out "${dir}/public-key.pem"
    openssl pkey -pubin -in "${dir}/public-key.pem" -outform DER 2>/dev/null | openssl dgst -sha256 -binary | base64 > "${dir}/spki-sha256.b64"
    log "kms: ${alias} (${spec}) public key exported, SPKI sha256 $(cat "${dir}/spki-sha256.b64")"
  else
    aws kms get-key-rotation-status --key-id "${key_id}" > "${dir}/rotation.json"
    log "kms: ${alias} (${spec}) symmetric, rotation enabled=$(jq -r '.KeyRotationEnabled' "${dir}/rotation.json")"
  fi
}

for purpose in ${KMS_KEY_PURPOSES}; do
  export_key "${purpose}"
done

log "pki: fetching CA chain and CRL from ${PKI_BASE_URL}"
if curl --fail --silent --show-error --max-time 30 "${PKI_BASE_URL}${PKI_CACERTS_PATH}" -o "${export_dir}/pki/cacerts.p7.b64"; then
  if base64 -d "${export_dir}/pki/cacerts.p7.b64" > "${export_dir}/pki/cacerts.p7.der" 2>/dev/null \
     && openssl pkcs7 -inform DER -in "${export_dir}/pki/cacerts.p7.der" -print_certs -out "${export_dir}/pki/ca-chain.pem" 2>/dev/null; then
    log "pki: CA chain has $(grep -c 'BEGIN CERTIFICATE' "${export_dir}/pki/ca-chain.pem") certificate(s)"
  else
    log "pki: cacerts response could not be parsed as base64 PKCS#7"
    warnings=$((warnings + 1))
  fi
else
  log "pki: cacerts fetch failed"
  warnings=$((warnings + 1))
fi
crl_url="${PKI_BASE_URL/https:/http:}${PKI_CRL_PATH}"
if curl --fail --silent --show-error --max-time 30 "${crl_url}" -o "${export_dir}/pki/device-ca.crl"; then
  if openssl crl -inform DER -in "${export_dir}/pki/device-ca.crl" -noout -nextupdate -crlnumber > "${export_dir}/pki/crl-info.txt" 2>/dev/null \
     || openssl crl -inform PEM -in "${export_dir}/pki/device-ca.crl" -noout -nextupdate -crlnumber > "${export_dir}/pki/crl-info.txt"; then
    log "pki: CRL $(tr '\n' ' ' < "${export_dir}/pki/crl-info.txt")"
  fi
else
  log "pki: CRL fetch failed"
  warnings=$((warnings + 1))
fi

log "secrets: exporting root-CA quorum inventory"
if aws secretsmanager get-secret-value --secret-id "${QUORUM_INVENTORY_SECRET}" --query SecretString --output text > "${export_dir}/root-ca-quorum-inventory.json" 2>/dev/null; then
  jq . "${export_dir}/root-ca-quorum-inventory.json" >/dev/null || die "quorum inventory is not valid JSON"
  log "secrets: inventory lists $(jq -r '.shares | length' "${export_dir}/root-ca-quorum-inventory.json" 2>/dev/null || echo '?') share holder(s)"
else
  log "secrets: quorum inventory ${QUORUM_INVENTORY_SECRET} not readable"
  warnings=$((warnings + 1))
fi

log "secrets: checking firmware signing secret replication"
aws secretsmanager describe-secret --secret-id "${FIRMWARE_SIGNING_SECRET}" > "${export_dir}/firmware-signing-secret.describe.json"
replicas="$(jq -r '[.ReplicationStatus[]? | select(.Status == "InSync") | .Region] | join(",")' "${export_dir}/firmware-signing-secret.describe.json")"
if [[ -z "${replicas}" ]]; then
  log "secrets: firmware signing secret has no in-sync replica"
  if [[ "${REQUIRE_REPLICATION}" == "true" ]]; then
    die "firmware signing secret must be replicated to a second region"
  fi
  warnings=$((warnings + 1))
else
  log "secrets: firmware signing secret replicated to ${replicas}"
fi

( cd "${export_dir}" && find . -type f ! -name 'SHA256SUMS' -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS )
log "uploading export to s3://${BACKUP_BUCKET}/${BACKUP_PREFIX}/${timestamp}/"
aws s3 cp "${export_dir}" "s3://${BACKUP_BUCKET}/${BACKUP_PREFIX}/${timestamp}/" --recursive \
  --sse aws:kms --sse-kms-key-id "${BACKUP_KMS_KEY_ID}" --only-show-errors
printf '%s\n' "${timestamp}" > "${WORK_DIR}/latest"
aws s3 cp "${WORK_DIR}/latest" "s3://${BACKUP_BUCKET}/${BACKUP_PREFIX}/latest" \
  --sse aws:kms --sse-kms-key-id "${BACKUP_KMS_KEY_ID}" --only-show-errors --content-type text/plain

if (( warnings > 0 )); then
  log "pki export complete with ${warnings} warning(s)"
  exit 2
fi
log "pki export complete"
