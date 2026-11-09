#!/usr/bin/env bash
# Helm deployment helper for .github/workflows/deploy.yml (staging and production).
#
# Images are deployed by digest only (THREAT_MODEL T-67): a release tag is resolved to the
# digest of its (multi-arch) index once, that digest is cosign-verified, and the same digest is
# what Helm and the canary run. A tag that is moved after verification changes nothing.
#
#   deploy_helm.sh resolve-digests TAG [DIR]
#                                        resolve ironmesh-<svc>:TAG (every service + fleet) to its
#                                        digest (crane digest, else docker buildx imagetools
#                                        inspect) and print {"<svc>":"sha256:...",...}. With DIR
#                                        (the release run's digests/<svc>.json artifacts) every
#                                        registry digest must equal the digest the release job
#                                        built and signed.
#   deploy_helm.sh verify-images [TAG]   cosign-verify the signature and the CycloneDX attestation
#                                        of every <svc>@<digest> in $IMAGE_DIGESTS (keyless,
#                                        identity = this repository's release.yml on main or a
#                                        v* tag)
#   deploy_helm.sh image-ref SVC         print <IMAGE_NAMESPACE>/ironmesh-SVC@<digest>
#   deploy_helm.sh values ENV            fetch values-ENV.generated.yaml (Terraform hand-off)
#                                        from SSM parameter $HELM_VALUES_SSM_PARAMETER
#   deploy_helm.sh revision              print the current Helm revision (0 = not installed)
#   deploy_helm.sh upgrade ENV TAG       helm upgrade --install --atomic with values.yaml,
#                                        values-ENV.yaml, values-ENV.generated.yaml and the
#                                        verified digests (services.<svc>.image.digest); TAG only
#                                        labels the release (global.imageTag)
#   deploy_helm.sh canary-up TAG [N]     canary without Argo Rollouts: clone every service
#                                        Deployment as <name>-canary (N replicas, image
#                                        <svc>@<digest> from $IMAGE_DIGESTS, label
#                                        ironmesh.dev/track=canary). The clones carry the stable
#                                        pod labels, so the existing Services send them
#                                        N/(N+stable) of the traffic (replica weighting).
#   deploy_helm.sh canary-down           delete the canary Deployments
#   deploy_helm.sh rollback REVISION     helm rollback to REVISION (no-op for 0) and wait
#
# Environment: RELEASE (ironmesh), NAMESPACE (ironmesh), CHART (deploy/helm/ironmesh),
# IMAGE_NAMESPACE (ghcr.io/lumidren), HELM_TIMEOUT (15m), GITHUB_REPOSITORY,
# IMAGE_DIGESTS (JSON from resolve-digests; required by verify-images, image-ref, upgrade and
# canary-up).
set -euo pipefail

RELEASE="${RELEASE:-ironmesh}"
NAMESPACE="${NAMESPACE:-ironmesh}"
CHART="${CHART:-deploy/helm/ironmesh}"
IMAGE_NAMESPACE="${IMAGE_NAMESPACE:-ghcr.io/lumidren}"
HELM_TIMEOUT="${HELM_TIMEOUT:-15m}"
SERVICES=(pki policy bridge registry ota anomaly console)
# Images the deploy uses but Helm does not run (smoke-test fleet simulator).
EXTRA_IMAGES=(fleet)
OIDC_ISSUER="https://token.actions.githubusercontent.com"
# release.yml signs on push to main and on v* tags (refs/tags/vX.Y.Z...).
RELEASE_REFS='refs/(heads/main|tags/v[0-9]+\.[0-9]+\.[0-9]+.*)'
DIGEST_RE='^sha256:[0-9a-f]{64}$'

log() { printf '%s deploy: %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

# Digest of a tag in the registry (the index digest for multi-arch images).
registry_digest() {
  local ref="$1"
  if command -v crane >/dev/null 2>&1; then
    crane digest "${ref}"
  else
    docker buildx imagetools inspect "${ref}" --format '{{json .Manifest}}' | jq -r '.digest'
  fi
}

# Digest of SVC from $IMAGE_DIGESTS (validated).
digest_of() {
  local svc="$1" digest
  : "${IMAGE_DIGESTS:?IMAGE_DIGESTS is required (output of resolve-digests)}"
  digest="$(jq -r --arg s "${svc}" '.[$s] // empty' <<<"${IMAGE_DIGESTS}")"
  [[ "${digest}" =~ ${DIGEST_RE} ]] || die "no valid digest for ${svc} in IMAGE_DIGESTS"
  printf '%s' "${digest}"
}

# Fulcio certificate identity of this repository's release workflow on main / a release tag.
identity_regexp() {
  : "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
  local repo="${GITHUB_REPOSITORY//./\\.}"
  printf '^https://github\\.com/%s/\\.github/workflows/release\\.yml@%s$' "${repo}" "${RELEASE_REFS}"
}

cmd="${1:?usage: deploy_helm.sh <resolve-digests|verify-images|image-ref|values|revision|upgrade|canary-up|canary-down|rollback> ...}"
shift

case "${cmd}" in
  resolve-digests)
    tag="${1:?tag}"
    release_dir="${2:-}"
    out='{}'
    for svc in "${SERVICES[@]}" "${EXTRA_IMAGES[@]}"; do
      ref="${IMAGE_NAMESPACE}/ironmesh-${svc}:${tag}"
      digest="$(registry_digest "${ref}")"
      [[ "${digest}" =~ ${DIGEST_RE} ]] || die "could not resolve ${ref} to a digest (got '${digest}')"
      if [[ -n "${release_dir}" ]]; then
        file="${release_dir}/${svc}.json"
        [[ -f "${file}" ]] || die "release run has no digest record ${file}"
        built="$(jq -r '.digest' "${file}")"
        [[ "${built}" == "${digest}" ]] \
          || die "${ref} now points to ${digest}, but the release run built and signed ${built}"
      fi
      log "${ref} -> ${digest}"
      out="$(jq -c --arg s "${svc}" --arg d "${digest}" '. + {($s): $d}' <<<"${out}")"
    done
    printf '%s\n' "${out}"
    ;;

  verify-images)
    regexp="$(identity_regexp)"
    for svc in "${SERVICES[@]}" "${EXTRA_IMAGES[@]}"; do
      digest="$(digest_of "${svc}")"
      ref="${IMAGE_NAMESPACE}/ironmesh-${svc}@${digest}"
      log "verifying ${ref}${1:+ (${1})}"
      cosign verify "${ref}" \
        --certificate-identity-regexp "${regexp}" \
        --certificate-oidc-issuer "${OIDC_ISSUER}" \
        --certificate-github-workflow-repository "${GITHUB_REPOSITORY}" >/dev/null
      cosign verify-attestation --type cyclonedx "${ref}" \
        --certificate-identity-regexp "${regexp}" \
        --certificate-oidc-issuer "${OIDC_ISSUER}" \
        --certificate-github-workflow-repository "${GITHUB_REPOSITORY}" >/dev/null
    done
    ;;

  image-ref)
    svc="${1:?service}"
    digest="$(digest_of "${svc}")"
    printf '%s/ironmesh-%s@%s\n' "${IMAGE_NAMESPACE}" "${svc}" "${digest}"
    ;;

  values)
    env="${1:?env}"
    : "${HELM_VALUES_SSM_PARAMETER:?HELM_VALUES_SSM_PARAMETER is required}"
    aws ssm get-parameter --name "${HELM_VALUES_SSM_PARAMETER}" --with-decryption \
      --query Parameter.Value --output text > "${CHART}/values-${env}.generated.yaml"
    log "wrote ${CHART}/values-${env}.generated.yaml"
    ;;

  revision)
    helm -n "${NAMESPACE}" history "${RELEASE}" --max 1 -o json 2>/dev/null | jq -r '.[-1].revision // 0' || echo 0
    ;;

  upgrade)
    env="${1:?env}"
    tag="${2:?tag}"
    # services.<svc>.image.digest for every service (JSON is valid YAML); fails without digests.
    digests_file="${CHART}/values-digests.generated.yaml"
    services_json='{}'
    for svc in "${SERVICES[@]}"; do
      digest="$(digest_of "${svc}")"
      services_json="$(jq -c --arg s "${svc}" --arg d "${digest}" \
        '. + {($s): {image: {digest: $d}}}' <<<"${services_json}")"
    done
    jq -n --argjson s "${services_json}" '{services: $s}' > "${digests_file}"
    log "deploying ${tag} by digest (${digests_file})"
    helm dependency update "${CHART}" >/dev/null
    helm upgrade --install "${RELEASE}" "${CHART}" -n "${NAMESPACE}" --create-namespace \
      -f "${CHART}/values.yaml" -f "${CHART}/values-${env}.yaml" -f "${CHART}/values-${env}.generated.yaml" \
      -f "${digests_file}" \
      --set "global.imageTag=${tag}" --atomic --wait --timeout "${HELM_TIMEOUT}" --history-max 10
    helm -n "${NAMESPACE}" test "${RELEASE}" --timeout 5m
    ;;

  canary-up)
    tag="${1:?tag}"
    replicas="${2:-1}"
    for svc in "${SERVICES[@]}"; do
      name="${RELEASE}-${svc}"
      kubectl -n "${NAMESPACE}" get deployment "${name}" -o json >/dev/null 2>&1 || continue
      digest="$(digest_of "${svc}")"
      log "canary ${name}-canary (${replicas} replica(s), ${tag} = ${digest})"
      kubectl -n "${NAMESPACE}" get deployment "${name}" -o json \
        | jq --arg name "${name}-canary" --arg digest "${digest}" --argjson replicas "${replicas}" '
            del(.metadata.uid, .metadata.resourceVersion, .metadata.creationTimestamp,
                .metadata.generation, .metadata.managedFields, .metadata.annotations, .status)
            | .metadata.name = $name
            | .metadata.labels["ironmesh.dev/track"] = "canary"
            | del(.metadata.labels["app.kubernetes.io/managed-by"])
            | .spec.replicas = $replicas
            | .spec.selector.matchLabels["ironmesh.dev/track"] = "canary"
            | .spec.template.metadata.labels["ironmesh.dev/track"] = "canary"
            | .spec.template.spec.containers |= map(.image = (.image | sub("(@sha256:[0-9a-f]+|:[^:/@]+)$"; "") + "@" + $digest))' \
        | kubectl -n "${NAMESPACE}" apply -f -
    done
    for svc in "${SERVICES[@]}"; do
      name="${RELEASE}-${svc}-canary"
      kubectl -n "${NAMESPACE}" get deployment "${name}" >/dev/null 2>&1 || continue
      kubectl -n "${NAMESPACE}" rollout status deployment "${name}" --timeout 10m
    done
    ;;

  canary-down)
    kubectl -n "${NAMESPACE}" delete deployment -l ironmesh.dev/track=canary --ignore-not-found --wait=true
    ;;

  rollback)
    revision="${1:?revision}"
    if [[ "${revision}" == "0" ]]; then
      log "no previous revision to roll back to"
      exit 0
    fi
    log "rolling back ${RELEASE} to revision ${revision}"
    helm -n "${NAMESPACE}" rollback "${RELEASE}" "${revision}" --wait --timeout "${HELM_TIMEOUT}" --cleanup-on-fail
    ;;

  *)
    echo "unknown command ${cmd}" >&2
    exit 2
    ;;
esac
