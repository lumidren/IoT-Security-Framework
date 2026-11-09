#!/usr/bin/env bash
# Helm deployment helper for .github/workflows/deploy.yml (staging and production).
#
#   deploy_helm.sh verify-images TAG     cosign-verify every IronMesh image of TAG (keyless,
#                                        identity = this repository's release.yml)
#   deploy_helm.sh values ENV            fetch values-ENV.generated.yaml (Terraform hand-off)
#                                        from SSM parameter $HELM_VALUES_SSM_PARAMETER
#   deploy_helm.sh revision              print the current Helm revision (0 = not installed)
#   deploy_helm.sh upgrade ENV TAG       helm upgrade --install --atomic with values.yaml,
#                                        values-ENV.yaml, values-ENV.generated.yaml
#   deploy_helm.sh canary-up TAG [N]     canary without Argo Rollouts: clone every service
#                                        Deployment as <name>-canary (N replicas, image TAG,
#                                        label ironmesh.dev/track=canary). The clones carry the
#                                        stable pod labels, so the existing Services send them
#                                        N/(N+stable) of the traffic (replica weighting).
#   deploy_helm.sh canary-down           delete the canary Deployments
#   deploy_helm.sh rollback REVISION     helm rollback to REVISION (no-op for 0) and wait
#
# Environment: RELEASE (ironmesh), NAMESPACE (ironmesh), CHART (deploy/helm/ironmesh),
# IMAGE_NAMESPACE (ghcr.io/lumidren), HELM_TIMEOUT (15m), GITHUB_REPOSITORY.
set -euo pipefail

RELEASE="${RELEASE:-ironmesh}"
NAMESPACE="${NAMESPACE:-ironmesh}"
CHART="${CHART:-deploy/helm/ironmesh}"
IMAGE_NAMESPACE="${IMAGE_NAMESPACE:-ghcr.io/lumidren}"
HELM_TIMEOUT="${HELM_TIMEOUT:-15m}"
SERVICES=(pki policy bridge registry ota anomaly console)

log() { printf '%s deploy: %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }

cmd="${1:?usage: deploy_helm.sh <verify-images|values|revision|upgrade|canary-up|canary-down|rollback> ...}"
shift

case "${cmd}" in
  verify-images)
    tag="${1:?tag}"
    : "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
    for svc in "${SERVICES[@]}"; do
      ref="${IMAGE_NAMESPACE}/ironmesh-${svc}:${tag}"
      log "verifying ${ref}"
      cosign verify "${ref}" \
        --certificate-identity-regexp "^https://github.com/${GITHUB_REPOSITORY}/.github/workflows/release.yml@" \
        --certificate-oidc-issuer https://token.actions.githubusercontent.com >/dev/null
      cosign verify-attestation --type cyclonedx "${ref}" \
        --certificate-identity-regexp "^https://github.com/${GITHUB_REPOSITORY}/.github/workflows/release.yml@" \
        --certificate-oidc-issuer https://token.actions.githubusercontent.com >/dev/null
    done
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
    helm dependency update "${CHART}" >/dev/null
    helm upgrade --install "${RELEASE}" "${CHART}" -n "${NAMESPACE}" --create-namespace \
      -f "${CHART}/values.yaml" -f "${CHART}/values-${env}.yaml" -f "${CHART}/values-${env}.generated.yaml" \
      --set "global.imageTag=${tag}" --atomic --wait --timeout "${HELM_TIMEOUT}" --history-max 10
    helm -n "${NAMESPACE}" test "${RELEASE}" --timeout 5m
    ;;

  canary-up)
    tag="${1:?tag}"
    replicas="${2:-1}"
    for svc in "${SERVICES[@]}"; do
      name="${RELEASE}-${svc}"
      kubectl -n "${NAMESPACE}" get deployment "${name}" -o json >/dev/null 2>&1 || continue
      log "canary ${name}-canary (${replicas} replica(s), ${tag})"
      kubectl -n "${NAMESPACE}" get deployment "${name}" -o json \
        | jq --arg name "${name}-canary" --arg tag "${tag}" --argjson replicas "${replicas}" '
            del(.metadata.uid, .metadata.resourceVersion, .metadata.creationTimestamp,
                .metadata.generation, .metadata.managedFields, .metadata.annotations, .status)
            | .metadata.name = $name
            | .metadata.labels["ironmesh.dev/track"] = "canary"
            | del(.metadata.labels["app.kubernetes.io/managed-by"])
            | .spec.replicas = $replicas
            | .spec.selector.matchLabels["ironmesh.dev/track"] = "canary"
            | .spec.template.metadata.labels["ironmesh.dev/track"] = "canary"
            | .spec.template.spec.containers |= map(.image = (.image | sub("(@sha256:[0-9a-f]+|:[^:/@]+)$"; "") + ":" + $tag))' \
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
