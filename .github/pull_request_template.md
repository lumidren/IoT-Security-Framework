## Summary

<!-- What changes and why. Link the issue: "Fixes #123". -->

## Components

- [ ] services (pki / policy / bridge / registry / ota / anomaly)
- [ ] console
- [ ] device (agent-rs / esp32) or `device/common` wire format
- [ ] deploy (compose / Helm / Kustomize / Terraform) or CI
- [ ] docs only

## Contract and security checklist

- [ ] No change to `docs/DESIGN_CONTRACT.md` / `docs/API_CONTRACT.md`, **or** the change is
      reflected in `CHANGELOG.md`, the conformance suite and both firmware targets
- [ ] New or renamed environment variables are wired in `deploy/docker`, the Helm chart (values
      + README table) and `deploy/k8s` (`python scripts/ci/check_env_contract.py` passes)
- [ ] No secrets, private keys or real device identities in the diff (gitleaks passes)
- [ ] Threat model updated (`THREAT_MODEL.md`) for new trust boundaries, inputs or key material
- [ ] Database changes go through the service's migrations; app roles keep `NOBYPASSRLS`
      and append-only tables stay append-only

## Testing

<!-- Unit / integration / conformance / manual steps. Coverage gates: Go internal >= 90 %,
Python >= 90 % (wire library 95 %), agent-rs >= 85 % lines. -->
