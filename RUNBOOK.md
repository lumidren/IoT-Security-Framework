# IronMesh Operations Runbook

Operational procedures for on-call engineers. Every procedure lists detection, immediate actions,
containment, recovery, and post-incident steps. Commands assume `kubectl` context set to the
production cluster and the `ironmesh` namespace, or `docker compose` in the local stack.

Severity levels: **SEV1** fleet-wide impact or active compromise; **SEV2** tenant-wide impact;
**SEV3** single device or degraded capability.

## 0. Quick reference

| Symptom / alert                         | Go to |
|-----------------------------------------|-------|
| `RevocationLatencyHigh`                 | §1.3  |
| CA key suspected compromised            | §1.1  |
| Operational cert expiry backlog         | §1.4  |
| Device behaving maliciously / anomaly   | §2    |
| OTA campaign halted                     | §3    |
| `AuthFailureBurst`                      | §4.1  |
| Broker overloaded / `ConnectedDevicesDrop` | §4.2 |
| Tenant isolation suspicion              | §5    |
| Restore from backup                     | §6    |

## 1. Certificate incidents

### 1.1 Suspected compromise of an intermediate CA key (SEV1)

**Detection**: CloudTrail `kms:Sign` calls from an unexpected principal; certificates in the
`certificates` table not matching an EST or management request (`scripts/pki/audit_issuance.py`
compares KMS sign events to issuance records nightly); external report.

**Immediate (first 15 minutes)**
1. Freeze issuance: `kubectl scale deploy/pki --replicas=0` (devices keep working on current certs;
   renewals start failing after 7 days of grace).
2. Deny the KMS key: attach the pre-written `deny-all` key policy statement
   (`deploy/terraform/aws/modules/kms/policies/ca-freeze.json`) to the affected CMK.
3. Open the incident channel, page the PKI owner and the security lead.

**Containment**
4. Determine blast radius: `SELECT count(*) FROM certificates WHERE issuer_key_id = '<kid>' AND
   not_after > now();`
5. If the Device CA is affected: generate a new Device CA from the offline root (quorum ceremony,
   §1.5), publish the new chain to the broker (`emqx.conf` `cacertfile` includes **both** old and
   new Device CA during migration), and set `PKI_ISSUER=device-ca-v2`.
6. Force re-enrollment: `pkictl revoke-issuer --issuer <old kid> --reason caCompromise` revokes every
   cert from the old CA; the policy service kicks all sessions within 10 s; devices fall back to
   **bootstrap enrollment** (Factory CA unaffected) and receive certs from the new Device CA. Expect
   a reconnect storm: pre-scale EMQX and policy (`kubectl scale deploy/policy --replicas=6`).
7. If the Factory CA is affected: no zero-touch recovery exists for devices still in `manufactured`
   state; they must be re-provisioned at a factory station. Already-enrolled devices are unaffected
   because enrollment uses the Device CA chain for re-enrollment.

**Recovery**: remove the old CA from `cacertfile` once `SELECT count(*) FROM certificates WHERE
issuer_key_id='<old>' AND revoked_at IS NULL` is 0. Rotate the KMS CMK alias to the new key, schedule
deletion of the old CMK (30 days).

**Post-incident**: root-cause in the KMS access path, update `THREAT_MODEL.md` T-table, run the
tabletop again.

### 1.2 Single device certificate compromise (SEV3)

1. `curl -X POST https://pki/v1/devices/<device_id>/revoke-all -d '{"reason":"keyCompromise"}'`
   or Console -> Device -> Quarantine (which revokes and drops ACLs).
2. Verify: `ironmesh_revocation_latency_seconds` for the event is < 10 s; the device appears
   disconnected in EMQX (`GET /api/v5/clients/<device_id>` -> 404).
3. Set lifecycle to `quarantined` so re-enrollment is refused (§2).

### 1.3 `RevocationLatencyHigh` (SEV2)

Revocation is propagated by push (PKI -> policy) with CRL polling as fallback (5 s).
1. Check the PKI publisher: `kubectl logs deploy/pki | jq 'select(.msg=="revocation publish failed")'`.
2. Check policy readiness: `curl policy:8081/readyz` reports `crl_age_seconds` and
   `emqx_api_reachable`. If EMQX API is unreachable the kick fails: verify the API key secret and
   NetworkPolicy `policy-to-emqx-api`.
3. If the CRL is stale (> 60 s): check `pki:8444/crl/device-ca.crl` `Last-Modified`.
4. Manual kick: `curl -u $EMQX_API_KEY:$EMQX_API_SECRET -X DELETE http://emqx:18083/api/v5/clients/<id>`.

### 1.4 `CertExpiryBacklog` (SEV2)

Devices renew at 50% of lifetime, so a backlog means renewals are failing.
1. `GET pki:8443/v1/stats` -> `expiring_24h`; group by tenant with
   `SELECT tenant_id, count(*) FROM certificates WHERE not_after < now() + interval '24 hours' AND revoked_at IS NULL GROUP BY 1`.
2. Check EST errors: `ironmesh_est_requests_total{op="simplereenroll",code!="200"}`. Common causes:
   nonce store full (Postgres disk), attestation policy tightened (`allow_software_keys` turned
   off for a tenant with software devices: they fail with 403 `se_type_not_allowed`), clock drift
   on devices (`ts` skew) — check `ironmesh_replay_rejected_total`.
3. Emergency extension is **not** possible (certs are immutable); if renewals cannot be fixed before
   expiry, devices will fall back to bootstrap enrollment automatically. Make sure the Factory CA
   chain is accepted by the EST listener and the policy allows it.

### 1.5 Root CA ceremony (planned, quorum)

Requires `K` of `N` share holders (default 3 of 5) physically present with an offline laptop booted
from the ceremony image.
1. `pkictl recover-root --shares share1.json share2.json share3.json` reconstructs the root wrapping
   key in memory only.
2. `pkictl init-intermediate --kind device --ttl 43800h --out device-ca-v2.pem` signs the new
   intermediate CSR exported from the online KMS (`pkictl csr --kms awskms --key alias/ironmesh-device-ca-v2`).
3. Shred the ceremony laptop's RAM disk; record the ceremony log (who, when, hashes) in the
   `pki_ceremonies` audit table via the console (Audit -> Ceremonies).

## 2. Compromised or anomalous device

**Detection**: anomaly alert (`im.alerts`, SIEM), `topic_violation` events from the policy
service, firmware hash mismatch, support report.

1. **Quarantine** (Console -> Device -> Quarantine, or `POST registry/v1/devices/<id>/quarantine`).
   This revokes all certs (PKI), drops ACLs (policy cache), kicks the session (EMQX), sets state
   `quarantined`, and writes an audit event. If `ANOMALY_AUTO_QUARANTINE=true` this already happened
   automatically; verify in Audit log.
2. **Preserve evidence**: export the device timeline (`GET registry/v1/devices/<id>/timeline?from=...`),
   last 24 h of telemetry from Redpanda (`rpk topic consume im.ingest --offset -1h | jq 'select(.key=="<t>/<d>")'`),
   and broker auth logs from `im.auth`.
3. **Assess**: compare reported `fw_hash` with the OTA service's known hashes
   (`GET ota/v1/firmware/by-hash/<hash>`). An unknown hash on a Secure Boot device indicates a
   Secure Boot bypass -> SEV1, involve the firmware team. On a software-key device assume the key is
   stolen; the attacker cannot re-enroll because the device is quarantined and all certs are revoked.
4. **Recover**: physical recovery (reflash via factory station) -> new bootstrap cert -> state back
   to `manufactured`, or decommission (`POST .../decommission`, terminal).
5. **Hunt**: query for other devices with the same anomaly signature
   (`GET anomaly/v1/alerts?rule=<rule>&since=...`), the same firmware hash, or the same source IP.
6. **Post-incident**: add a detection rule if the behaviour was not caught, update the Isolation
   Forest baseline exclusion list so the attacker's traffic does not become "normal".

### 2.1 False-positive quarantine

1. Confirm with the device owner; check the alert explanation (`features`, `score`).
2. `POST registry/v1/devices/<id>/release` -> state `active`. The device **must** re-enroll
   (its certs were revoked); it does so automatically via bootstrap enrollment within one backoff
   cycle (<= 6 h, usually < 5 min).
3. Tune: raise the rule threshold or add the device class to the rule's exclusion list, and run the
   anomaly service in dry-run (`ANOMALY_AUTO_QUARANTINE=false`) for that tenant for 7 days.

## 3. OTA incidents

### 3.1 Rollout halted automatically (SEV2)

The rollout controller halts when `failures / attempted > OTA_HALT_FAILURE_RATE` (default 5%)
within a stage, or when any device reports `rolled_back` in the canary stage.
1. Console -> Campaigns -> <campaign> shows the halt reason and failing devices; or
   `GET ota/v1/campaigns/<id>` -> `halt_reason`.
2. Pull failing devices' `ota/status` errors: `GET ota/v1/campaigns/<id>/devices?state=failed`.
   Common: `signature_invalid` (wrong signing key in device bundle: check `fw_signing_pubkeys`
   rotation), `version_code_not_greater` (manifest built with stale `version_code`),
   `health_check_failed` (new firmware cannot connect: usually a pinned-CA or config change).
3. Decide: **resume** (`POST .../resume`, after confirming failures are device-specific), or
   **rollback campaign** (`POST ota/v1/campaigns/<id>/rollback` creates a child campaign targeting
   the same group with the previous firmware; devices that already applied the new image receive it
   as a normal update because the previous image gets a **new, higher** `version_code` built by the
   OTA service as a re-signed "rollback release" — anti-rollback forbids installing a lower code).
4. Communicate in the tenant status page; record in the campaign audit trail (automatic).

### 3.2 Bricked devices after OTA

Devices that fail the 120 s health check revert automatically to slot A. If a device does not come
back at all:
* ESP32: the bootloader rollback requires the previous image to still be valid; if flash encryption
  keys were changed by the update (never do this via OTA) only physical recovery works.
* Linux: `ironmesh-agent --boot-status` on the device shows `boot_count` and `pending_slot`; the
  systemd unit `ironmesh-agent.service` has `OnFailure=ironmesh-rollback.service`.

### 3.3 Emergency security update

Create the campaign with `severity: security` and `stages: [{percent: 5, dwell: 10m}, {percent: 100}]`;
the console requires a second operator's approval (four-eyes) for dwell times under 1 h.

## 4. Broker and auth

### 4.1 `AuthFailureBurst`

1. `ironmesh_auth_failures_total` by `reason`: `revoked` (expected after mass revocation),
   `clientid_mismatch` (misconfigured or malicious client), `lifecycle` (devices in
   `manufactured` state trying to connect before enrollment), `registry_unreachable` (fail-closed).
2. Source IPs from `im.auth` topic; if a single IP: block at the NLB security group / WAF rate rule.
3. If `registry_unreachable`: policy fails closed and all new connections are refused; existing
   sessions continue. Scale/repair the registry; do **not** set `POLICY_REGISTRY_FAIL_OPEN=true`
   without the security lead's approval (it is logged at ERROR on every decision).

### 4.2 Broker capacity / `ConnectedDevicesDrop`

1. `GET emqx:18083/api/v5/stats` for `connections.count`, `sessions.count`, dropped messages.
2. Reconnect storms after a broker restart are expected to settle within `backoff cap` (300 s);
   watch `ironmesh_connected_devices` recovering. If not: check the policy service latency
   (`ironmesh_authz_decision_seconds` p99 should be < 5 ms with cache); EMQX's authn HTTP timeout is 5 s.
3. Scale EMQX (`kubectl scale sts/emqx --replicas=5`); sessions are persistent (7 d), so devices
   resume without re-subscribing.

## 5. Tenant isolation suspicion (SEV1)

1. Collect: which API call or topic returned data for another tenant; request id from the console.
2. Check RLS is active: `SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname IN ('devices','twins','commands','audit_events');` must be `true,true`.
3. Check the DB role: services must connect as `registry_app` (non-owner). `SELECT current_user;` in
   service logs at startup; a connection as the owner role bypasses RLS and is a deployment defect.
4. Check the policy service: `opa test services/policy/policy/rego` and the cross-tenant test
   cases; re-run the conformance ACL tests against production broker with a test tenant.
5. If confirmed: rotate all tenant command-signing keys and OIDC client secrets, notify affected
   tenants within the contractual window (default 72 h), file the incident.

## 6. Backup and restore

See `docs/ops/BACKUP_RESTORE.md`. Summary:
* Postgres: automated snapshots (RDS, 35 d) + nightly logical dumps to S3 (SSE-KMS);
  `scripts/backup/pg_restore_test.sh` restores the latest dump into a scratch DB nightly in CI.
* PKI: private keys never leave KMS/HSM; the root wrapping key is Shamir-split (3 of 5) into
  shares held by named officers; intermediates are re-creatable from the root. The `pki` database
  (issuance and revocation records) is backed up with Postgres; losing it loses CRL completeness,
  so after a restore run `pkictl crl --rebuild` and set `PKI_FAIL_UNKNOWN_SERIALS=true` so OCSP
  answers `unknown` for serials not in the restored DB (policy treats `unknown` as deny).
* Firmware artifacts: S3 versioning + Object Lock + cross-region replication; the OTA DB stores the
  SHA-256 of every artifact and `firmware_backup.sh` verifies replicas.

### 6.1 Restore procedure (registry)
1. `kubectl scale deploy/registry --replicas=0`.
2. `scripts/backup/pg_restore.sh --db registry --from s3://<bucket>/registry/<date>.dump.enc`.
3. Run migrations check: `alembic -c services/registry/alembic.ini current` must equal `head`.
4. `kubectl scale deploy/registry --replicas=3`; verify `/readyz` and a device detail page.
5. Devices that sent telemetry during the outage replayed from their offline buffers; `seq` gaps
   are logged, not rejected.

## 7. On-call checklist (daily)

* Grafana `SLO` dashboard green; no `CertExpiryBacklog`.
* `pg_restore_test` CI job green last night.
* No campaigns in `halted` state older than 24 h.
* `anomaly` model retrain job succeeded (`ironmesh_anomaly_model_age_seconds` < 86400).
* Dependabot/Trivy: no open HIGH/CRITICAL older than the SLA in `SECURITY.md`.
