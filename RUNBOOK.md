# IronMesh Operations Runbook

Operational procedures for on-call engineers. Every procedure lists detection, immediate actions,
containment, recovery, and post-incident steps. Commands assume `kubectl` context set to the
production cluster and the `ironmesh` namespace, or `docker compose` in the local stack.

Severity levels: **SEV1** fleet-wide impact or active compromise; **SEV2** tenant-wide impact;
**SEV3** single device or degraded capability.

## 0. Quick reference

| Symptom / alert                         | Go to |
|-----------------------------------------|-------|
| `RevocationLatencyHigh`, `RevocationPublishFailures`, `ironmesh_revocation_outbox_pending` > 0 | §1.3 |
| CA key suspected compromised            | §1.1  |
| Operational cert expiry backlog         | §1.4  |
| Device behaving maliciously / anomaly   | §2    |
| OTA campaign halted                     | §3    |
| `AuthFailureBurst`                      | §4.1  |
| Broker overloaded / `ConnectedDevicesDrop` | §4.2 |
| `BrokerMessagesDropped`, `BrokerClientQuotaExceeded` | §4.3 |
| Released device still refused at CONNECT | §2.1  |
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

1. Console -> Device -> Quarantine (step-up re-authentication required), or
   `POST registry/v1/devices/<id>/quarantine`. The registry calls the PKI `revoke-all`, which writes
   one `device_deny` event per valid serial to the revocation outbox and delivers it to every
   policy replica; policy deny-lists the device id and the serials and kicks the session. Calling
   `POST pki:8443/v1/devices/<device_id>/revoke-all` directly (Services CA certificate and a fresh
   single-use service JWT, `aud=pki`) revokes without the lifecycle change, so re-enrollment would
   still be allowed: prefer the quarantine.
2. Verify: `ironmesh_revocation_outbox_pending` (PKI) returns to 0, `ironmesh_revocation_latency_seconds`
   for the event is < 10 s, and the device is disconnected in EMQX
   (`GET emqx:18083/api/v5/clients/<device_id>` -> 404). A reconnect attempt shows up as
   `ironmesh_auth_failures_total{reason="revoked"}` (device id) or `{reason="revoked_serial"}`.
3. Only one certificate leaked and the device must keep working (rare): revoke that serial with
   `POST pki:8443/v1/certificates/<serial>/revoke` instead. The event is serial-scoped: the authn hook
   refuses that serial at CONNECT and kicks the session only if it was admitted with that serial;
   the device re-enrolls with its bootstrap certificate.

### 1.3 `RevocationLatencyHigh` / `RevocationPublishFailures` (SEV2)

<a id="revocationlatencyhigh"></a><a id="revocationpublishfailures"></a>

Every revocation and every `device_release` is written to the PKI's durable `revocation_outbox` in
the same transaction as the change itself. The PKI makes one delivery attempt inline; the outbox
dispatcher retries the rest (backoff from 500 ms, capped at 30 s) until **every** policy replica
behind `PKI_POLICY_URL` (the `policy-headless` Service, `PKI_POLICY_FANOUT=dns`) has answered 2xx.
Policy deduplicates by `event_id`, so redelivery is safe. Independently, the policy authn hook
checks the certificate serial at every CONNECT and polls the CRL every 5 s, so a lost push delays
the kick of a live session but not the refusal of the next CONNECT.

1. Backlog: `ironmesh_revocation_outbox_pending` (PKI) above 0 for more than a minute means some
   replica has not acknowledged. `ironmesh_revocation_publish_endpoint_total{result="error"}` shows
   failing fan-out endpoints; logs:
   `kubectl -n ironmesh logs deploy/pki | jq 'select(.msg=="policy event delivery failed; will retry")'`
   (fields `error`, `retry_at`). Pending rows:
   `SELECT event_id, attempts, next_attempt_at, last_error FROM revocation_outbox WHERE delivered_at IS NULL ORDER BY created_at;`
   (as the schema owner; nothing ever deletes rows). Do not edit or delete rows to "unstick" them.
2. Typical causes: a policy pod not ready or crash-looping (the fan-out waits for every resolved
   address: fix or remove the pod, the dispatcher then completes), a token/HMAC mismatch between
   `PKI_POLICY_TOKEN`/`PKI_POLICY_HMAC_KEY` and the policy secret (every endpoint fails with 401),
   or NetworkPolicy between `pki` and `policy`.
3. Kick failures on the policy side: `kubectl -n ironmesh logs deploy/policy | jq 'select(.msg=="failed to kick revoked session; will retry")'`.
   Unkicked entries are requeued every 30 s; check the EMQX API key secret and that the
   `emqx` NetworkPolicy admits `policy` on 18083. `/readyz` only reports shutdown, not cache or EMQX
   health.
4. CRL fallback stale (`CrlStale`): check `pki:8444/crl/device-ca.crl` `Last-Modified` and
   `ironmesh_crl_poll_total{result}` on policy.
5. Manual kick while the backlog drains:
   `curl -u $EMQX_API_KEY:$EMQX_API_SECRET -X DELETE http://emqx:18083/api/v5/clients/<id>` from a
   pod that NetworkPolicy admits to 18083 (policy, registry or ota).

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

1. **Quarantine** (Console -> Device -> Quarantine with step-up re-authentication, or
   `POST registry/v1/devices/<id>/quarantine`). This sets state `quarantined` and writes an audit
   event in one transaction, then calls the PKI `revoke-all`: every valid certificate is revoked and
   a `device_deny` event per serial goes through the revocation outbox to every policy replica, which
   deny-lists the device id and the serials and kicks the session (§1.3). If the PKI is unreachable
   the registry kicks the session itself and retries `revoke-all` from its action outbox
   (`pki_revoke_all`). Verify: audit shows `device.lifecycle` (`active -> quarantined`), `ironmesh_revocation_outbox_pending`
   returns to 0, the device is gone from `GET emqx:18083/api/v5/clients/<id>`. If auto-quarantine is
   enabled for the tenant this already happened automatically; verify in the Audit log.
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

### 2.1 False-positive quarantine and release

1. Confirm with the device owner; check the alert explanation (`features`, `score`).
2. Release (admin, step-up): Console -> Device -> Release, or `POST registry/v1/devices/<id>/release`
   -> state `active`. The registry calls the PKI `POST /v1/devices/<id>/release`, which queues a
   `device_release` event in the revocation outbox and delivers it to every policy replica. Policy
   lifts the **device-level** deny for denies revoked at or before `released_at`; the serials revoked
   by the quarantine stay revoked (`revoked_serial`), so the device **must** re-enroll. It does so
   automatically with its bootstrap certificate within one backoff cycle (<= 6 h, usually < 5 min).
3. Verify: audit shows `device.pki_released`; policy logs
   `kubectl -n ironmesh logs deploy/policy | jq 'select(.msg=="device release applied")'` with
   `device_deny_lifted=true` on every replica; `ironmesh_revocation_events_total{kind="device_release"}`
   increments; the next CONNECT with the **new** certificate is allowed.
4. If the release answered `503` (`Retry-After: 30`): the quarantine's `revoke-all` was still queued;
   the device stays quarantined. Retry after the PKI recovers. If the PKI was unreachable at
   release time the device is `active` in the registry but still denied at CONNECT (`revoked`):
   the sweeper retries the `pki_release` action (audit `device.pki_release_failed`, later
   `action.pki_release.completed`); check §1.3 for the outbox. A new quarantine or a decommission
   cancels a queued release (`action.pki_release.cancelled`).
5. Tune: raise the rule threshold or add the device class to the rule's exclusion list, and keep
   auto-quarantine off for that tenant while the rule is re-baselined (7 days).

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

1. `ironmesh_auth_failures_total` by `reason`: `revoked` (device id deny-listed: quarantine,
   decommission, key compromise), `revoked_serial` (a revoked or superseded certificate; expected
   for an hour-old renewal or after a quarantine), `no_cert_serial` (EMQX did not render
   `${cert_pem}` in the authn body: **every** CONNECT is denied; fix the EMQX authn body template,
   or set `POLICY_REQUIRE_CERT_SERIAL=false` only with the security lead's approval because serial
   revocation then stops applying), `untrusted_issuer` / `cert_serial_mismatch` (certificate not from
   the expected CA, or a forged serial), `clientid_mismatch` (misconfigured or malicious client),
   `lifecycle_*` (devices in `manufactured` state trying to connect before enrollment),
   `registry_unreachable` (fail-closed).
2. Source IPs from `im.auth` topic; if a single IP: block at the NLB security group / WAF rate rule.
3. If `registry_unreachable`: policy fails closed and all new connections are refused; existing
   sessions continue. Scale/repair the registry; do **not** set `POLICY_REGISTRY_FAIL_OPEN=true`
   without the security lead's approval (it is logged at ERROR on every decision).

### 4.2 Broker capacity / `ConnectedDevicesDrop`

1. `GET emqx:18083/api/v5/stats` for `connections.count`, `sessions.count`, dropped messages (18083
   is reachable only from policy, registry, ota and Prometheus pods; from an operator workstation
   port-forward the EMQX management Service, e.g. `kubectl -n ironmesh port-forward svc/emqx-api 18083:18083`
   in the Kubernetes base).
2. Reconnect storms after a broker restart are expected to settle within `backoff cap` (300 s);
   watch `ironmesh_connected_devices` recovering. If not: check the policy service latency
   (`ironmesh_authz_decision_seconds` p99 should be < 5 ms with cache); EMQX's authn HTTP timeout is 5 s.
3. Scale EMQX (`kubectl scale sts/emqx --replicas=5`); sessions are persistent (7 d), so devices
   resume without re-subscribing.

### 4.3 `BrokerMessagesDropped` and `BrokerClientQuotaExceeded` (SEV3, SEV2 if widespread)

<a id="brokermessagesdropped"></a><a id="brokerclientquotaexceeded"></a>

`BrokerMessagesDropped` fires on any sustained EMQX drop (expired, no subscribers, quota).
`BrokerClientQuotaExceeded` (THREAT_MODEL T-40) fires when
`emqx_messages_dropped_quota_exceeded` + `emqx_messages_dropped_receive_maximum` stays above 1/s
for 10 minutes: clients exceed their session quota (`mqtt.max_inflight` 32, `max_awaiting_rel`) or
their receive maximum. The device listener also limits each client to `messages_rate` 10/s and
`bytes_rate` 64KB/s by pausing its socket; EMQX exports no counter for those pauses, so a flood
shows up here only once it overflows the session quota (watch `emqx_messages_received` too).
1. Find the clients: `GET emqx:18083/api/v5/clients?_limit=1000` from a pod admitted to 18083 (or
   `emqx ctl clients list` in an EMQX pod) and sort by `recv_msg` / `recv_oct` with `jq`; map client
   ids (device ids) to tenants with `GET registry/v1/devices/<id>`.
2. A handful of devices: treat as compromised or broken firmware. Quarantine them (§2); check
   `fw_hash` against the catalogue and the anomaly `beaconing` alerts.
3. Many devices of one product after an OTA: likely a firmware regression (publish loop). Halt the
   campaign (§3.1) before quarantining at scale.
4. Bridge-side drops (`no subscribers`, receive maximum on `svc-bridge`): check that the bridge is
   connected on the internal listener 8884 and that `BRIDGE_MAX_INFLIGHT` matches the broker's
   receive maximum; scale the bridge rather than raising device quotas.
5. Do not raise `messages_rate` / `bytes_rate` to silence the alert; they are the per-client flood
   control (T-40). Change them only per listener in the Helm values, with the security lead.

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
