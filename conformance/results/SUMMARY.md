# IronMesh conformance summary

Generated 2026-11-09T23:06:08.9817664Z from `git rev-parse HEAD` = `12c456ca9357771a67989557787bdab201342b2a`.

| Target | Run started | Commit | Mode | Passed | Failed | N/A | Errors |
|---|---|---|---|---|---|---|---|
| `agent-rs` | 2026-11-09T22:53:12.5177074Z | `12c456ca9357` | hermetic | 28 | 0 | 0 | 0 |
| `esp32-host` | 2026-11-09T22:55:09.1845245Z | `12c456ca9357` | hermetic | 27 | 0 | 1 | 0 |

## Matrix

| Case | Title | `agent-rs` | `esp32-host` |
|---|---|---|---|
| C-TLS-1 | mTLS handshake with valid operational cert | pass (tls_version: TLSv1.3, alpn mqtt) | pass (tls_version: TLSv1.3, alpn mqtt) |
| C-TLS-2 | Broker presents cert from an unpinned CA (rogue broker) | pass | pass |
| C-TLS-3 | Broker offers TLS 1.2 only | pass | pass |
| C-TLS-4 | Session resumption on reconnect | pass (broker_observed_resumed: true) | pass (broker_observed_resumed: true) |
| C-TLS-5 | Bounded reconnect backoff | pass (attempts_observed: 13, max gap 4.619 s) | pass (attempts_observed: 5, max gap 15.981 s) |
| C-ENR-1 | Zero-touch enrollment with attestation | pass | pass |
| C-ENR-2 | Enrollment refused for quarantined device | pass (http_status: 403) | pass (http_status: 403) |
| C-ROT-1 | Certificate rotation (`renew`) keeps identity, changes key and serial | pass | pass |
| C-ROT-2 | Automatic rotation at 50 % lifetime (short-lived test certs) | pass (renewed_at_fraction_of_lifetime: 0.574) | pass (renewed_at_fraction_of_lifetime: 0.600) |
| C-REV-1 | Revocation reaction time | pass (denied p50 0.015 s, p95 0.018 s, max 0.026 s) | pass (denied p50 0.538 s, p95 0.999 s, max 0.999 s) |
| C-REV-2 | Single-certificate revocation refuses the serial, renewed certificate admitted | pass (superseded serial refused, renewed admitted; own serial refused in 0.004 s) | pass (superseded serial refused, renewed admitted; own serial refused in 0.944 s) |
| C-ACL-1 | Publish to another device's topic | pass | pass |
| C-ACL-2 | Subscribe to another device's command topic or wildcard | pass | pass |
| C-ACL-3 | Retained publish on telemetry | pass | pass |
| C-OTA-1 | Unsigned image | pass (rejected (unsigned)) | pass (rejected (unsigned)) |
| C-OTA-2 | Tampered image (1 byte flipped, valid manifest) | pass (rejected (image_hash)) | pass (rejected (image_hash)) |
| C-OTA-3 | Manifest signed by an untrusted key | pass (rejected (untrusted_key)) | pass (rejected (untrusted_key)) |
| C-OTA-4 | Downgrade (`version_code` not greater) | pass (rejected (downgrade)) | pass (rejected (downgrade)) |
| C-OTA-5 | Valid update applies and is marked healthy | pass (new_version_code: 101) | pass (new_version_code: 10001) |
| C-OTA-6 | Update that fails its health check rolls back | pass (seconds_apply_to_rollback: 15.0) | pass (seconds_apply_to_rollback: 120.0) |
| C-OTA-7 | Delta update | pass (patch 16650 B / image 53361 B) | pass (patch 16670 B / image 69745 B) |
| C-RPL-1 | Replayed command (same `seq`) | pass (rejection_code: ENV_REPLAY) | pass (rejection_code: ENV_REPLAY) |
| C-RPL-2 | Command with stale timestamp | pass (rejection_code: ENV_TS_SKEW) | pass (rejection_code: ENV_TS_SKEW) |
| C-RPL-3 | Command signed by a non-tenant key | pass (rejection_code: COSE_SIGNATURE) | pass (rejection_code: COSE_SIGNATURE) |
| C-RPL-4 | Device `seq` strictly increases across reboot | pass (seq_out 5 -> 6) | pass (seq_out 5 -> 18) |
| C-OFF-1 | Offline buffering and resync | pass | pass |
| C-CFG-1 | Encrypted config delivery | pass | pass |
| C-HOOK-1 | Release build has no control channel | pass (exit_code: 2) | n/a |

## Revocation reaction time (C-REV-1, budget < 10 s)

| Target | revoke -> broker disconnect | revoke -> reconnect denied (end to end) | revoke -> kick call |
|---|---|---|---|
| `agent-rs` | n=20 p50 0.002 s, p95 0.004 s, max 0.011 s | n=20 p50 0.015 s, p95 0.018 s, max 0.026 s | n=20 p50 0.002 s, p95 0.004 s, max 0.011 s |
| `esp32-host` | n=20 p50 0.003 s, p95 0.015 s, max 0.015 s | n=20 p50 0.538 s, p95 0.999 s, max 0.999 s | n=20 p50 0.003 s, p95 0.015 s, max 0.015 s |
| `agent-rs` (real PKI) | n=20 p50 0.004 s, p95 0.013 s, max 0.014 s | n=20 p50 0.008 s, p95 0.018 s, max 0.018 s | n=20 p50 0.004 s, p95 0.013 s, max 0.014 s |
| `esp32-host` (real PKI) | n=20 p50 0.004 s, p95 0.016 s, max 0.016 s | n=20 p50 0.401 s, p95 0.898 s, max 0.921 s | n=20 p50 0.004 s, p95 0.016 s, max 0.016 s |

### Single-certificate revocation (C-REV-2)

| Target | Verdict | CONNECT presenting the superseded serial | renewed certificate | revoke current serial -> own reconnect refused | device-level denials |
|---|---|---|---|---|---|
| `agent-rs` | pass | deny, reason revoked_serial | allow | 0.004 s | +0 |
| `esp32-host` | pass | deny, reason revoked_serial | allow | 0.944 s | +0 |
| `agent-rs` (real PKI) | pass | deny, reason revoked_serial | allow | 0.017 s | +0 |
| `esp32-host` (real PKI) | pass | deny, reason revoked_serial | allow | 0.824 s | +0 |

## OTA rejection evidence

| Target | Case | Verdict | Final state (error) | ota_state sequence |
|---|---|---|---|---|
| `agent-rs` | C-OTA-1 | pass | rejected (unsigned) | ["received", "rejected(unsigned)"] |
| `agent-rs` | C-OTA-2 | pass | rejected (image_hash) | ["received", "downloading", "downloading", "verifying", "rejected(image_hash)"] |
| `agent-rs` | C-OTA-3 | pass | rejected (untrusted_key) | ["received", "rejected(untrusted_key)"] |
| `agent-rs` | C-OTA-4 | pass | rejected (downgrade) | ["received", "rejected(downgrade)"] |
| `agent-rs` | C-OTA-5 | pass | new_version_code: 101 | ["received", "downloading", "downloading", "verifying", "applying", "rebooting", "success"] |
| `agent-rs` | C-OTA-6 | pass | seconds_apply_to_rollback: 15.0 | ["received", "downloading", "downloading", "verifying", "applying", "rebooting", "rolled_back(health_check)"] |
| `agent-rs` | C-OTA-7 | pass | patch 16650 B / image 53361 B | ["received", "downloading", "downloading", "verifying", "applying", "rebooting", "success"] |
| `esp32-host` | C-OTA-1 | pass | rejected (unsigned) | ["received", "rejected(unsigned)"] |
| `esp32-host` | C-OTA-2 | pass | rejected (image_hash) | ["received", "downloading", "downloading", "downloading", "downloading", "downloading", "downloading", "downloading", "downloading", "downloading", "downloading", "downloading", "verifying", "rejected(image_hash)"] |
| `esp32-host` | C-OTA-3 | pass | rejected (untrusted_key) | ["received", "rejected(untrusted_key)"] |
| `esp32-host` | C-OTA-4 | pass | rejected (downgrade) | ["received", "rejected(downgrade)"] |
| `esp32-host` | C-OTA-5 | pass | new_version_code: 10001 | ["received", "downloading", "downloading", "downloading", "downloading", "downloading", "downloading", "downloading", "downloading", "downloading", "downloading", "downloading", "verifying", "applying", "rebooting", "success"] |
| `esp32-host` | C-OTA-6 | pass | seconds_apply_to_rollback: 120.0 | ["received", "downloading", "downloading", "downloading", "downloading", "downloading", "downloading", "downloading", "downloading", "downloading", "downloading", "downloading", "verifying", "applying", "rebooting", "rolled_back(health_check)"] |
| `esp32-host` | C-OTA-7 | pass | patch 16670 B / image 69745 B | ["received", "downloading", "downloading", "downloading", "downloading", "downloading", "downloading", "downloading", "downloading", "downloading", "downloading", "downloading", "verifying", "applying", "rebooting", "success"] |

## Not applicable (with reasons)

- `esp32-host` C-HOOK-1: C-HOOK-1 is defined for the agent-rs release binary. On ESP32 the channel is excluded at build time: the prod profile forces CONFIG_IRONMESH_DUT_CONTROL=n (checked by device/esp32/tools/check_prod_config.py in CI); the esp32-host shim and the hil profile are test builds by definition

## Real PKI interoperability probe (`--pki-bin`)

The same suite with the real `services/pki` binary (key ceremony by the real `pkictl`, in-memory store, file KMS) as the enrollment authority instead of the in-process EST server; everything else as above. Before any device enrolls, the harness provisions the tenant policy through the PKI tenant-policy API exactly as the owning services do - `PUT /v1/tenants/{t}/command-key` and `/enrollment` as `svc-registry`, `PUT /v1/tenants/{t}/firmware-keys` as `svc-ota` (Services CA client certificates from the `pkictl` ceremony plus a fresh single-use ES256 JWT per request) - so the PKI's trust bundles carry the tenant command key and firmware key and the downlink / OTA cases apply. `PKI_SUPERSEDE_GRACE` is 5 s, so C-REV-2 observes the PKI's own supersede-on-renewal revocation. C-ROT-2 stays not applicable (`PKI_OPERATIONAL_CERT_TTL` is bounded to 168h-720h).

| Target | Run started | Passed | Failed | N/A | Errors |
|---|---|---|---|---|---|
| `agent-rs` | 2026-11-09T22:59:46.6495246Z | 27 | 0 | 1 | 0 |
| `esp32-host` | 2026-11-09T23:02:04.3342141Z | 26 | 0 | 2 | 0 |

| Case | `agent-rs` | `esp32-host` |
|---|---|---|
| C-TLS-1 | pass | pass |
| C-TLS-2 | pass | pass |
| C-TLS-3 | pass | pass |
| C-TLS-4 | pass | pass |
| C-TLS-5 | pass | pass |
| C-ENR-1 | pass | pass |
| C-ENR-2 | pass | pass |
| C-ROT-1 | pass | pass |
| C-ROT-2 | n/a | n/a |
| C-REV-1 | pass | pass |
| C-REV-2 | pass | pass |
| C-ACL-1 | pass | pass |
| C-ACL-2 | pass | pass |
| C-ACL-3 | pass | pass |
| C-OTA-1 | pass | pass |
| C-OTA-2 | pass | pass |
| C-OTA-3 | pass | pass |
| C-OTA-4 | pass | pass |
| C-OTA-5 | pass | pass |
| C-OTA-6 | pass | pass |
| C-OTA-7 | pass | pass |
| C-RPL-1 | pass | pass |
| C-RPL-2 | pass | pass |
| C-RPL-3 | pass | pass |
| C-RPL-4 | pass | pass |
| C-OFF-1 | pass | pass |
| C-CFG-1 | pass | pass |
| C-HOOK-1 | pass | n/a |

## Warnings (contract deviations outside the pass criteria)

- `agent-rs` C-ENR-1: a fresh, never-enrolled device reports status.state="offline" (DUT_PROTOCOL: unprovisioned = no usable certificate)
- `agent-rs` C-REV-2: policy GET /v1/revocations reports kicked=true (with kicked_at) for the superseded serial although no kick was sent: the cache records KickSkipped (internal/revocation/cache.go markKicked) but internal/mgmt/api.go revocationItem does not expose it
- `esp32-host` C-TLS-5: no clock scaling on this target: bound and jitter verified for 5 attempts (up to 16 s); the 300 s cap was not reached
- `esp32-host` C-REV-2: policy GET /v1/revocations reports kicked=true (with kicked_at) for the superseded serial although no kick was sent: the cache records KickSkipped (internal/revocation/cache.go markKicked) but internal/mgmt/api.go revocationItem does not expose it
- `esp32-host` C-OTA-6: no signed OtaStatus{state=6 rolled_back} reached the broker after reconnecting
