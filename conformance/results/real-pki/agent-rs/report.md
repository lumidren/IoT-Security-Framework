# IronMesh conformance report: `agent-rs`

| | |
|---|---|
| Run started | 2026-11-09T22:59:46.6495246Z |
| Duration | 107 s |
| Git commit | `12c456ca9357771a67989557787bdab201342b2a (working tree modified)` |
| Cloud mode | hermetic + real PKI |
| Host | MUSTAFAGOMAA (windows x86_64) |
| tenant_id | de0864f4-9d14-4eca-b176-01b1367b1fd5 |
| run_dir | C:\Users\mgoma\Desktop\Security Assignments\IoT-Security-Framework\conformance\target\runs\agent-rs-1794265186 |
| policy_service | C:\Users\mgoma\Desktop\Security Assignments\IoT-Security-Framework\conformance\target\bin\policy.exe (sha256 6408a8a7a0cc94c2) |
| signing_keys | test-vector keys from C:\Users\mgoma\Desktop\Security Assignments\IoT-Security-Framework\libs\python\ironmesh-wire\tests\keys |
| policy_wiring | authn bodies carry cert_pem + cert_serial (emqx.conf template); POLICY_REQUIRE_CERT_SERIAL=true, POLICY_DEVICE_CA_FILE / POLICY_SERVICES_CA_FILE set, POLICY_JWT_PUBLIC_KEY_PEM + POLICY_JWT_SINGLE_USE=true; svc-registry authenticated with a Services CA client certificate |
| policy_mgmt_jwt_single_use | GET /v1/revocations with one token twice -> 200 then 401 (want 200 then 401) |
| pki_tenant_policy | provisioned via the PKI tenant-policy API: {"allow_software_keys":true,"command_key_b64":"TmfAMF93PueOwcIf+bYLXktO6/UtQnF5iOVbg07GLsE=","firmware_keys_b64":["n6tpyGkMUcANm4+/51p5BnVtuanVsgmopuBEWlW8lpU="],"updated_at":"2026-11-09T22:59:48.6790163Z"} |
| pki_mgmt_authorization | svc-ota PUT command-key -> 403 (want 403); one operator token used twice -> 200 then 401 (want 200 then 401) |
| pki_supersede_grace | 5 s |
| dut_binary | C:\Users\mgoma\Desktop\Security Assignments\IoT-Security-Framework\conformance\target\duts\agent-rs-dut\debug\ironmesh-agent.exe (sha256 db7a555e8769b9b2) |
| release_binary | C:\Users\mgoma\Desktop\Security Assignments\IoT-Security-Framework\conformance\target\duts\agent-rs-release\release\ironmesh-agent.exe (sha256 1e1930e803bcbf51) |
| pki_service | target/bin/pki.exe (sha256 3511a91248979d40): real PKI is the enrollment authority |
| product | gateway-rpi |
| reconnect_backoff_clock_scale | 0.02 |
| ota_health_timeout_s | 15 |

**Result: 27 passed, 0 failed, 1 not applicable, 0 errors** (of 28).

| Case | Title | Verdict | Measured | Time |
|---|---|---|---|---|
| C-TLS-1 | mTLS handshake with valid operational cert | pass | tls_version: TLSv1.3, alpn mqtt | 0.3 s |
| C-TLS-2 | Broker presents cert from an unpinned CA (rogue broker) | pass |  | 0.7 s |
| C-TLS-3 | Broker offers TLS 1.2 only | pass |  | 0.5 s |
| C-TLS-4 | Session resumption on reconnect | pass | broker_observed_resumed: true | 0.5 s |
| C-TLS-5 | Bounded reconnect backoff | pass | attempts_observed: 13, max gap 5.928 s | 19.0 s |
| C-ENR-1 | Zero-touch enrollment with attestation | pass |  | 0.3 s |
| C-ENR-2 | Enrollment refused for quarantined device | pass | http_status: 403 | 0.2 s |
| C-ROT-1 | Certificate rotation (`renew`) keeps identity, changes key and serial | pass |  | 0.4 s |
| C-ROT-2 | Automatic rotation at 50 % lifetime (short-lived test certs) | n/a |  | 0.3 s |
| C-REV-1 | Revocation reaction time | pass | denied p50 0.008 s, p95 0.018 s, max 0.018 s | 36.5 s |
| C-REV-2 | Single-certificate revocation refuses the serial, renewed certificate admitted | pass | superseded serial refused, renewed admitted; own serial refused in 0.017 s | 10.1 s |
| C-ACL-1 | Publish to another device's topic | pass |  | 1.7 s |
| C-ACL-2 | Subscribe to another device's command topic or wildcard | pass |  | 0.3 s |
| C-ACL-3 | Retained publish on telemetry | pass |  | 1.1 s |
| C-OTA-1 | Unsigned image | pass | rejected (unsigned) | 1.4 s |
| C-OTA-2 | Tampered image (1 byte flipped, valid manifest) | pass | rejected (image_hash) | 1.4 s |
| C-OTA-3 | Manifest signed by an untrusted key | pass | rejected (untrusted_key) | 1.3 s |
| C-OTA-4 | Downgrade (`version_code` not greater) | pass | rejected (downgrade) | 1.4 s |
| C-OTA-5 | Valid update applies and is marked healthy | pass | new_version_code: 101 | 0.5 s |
| C-OTA-6 | Update that fails its health check rolls back | pass | seconds_apply_to_rollback: 15.0 | 15.9 s |
| C-OTA-7 | Delta update | pass | patch 16650 B / image 53361 B | 0.4 s |
| C-RPL-1 | Replayed command (same `seq`) | pass | rejection_code: ENV_REPLAY | 2.3 s |
| C-RPL-2 | Command with stale timestamp | pass | rejection_code: ENV_TS_SKEW | 2.4 s |
| C-RPL-3 | Command signed by a non-tenant key | pass | rejection_code: COSE_SIGNATURE | 2.4 s |
| C-RPL-4 | Device `seq` strictly increases across reboot | pass | seq_out 5 -> 6 | 0.3 s |
| C-OFF-1 | Offline buffering and resync | pass |  | 1.4 s |
| C-CFG-1 | Encrypted config delivery | pass |  | 2.3 s |
| C-HOOK-1 | Release build has no control channel | pass | exit_code: 2 | 0.0 s |

## Revocation reaction time (C-REV-1)

Path: harness PKI revokes the certificate (CRL regenerated) and pushes the signed event to the **real** policy service (`POST /internal/v1/revocations`, bearer + `X-IronMesh-Signature` HMAC) -> policy deny-lists the device and calls the broker's EMQX management API `DELETE /api/v5/clients/{id}` -> session dropped -> the DUT's reconnect is refused by the real authn hook.

| Interval | Value |
|---|---|
| iterations | 20 |
| revoke -> policy 202 | p50 0.004 s, p95 0.013 s, max 0.015 s |
| revoke -> kick (EMQX API) | p50 0.004 s, p95 0.013 s, max 0.014 s |
| revoke -> broker disconnect | p50 0.004 s, p95 0.013 s, max 0.014 s |
| revoke -> DUT disconnected event | p50 0.005 s, p95 0.014 s, max 0.015 s |
| revoke -> reconnect denied (end to end) | p50 0.008 s, p95 0.018 s, max 0.018 s |

## OTA results

| Case | Verdict | Outcome | Evidence |
|---|---|---|---|
| C-OTA-1 | pass | rejected (unsigned) | ota_state sequence: ["received", "rejected(unsigned)"]; ota_slots before {"active_slot":"a","pending_slot":null,"slots":[{"name":"a","sha256_hex":"4cb2d74483ab36b04aff112fc132c1d86c5017c460e151f6ddce991541119e13","state":"valid","version":"1.0.0","version_code":100},{"name":"b","sha256_hex":"","state":"empty","version":"","version_code":0}]} after {"active_slot":"a","pending_slot":null,"slots":[{"name":"a","sha256_hex":"4cb2d74483ab36b04aff112fc132c1d86c5017c460e151f6ddce991541119e13","state":"valid","version":"1.0.0","version_code":100},{"name":"b","sha256_hex":"","state":"empty","version":"","version_code":0}]} |
| C-OTA-2 | pass | rejected (image_hash) | ota_state sequence: ["received", "downloading", "downloading", "verifying", "rejected(image_hash)"]; ota_slots before {"active_slot":"a","pending_slot":null,"slots":[{"name":"a","sha256_hex":"4cb2d74483ab36b04aff112fc132c1d86c5017c460e151f6ddce991541119e13","state":"valid","version":"1.0.0","version_code":100},{"name":"b","sha256_hex":"","state":"empty","version":"","version_code":0}]} after {"active_slot":"a","pending_slot":null,"slots":[{"name":"a","sha256_hex":"4cb2d74483ab36b04aff112fc132c1d86c5017c460e151f6ddce991541119e13","state":"valid","version":"1.0.0","version_code":100},{"name":"b","sha256_hex":"","state":"empty","version":"","version_code":0}]} |
| C-OTA-3 | pass | rejected (untrusted_key) | ota_state sequence: ["received", "rejected(untrusted_key)"]; ota_slots before {"active_slot":"a","pending_slot":null,"slots":[{"name":"a","sha256_hex":"4cb2d74483ab36b04aff112fc132c1d86c5017c460e151f6ddce991541119e13","state":"valid","version":"1.0.0","version_code":100},{"name":"b","sha256_hex":"","state":"empty","version":"","version_code":0}]} after {"active_slot":"a","pending_slot":null,"slots":[{"name":"a","sha256_hex":"4cb2d74483ab36b04aff112fc132c1d86c5017c460e151f6ddce991541119e13","state":"valid","version":"1.0.0","version_code":100},{"name":"b","sha256_hex":"","state":"empty","version":"","version_code":0}]} |
| C-OTA-4 | pass | rejected (downgrade) | ota_state sequence: ["received", "rejected(downgrade)"]; ota_slots before {"active_slot":"a","pending_slot":null,"slots":[{"name":"a","sha256_hex":"4cb2d74483ab36b04aff112fc132c1d86c5017c460e151f6ddce991541119e13","state":"valid","version":"1.0.0","version_code":100},{"name":"b","sha256_hex":"","state":"empty","version":"","version_code":0}]} after {"active_slot":"a","pending_slot":null,"slots":[{"name":"a","sha256_hex":"4cb2d74483ab36b04aff112fc132c1d86c5017c460e151f6ddce991541119e13","state":"valid","version":"1.0.0","version_code":100},{"name":"b","sha256_hex":"","state":"empty","version":"","version_code":0}]} |
| C-OTA-5 | pass | new_version_code: 101 | ota_state sequence: ["received", "downloading", "downloading", "verifying", "applying", "rebooting", "success"]; ota_slots after: {"active_slot":"b","pending_slot":null,"slots":[{"name":"a","sha256_hex":"","state":"empty","version":"","version_code":0},{"name":"b","sha256_hex":"38a75ec340d75debddaf93f02cde6099b90d0dda7f073b9d249412a46a56a558","state":"valid","version":"1.1.0","version_code":101}]} |
| C-OTA-6 | pass | seconds_apply_to_rollback: 15.0 | ota_state sequence: ["received", "downloading", "downloading", "verifying", "applying", "rebooting", "rolled_back(health_check)"]; ota_slots before {"active_slot":"a","pending_slot":null,"slots":[{"name":"a","sha256_hex":"4cb2d74483ab36b04aff112fc132c1d86c5017c460e151f6ddce991541119e13","state":"valid","version":"1.0.0","version_code":100},{"name":"b","sha256_hex":"","state":"empty","version":"","version_code":0}]} after {"active_slot":"a","pending_slot":null,"slots":[{"name":"a","sha256_hex":"4cb2d74483ab36b04aff112fc132c1d86c5017c460e151f6ddce991541119e13","state":"valid","version":"1.0.0","version_code":100},{"name":"b","sha256_hex":"d707cc4e82429a8ad6fb618fd6094621f2f7752dbba674d826ece0426835f281","state":"inval... |
| C-OTA-7 | pass | patch 16650 B / image 53361 B | delta base: the factory image (hash verified against ota_slots); ota_state sequence: ["received", "downloading", "downloading", "verifying", "applying", "rebooting", "success"] |

## Case details

### C-TLS-1 mTLS handshake with valid operational cert - pass

*Criterion:* `connected` with `tls_version=TLSv1.3`, `alpn=mqtt`

| Measurement | Value |
|---|---|
| tls_version | TLSv1.3 |
| alpn | mqtt |

- DUT dev-c5ffc07e71ac5469 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 7275d2d8aed530bd71e6a1ffffef6808
- connected {"alpn":"mqtt","broker":"127.0.0.1:5395","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- broker handshake: version Some("TLSv1.3"), alpn Some("mqtt"), client cert serial Some("a4c64807fb6424ae4ec829d73b57daea")
- CONNECT: client id = CN, clean_start=false, session_expiry=Some(604800), keep_alive=60, receive_maximum=Some(32); policy authn allow=true

### C-TLS-2 Broker presents cert from an unpinned CA (rogue broker) - pass

*Criterion:* `connect_failed{reason=tls_pin_mismatch}`; no CONNECT packet observed

| Measurement | Value |
|---|---|
| RogueUnknownCa: connect_failed.reason | tls_pin_mismatch |
| RogueUnknownCa: CONNECT packets observed | 0 |
| Rogue: connect_failed.reason | tls_pin_mismatch |
| Rogue: CONNECT packets observed | 0 |

- DUT dev-cf04c5e22158d32f (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 841b614917a62b7e94ede3b89428e869
- broker mode RogueUnknownCa: connect_failed {"detail":"invalid peer certificate: Other(OtherError(PinMismatch))","reason":"tls_pin_mismatch"}
- broker-side handshakes in mode RogueUnknownCa: ["ok=false version=None error=Some(\"received fatal alert: CertificateUnknown\")"]
- broker mode Rogue: connect_failed {"detail":"invalid peer certificate: Other(OtherError(PinMismatch))","reason":"tls_pin_mismatch"}
- broker-side handshakes in mode Rogue: ["ok=false version=None error=Some(\"received fatal alert: CertificateUnknown\")"]

### C-TLS-3 Broker offers TLS 1.2 only - pass

*Criterion:* `connect_failed{reason=tls_handshake}`

| Measurement | Value |
|---|---|
| Tls12Only: connect_failed.reason | tls_handshake |
| Tls12Only: CONNECT packets observed | 0 |

- DUT dev-67f92f33cc83a558 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial b156f262d8d44d5d81243e9a4c3cde81
- broker mode Tls12Only: connect_failed {"detail":"received fatal alert: ProtocolVersion","reason":"tls_handshake"}
- broker-side handshakes in mode Tls12Only: ["ok=false version=None error=Some(\"peer is incompatible: Tls12NotOfferedOrEnabled\")"]

### C-TLS-4 Session resumption on reconnect - pass

*Criterion:* second `connected.resumed=true` (where the target supports tickets)

| Measurement | Value |
|---|---|
| dut_reported_resumed | true |
| broker_observed_resumed | true |
| session_present | true |

- DUT dev-7e168dc01ce52c24 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 260700133bb9a195e1ea02433f5f73da
- enrolled {"cert_serial_hex":"55046e6e9cfe26aa26573b63eae13f42","not_after":1795474790,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5395","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- second connected {"alpn":"mqtt","broker":"127.0.0.1:5395","resumed":true,"session_present":true,"tls_version":"TLSv1.3"}

### C-TLS-5 Bounded reconnect backoff - pass

*Criterion:* reconnect attempts follow base 1 s, factor 2, cap 300 s, full jitter (verified on attempt timestamps with clock scaling)

| Measurement | Value |
|---|---|
| clock_scale | 0.02 |
| attempts_observed | 13 |
| max_gap_s | 5.928 |
| capped_gaps_checked | 4 |

- DUT dev-e32557f1068372b5 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial da8cf7dcebdfffe0e0445cecea3d8700
- enrolled {"cert_serial_hex":"c7bba8f382097db552bc463675feedfa","not_after":1795474790,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5395","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- connect_failed reasons (first 3): ["not_authorized", "not_authorized", "not_authorized"]; status.state=backoff observed: true
- gap_k <= min(300, 2^k) x scale [s]: 0.002<=0.020, 0.006<=0.040, 0.027<=0.080, 0.088<=0.160, 0.100<=0.320, 0.167<=0.640, 0.537<=1.280, 0.195<=2.560, 0.242<=5.120, 2.690<=6.000, 5.928<=6.000, 4.859<=6.000, 3.761<=6.000

### C-ENR-1 Zero-touch enrollment with attestation - pass

*Criterion:* `enrolled`; harness verifies attestation, CSR CN, fresh key

| Measurement | Value |
|---|---|
| issued_serial | 0abb5da1361347c09b470b458c26eb80 |
| attestation_verified_by | services/pki EST handler (real PKI) |

- DUT dev-ef6aee04d2bc609d (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial c09686aa364cdec521f59a93eec05c2f
- enrolled {"cert_serial_hex":"0abb5da1361347c09b470b458c26eb80","not_after":1795474809,"se_type":"software"}
- issued by the real PKI: subject O=IronMesh, OU=assurance:software + OU=de0864f4-9d14-4eca-b176-01b1367b1fd5, CN=dev-ef6aee04d2bc609d, issuer O=IronMesh, CN=IronMesh Device CA, SAN ["urn:ironmesh:tenant:de0864f4-9d14-4eca-b176-01b1367b1fd5:device:dev-ef6aee04d2bc609d"]
- PKI record: {"assurance_level":"software","device_id":"dev-ef6aee04d2bc609d","issuer":"IronMesh Device CA","kind":"operational","not_after":"2026-11-23T23:00:09Z","not_before":"2026-11-09T23:00:09Z","serial":"0abb5da1361347c09b470b458c26eb80","status":"valid","tenant_id":"de0864f4-9d14-4eca-b176-01b1367b1fd5"}
- **warning:** a fresh, never-enrolled device reports status.state="offline" (DUT_PROTOCOL: unprovisioned = no usable certificate)

### C-ENR-2 Enrollment refused for quarantined device - pass

*Criterion:* `enroll_failed{http_status=403}`

| Measurement | Value |
|---|---|
| http_status | 403 |

- DUT dev-6ac99886981b782d (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 189adfec4b76ea4168348f93f63fbe44
- enroll_failed {"http_status":403,"reason":"device lifecycle state \"quarantined\" does not permit enrollment"}

### C-ROT-1 Certificate rotation (`renew`) keeps identity, changes key and serial - pass

*Criterion:* `cert_renewed`, new serial, new SPKI, reconnect succeeds

| Measurement | Value |
|---|---|
| old_serial | 734908437688172d0b043ec39a08a21a |
| new_serial | 27708178928b48b09842488bb9ad3108 |
| spki_changed | true |
| reconnected_automatically | true |

- DUT dev-0d5ebe87da974e61 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 97c66192945bb6206bd3ad4ca6b98541
- enrolled {"cert_serial_hex":"734908437688172d0b043ec39a08a21a","not_after":1795474810,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5395","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- cert_renewed {"new_serial_hex":"27708178928b48b09842488bb9ad3108","not_after":1795474810,"old_serial_hex":"734908437688172d0b043ec39a08a21a"}
- telemetry seq 3 verified with the renewed key (kid 27708178928b48b09842488bb9ad3108)

### C-ROT-2 Automatic rotation at 50 % lifetime (short-lived test certs) - n/a

*Criterion:* `cert_renewed` without an explicit `renew`

**Reason:** short-lived operational certificates (the real PKI bounds PKI_OPERATIONAL_CERT_TTL to 168h-720h) needs the in-process EST server (the real PKI handles EST in this run)

- DUT dev-c010f15fb7f71e3c (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial ed606fbaeba33c464ec0959ecf69a61b

### C-REV-1 Revocation reaction time - pass

*Criterion:* revoke -> broker disconnect -> DUT cannot reconnect with the revoked cert, measured < 10 s

| Measurement | Value |
|---|---|
| iterations | 20 |
| revoke -> policy 202 | p50 0.004 s, p95 0.013 s, max 0.015 s |
| revoke -> kick (EMQX API) | p50 0.004 s, p95 0.013 s, max 0.014 s |
| revoke -> broker disconnect | p50 0.004 s, p95 0.013 s, max 0.014 s |
| revoke -> DUT disconnected event | p50 0.005 s, p95 0.014 s, max 0.015 s |
| revoke -> reconnect denied (end to end) | p50 0.008 s, p95 0.018 s, max 0.018 s |

- DUT dev-0a384b0e4646809e (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial dff241b541c00e13e5449266ecbc4d8c
- enrolled {"cert_serial_hex":"59e760fa7c26c40710f82c1c9286e3fa","not_after":1795474811,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5395","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- revocation path: real PKI POST /v1/certificates/{serial}/revoke (reason keyCompromise, single-use ES256 JWT) -> outbox -> PKI publisher (device_deny=false) -> real policy -> EMQX API kick
- DUT disconnected {"reason":"broker DISCONNECT 0x98 ","reason_code":152} then connect_failed {"detail":"CONNACK reason 0x87 ","reason":"not_authorized"}
- reconnect with revoked serial Some("59e760fa7c26c40710f82c1c9286e3fa") answered CONNACK 0x87 by the policy authn hook
- DUT dev-40387afaa6e4d092 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial da54aff7c9623b8ad901f43e0026b0ef
- enrolled {"cert_serial_hex":"d1f24f4af2ecf69238396e7bdf9c4240","not_after":1795474812,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5395","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-123318620d197c46 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial fc1c62a05601ba4f5fb961e50413e4ac
- enrolled {"cert_serial_hex":"33f2e59973fc51724d725b693600202f","not_after":1795474814,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5395","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-2f12a87c2f08d97c (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 24df0961cefd727df7f426307227c1f0
- enrolled {"cert_serial_hex":"71f6d817318321ec9fe399a290695eac","not_after":1795474816,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5395","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-7530d9c9eba9dec8 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 6a00c7e732cd489e40f872b682100393
- enrolled {"cert_serial_hex":"23ae7e2658d16228d10a02fa37f47445","not_after":1795474818,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5395","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-68d33b4defd0128f (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 978df29a75a8477c49e28ed6af562120
- enrolled {"cert_serial_hex":"f62f19877d8e7d7af4ab3d6a2e7a5afc","not_after":1795474820,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5395","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-70b48a8822d9cbd4 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial c51d876842a4fa455310fb98c086effb
- enrolled {"cert_serial_hex":"d9c29cf92d2b2e90e8ae32f633c1d411","not_after":1795474822,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5395","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-bc7bf14cde3794fb (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 81e74edbf33ef2dcb4a7a4b67d70b7eb
- enrolled {"cert_serial_hex":"e22cec21355238fcfcdd6fbaa9e71882","not_after":1795474823,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5395","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-0134938760cc31f4 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial faf92963a6c41989600589955552b23b
- enrolled {"cert_serial_hex":"275ad6ba2e970af6a21b04f0001dd3c2","not_after":1795474825,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5395","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-178df99c7d257ce1 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 67614f0f97836982b95ef20f217989a2
- enrolled {"cert_serial_hex":"1327bf54232f909d36fade9763f12f5b","not_after":1795474827,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5395","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-4eabd818df6eebfb (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial eb63c761e46e10bdb115c7648e677e99
- enrolled {"cert_serial_hex":"4e8b57582c9751c49c05ea3d7c56c442","not_after":1795474829,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5395","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-1b5f78173be547da (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 48f881e2de44d9f5deac4743cc9e1e9c
- enrolled {"cert_serial_hex":"951365a9506c4197fff372ee4802404a","not_after":1795474831,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5395","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-d965e9c8db286656 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial a60c3bc968ce5f5d4bd12a0319209228
- enrolled {"cert_serial_hex":"8b0baec17865e5d3bdeeb9b01a469f54","not_after":1795474832,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5395","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-448dea7787206072 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 5cd4fe0ce042d8b78056c3f39ddeb896
- enrolled {"cert_serial_hex":"1c2350469846ce2d761d0241546d6ad6","not_after":1795474834,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5395","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-0cb3dc2a021b9664 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial ea02637f4981dc4714603c366c1dea2b
- enrolled {"cert_serial_hex":"d35c5bfb431ab48cba5214e37eaee224","not_after":1795474836,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5395","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-03f154cfe9dde45f (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 15e53a010d2b6116599cd7cd6f3ffad2
- enrolled {"cert_serial_hex":"2c4b94e85c8ef443f2d81bfa2e771ffa","not_after":1795474838,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5395","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-4fe443e9f360144a (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial b7fb54286aee93555d35be296e219a4e
- enrolled {"cert_serial_hex":"5ba897571f434c1e8fb9c400ffc4cb80","not_after":1795474840,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5395","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-a0bf896a7e8e7526 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 1a5a9706fbea49c2a4b39622bd8a0535
- enrolled {"cert_serial_hex":"6ae004a0b890deb57da9a6e497a2c3ce","not_after":1795474842,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5395","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-5f26fe4950a2ac6b (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial c3b0b70f9296ecb38664668b7d3505e6
- enrolled {"cert_serial_hex":"e1c04a5eda027d7ed9d650aa7da76b99","not_after":1795474843,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5395","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-4628648b03453e02 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial c7dcc6154dfb541b87c34b0f01b55c7f
- enrolled {"cert_serial_hex":"453e383f55f01f6e2fc9b324abd3ce96","not_after":1795474845,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5395","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- policy /metrics: ironmesh_kick_total{result=ok} +20, ironmesh_revocation_latency_seconds count 20 sum 0.057 s (mean 0.003 s, revoked_at -> kick)
- policy log: {"ts":"2026-11-10T01:00:45.7590512+02:00","level":"info","msg":"revoked session kicked","service":"policy","device_id":"dev-4628648b03453e02","tenant_id":"de0864f4-9d14-4eca-b176-01b1367b1fd5","event_id":"30c1926a-28b3-4fdb-a090-a4b7523ed2c

### C-REV-2 Single-certificate revocation refuses the serial, renewed certificate admitted - pass

*Criterion:* after a single-certificate revocation (`device_deny=false`) the revoked serial is refused at CONNECT (policy reason `revoked_serial`) while the renewed certificate is admitted and its session is not kicked; the device id is never deny-listed

| Measurement | Value |
|---|---|
| serial A (renewed away) | 465a4b3ed98cc23178ede60e31755002 |
| serial B (renewed) | 91b3e04e18c9022667b74e0d40b0009a |
| CONNECT presenting A (cert_pem + cert_serial) | deny, reason revoked_serial |
| CONNECT presenting B after A was revoked | allow |
| revoke B -> kick | 0.003 s |
| revoke B -> DUT reconnect presenting B refused | 0.017 s |
| ironmesh_auth_failures_total{reason=revoked_serial} | +8 |
| ironmesh_auth_failures_total{reason=revoked} (device-level) | +0 |

- DUT dev-edff35729f7ebcdc (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial f1d5a52c4b3fd2b019e8343b20105cf5
- enrolled {"cert_serial_hex":"465a4b3ed98cc23178ede60e31755002","not_after":1795474847,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5395","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- real PKI supersede-on-renewal (PKI_SUPERSEDE_GRACE 5 s): GET /v1/certificates/465a4b3ed98cc23178ede60e31755002 -> status "revoked", revocation {"reason":"superseded","revoked_at":"2026-11-09T23:00:52.6138655Z","revoked_by":"pki:supersede:91b3e04e18c9022667b74e0d40b0009a"}
- policy GET /v1/revocations (single-use service JWT) entry for A: {"applied_at":"2026-11-10T01:00:52.6144748+02:00","device_id":"dev-edff35729f7ebcdc","event_id":"472c33bb-e4b8-43ca-af32-7bb8d4a60a46","kicked":true,"kicked_at":"2026-11-10T01:00:52.6172194+02:00","reason":"superseded","revoked_at":"2026-11-09T23:00:52.6138655Z","serial_hex":"465a4b3ed98cc23178ede60...
- policy log: {"ts":"2026-11-10T01:00:52.6188421+02:00","level":"info","msg":"revoked certificate is not the live session's; kick skipped","service":"policy","device_id":"dev-edff35729f7ebcdc","tenant_id":"de0864f4-9d14-4eca-b176-01b1367b1fd5","event_id":"472c33bb-e4b8-43ca
- reconnect presenting B: authn allow, CONNACK 0x00, session_present true
- revocation of B: real PKI POST /v1/certificates/{serial}/revoke (reason affiliationChanged, single-use ES256 JWT) -> outbox -> PKI publisher (device_deny=false) -> real policy -> EMQX API kick
- policy GET /v1/revocations entry for B: {"applied_at":"2026-11-10T01:00:55.8052717+02:00","device_id":"dev-edff35729f7ebcdc","event_id":"a2de2ca7-f246-4977-af22-9786feb58311","kicked":true,"kicked_at":"2026-11-10T01:00:55.806381+02:00","reason":"affiliationChanged","revoked_at":"2026-11-09T23:00:55.8047144Z","serial_hex":"91b3e04e18c90226...
- policy log: {"ts":"2026-11-10T01:00:55.788441+02:00","level":"info","msg":"authn deny","service":"policy","client_id":"dev-edff35729f7ebcdc","username":"dev-edff35729f7ebcdc","peerhost":"127.0.0.1","cert_cn":"dev-edff35729f7ebcdc","kind":"device","reason":"revoked_serial"
- policy log: {"ts":"2026-11-10T01:00:55.8203646+02:00","level":"info","msg":"authn deny","service":"policy","client_id":"dev-edff35729f7ebcdc","username":"dev-edff35729f7ebcdc","peerhost":"127.0.0.1","cert_cn":"dev-edff35729f7ebcdc","kind":"device","reason":"revoked_serial
- **warning:** policy GET /v1/revocations reports kicked=true (with kicked_at) for the superseded serial although no kick was sent: the cache records KickSkipped (internal/revocation/cache.go markKicked) but internal/mgmt/api.go revocationItem does not expose it

### C-ACL-1 Publish to another device's topic - pass

*Criterion:* `publish_result.ok=false` (or disconnect) and harness subscriber receives nothing

| Measurement | Value |
|---|---|
| outcome im/v1/de0864f4-9d14-4eca-b176-01b1367b1fd5/dev-e617930fdb87a99b/telemetry | disconnected |
| outcome im/v1/de0864f4-9d14-4eca-b176-01b1367b1fd5/dev-e617930fdb87a99b/cmd/ack | disconnected |
| outcome im/v1/62338f7f-61f5-462c-826e-c5c7e1c3383d/dev-97bc1f51fbd175b7/telemetry | disconnected |
| outcome im/v1/de0864f4-9d14-4eca-b176-01b1367b1fd5/dev-97bc1f51fbd175b7/cmd/req | disconnected |

- DUT dev-97bc1f51fbd175b7 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial e5daeb31f54c216e250e7e6a654c26b6
- enrolled {"cert_serial_hex":"d7c8e8feb0696e81ebd65ddcad708275","not_after":1795474857,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5395","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- publish_raw im/v1/de0864f4-9d14-4eca-b176-01b1367b1fd5/dev-e617930fdb87a99b/telemetry retain=false: first event publish_result {"ok":false,"reason_code":128,"topic":"im/v1/de0864f4-9d14-4eca-b176-01b1367b1fd5/dev-e617930fdb87a99b/telemetry"}; publish_result {"ok":false,"reason_code":128,"topic":"im/v1/de0864f4-9d14-4eca-b176-01b1367b1fd5/dev-e617930fdb87a99b/telemetry"}; policy authz allowed=false
- publish_raw im/v1/de0864f4-9d14-4eca-b176-01b1367b1fd5/dev-e617930fdb87a99b/cmd/ack retain=false: first event publish_result {"ok":false,"reason_code":128,"topic":"im/v1/de0864f4-9d14-4eca-b176-01b1367b1fd5/dev-e617930fdb87a99b/cmd/ack"}; publish_result {"ok":false,"reason_code":128,"topic":"im/v1/de0864f4-9d14-4eca-b176-01b1367b1fd5/dev-e617930fdb87a99b/cmd/ack"}; policy authz allowed=false
- publish_raw im/v1/62338f7f-61f5-462c-826e-c5c7e1c3383d/dev-97bc1f51fbd175b7/telemetry retain=false: first event publish_result {"ok":false,"reason_code":128,"topic":"im/v1/62338f7f-61f5-462c-826e-c5c7e1c3383d/dev-97bc1f51fbd175b7/telemetry"}; publish_result {"ok":false,"reason_code":128,"topic":"im/v1/62338f7f-61f5-462c-826e-c5c7e1c3383d/dev-97bc1f51fbd175b7/telemetry"}; policy authz allowed=false
- publish_raw im/v1/de0864f4-9d14-4eca-b176-01b1367b1fd5/dev-97bc1f51fbd175b7/cmd/req retain=false: first event publish_result {"ok":false,"reason_code":128,"topic":"im/v1/de0864f4-9d14-4eca-b176-01b1367b1fd5/dev-97bc1f51fbd175b7/cmd/req"}; publish_result {"ok":false,"reason_code":128,"topic":"im/v1/de0864f4-9d14-4eca-b176-01b1367b1fd5/dev-97bc1f51fbd175b7/cmd/req"}; policy authz allowed=false

### C-ACL-2 Subscribe to another device's command topic or wildcard - pass

*Criterion:* `subscribe_result.granted=false`

| Measurement | Value |
|---|---|
| reason_code im/v1/de0864f4-9d14-4eca-b176-01b1367b1fd5/dev-3048f9c5ca4f4007/cmd/req | 135 |
| reason_code im/v1/de0864f4-9d14-4eca-b176-01b1367b1fd5/dev-3048f9c5ca4f4007/config | 135 |
| reason_code im/v1/de0864f4-9d14-4eca-b176-01b1367b1fd5/# | 135 |
| reason_code im/v1/de0864f4-9d14-4eca-b176-01b1367b1fd5/+/cmd/req | 135 |
| reason_code im/v1/de0864f4-9d14-4eca-b176-01b1367b1fd5/dev-a7dcd0a70cb0c0ef/# | 135 |
| reason_code # | 135 |
| reason_code $SYS/# | 135 |
| reason_code $share/bridge/im/v1/# | 135 |
| reason_code im/v1/de0864f4-9d14-4eca-b176-01b1367b1fd5/dev-a7dcd0a70cb0c0ef/telemetry | 135 |

- DUT dev-a7dcd0a70cb0c0ef (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial c385a952368b2de8a24e65a2ca1564a3
- enrolled {"cert_serial_hex":"3e0271c7e16bd92fb40b317188707ed2","not_after":1795474859,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5395","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- subscribe_raw im/v1/de0864f4-9d14-4eca-b176-01b1367b1fd5/dev-3048f9c5ca4f4007/cmd/req: subscribe_result {"granted":false,"reason_code":135,"topic":"im/v1/de0864f4-9d14-4eca-b176-01b1367b1fd5/dev-3048f9c5ca4f4007/cmd/req"}
- subscribe_raw im/v1/de0864f4-9d14-4eca-b176-01b1367b1fd5/dev-3048f9c5ca4f4007/config: subscribe_result {"granted":false,"reason_code":135,"topic":"im/v1/de0864f4-9d14-4eca-b176-01b1367b1fd5/dev-3048f9c5ca4f4007/config"}
- subscribe_raw im/v1/de0864f4-9d14-4eca-b176-01b1367b1fd5/#: subscribe_result {"granted":false,"reason_code":135,"topic":"im/v1/de0864f4-9d14-4eca-b176-01b1367b1fd5/#"}
- subscribe_raw im/v1/de0864f4-9d14-4eca-b176-01b1367b1fd5/+/cmd/req: subscribe_result {"granted":false,"reason_code":135,"topic":"im/v1/de0864f4-9d14-4eca-b176-01b1367b1fd5/+/cmd/req"}
- subscribe_raw im/v1/de0864f4-9d14-4eca-b176-01b1367b1fd5/dev-a7dcd0a70cb0c0ef/#: subscribe_result {"granted":false,"reason_code":135,"topic":"im/v1/de0864f4-9d14-4eca-b176-01b1367b1fd5/dev-a7dcd0a70cb0c0ef/#"}
- subscribe_raw #: subscribe_result {"granted":false,"reason_code":135,"topic":"#"}
- subscribe_raw $SYS/#: subscribe_result {"granted":false,"reason_code":135,"topic":"$SYS/#"}
- subscribe_raw $share/bridge/im/v1/#: subscribe_result {"granted":false,"reason_code":135,"topic":"$share/bridge/im/v1/#"}
- subscribe_raw im/v1/de0864f4-9d14-4eca-b176-01b1367b1fd5/dev-a7dcd0a70cb0c0ef/telemetry: subscribe_result {"granted":false,"reason_code":135,"topic":"im/v1/de0864f4-9d14-4eca-b176-01b1367b1fd5/dev-a7dcd0a70cb0c0ef/telemetry"}

### C-ACL-3 Retained publish on telemetry - pass

*Criterion:* rejected

| Measurement | Value |
|---|---|
| outcome | disconnected |
| outcome events (retained) | disconnected |

- DUT dev-992094f502e0e25f (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial ce68801eb3fbb7b6aa4f4b1ee8dbef76
- enrolled {"cert_serial_hex":"31effdb731f8e981540712d4d6f1e969","not_after":1795474859,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5395","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- publish_raw im/v1/de0864f4-9d14-4eca-b176-01b1367b1fd5/dev-992094f502e0e25f/telemetry retain=true: first event publish_result {"ok":false,"reason_code":128,"topic":"im/v1/de0864f4-9d14-4eca-b176-01b1367b1fd5/dev-992094f502e0e25f/telemetry"}; publish_result {"ok":false,"reason_code":128,"topic":"im/v1/de0864f4-9d14-4eca-b176-01b1367b1fd5/dev-992094f502e0e25f/telemetry"}; policy authz allowed=false
- publish_raw im/v1/de0864f4-9d14-4eca-b176-01b1367b1fd5/dev-992094f502e0e25f/events retain=true: first event publish_result {"ok":false,"reason_code":128,"topic":"im/v1/de0864f4-9d14-4eca-b176-01b1367b1fd5/dev-992094f502e0e25f/events"}; publish_result {"ok":false,"reason_code":128,"topic":"im/v1/de0864f4-9d14-4eca-b176-01b1367b1fd5/dev-992094f502e0e25f/events"}; policy authz allowed=false

### C-OTA-1 Unsigned image - pass

*Criterion:* `ota_state{state=rejected}`; active slot unchanged

| Measurement | Value |
|---|---|
| final_state | rejected |
| error | unsigned |
| artifact_downloads | 0 |

- DUT dev-7664f811cddbadf0 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 3d5f8bbc11f01cd29e2ba2c1a9f9a19a
- enrolled {"cert_serial_hex":"91eca279721d4ea81e7436f91ca5a851","not_after":1795474860,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5395","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- OtaNotify campaign 582d30ea-c20c-4235-8674-7c61ab496b95: version_code 101, image 49664 B sha256 9cda2235d9ba61d1eecfbf35fa33f4126f5ece209ceeab9d9a5743a6ee47e3bb, served 49664 B
- ota_state sequence: ["received", "rejected(unsigned)"]
- ota_slots before {"active_slot":"a","pending_slot":null,"slots":[{"name":"a","sha256_hex":"4cb2d74483ab36b04aff112fc132c1d86c5017c460e151f6ddce991541119e13","state":"valid","version":"1.0.0","version_code":100},{"name":"b","sha256_hex":"","state":"empty","version":"","version_code":0}]} after {"active_slot":"a","pending_slot":null,"slots":[{"name":"a","sha256_hex":"4cb2d74483ab36b04aff112fc132c1d86c5017c460e151f6ddce991541119e13","state":"valid","version":"1.0.0","version_code":100},{"name":"b","sha256_hex":"","state":"empty","version":"","version_code":0}]}
- signed OtaStatus uplinks (state, error): [(0, None), (7, Some("COSE_TAG"))]

### C-OTA-2 Tampered image (1 byte flipped, valid manifest) - pass

*Criterion:* `ota_state{state=rejected, error=image_hash}`

| Measurement | Value |
|---|---|
| final_state | rejected |
| error | image_hash |
| artifact_downloads | 1 |

- DUT dev-7b02d89e30604e25 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 43b3d40739cc000469991424b7f3c6ec
- enrolled {"cert_serial_hex":"f46fbe26da68c3912d710a52c47c45a8","not_after":1795474862,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5395","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- OtaNotify campaign 02942e73-0f33-43ea-91e6-133d21deef04: version_code 101, image 49664 B sha256 9cda2235d9ba61d1eecfbf35fa33f4126f5ece209ceeab9d9a5743a6ee47e3bb, served 49664 B
- ota_state sequence: ["received", "downloading", "downloading", "verifying", "rejected(image_hash)"]
- ota_slots before {"active_slot":"a","pending_slot":null,"slots":[{"name":"a","sha256_hex":"4cb2d74483ab36b04aff112fc132c1d86c5017c460e151f6ddce991541119e13","state":"valid","version":"1.0.0","version_code":100},{"name":"b","sha256_hex":"","state":"empty","version":"","version_code":0}]} after {"active_slot":"a","pending_slot":null,"slots":[{"name":"a","sha256_hex":"4cb2d74483ab36b04aff112fc132c1d86c5017c460e151f6ddce991541119e13","state":"valid","version":"1.0.0","version_code":100},{"name":"b","sha256_hex":"","state":"empty","version":"","version_code":0}]}
- signed OtaStatus uplinks (state, error): [(0, None), (1, None), (1, None), (2, None), (7, Some("MF_HASH_MISMATCH"))]

### C-OTA-3 Manifest signed by an untrusted key - pass

*Criterion:* rejected

| Measurement | Value |
|---|---|
| final_state | rejected |
| error | untrusted_key |
| artifact_downloads | 0 |

- DUT dev-be29ad85ffbb64b7 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial f2b4a59aae7fc8daddaf51fe9b4a781e
- enrolled {"cert_serial_hex":"b8377250bcc84069f095bf3127413ad2","not_after":1795474863,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5395","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- OtaNotify campaign b096ba62-e0a9-4a87-8e34-582aad465ac9: version_code 101, image 49664 B sha256 9cda2235d9ba61d1eecfbf35fa33f4126f5ece209ceeab9d9a5743a6ee47e3bb, served 49664 B
- ota_state sequence: ["received", "rejected(untrusted_key)"]
- ota_slots before {"active_slot":"a","pending_slot":null,"slots":[{"name":"a","sha256_hex":"4cb2d74483ab36b04aff112fc132c1d86c5017c460e151f6ddce991541119e13","state":"valid","version":"1.0.0","version_code":100},{"name":"b","sha256_hex":"","state":"empty","version":"","version_code":0}]} after {"active_slot":"a","pending_slot":null,"slots":[{"name":"a","sha256_hex":"4cb2d74483ab36b04aff112fc132c1d86c5017c460e151f6ddce991541119e13","state":"valid","version":"1.0.0","version_code":100},{"name":"b","sha256_hex":"","state":"empty","version":"","version_code":0}]}
- signed OtaStatus uplinks (state, error): [(0, None), (7, Some("COSE_UNKNOWN_KEY"))]

### C-OTA-4 Downgrade (`version_code` not greater) - pass

*Criterion:* rejected

| Measurement | Value |
|---|---|
| final_state | rejected |
| error | downgrade |
| artifact_downloads | 0 |

- DUT dev-9d851d2f3e6af348 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 9d137a6f57be06e97b22f955f2edec67
- enrolled {"cert_serial_hex":"a5d658fa1f55096adcf5d56385f1e9df","not_after":1795474864,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5395","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- OtaNotify campaign 6a65ae43-d049-4077-b351-3f51ba79804a: version_code 100, image 49664 B sha256 9cda2235d9ba61d1eecfbf35fa33f4126f5ece209ceeab9d9a5743a6ee47e3bb, served 49664 B
- ota_state sequence: ["received", "rejected(downgrade)"]
- ota_slots before {"active_slot":"a","pending_slot":null,"slots":[{"name":"a","sha256_hex":"4cb2d74483ab36b04aff112fc132c1d86c5017c460e151f6ddce991541119e13","state":"valid","version":"1.0.0","version_code":100},{"name":"b","sha256_hex":"","state":"empty","version":"","version_code":0}]} after {"active_slot":"a","pending_slot":null,"slots":[{"name":"a","sha256_hex":"4cb2d74483ab36b04aff112fc132c1d86c5017c460e151f6ddce991541119e13","state":"valid","version":"1.0.0","version_code":100},{"name":"b","sha256_hex":"","state":"empty","version":"","version_code":0}]}
- signed OtaStatus uplinks (state, error): [(0, None), (7, Some("MF_ROLLBACK"))]

### C-OTA-5 Valid update applies and is marked healthy - pass

*Criterion:* `rebooted{reason=ota_apply}`, new `version_code`, `ota_state=success`

| Measurement | Value |
|---|---|
| new_version_code | 101 |
| image_sha256 | 38a75ec340d75debddaf93f02cde6099b90d0dda7f073b9d249412a46a56a558 |

- DUT dev-921891b19e8d0b89 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 97532960a94ad0cf3752e26fb564841e
- enrolled {"cert_serial_hex":"d0cbbd95d2562514bdaabe7b56c3022c","not_after":1795474866,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5395","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- OtaNotify campaign b3fbc830-4c6a-4a6b-8b87-c8b804d7f635: version_code 101, image 53329 B sha256 38a75ec340d75debddaf93f02cde6099b90d0dda7f073b9d249412a46a56a558, served 53329 B
- ota_state sequence: ["received", "downloading", "downloading", "verifying", "applying", "rebooting", "success"]
- rebooted {"active_slot":"b","reason":"ota_apply","version_code":101}
- ota_slots after: {"active_slot":"b","pending_slot":null,"slots":[{"name":"a","sha256_hex":"","state":"empty","version":"","version_code":0},{"name":"b","sha256_hex":"38a75ec340d75debddaf93f02cde6099b90d0dda7f073b9d249412a46a56a558","state":"valid","version":"1.1.0","version_code":101}]}
- signed OtaStatus{state=5 success} uplink, fw_hash matches the image: true

### C-OTA-6 Update that fails its health check rolls back - pass

*Criterion:* `rebooted{reason=rollback}`, previous slot active, `ota_state=rolled_back`

| Measurement | Value |
|---|---|
| rollback_error | health_check |
| seconds_apply_to_rollback | 15.0 |

- DUT dev-9e14454ba1f30589 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial cf14e46cddf580842eff071452a57453
- enrolled {"cert_serial_hex":"2a9c08ffd79269b3d7b8d58adfca3788","not_after":1795474866,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5395","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- OtaNotify campaign ca9c3c4b-a96b-4e19-97c9-d0e596b1d209: version_code 101, image 49852 B sha256 d707cc4e82429a8ad6fb618fd6094621f2f7752dbba674d826ece0426835f281, served 49852 B
- rebooted {"active_slot":"b","reason":"ota_apply","version_code":101} then health check without broker access
- rebooted {"active_slot":"a","reason":"rollback","version_code":100}
- ota_state sequence: ["received", "downloading", "downloading", "verifying", "applying", "rebooting", "rolled_back(health_check)"]
- ota_slots before {"active_slot":"a","pending_slot":null,"slots":[{"name":"a","sha256_hex":"4cb2d74483ab36b04aff112fc132c1d86c5017c460e151f6ddce991541119e13","state":"valid","version":"1.0.0","version_code":100},{"name":"b","sha256_hex":"","state":"empty","version":"","version_code":0}]} after {"active_slot":"a","pending_slot":null,"slots":[{"name":"a","sha256_hex":"4cb2d74483ab36b04aff112fc132c1d86c5017c460e151f6ddce991541119e13","state":"valid","version":"1.0.0","version_code":100},{"name":"b","sha256_hex":"d707cc4e82429a8ad6fb618fd6094621f2f7752dbba674d826ece0426835f281","state":"inval...
- signed OtaStatus{state=6 rolled_back} delivered after reconnecting

### C-OTA-7 Delta update - pass

*Criterion:* applied image hash equals full image hash

| Measurement | Value |
|---|---|
| patch_bytes | 16650 |
| image_bytes | 53361 |
| applied_image_sha256 | dc8ef08b09eb854409e8e32e8fb3663b8f5eaf544a80198f2633ab183c588f5a |

- DUT dev-23e7209f087cb70a (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial b504aeedfd7f318a33d31af55798ab39
- enrolled {"cert_serial_hex":"6269d2f7af6c9246a3a7388643eb6da1","not_after":1795474882,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5395","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- delta base: the factory image (hash verified against ota_slots)
- OtaNotify campaign f3bfcca5-74ed-4ff8-a11c-460c15675f2b: version_code 101, image 53361 B sha256 dc8ef08b09eb854409e8e32e8fb3663b8f5eaf544a80198f2633ab183c588f5a, served 16650 B (IMDELTA1 patch)
- ota_state sequence: ["received", "downloading", "downloading", "verifying", "applying", "rebooting", "success"]
- rebooted {"active_slot":"b","reason":"ota_apply","version_code":101}
- ota_slots after: {"active_slot":"b","pending_slot":null,"slots":[{"name":"a","sha256_hex":"","state":"empty","version":"","version_code":0},{"name":"b","sha256_hex":"dc8ef08b09eb854409e8e32e8fb3663b8f5eaf544a80198f2633ab183c588f5a","state":"valid","version":"1.1.0","version_code":101}]}
- signed OtaStatus{state=5 success} uplink, fw_hash matches the image: true

### C-RPL-1 Replayed command (same `seq`) - pass

*Criterion:* `message_rejected{code=ENV_REPLAY}`; command not executed twice

| Measurement | Value |
|---|---|
| rejection_code | ENV_REPLAY |
| command_executed_count | 1 |
| command_acks_on_wire | 1 |

- DUT dev-a7541efa85cff54e (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 944b73eeb0d70f49311708584c73714d
- enrolled {"cert_serial_hex":"f0819355ccd029d13f71c6f686c9d31a","not_after":1795474882,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5395","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- original seq 1000: command_executed {"cmd_id":"6982a5a3-89dd-441f-b45b-d8b1f7a69277","status":0}
- signed CommandAck seq 2 echoes cmd_id and nonce
- message_rejected {"code":"ENV_REPLAY","topic":"im/v1/de0864f4-9d14-4eca-b176-01b1367b1fd5/dev-a7541efa85cff54e/cmd/req"}

### C-RPL-2 Command with stale timestamp - pass

*Criterion:* `message_rejected{code=ENV_TS_SKEW}`

| Measurement | Value |
|---|---|
| rejection_code | ENV_TS_SKEW |
| rejection_code | ENV_TS_SKEW |

- DUT dev-3fcd5f74a5a1192b (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 197c077daa94e556a5a01577b27f4485
- enrolled {"cert_serial_hex":"5568962c6c49f5cc257edc07a19625e4","not_after":1795474885,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5395","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- command seq 1001 with ts = now - 400 s (window 300 s)
- message_rejected {"code":"ENV_TS_SKEW","topic":"im/v1/de0864f4-9d14-4eca-b176-01b1367b1fd5/dev-3fcd5f74a5a1192b/cmd/req"}
- message_rejected {"code":"ENV_TS_SKEW","topic":"im/v1/de0864f4-9d14-4eca-b176-01b1367b1fd5/dev-3fcd5f74a5a1192b/cmd/req"}

### C-RPL-3 Command signed by a non-tenant key - pass

*Criterion:* `message_rejected{code=COSE_SIGNATURE}`

| Measurement | Value |
|---|---|
| rejection_code | COSE_SIGNATURE |

- DUT dev-082a80369e0dc6af (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 1c35f4335b0fe3879b12d3ce84dbef30
- enrolled {"cert_serial_hex":"800c24c4eda52482967d58f5e19d0187","not_after":1795474887,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5395","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- command seq 1003 with kid tenant-cmd-<tenant> signed by a non-tenant Ed25519 key
- message_rejected {"code":"COSE_SIGNATURE","topic":"im/v1/de0864f4-9d14-4eca-b176-01b1367b1fd5/dev-082a80369e0dc6af/cmd/req"}
- a genuine command with the forged seq was executed afterwards (store not advanced by the forgery)

### C-RPL-4 Device `seq` strictly increases across reboot - pass

*Criterion:* `status.seq_out` after reboot > before

| Measurement | Value |
|---|---|
| seq_out_before | 5 |
| seq_out_after | 6 |
| last_seq_sent_before | 4 |
| first_seq_sent_after | 6 |

- DUT dev-8bd2a5fd3e95ba9e (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial d2abb7b0f8ffe040648589355ad39c30
- enrolled {"cert_serial_hex":"63de9e3acbc5b885b8fdd07a81262df4","not_after":1795474889,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5395","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- rebooted {"active_slot":"a","reason":"requested","version_code":100}
- telemetry seqs on the wire: [2, 3, 4, 6]

### C-OFF-1 Offline buffering and resync - pass

*Criterion:* telemetry sent while `net_down` is delivered after `net_up`, in order, no gaps, `buffer_flushed`

| Measurement | Value |
|---|---|
| buffered_and_flushed | 25 |
| telemetry_on_wire | 32 |

- DUT dev-6b3186532925ef49 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial bd763f1c364e5c96daaf4df0bb3d163b
- enrolled {"cert_serial_hex":"9206162efc1fe2c79373a49ece5363a0","not_after":1795474890,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5395","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- net_down -> disconnected {"reason":"network down","reason_code":128}
- offline send_telemetry 25 -> {"first_seq":4,"last_seq":28}, status.buffered=25
- net_up -> buffer_flushed {"count":25,"first_seq":4,"last_seq":28}
- telemetry seqs on the wire (32): [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33]

### C-CFG-1 Encrypted config delivery - pass

*Criterion:* DUT applies config; retained broker copy is ciphertext only

| Measurement | Value |
|---|---|
| applied | yes (replay of the same ciphertext rejected with ENV_REPLAY) |
| retained_bytes | 352 |
| retained_ciphertext_bytes | 204 |

- DUT dev-002e8047316670aa (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 978b2f5795e22af1e8723bc3809870b8
- enrolled {"cert_serial_hex":"90da197221052ee77b8ff5e8a4a54121","not_after":1795474891,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5395","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- Config v7 (tenant-signed, seq 1000) HPKE-wrapped to the certificate key of 90da197221052ee77b8ff5e8a4a54121, published retained
- config_applied {"version":7}
- re-delivery: message_rejected {"code":"ENV_REPLAY","topic":"im/v1/de0864f4-9d14-4eca-b176-01b1367b1fd5/dev-002e8047316670aa/config"}
- config wrapped to a foreign key: message_rejected {"code":"HPKE_OPEN","topic":"im/v1/de0864f4-9d14-4eca-b176-01b1367b1fd5/dev-002e8047316670aa/config"}

### C-HOOK-1 Release build has no control channel - pass

*Criterion:* release `agent-rs` exits non-zero on `--dut`

| Measurement | Value |
|---|---|
| exit_code | 2 |

- C:\Users\mgoma\Desktop\Security Assignments\IoT-Security-Framework\conformance\target\duts\agent-rs-release\release\ironmesh-agent.exe --dut -> exit Some(2); stderr: ironmesh-agent: the DUT control channel is not compiled into this build (cargo feature `dut-control`); refusing --dut
