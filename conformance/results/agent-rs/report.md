# IronMesh conformance report: `agent-rs`

| | |
|---|---|
| Run started | 2026-11-09T22:53:12.5177074Z |
| Duration | 116 s |
| Git commit | `12c456ca9357771a67989557787bdab201342b2a (working tree modified)` |
| Cloud mode | hermetic |
| Host | MUSTAFAGOMAA (windows x86_64) |
| tenant_id | da885108-b8ab-46cf-b9c6-0ca580731548 |
| run_dir | C:\Users\mgoma\Desktop\Security Assignments\IoT-Security-Framework\conformance\target\runs\agent-rs-1794264792 |
| policy_service | C:\Users\mgoma\Desktop\Security Assignments\IoT-Security-Framework\conformance\target\bin\policy.exe (sha256 6408a8a7a0cc94c2) |
| signing_keys | test-vector keys from C:\Users\mgoma\Desktop\Security Assignments\IoT-Security-Framework\libs\python\ironmesh-wire\tests\keys |
| policy_wiring | authn bodies carry cert_pem + cert_serial (emqx.conf template); POLICY_REQUIRE_CERT_SERIAL=true, POLICY_DEVICE_CA_FILE / POLICY_SERVICES_CA_FILE set, POLICY_JWT_PUBLIC_KEY_PEM + POLICY_JWT_SINGLE_USE=true; svc-registry authenticated with a Services CA client certificate |
| policy_mgmt_jwt_single_use | GET /v1/revocations with one token twice -> 200 then 401 (want 200 then 401) |
| dut_binary | C:\Users\mgoma\Desktop\Security Assignments\IoT-Security-Framework\conformance\target\duts\agent-rs-dut\debug\ironmesh-agent.exe (sha256 db7a555e8769b9b2) |
| release_binary | C:\Users\mgoma\Desktop\Security Assignments\IoT-Security-Framework\conformance\target\duts\agent-rs-release\release\ironmesh-agent.exe (sha256 1e1930e803bcbf51) |
| product | gateway-rpi |
| reconnect_backoff_clock_scale | 0.02 |
| ota_health_timeout_s | 15 |

**Result: 28 passed, 0 failed, 0 not applicable, 0 errors** (of 28).

| Case | Title | Verdict | Measured | Time |
|---|---|---|---|---|
| C-TLS-1 | mTLS handshake with valid operational cert | pass | tls_version: TLSv1.3, alpn mqtt | 0.2 s |
| C-TLS-2 | Broker presents cert from an unpinned CA (rogue broker) | pass |  | 0.6 s |
| C-TLS-3 | Broker offers TLS 1.2 only | pass |  | 0.4 s |
| C-TLS-4 | Session resumption on reconnect | pass | broker_observed_resumed: true | 0.4 s |
| C-TLS-5 | Bounded reconnect backoff | pass | attempts_observed: 13, max gap 4.619 s | 16.4 s |
| C-ENR-1 | Zero-touch enrollment with attestation | pass |  | 0.2 s |
| C-ENR-2 | Enrollment refused for quarantined device | pass | http_status: 403 | 0.2 s |
| C-ROT-1 | Certificate rotation (`renew`) keeps identity, changes key and serial | pass |  | 0.3 s |
| C-ROT-2 | Automatic rotation at 50 % lifetime (short-lived test certs) | pass | renewed_at_fraction_of_lifetime: 0.574 | 21.3 s |
| C-REV-1 | Revocation reaction time | pass | denied p50 0.015 s, p95 0.018 s, max 0.026 s | 35.1 s |
| C-REV-2 | Single-certificate revocation refuses the serial, renewed certificate admitted | pass | superseded serial refused, renewed admitted; own serial refused in 0.004 s | 4.9 s |
| C-ACL-1 | Publish to another device's topic | pass |  | 1.6 s |
| C-ACL-2 | Subscribe to another device's command topic or wildcard | pass |  | 0.3 s |
| C-ACL-3 | Retained publish on telemetry | pass |  | 0.9 s |
| C-OTA-1 | Unsigned image | pass | rejected (unsigned) | 1.3 s |
| C-OTA-2 | Tampered image (1 byte flipped, valid manifest) | pass | rejected (image_hash) | 1.3 s |
| C-OTA-3 | Manifest signed by an untrusted key | pass | rejected (untrusted_key) | 1.3 s |
| C-OTA-4 | Downgrade (`version_code` not greater) | pass | rejected (downgrade) | 1.3 s |
| C-OTA-5 | Valid update applies and is marked healthy | pass | new_version_code: 101 | 0.4 s |
| C-OTA-6 | Update that fails its health check rolls back | pass | seconds_apply_to_rollback: 15.0 | 15.7 s |
| C-OTA-7 | Delta update | pass | patch 16650 B / image 53361 B | 0.3 s |
| C-RPL-1 | Replayed command (same `seq`) | pass | rejection_code: ENV_REPLAY | 2.3 s |
| C-RPL-2 | Command with stale timestamp | pass | rejection_code: ENV_TS_SKEW | 2.3 s |
| C-RPL-3 | Command signed by a non-tenant key | pass | rejection_code: COSE_SIGNATURE | 2.2 s |
| C-RPL-4 | Device `seq` strictly increases across reboot | pass | seq_out 5 -> 6 | 0.3 s |
| C-OFF-1 | Offline buffering and resync | pass |  | 1.5 s |
| C-CFG-1 | Encrypted config delivery | pass |  | 2.3 s |
| C-HOOK-1 | Release build has no control channel | pass | exit_code: 2 | 0.3 s |

## Revocation reaction time (C-REV-1)

Path: harness PKI revokes the certificate (CRL regenerated) and pushes the signed event to the **real** policy service (`POST /internal/v1/revocations`, bearer + `X-IronMesh-Signature` HMAC) -> policy deny-lists the device and calls the broker's EMQX management API `DELETE /api/v5/clients/{id}` -> session dropped -> the DUT's reconnect is refused by the real authn hook.

| Interval | Value |
|---|---|
| iterations | 20 |
| revoke -> policy 202 | p50 0.002 s, p95 0.004 s, max 0.011 s |
| revoke -> kick (EMQX API) | p50 0.002 s, p95 0.004 s, max 0.011 s |
| revoke -> broker disconnect | p50 0.002 s, p95 0.004 s, max 0.011 s |
| revoke -> DUT disconnected event | p50 0.003 s, p95 0.005 s, max 0.012 s |
| revoke -> reconnect denied (end to end) | p50 0.015 s, p95 0.018 s, max 0.026 s |

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

- DUT dev-6d90c6b36dabc702 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 4995cc7d03d9eb13293959d9074a3820
- connected {"alpn":"mqtt","broker":"127.0.0.1:5180","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- broker handshake: version Some("TLSv1.3"), alpn Some("mqtt"), client cert serial Some("4f247000118c8deb51c958f4693e510d")
- CONNECT: client id = CN, clean_start=false, session_expiry=Some(604800), keep_alive=60, receive_maximum=Some(32); policy authn allow=true

### C-TLS-2 Broker presents cert from an unpinned CA (rogue broker) - pass

*Criterion:* `connect_failed{reason=tls_pin_mismatch}`; no CONNECT packet observed

| Measurement | Value |
|---|---|
| RogueUnknownCa: connect_failed.reason | tls_pin_mismatch |
| RogueUnknownCa: CONNECT packets observed | 0 |
| Rogue: connect_failed.reason | tls_pin_mismatch |
| Rogue: CONNECT packets observed | 0 |

- DUT dev-a06e68d2b909402c (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 259546c88703f1a083718e6e3fde7849
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

- DUT dev-32a7a40f93082b95 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 17599a5bbec8cf6fa995a5f9ebbd20db
- broker mode Tls12Only: connect_failed {"detail":"received fatal alert: ProtocolVersion","reason":"tls_handshake"}
- broker-side handshakes in mode Tls12Only: ["ok=false version=None error=Some(\"peer is incompatible: Tls12NotOfferedOrEnabled\")"]

### C-TLS-4 Session resumption on reconnect - pass

*Criterion:* second `connected.resumed=true` (where the target supports tickets)

| Measurement | Value |
|---|---|
| dut_reported_resumed | true |
| broker_observed_resumed | true |
| session_present | true |

- DUT dev-b011dc6223efe91e (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 69064757ae61d9ea6632d14ebb177dca
- enrolled {"cert_serial_hex":"07efedd86ab2304d17c27aa234ea181e","not_after":1795474393,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5180","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- second connected {"alpn":"mqtt","broker":"127.0.0.1:5180","resumed":true,"session_present":true,"tls_version":"TLSv1.3"}

### C-TLS-5 Bounded reconnect backoff - pass

*Criterion:* reconnect attempts follow base 1 s, factor 2, cap 300 s, full jitter (verified on attempt timestamps with clock scaling)

| Measurement | Value |
|---|---|
| clock_scale | 0.02 |
| attempts_observed | 13 |
| max_gap_s | 4.619 |
| capped_gaps_checked | 4 |

- DUT dev-2d417eaa72abf1ae (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 250b91a4e9d16338f5d51a5e6ffeeaed
- enrolled {"cert_serial_hex":"15e1d3753516050e926f7bd0285162c7","not_after":1795474393,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5180","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- connect_failed reasons (first 3): ["not_authorized", "not_authorized", "not_authorized"]; status.state=backoff observed: true
- gap_k <= min(300, 2^k) x scale [s]: 0.013<=0.020, 0.020<=0.040, 0.020<=0.080, 0.065<=0.160, 0.116<=0.320, 0.270<=0.640, 0.165<=1.280, 0.574<=2.560, 1.634<=5.120, 4.376<=6.000, 3.361<=6.000, 0.839<=6.000, 4.619<=6.000

### C-ENR-1 Zero-touch enrollment with attestation - pass

*Criterion:* `enrolled`; harness verifies attestation, CSR CN, fresh key

| Measurement | Value |
|---|---|
| issued_serial | 1501c5ebfbdf8bba7712cd056726319c |
| assurance_ou | da885108-b8ab-46cf-b9c6-0ca580731548,assurance:software |

- DUT dev-606f20faf4668bff (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 6b5b53365bd2227af289edc8bde5a85e
- enrolled {"cert_serial_hex":"1501c5ebfbdf8bba7712cd056726319c","not_after":1795474410,"se_type":"software"}
- EST: op=simpleenroll, client cert serial 6b5b53365bd2227af289edc8bde5a85e (bootstrap 6b5b53365bd2227af289edc8bde5a85e), CSR CN=Some("dev-606f20faf4668bff") OU=["da885108-b8ab-46cf-b9c6-0ca580731548"], fresh key=true
- attestation: kid 6b5b53365bd2227af289edc8bde5a85e, seq 1, ts 1794264811, se_type software, fw_version 1.0.0, fw_hash 4cb2d74483ab36b04aff112fc132c1d86c5017c460e151f6ddce991541119e13, signature by the TLS client key verified=true
- **warning:** a fresh, never-enrolled device reports status.state="offline" (DUT_PROTOCOL: unprovisioned = no usable certificate)

### C-ENR-2 Enrollment refused for quarantined device - pass

*Criterion:* `enroll_failed{http_status=403}`

| Measurement | Value |
|---|---|
| http_status | 403 |

- DUT dev-2a0753cdc4efde11 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 4b5c805caa17e34c184b567d9b089c09
- enroll_failed {"http_status":403,"reason":"device lifecycle state \"quarantined\" does not permit enrollment"}
- EST answered 403: device lifecycle state "quarantined" does not permit enrollment

### C-ROT-1 Certificate rotation (`renew`) keeps identity, changes key and serial - pass

*Criterion:* `cert_renewed`, new serial, new SPKI, reconnect succeeds

| Measurement | Value |
|---|---|
| old_serial | 2d4468257ea996a6da39f7671fcdae3f |
| new_serial | 2d1e1524fe05e8327ba82cae3116810d |
| spki_changed | true |
| reconnected_automatically | true |

- DUT dev-990730941c12ad2e (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 4d32157be47370f25354d0041bda8e87
- enrolled {"cert_serial_hex":"2d4468257ea996a6da39f7671fcdae3f","not_after":1795474410,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5180","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- cert_renewed {"new_serial_hex":"2d1e1524fe05e8327ba82cae3116810d","not_after":1795474410,"old_serial_hex":"2d4468257ea996a6da39f7671fcdae3f"}
- EST: op=simplereenroll, client cert serial 2d4468257ea996a6da39f7671fcdae3f, attestation kid Some("2d4468257ea996a6da39f7671fcdae3f"), CSR fresh key true
- telemetry seq 3 verified with the renewed key (kid 2d1e1524fe05e8327ba82cae3116810d)

### C-ROT-2 Automatic rotation at 50 % lifetime (short-lived test certs) - pass

*Criterion:* `cert_renewed` without an explicit `renew`

| Measurement | Value |
|---|---|
| test_cert_lifetime_s | 40 |
| renewed_at_fraction_of_lifetime | 0.574 |
| reconnected_automatically | true |

- DUT dev-83fc6be7dee07bd3 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 496a06e3cfae89220258156437334179
- enrolled {"cert_serial_hex":"3503c57dcdf209f56d4044093504c60a","not_after":1794264850,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5180","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- cert_renewed {"new_serial_hex":"4f834fd80b70ce43426e5ad7eda29254","not_after":1794264871,"old_serial_hex":"3503c57dcdf209f56d4044093504c60a"}
- renewal at 23.0 s of 40 s (contract §2: 50 % + up to 10 % jitter)

### C-REV-1 Revocation reaction time - pass

*Criterion:* revoke -> broker disconnect -> DUT cannot reconnect with the revoked cert, measured < 10 s

| Measurement | Value |
|---|---|
| iterations | 20 |
| revoke -> policy 202 | p50 0.002 s, p95 0.004 s, max 0.011 s |
| revoke -> kick (EMQX API) | p50 0.002 s, p95 0.004 s, max 0.011 s |
| revoke -> broker disconnect | p50 0.002 s, p95 0.004 s, max 0.011 s |
| revoke -> DUT disconnected event | p50 0.003 s, p95 0.005 s, max 0.012 s |
| revoke -> reconnect denied (end to end) | p50 0.015 s, p95 0.018 s, max 0.026 s |

- DUT dev-ebd38e78ead32ed7 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 11894ac08de5afa5c9770e44bc994365
- enrolled {"cert_serial_hex":"5f29265aef47b41afb3a1ce962a2bf10","not_after":1795474432,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5180","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- revocation path: harness PKI (CRL regenerated, reason keyCompromise) -> signed POST /internal/v1/revocations (bearer + HMAC, device_deny=false) -> real policy -> EMQX API kick
- DUT disconnected {"reason":"broker DISCONNECT 0x98 ","reason_code":152} then connect_failed {"detail":"CONNACK reason 0x87 ","reason":"not_authorized"}
- reconnect with revoked serial Some("5f29265aef47b41afb3a1ce962a2bf10") answered CONNACK 0x87 by the policy authn hook
- DUT dev-becd173916dc2ca3 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 1f452fcf2e5cd7a691e6f3fce157807d
- enrolled {"cert_serial_hex":"11558cd9aee2d4dbb03530a89423667d","not_after":1795474434,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5180","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-ae801613de690427 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 61790f9ec378b7de0a1c6e6ef6dbe57d
- enrolled {"cert_serial_hex":"69e529883cae2f97792de748e760a85a","not_after":1795474435,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5180","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-5b029e03e77eabef (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 51f460addbbc2a58049f58fb8a5a3a64
- enrolled {"cert_serial_hex":"7d7ad883fb0ee360946413b804b78e4e","not_after":1795474437,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5180","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-e689bdb81e65b934 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 338e4f39af20fc24d181a65db2029f4d
- enrolled {"cert_serial_hex":"3be4e4b5d03bca72a6caf36a5f75963e","not_after":1795474439,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5180","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-f0e7055608199ca5 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 19557a745f5109b2016d7d8271bf9eb5
- enrolled {"cert_serial_hex":"3927deec7d8c6a66519e88db64fef924","not_after":1795474440,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5180","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-9a7515818efe1cf6 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 0d9b34b501481a74e2cd75d8df536645
- enrolled {"cert_serial_hex":"53ffd7a884539ac9d8a2f4782302f6d1","not_after":1795474442,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5180","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-9f854ea234757e21 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 7b363eda003a0404bab1c0dc70cf2cbe
- enrolled {"cert_serial_hex":"6d59053946e3f975ae144618e2f60019","not_after":1795474444,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5180","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-a4d85041e947cf33 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 2df15470cc49c4e2e51036e01905824b
- enrolled {"cert_serial_hex":"5d715328dd3ee3f3e85ac0bd8fda1c9f","not_after":1795474446,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5180","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-cde30f8edd395fa9 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 53dea8bf1742120d26bb5ca2f1795144
- enrolled {"cert_serial_hex":"61772e6fd0a8e8705900429870a3827e","not_after":1795474448,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5180","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-09b66f4f74e84c54 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 7f79ed9f0a4e04132726cb1ee7748f84
- enrolled {"cert_serial_hex":"6b690f0a336f385e3d7118a7977d2726","not_after":1795474449,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5180","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-865a4b35b03b3da2 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 736d48e84095d0508c3525defc6c9b03
- enrolled {"cert_serial_hex":"271c81b0766a571b362ec8020548d97f","not_after":1795474451,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5180","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-e20ecb177b74d266 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 2fa0c0bb63281b522f3f3a645771b6a6
- enrolled {"cert_serial_hex":"6975e8f55ef361be5d8f09314ae8e5c0","not_after":1795474453,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5180","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-6ff21694532ec956 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 21cc95f5485764665c653323bb445e09
- enrolled {"cert_serial_hex":"49db88266c4fcc00a3cada3ebda358f1","not_after":1795474455,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5180","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-692a5c8adb965b7a (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 292391ba8b192d6796c40f1a737df446
- enrolled {"cert_serial_hex":"55dd774df09206bb4dae80fb38627d4b","not_after":1795474456,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5180","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-75338433d33b7495 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 6b5555ab4164b31c2cd60e2ee2b3d6af
- enrolled {"cert_serial_hex":"25107569023eab9a65cecf2caa93eb48","not_after":1795474458,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5180","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-b0c04672d51584be (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 55d68ffaaecbf6beccbf760e883f1bfe
- enrolled {"cert_serial_hex":"79075c3e181dd0362e962316b329b088","not_after":1795474460,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5180","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-ef5a7bba1e7590cf (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 05925fb173a55028252bdf11865f38cf
- enrolled {"cert_serial_hex":"038297dfb19a7eebd6cd6abcb0054472","not_after":1795474462,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5180","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-764731fa0522a888 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 7980b9cfebc94606790f68e4dd8a27b8
- enrolled {"cert_serial_hex":"13b44e00f908d9bbe3726049d6d21683","not_after":1795474463,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5180","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-f37c4afe2db780aa (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 6f8ab9d9aca1c3fa4c1370e928b4597c
- enrolled {"cert_serial_hex":"4d3a5467e4d137f44404a120c19eaed3","not_after":1795474465,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5180","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- policy /metrics: ironmesh_kick_total{result=ok} +20, ironmesh_revocation_latency_seconds count 20 sum 0.055 s (mean 0.003 s, revoked_at -> kick)
- policy log: {"ts":"2026-11-10T00:54:26.6429332+02:00","level":"info","msg":"revoked session kicked","service":"policy","device_id":"dev-f37c4afe2db780aa","tenant_id":"da885108-b8ab-46cf-b9c6-0ca580731548","event_id":"conformance-01ccb365-007d-4810-97ed

### C-REV-2 Single-certificate revocation refuses the serial, renewed certificate admitted - pass

*Criterion:* after a single-certificate revocation (`device_deny=false`) the revoked serial is refused at CONNECT (policy reason `revoked_serial`) while the renewed certificate is admitted and its session is not kicked; the device id is never deny-listed

| Measurement | Value |
|---|---|
| serial A (renewed away) | 1d74f84de3834d8bf2c95dc8de6fe39c |
| serial B (renewed) | 6dd7c436f5fd992edd3cb1f72c4bf88f |
| CONNECT presenting A (cert_pem + cert_serial) | deny, reason revoked_serial |
| CONNECT presenting B after A was revoked | allow |
| revoke B -> kick | 0.002 s |
| revoke B -> DUT reconnect presenting B refused | 0.004 s |
| ironmesh_auth_failures_total{reason=revoked_serial} | +9 |
| ironmesh_auth_failures_total{reason=revoked} (device-level) | +0 |

- DUT dev-711696dd9d4b6b49 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 77e6218d0adb7766eccecfce3f3b37cb
- enrolled {"cert_serial_hex":"1d74f84de3834d8bf2c95dc8de6fe39c","not_after":1795474467,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5180","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- revocation of A: harness PKI (CRL regenerated, reason superseded) -> signed POST /internal/v1/revocations (bearer + HMAC, device_deny=false) -> real policy -> EMQX API kick
- policy GET /v1/revocations (single-use service JWT) entry for A: {"applied_at":"2026-11-10T00:54:28.4917579+02:00","device_id":"dev-711696dd9d4b6b49","event_id":"conformance-0f3bb20d-5293-43e7-be21-147442c4ea33","kicked":true,"kicked_at":"2026-11-10T00:54:28.4937446+02:00","reason":"superseded","revoked_at":"2026-11-09T22:54:28.4816524Z","serial_hex":"1d74f84de38...
- policy log: {"ts":"2026-11-10T00:54:28.4950071+02:00","level":"info","msg":"revoked certificate is not the live session's; kick skipped","service":"policy","device_id":"dev-711696dd9d4b6b49","tenant_id":"da885108-b8ab-46cf-b9c6-0ca580731548","event_id":"conformance-0f3bb2
- reconnect presenting B: authn allow, CONNACK 0x00, session_present true
- revocation of B: harness PKI (CRL regenerated, reason affiliationChanged) -> signed POST /internal/v1/revocations (bearer + HMAC, device_deny=false) -> real policy -> EMQX API kick
- policy GET /v1/revocations entry for B: {"applied_at":"2026-11-10T00:54:31.5406116+02:00","device_id":"dev-711696dd9d4b6b49","event_id":"conformance-ba730a0b-20b0-4307-a372-054848b3217f","kicked":true,"kicked_at":"2026-11-10T00:54:31.5422235+02:00","reason":"affiliationChanged","revoked_at":"2026-11-09T22:54:31.5403002Z","serial_hex":"6dd...
- policy log: {"ts":"2026-11-10T00:54:31.5351835+02:00","level":"info","msg":"authn deny","service":"policy","client_id":"dev-711696dd9d4b6b49","username":"dev-711696dd9d4b6b49","peerhost":"127.0.0.1","cert_cn":"dev-711696dd9d4b6b49","kind":"device","reason":"revoked_serial
- policy log: {"ts":"2026-11-10T00:54:31.5443587+02:00","level":"info","msg":"authn deny","service":"policy","client_id":"dev-711696dd9d4b6b49","username":"dev-711696dd9d4b6b49","peerhost":"127.0.0.1","cert_cn":"dev-711696dd9d4b6b49","kind":"device","reason":"revoked_serial
- **warning:** policy GET /v1/revocations reports kicked=true (with kicked_at) for the superseded serial although no kick was sent: the cache records KickSkipped (internal/revocation/cache.go markKicked) but internal/mgmt/api.go revocationItem does not expose it

### C-ACL-1 Publish to another device's topic - pass

*Criterion:* `publish_result.ok=false` (or disconnect) and harness subscriber receives nothing

| Measurement | Value |
|---|---|
| outcome im/v1/da885108-b8ab-46cf-b9c6-0ca580731548/dev-067be8afde657431/telemetry | disconnected |
| outcome im/v1/da885108-b8ab-46cf-b9c6-0ca580731548/dev-067be8afde657431/cmd/ack | disconnected |
| outcome im/v1/bf36ea20-617b-4a88-a158-af2dd4beb052/dev-6f5156b25b4b2381/telemetry | disconnected |
| outcome im/v1/da885108-b8ab-46cf-b9c6-0ca580731548/dev-6f5156b25b4b2381/cmd/req | disconnected |

- DUT dev-6f5156b25b4b2381 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 53c1d851bce2a7f358beebef87ec22f2
- enrolled {"cert_serial_hex":"49ffb7b393803b0db85c4fbbbca7ae02","not_after":1795474472,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5180","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- publish_raw im/v1/da885108-b8ab-46cf-b9c6-0ca580731548/dev-067be8afde657431/telemetry retain=false: first event publish_result {"ok":false,"reason_code":128,"topic":"im/v1/da885108-b8ab-46cf-b9c6-0ca580731548/dev-067be8afde657431/telemetry"}; publish_result {"ok":false,"reason_code":128,"topic":"im/v1/da885108-b8ab-46cf-b9c6-0ca580731548/dev-067be8afde657431/telemetry"}; policy authz allowed=false
- publish_raw im/v1/da885108-b8ab-46cf-b9c6-0ca580731548/dev-067be8afde657431/cmd/ack retain=false: first event publish_result {"ok":false,"reason_code":128,"topic":"im/v1/da885108-b8ab-46cf-b9c6-0ca580731548/dev-067be8afde657431/cmd/ack"}; publish_result {"ok":false,"reason_code":128,"topic":"im/v1/da885108-b8ab-46cf-b9c6-0ca580731548/dev-067be8afde657431/cmd/ack"}; policy authz allowed=false
- publish_raw im/v1/bf36ea20-617b-4a88-a158-af2dd4beb052/dev-6f5156b25b4b2381/telemetry retain=false: first event publish_result {"ok":false,"reason_code":128,"topic":"im/v1/bf36ea20-617b-4a88-a158-af2dd4beb052/dev-6f5156b25b4b2381/telemetry"}; publish_result {"ok":false,"reason_code":128,"topic":"im/v1/bf36ea20-617b-4a88-a158-af2dd4beb052/dev-6f5156b25b4b2381/telemetry"}; policy authz allowed=false
- publish_raw im/v1/da885108-b8ab-46cf-b9c6-0ca580731548/dev-6f5156b25b4b2381/cmd/req retain=false: first event publish_result {"ok":false,"reason_code":128,"topic":"im/v1/da885108-b8ab-46cf-b9c6-0ca580731548/dev-6f5156b25b4b2381/cmd/req"}; publish_result {"ok":false,"reason_code":128,"topic":"im/v1/da885108-b8ab-46cf-b9c6-0ca580731548/dev-6f5156b25b4b2381/cmd/req"}; policy authz allowed=false

### C-ACL-2 Subscribe to another device's command topic or wildcard - pass

*Criterion:* `subscribe_result.granted=false`

| Measurement | Value |
|---|---|
| reason_code im/v1/da885108-b8ab-46cf-b9c6-0ca580731548/dev-12e272bbdade8507/cmd/req | 135 |
| reason_code im/v1/da885108-b8ab-46cf-b9c6-0ca580731548/dev-12e272bbdade8507/config | 135 |
| reason_code im/v1/da885108-b8ab-46cf-b9c6-0ca580731548/# | 135 |
| reason_code im/v1/da885108-b8ab-46cf-b9c6-0ca580731548/+/cmd/req | 135 |
| reason_code im/v1/da885108-b8ab-46cf-b9c6-0ca580731548/dev-2d3205fb1d0b7fca/# | 135 |
| reason_code # | 135 |
| reason_code $SYS/# | 135 |
| reason_code $share/bridge/im/v1/# | 135 |
| reason_code im/v1/da885108-b8ab-46cf-b9c6-0ca580731548/dev-2d3205fb1d0b7fca/telemetry | 135 |

- DUT dev-2d3205fb1d0b7fca (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 05c4e77cad648a1b86a963fb6cfbf70f
- enrolled {"cert_serial_hex":"3b635bd521b9804935469c3b0baadf85","not_after":1795474473,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5180","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- subscribe_raw im/v1/da885108-b8ab-46cf-b9c6-0ca580731548/dev-12e272bbdade8507/cmd/req: subscribe_result {"granted":false,"reason_code":135,"topic":"im/v1/da885108-b8ab-46cf-b9c6-0ca580731548/dev-12e272bbdade8507/cmd/req"}
- subscribe_raw im/v1/da885108-b8ab-46cf-b9c6-0ca580731548/dev-12e272bbdade8507/config: subscribe_result {"granted":false,"reason_code":135,"topic":"im/v1/da885108-b8ab-46cf-b9c6-0ca580731548/dev-12e272bbdade8507/config"}
- subscribe_raw im/v1/da885108-b8ab-46cf-b9c6-0ca580731548/#: subscribe_result {"granted":false,"reason_code":135,"topic":"im/v1/da885108-b8ab-46cf-b9c6-0ca580731548/#"}
- subscribe_raw im/v1/da885108-b8ab-46cf-b9c6-0ca580731548/+/cmd/req: subscribe_result {"granted":false,"reason_code":135,"topic":"im/v1/da885108-b8ab-46cf-b9c6-0ca580731548/+/cmd/req"}
- subscribe_raw im/v1/da885108-b8ab-46cf-b9c6-0ca580731548/dev-2d3205fb1d0b7fca/#: subscribe_result {"granted":false,"reason_code":135,"topic":"im/v1/da885108-b8ab-46cf-b9c6-0ca580731548/dev-2d3205fb1d0b7fca/#"}
- subscribe_raw #: subscribe_result {"granted":false,"reason_code":135,"topic":"#"}
- subscribe_raw $SYS/#: subscribe_result {"granted":false,"reason_code":135,"topic":"$SYS/#"}
- subscribe_raw $share/bridge/im/v1/#: subscribe_result {"granted":false,"reason_code":135,"topic":"$share/bridge/im/v1/#"}
- subscribe_raw im/v1/da885108-b8ab-46cf-b9c6-0ca580731548/dev-2d3205fb1d0b7fca/telemetry: subscribe_result {"granted":false,"reason_code":135,"topic":"im/v1/da885108-b8ab-46cf-b9c6-0ca580731548/dev-2d3205fb1d0b7fca/telemetry"}

### C-ACL-3 Retained publish on telemetry - pass

*Criterion:* rejected

| Measurement | Value |
|---|---|
| outcome | disconnected |
| outcome events (retained) | disconnected |

- DUT dev-420469ba4b67eae1 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 0d854a3192d78a8e63806434d10f5258
- enrolled {"cert_serial_hex":"67a9c346f651935d9c43446159e4c42c","not_after":1795474474,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5180","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- publish_raw im/v1/da885108-b8ab-46cf-b9c6-0ca580731548/dev-420469ba4b67eae1/telemetry retain=true: first event publish_result {"ok":false,"reason_code":128,"topic":"im/v1/da885108-b8ab-46cf-b9c6-0ca580731548/dev-420469ba4b67eae1/telemetry"}; publish_result {"ok":false,"reason_code":128,"topic":"im/v1/da885108-b8ab-46cf-b9c6-0ca580731548/dev-420469ba4b67eae1/telemetry"}; policy authz allowed=false
- publish_raw im/v1/da885108-b8ab-46cf-b9c6-0ca580731548/dev-420469ba4b67eae1/events retain=true: first event publish_result {"ok":false,"reason_code":128,"topic":"im/v1/da885108-b8ab-46cf-b9c6-0ca580731548/dev-420469ba4b67eae1/events"}; publish_result {"ok":false,"reason_code":128,"topic":"im/v1/da885108-b8ab-46cf-b9c6-0ca580731548/dev-420469ba4b67eae1/events"}; policy authz allowed=false

### C-OTA-1 Unsigned image - pass

*Criterion:* `ota_state{state=rejected}`; active slot unchanged

| Measurement | Value |
|---|---|
| final_state | rejected |
| error | unsigned |
| artifact_downloads | 0 |

- DUT dev-553d24e09e01d760 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 71002480a5de319677f991d04142b6de
- enrolled {"cert_serial_hex":"2bbd9fb5df7b294ec35c8eef2da33d29","not_after":1795474475,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5180","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- OtaNotify campaign 4d49ae47-4a63-4b93-af03-59fcb6cdc9a0: version_code 101, image 49664 B sha256 9cda2235d9ba61d1eecfbf35fa33f4126f5ece209ceeab9d9a5743a6ee47e3bb, served 49664 B
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

- DUT dev-3aec5d35b530a929 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 1323b019f5149378dfd47667c586b326
- enrolled {"cert_serial_hex":"5f2fccc4f9d4f8fdfb87b02c0618708d","not_after":1795474476,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5180","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- OtaNotify campaign 3eef3547-cb4d-4da8-b2b3-6b6c46bd4068: version_code 101, image 49664 B sha256 9cda2235d9ba61d1eecfbf35fa33f4126f5ece209ceeab9d9a5743a6ee47e3bb, served 49664 B
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

- DUT dev-931f1e71d988ba57 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 2f37338008ab6c439c2cb7c4cda9a60b
- enrolled {"cert_serial_hex":"7f5f850930bf7b6698f13d0026ce57c3","not_after":1795474477,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5180","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- OtaNotify campaign d43da9a4-15f6-49db-bad1-709037c636ec: version_code 101, image 49664 B sha256 9cda2235d9ba61d1eecfbf35fa33f4126f5ece209ceeab9d9a5743a6ee47e3bb, served 49664 B
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

- DUT dev-e30e80bd02125da5 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 313f5dd815e5c7486b89d2ddaebea09f
- enrolled {"cert_serial_hex":"5f94de7bedcf890b03b96fdba9b76153","not_after":1795474478,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5180","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- OtaNotify campaign 967706e2-44be-4e2e-a77e-039d4034d641: version_code 100, image 49664 B sha256 9cda2235d9ba61d1eecfbf35fa33f4126f5ece209ceeab9d9a5743a6ee47e3bb, served 49664 B
- ota_state sequence: ["received", "rejected(downgrade)"]
- ota_slots before {"active_slot":"a","pending_slot":null,"slots":[{"name":"a","sha256_hex":"4cb2d74483ab36b04aff112fc132c1d86c5017c460e151f6ddce991541119e13","state":"valid","version":"1.0.0","version_code":100},{"name":"b","sha256_hex":"","state":"empty","version":"","version_code":0}]} after {"active_slot":"a","pending_slot":null,"slots":[{"name":"a","sha256_hex":"4cb2d74483ab36b04aff112fc132c1d86c5017c460e151f6ddce991541119e13","state":"valid","version":"1.0.0","version_code":100},{"name":"b","sha256_hex":"","state":"empty","version":"","version_code":0}]}
- signed OtaStatus uplinks (state, error): [(0, None), (7, Some("MF_ROLLBACK"))]

### C-OTA-5 Valid update applies and is marked healthy - pass

*Criterion:* `rebooted{reason=ota_apply}`, new `version_code`, `ota_state=success`

| Measurement | Value |
|---|---|
| new_version_code | 101 |
| image_sha256 | 38a75ec340d75debddaf93f02cde6099b90d0dda7f073b9d249412a46a56a558 |

- DUT dev-0a307fceb6aaa3f5 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 5fd3e8ecee3e34f12a3ff25208266a30
- enrolled {"cert_serial_hex":"49e0f6c8d9c4d68c5ec3a27b906098d3","not_after":1795474480,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5180","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- OtaNotify campaign bd22719d-c5c6-4e1c-a77d-6634e7b25916: version_code 101, image 53329 B sha256 38a75ec340d75debddaf93f02cde6099b90d0dda7f073b9d249412a46a56a558, served 53329 B
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

- DUT dev-eb2f676ef2cb6d8a (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 0b187220374b4cfc1fe14f1c9d5b19f9
- enrolled {"cert_serial_hex":"152c0b6647e73d7a33f22a92333da497","not_after":1795474480,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5180","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- OtaNotify campaign 70c22579-fe05-48a2-a7e7-389e8f892f41: version_code 101, image 49852 B sha256 d707cc4e82429a8ad6fb618fd6094621f2f7752dbba674d826ece0426835f281, served 49852 B
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

- DUT dev-194b9682c6911700 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 01476124a5acc48fbd4732dae6e2ac7c
- enrolled {"cert_serial_hex":"27c0f42461e8f1083d460dadea7eb910","not_after":1795474496,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5180","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- delta base: the factory image (hash verified against ota_slots)
- OtaNotify campaign 308b3ab3-0d2f-424d-bdc9-69b0d60b70d3: version_code 101, image 53361 B sha256 dc8ef08b09eb854409e8e32e8fb3663b8f5eaf544a80198f2633ab183c588f5a, served 16650 B (IMDELTA1 patch)
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

- DUT dev-55d032da40ac44ce (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 59fb5f908ea9dee8e4f38a2db162307c
- enrolled {"cert_serial_hex":"47be62ac5fbd09738dbd4d6f73a74881","not_after":1795474496,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5180","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- original seq 1000: command_executed {"cmd_id":"c77f73de-754b-4688-8c5f-a8ff411acc9a","status":0}
- signed CommandAck seq 2 echoes cmd_id and nonce
- message_rejected {"code":"ENV_REPLAY","topic":"im/v1/da885108-b8ab-46cf-b9c6-0ca580731548/dev-55d032da40ac44ce/cmd/req"}

### C-RPL-2 Command with stale timestamp - pass

*Criterion:* `message_rejected{code=ENV_TS_SKEW}`

| Measurement | Value |
|---|---|
| rejection_code | ENV_TS_SKEW |
| rejection_code | ENV_TS_SKEW |

- DUT dev-46bf1bb3105dc1cd (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 45fd0af2fb867f85566c55783b8fc337
- enrolled {"cert_serial_hex":"570dde87368d1fb83269188f6e92b306","not_after":1795474498,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5180","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- command seq 1001 with ts = now - 400 s (window 300 s)
- message_rejected {"code":"ENV_TS_SKEW","topic":"im/v1/da885108-b8ab-46cf-b9c6-0ca580731548/dev-46bf1bb3105dc1cd/cmd/req"}
- message_rejected {"code":"ENV_TS_SKEW","topic":"im/v1/da885108-b8ab-46cf-b9c6-0ca580731548/dev-46bf1bb3105dc1cd/cmd/req"}

### C-RPL-3 Command signed by a non-tenant key - pass

*Criterion:* `message_rejected{code=COSE_SIGNATURE}`

| Measurement | Value |
|---|---|
| rejection_code | COSE_SIGNATURE |

- DUT dev-3aab55b5e8a9a1e7 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 41454ca5c842eba52436ef4a0daddbd6
- enrolled {"cert_serial_hex":"7970b1e9866b88d979100227fbb9529c","not_after":1795474501,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5180","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- command seq 1003 with kid tenant-cmd-<tenant> signed by a non-tenant Ed25519 key
- message_rejected {"code":"COSE_SIGNATURE","topic":"im/v1/da885108-b8ab-46cf-b9c6-0ca580731548/dev-3aab55b5e8a9a1e7/cmd/req"}
- a genuine command with the forged seq was executed afterwards (store not advanced by the forgery)

### C-RPL-4 Device `seq` strictly increases across reboot - pass

*Criterion:* `status.seq_out` after reboot > before

| Measurement | Value |
|---|---|
| seq_out_before | 5 |
| seq_out_after | 6 |
| last_seq_sent_before | 4 |
| first_seq_sent_after | 6 |

- DUT dev-563f4c9ab52a14f8 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 31ad58b8e8b14264adb9dab0eebf08af
- enrolled {"cert_serial_hex":"374d7d0808428765cefdf74d1349b76d","not_after":1795474503,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5180","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- rebooted {"active_slot":"a","reason":"requested","version_code":100}
- telemetry seqs on the wire: [2, 3, 4, 6]

### C-OFF-1 Offline buffering and resync - pass

*Criterion:* telemetry sent while `net_down` is delivered after `net_up`, in order, no gaps, `buffer_flushed`

| Measurement | Value |
|---|---|
| buffered_and_flushed | 25 |
| telemetry_on_wire | 32 |

- DUT dev-c717bf0c2698ae3d (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 55dfb03859590d3a3121117bc49a0812
- enrolled {"cert_serial_hex":"51f0faa0d1f71208f8810df4c183c09f","not_after":1795474503,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5180","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
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

- DUT dev-5d1cdc91c88e1f64 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 0143f0a679404724a53366a70c99ecc8
- enrolled {"cert_serial_hex":"01965bf0890db9bc791e726a56c99982","not_after":1795474505,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:5180","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- Config v7 (tenant-signed, seq 1000) HPKE-wrapped to the certificate key of 01965bf0890db9bc791e726a56c99982, published retained
- config_applied {"version":7}
- re-delivery: message_rejected {"code":"ENV_REPLAY","topic":"im/v1/da885108-b8ab-46cf-b9c6-0ca580731548/dev-5d1cdc91c88e1f64/config"}
- config wrapped to a foreign key: message_rejected {"code":"HPKE_OPEN","topic":"im/v1/da885108-b8ab-46cf-b9c6-0ca580731548/dev-5d1cdc91c88e1f64/config"}

### C-HOOK-1 Release build has no control channel - pass

*Criterion:* release `agent-rs` exits non-zero on `--dut`

| Measurement | Value |
|---|---|
| exit_code | 2 |

- C:\Users\mgoma\Desktop\Security Assignments\IoT-Security-Framework\conformance\target\duts\agent-rs-release\release\ironmesh-agent.exe --dut -> exit Some(2); stderr: ironmesh-agent: the DUT control channel is not compiled into this build (cargo feature `dut-control`); refusing --dut
