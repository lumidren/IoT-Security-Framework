# IronMesh conformance report: `esp32-host`

| | |
|---|---|
| Run started | 2026-11-09T20:44:24.1083713Z |
| Duration | 78 s |
| Git commit | `8904ed970ffcb9fbbf516fb6cd9b1d79c7509427 (working tree modified)` |
| Cloud mode | hermetic + real PKI |
| Host | MUSTAFAGOMAA (windows x86_64) |
| tenant_id | 275a7dc9-91de-40a2-8d47-7412a31004fc |
| run_dir | C:\Users\mgoma\Desktop\Security Assignments\IoT-Security-Framework\conformance\target\runs\esp32-host-1794257064 |
| policy_service | C:\Users\mgoma\Desktop\Security Assignments\IoT-Security-Framework\conformance\target\bin\policy.exe (sha256 2965de8111b46a59) |
| signing_keys | test-vector keys from C:\Users\mgoma\Desktop\Security Assignments\IoT-Security-Framework\libs\python\ironmesh-wire\tests\keys |
| dut_binary | C:\Users\mgoma\Desktop\Security Assignments\IoT-Security-Framework\conformance\target\duts\esp32-host\debug\im-dut-shim.exe (sha256 bbfccb0e331ff831), real-network mode |
| pki_service | target/bin/pki.exe (sha256 a66e8ce986730a79): real PKI is the enrollment authority |
| product | sensor-esp32 |
| reconnect_backoff_clock_scale | 1 |
| ota_health_timeout_s | 120 |

**Result: 14 passed, 0 failed, 13 not applicable, 0 errors** (of 27).

| Case | Title | Verdict | Measured | Time |
|---|---|---|---|---|
| C-TLS-1 | mTLS handshake with valid operational cert | pass | tls_version: TLSv1.3, alpn mqtt | 0.3 s |
| C-TLS-2 | Broker presents cert from an unpinned CA (rogue broker) | pass |  | 0.5 s |
| C-TLS-3 | Broker offers TLS 1.2 only | pass |  | 0.3 s |
| C-TLS-4 | Session resumption on reconnect | pass | broker_observed_resumed: true | 0.4 s |
| C-TLS-5 | Bounded reconnect backoff | pass | attempts_observed: 5, max gap 5.977 s | 8.8 s |
| C-ENR-1 | Zero-touch enrollment with attestation | pass |  | 0.1 s |
| C-ENR-2 | Enrollment refused for quarantined device | pass | http_status: 403 | 0.1 s |
| C-ROT-1 | Certificate rotation (`renew`) keeps identity, changes key and serial | pass |  | 8.2 s |
| C-ROT-2 | Automatic rotation at 50 % lifetime (short-lived test certs) | n/a |  | 0.1 s |
| C-REV-1 | Revocation reaction time | pass | denied p50 0.364 s, p95 1.024 s, max 1.029 s | 43.4 s |
| C-ACL-1 | Publish to another device's topic | pass |  | 7.5 s |
| C-ACL-2 | Subscribe to another device's command topic or wildcard | pass |  | 0.4 s |
| C-ACL-3 | Retained publish on telemetry | pass |  | 3.8 s |
| C-OTA-1 | Unsigned image | n/a |  | 0.0 s |
| C-OTA-2 | Tampered image (1 byte flipped, valid manifest) | n/a |  | 0.0 s |
| C-OTA-3 | Manifest signed by an untrusted key | n/a |  | 0.0 s |
| C-OTA-4 | Downgrade (`version_code` not greater) | n/a |  | 0.0 s |
| C-OTA-5 | Valid update applies and is marked healthy | n/a |  | 0.0 s |
| C-OTA-6 | Update that fails its health check rolls back | n/a |  | 0.0 s |
| C-OTA-7 | Delta update | n/a |  | 0.0 s |
| C-RPL-1 | Replayed command (same `seq`) | n/a |  | 0.0 s |
| C-RPL-2 | Command with stale timestamp | n/a |  | 0.0 s |
| C-RPL-3 | Command signed by a non-tenant key | n/a |  | 0.0 s |
| C-RPL-4 | Device `seq` strictly increases across reboot | pass | seq_out 5 -> 18 | 0.2 s |
| C-OFF-1 | Offline buffering and resync | pass |  | 2.3 s |
| C-CFG-1 | Encrypted config delivery | n/a |  | 0.0 s |
| C-HOOK-1 | Release build has no control channel | n/a |  | 0.0 s |

## Revocation reaction time (C-REV-1)

Path: harness PKI revokes the certificate (CRL regenerated) and pushes the signed event to the **real** policy service (`POST /internal/v1/revocations`, bearer + `X-IronMesh-Signature` HMAC) -> policy deny-lists the device and calls the broker's EMQX management API `DELETE /api/v5/clients/{id}` -> session dropped -> the DUT's reconnect is refused by the real authn hook.

| Interval | Value |
|---|---|
| iterations | 20 |
| revoke -> policy 202 | p50 0.004 s, p95 0.014 s, max 0.014 s |
| revoke -> kick (EMQX API) | p50 0.004 s, p95 0.013 s, max 0.014 s |
| revoke -> broker disconnect | p50 0.004 s, p95 0.013 s, max 0.014 s |
| revoke -> DUT disconnected event | p50 0.020 s, p95 0.022 s, max 0.023 s |
| revoke -> reconnect denied (end to end) | p50 0.364 s, p95 1.024 s, max 1.029 s |

## OTA results

| Case | Verdict | Outcome | Evidence |
|---|---|---|---|
| C-OTA-1 | n/a |  |  |
| C-OTA-2 | n/a |  |  |
| C-OTA-3 | n/a |  |  |
| C-OTA-4 | n/a |  |  |
| C-OTA-5 | n/a |  |  |
| C-OTA-6 | n/a |  |  |
| C-OTA-7 | n/a |  |  |

## Case details

### C-TLS-1 mTLS handshake with valid operational cert - pass

*Criterion:* `connected` with `tls_version=TLSv1.3`, `alpn=mqtt`

| Measurement | Value |
|---|---|
| tls_version | TLSv1.3 |
| alpn | mqtt |

- DUT dev-7c41d0cd1b8d1b5f (esp32-host fw 1.0.0 code 10000, se_type software), bootstrap serial 79d75fce1e90eb4629f2689d04e77eae
- connected {"alpn":"mqtt","broker":"127.0.0.1","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- broker handshake: version Some("TLSv1.3"), alpn Some("mqtt"), client cert serial Some("c6c1c5aa29692200fc656e3bb4c0960b")
- CONNECT: client id = CN, clean_start=false, session_expiry=Some(604800), keep_alive=60, receive_maximum=Some(32); policy authn allow=true

### C-TLS-2 Broker presents cert from an unpinned CA (rogue broker) - pass

*Criterion:* `connect_failed{reason=tls_pin_mismatch}`; no CONNECT packet observed

| Measurement | Value |
|---|---|
| RogueUnknownCa: connect_failed.reason | tls_pin_mismatch |
| RogueUnknownCa: CONNECT packets observed | 0 |
| Rogue: connect_failed.reason | tls_pin_mismatch |
| Rogue: CONNECT packets observed | 0 |

- DUT dev-92f07f982fee16f6 (esp32-host fw 1.0.0 code 10000, se_type software), bootstrap serial f29a6b91fff7dbef2b24dffd32d60787
- broker mode RogueUnknownCa: connect_failed {"reason":"tls_pin_mismatch"}
- broker-side handshakes in mode RogueUnknownCa: ["ok=false version=None error=Some(\"received fatal alert: UnknownCA\")"]
- broker mode Rogue: connect_failed {"reason":"tls_pin_mismatch"}
- broker-side handshakes in mode Rogue: ["ok=false version=None error=Some(\"received fatal alert: UnknownCA\")"]

### C-TLS-3 Broker offers TLS 1.2 only - pass

*Criterion:* `connect_failed{reason=tls_handshake}`

| Measurement | Value |
|---|---|
| Tls12Only: connect_failed.reason | tls_handshake |
| Tls12Only: CONNECT packets observed | 0 |

- DUT dev-7f2b150a9b13d152 (esp32-host fw 1.0.0 code 10000, se_type software), bootstrap serial 142f87e6fe6e24af65ec4ee295bbb6ab
- broker mode Tls12Only: connect_failed {"reason":"tls_handshake"}
- broker-side handshakes in mode Tls12Only: ["ok=false version=None error=Some(\"peer is incompatible: Tls12NotOfferedOrEnabled\")"]

### C-TLS-4 Session resumption on reconnect - pass

*Criterion:* second `connected.resumed=true` (where the target supports tickets)

| Measurement | Value |
|---|---|
| dut_reported_resumed | true |
| broker_observed_resumed | true |
| session_present | true |

- DUT dev-a7afacb9b68916fa (esp32-host fw 1.0.0 code 10000, se_type software), bootstrap serial ee93af7e9cf2c59dbf754e5f6fcd90a9
- enrolled {"cert_serial_hex":"d981737158bffa5b301fd6bb8e20fece","not_after":1795466667,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- second connected {"alpn":"mqtt","broker":"127.0.0.1","resumed":true,"session_present":true,"tls_version":"TLSv1.3"}
- target semantics: ticket offered (the broker-side resumed handshake is the criterion)

### C-TLS-5 Bounded reconnect backoff - pass

*Criterion:* reconnect attempts follow base 1 s, factor 2, cap 300 s, full jitter (verified on attempt timestamps with clock scaling)

| Measurement | Value |
|---|---|
| clock_scale | 1 |
| attempts_observed | 5 |
| max_gap_s | 5.977 |
| capped_gaps_checked | 0 |

- DUT dev-a579c3dedb054a93 (esp32-host fw 1.0.0 code 10000, se_type software), bootstrap serial de52e60de65e6db8a9d06845d2ccfe75
- enrolled {"cert_serial_hex":"1c2ae4d337c7be6581643cdb6b6f1cc0","not_after":1795466667,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- connect_failed reasons (first 3): ["not_authorized", "not_authorized", "not_authorized"]; status.state=backoff observed: true
- gap_k <= min(300, 2^k) x scale [s]: 0.390<=1.000, 0.044<=2.000, 0.928<=4.000, 1.237<=8.000, 5.977<=16.000
- **warning:** no clock scaling on this target: bound and jitter verified for 5 attempts (up to 16 s); the 300 s cap was not reached

### C-ENR-1 Zero-touch enrollment with attestation - pass

*Criterion:* `enrolled`; harness verifies attestation, CSR CN, fresh key

| Measurement | Value |
|---|---|
| issued_serial | 50052bf38b6716b3d64c9eed6c5cd739 |
| attestation_verified_by | services/pki EST handler (real PKI) |

- DUT dev-6626a72584c3a5b2 (esp32-host fw 1.0.0 code 10000, se_type software), bootstrap serial 7ceaf63a3603b890b62a76cf5049e5d3
- enrolled {"cert_serial_hex":"50052bf38b6716b3d64c9eed6c5cd739","not_after":1795466676,"se_type":"software"}
- issued by the real PKI: subject O=IronMesh, OU=assurance:software + OU=275a7dc9-91de-40a2-8d47-7412a31004fc, CN=dev-6626a72584c3a5b2, issuer O=IronMesh, CN=IronMesh Device CA, SAN ["urn:ironmesh:tenant:275a7dc9-91de-40a2-8d47-7412a31004fc:device:dev-6626a72584c3a5b2"]
- PKI record: {"assurance_level":"software","device_id":"dev-6626a72584c3a5b2","issuer":"IronMesh Device CA","kind":"operational","not_after":"2026-11-23T20:44:36Z","not_before":"2026-11-09T20:44:36Z","serial":"50052bf38b6716b3d64c9eed6c5cd739","status":"valid","tenant_id":"275a7dc9-91de-40a2-8d47-7412a31004fc"}

### C-ENR-2 Enrollment refused for quarantined device - pass

*Criterion:* `enroll_failed{http_status=403}`

| Measurement | Value |
|---|---|
| http_status | 403 |

- DUT dev-44bc851f18314c9a (esp32-host fw 1.0.0 code 10000, se_type software), bootstrap serial ff780e736fec4c28013b1bacab409431
- enroll_failed {"http_status":403,"reason":"device lifecycle state \"quarantined\" does not permit enrollment\n"}

### C-ROT-1 Certificate rotation (`renew`) keeps identity, changes key and serial - pass

*Criterion:* `cert_renewed`, new serial, new SPKI, reconnect succeeds

| Measurement | Value |
|---|---|
| old_serial | 0f7f41abc5c6d721f616a180e0495f2c |
| new_serial | 6164acfbd1d6d7c1f540a9b90cc10f97 |
| spki_changed | true |
| reconnected_automatically | false |

- DUT dev-b52b0aa804268e7a (esp32-host fw 1.0.0 code 10000, se_type software), bootstrap serial 15d40a1fff18779396b7e7f49bd919d3
- enrolled {"cert_serial_hex":"0f7f41abc5c6d721f616a180e0495f2c","not_after":1795466676,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- cert_renewed {"new_serial_hex":"6164acfbd1d6d7c1f540a9b90cc10f97","not_after":1795466676,"old_serial_hex":"0f7f41abc5c6d721f616a180e0495f2c"}
- telemetry seq 3 verified with the renewed key (kid 6164acfbd1d6d7c1f540a9b90cc10f97)

### C-ROT-2 Automatic rotation at 50 % lifetime (short-lived test certs) - n/a

*Criterion:* `cert_renewed` without an explicit `renew`

**Reason:** short-lived operational certificates (the real PKI bounds PKI_OPERATIONAL_CERT_TTL to 168h-720h) needs the in-process EST server (the real PKI handles EST in this run)

- DUT dev-eefa0d962848145b (esp32-host fw 1.0.0 code 10000, se_type software), bootstrap serial d78a9dd7bd2d9c55d50cf1088d803a9f

### C-REV-1 Revocation reaction time - pass

*Criterion:* revoke -> broker disconnect -> DUT cannot reconnect with the revoked cert, measured < 10 s

| Measurement | Value |
|---|---|
| iterations | 20 |
| revoke -> policy 202 | p50 0.004 s, p95 0.014 s, max 0.014 s |
| revoke -> kick (EMQX API) | p50 0.004 s, p95 0.013 s, max 0.014 s |
| revoke -> broker disconnect | p50 0.004 s, p95 0.013 s, max 0.014 s |
| revoke -> DUT disconnected event | p50 0.020 s, p95 0.022 s, max 0.023 s |
| revoke -> reconnect denied (end to end) | p50 0.364 s, p95 1.024 s, max 1.029 s |

- DUT dev-3553e6d3b3b583aa (esp32-host fw 1.0.0 code 10000, se_type software), bootstrap serial d2622436a15ea5d54cfb29fab223a2be
- enrolled {"cert_serial_hex":"1ae94b7d3c90fb5ff8d8691230bd37d3","not_after":1795466685,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- revocation path: real PKI POST /v1/certificates/{serial}/revoke (ES256 JWT) -> PKI publisher -> real policy -> EMQX API kick
- DUT disconnected {"reason":"broker","reason_code":152} then connect_failed {"reason":"not_authorized"}
- reconnect with revoked serial Some("1ae94b7d3c90fb5ff8d8691230bd37d3") answered CONNACK 0x87 by the policy authn hook
- DUT dev-3ccd9dd79a8fa6ff (esp32-host fw 1.0.0 code 10000, se_type software), bootstrap serial d8d4ea1d361aeb2f33a7018ae820ae80
- enrolled {"cert_serial_hex":"c0fe281025a78dec77035a02c4ab80b6","not_after":1795466686,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-06e4692b2e01b480 (esp32-host fw 1.0.0 code 10000, se_type software), bootstrap serial 515ce5e87c6f9a433aaa9d6005310572
- enrolled {"cert_serial_hex":"4d78d23d159809404a6e08cb900d6dd2","not_after":1795466688,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-b9f650fbaa9f8f56 (esp32-host fw 1.0.0 code 10000, se_type software), bootstrap serial b607c0f04e2d2ff572069a502316fe1f
- enrolled {"cert_serial_hex":"9291fe893d37c488be39e953cf2103c8","not_after":1795466690,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-069ad84dedc51b6e (esp32-host fw 1.0.0 code 10000, se_type software), bootstrap serial 3fe1257d1af15d2253f3cf94102ebcf3
- enrolled {"cert_serial_hex":"3b2a958a09b6c9b52ca7f904f5b8f1dd","not_after":1795466693,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-db8592c94df5cf4d (esp32-host fw 1.0.0 code 10000, se_type software), bootstrap serial c1930cd4f8e67cf0e538a168cd3bdd08
- enrolled {"cert_serial_hex":"c0f7a41ac74c9a6186200fdbdeac36c7","not_after":1795466695,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-636ff72a90777ab9 (esp32-host fw 1.0.0 code 10000, se_type software), bootstrap serial d6ee68629b0aaccf0962f8e3f7439463
- enrolled {"cert_serial_hex":"a1810b1380a0dd66700e214c27fec0fc","not_after":1795466697,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-41ed9b3f3988763f (esp32-host fw 1.0.0 code 10000, se_type software), bootstrap serial 0cd670e02033214b61d883fefdc88ed9
- enrolled {"cert_serial_hex":"752ec30f4cda9a55587acedf0e94596f","not_after":1795466700,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-a1047f7e198c8492 (esp32-host fw 1.0.0 code 10000, se_type software), bootstrap serial a983e279e782ea948d5276b8cc06af1d
- enrolled {"cert_serial_hex":"27251a2ef3976dbfb00a499274f68e6d","not_after":1795466702,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-d2d27c2f2065edeb (esp32-host fw 1.0.0 code 10000, se_type software), bootstrap serial 0c76daa49df30f85a29da33bf084dec5
- enrolled {"cert_serial_hex":"2c49e44de24e2bc5991bb8b0d0cf5eff","not_after":1795466703,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-9c59118688112ea6 (esp32-host fw 1.0.0 code 10000, se_type software), bootstrap serial 7725e2bef10712bfd27016cab98a1c37
- enrolled {"cert_serial_hex":"55b37afd866819e5e3b1ac026568b4cc","not_after":1795466706,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-5e2f599b7f6ed6f9 (esp32-host fw 1.0.0 code 10000, se_type software), bootstrap serial 306d78d409d4c04df7e851721815f03d
- enrolled {"cert_serial_hex":"5b4d5c0804c2af2c9a010647adbe4c55","not_after":1795466708,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-89d31c1f117606ba (esp32-host fw 1.0.0 code 10000, se_type software), bootstrap serial 875f142950fe6c83c70a3d22ab436c09
- enrolled {"cert_serial_hex":"a5d53148c14b828dddc65afe8561d331","not_after":1795466711,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-e790983f43cbbbf9 (esp32-host fw 1.0.0 code 10000, se_type software), bootstrap serial 8f16d348b2e67cd6a5c5067f824bd130
- enrolled {"cert_serial_hex":"054afccdff4f11759110fec98cc4dca3","not_after":1795466713,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-97249ed8ca96b8c4 (esp32-host fw 1.0.0 code 10000, se_type software), bootstrap serial b00290cf7f9e5991cd7a18791d050c72
- enrolled {"cert_serial_hex":"617160d6ad9192d9a5857d28e4380124","not_after":1795466715,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-92345905adf5ccf1 (esp32-host fw 1.0.0 code 10000, se_type software), bootstrap serial f048f632e4d262c17104794a0bc9b241
- enrolled {"cert_serial_hex":"7783dd3b7caf93fa3274c2b85dd28ba6","not_after":1795466717,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-5c63ff285e4fd348 (esp32-host fw 1.0.0 code 10000, se_type software), bootstrap serial fbba62130d8a88c997fe82f15a4d58cd
- enrolled {"cert_serial_hex":"0703674b8a7327236ee3a299c66d06ad","not_after":1795466720,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-e18e59d3427c3287 (esp32-host fw 1.0.0 code 10000, se_type software), bootstrap serial de17c0bd7a9c162bde7fb4895c86fa11
- enrolled {"cert_serial_hex":"53b11bad193ce229698d28560a84d2c5","not_after":1795466722,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-87f3c439b6a82799 (esp32-host fw 1.0.0 code 10000, se_type software), bootstrap serial f63ea16aa791eb0d62f50ed2d0c6d05d
- enrolled {"cert_serial_hex":"e617e70504d429c84a600ad1456e6d0b","not_after":1795466724,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-0b2374c99fe22eed (esp32-host fw 1.0.0 code 10000, se_type software), bootstrap serial 4518c7024cc4d03999ff60cc2fb262db
- enrolled {"cert_serial_hex":"145e0f93bcd8a9325c314f7a829971e9","not_after":1795466726,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- policy /metrics: ironmesh_kick_total{result=ok} +20, ironmesh_revocation_latency_seconds count 20 sum 0.049 s (mean 0.002 s, revoked_at -> kick)
- policy log: {"ts":"2026-11-09T22:45:26.471906+02:00","level":"info","msg":"revoked session kicked","service":"policy","device_id":"dev-0b2374c99fe22eed","tenant_id":"275a7dc9-91de-40a2-8d47-7412a31004fc","event_id":"5d382ff5-2d74-431c-a617-787b4583c7c5

### C-ACL-1 Publish to another device's topic - pass

*Criterion:* `publish_result.ok=false` (or disconnect) and harness subscriber receives nothing

| Measurement | Value |
|---|---|
| outcome im/v1/275a7dc9-91de-40a2-8d47-7412a31004fc/dev-c0e6e66e95edd139/telemetry | disconnected |
| outcome im/v1/275a7dc9-91de-40a2-8d47-7412a31004fc/dev-c0e6e66e95edd139/cmd/ack | disconnected |
| outcome im/v1/b9d9d14f-e973-4010-84a8-634dc5443d44/dev-b7ba7f514adbe8b9/telemetry | disconnected |
| outcome im/v1/275a7dc9-91de-40a2-8d47-7412a31004fc/dev-b7ba7f514adbe8b9/cmd/req | disconnected |

- DUT dev-b7ba7f514adbe8b9 (esp32-host fw 1.0.0 code 10000, se_type software), bootstrap serial ffa5e5c6242d463b7c58dc02c85d3bac
- enrolled {"cert_serial_hex":"86fe64007cc850098fb9fa1967f92bc5","not_after":1795466728,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- publish_raw im/v1/275a7dc9-91de-40a2-8d47-7412a31004fc/dev-c0e6e66e95edd139/telemetry retain=false: first event disconnected {"reason":"broker","reason_code":135}; publish_result (none); policy authz allowed=false
- publish_raw im/v1/275a7dc9-91de-40a2-8d47-7412a31004fc/dev-c0e6e66e95edd139/cmd/ack retain=false: first event disconnected {"reason":"broker","reason_code":135}; publish_result (none); policy authz allowed=false
- publish_raw im/v1/b9d9d14f-e973-4010-84a8-634dc5443d44/dev-b7ba7f514adbe8b9/telemetry retain=false: first event disconnected {"reason":"broker","reason_code":135}; publish_result (none); policy authz allowed=false
- publish_raw im/v1/275a7dc9-91de-40a2-8d47-7412a31004fc/dev-b7ba7f514adbe8b9/cmd/req retain=false: first event disconnected {"reason":"broker","reason_code":135}; publish_result (none); policy authz allowed=false

### C-ACL-2 Subscribe to another device's command topic or wildcard - pass

*Criterion:* `subscribe_result.granted=false`

| Measurement | Value |
|---|---|
| reason_code im/v1/275a7dc9-91de-40a2-8d47-7412a31004fc/dev-165832819b769900/cmd/req | 135 |
| reason_code im/v1/275a7dc9-91de-40a2-8d47-7412a31004fc/dev-165832819b769900/config | 135 |
| reason_code im/v1/275a7dc9-91de-40a2-8d47-7412a31004fc/# | 135 |
| reason_code im/v1/275a7dc9-91de-40a2-8d47-7412a31004fc/+/cmd/req | 135 |
| reason_code im/v1/275a7dc9-91de-40a2-8d47-7412a31004fc/dev-e1c58215a88b991d/# | 135 |
| reason_code # | 135 |
| reason_code $SYS/# | 135 |
| reason_code $share/bridge/im/v1/# | 135 |
| reason_code im/v1/275a7dc9-91de-40a2-8d47-7412a31004fc/dev-e1c58215a88b991d/telemetry | 135 |

- DUT dev-e1c58215a88b991d (esp32-host fw 1.0.0 code 10000, se_type software), bootstrap serial ecace9fe72588b0ae986e16be45719cb
- enrolled {"cert_serial_hex":"d7dc6651b18be3297a520ef27e03121f","not_after":1795466735,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- subscribe_raw im/v1/275a7dc9-91de-40a2-8d47-7412a31004fc/dev-165832819b769900/cmd/req: subscribe_result {"granted":false,"reason_code":135,"topic":"im/v1/275a7dc9-91de-40a2-8d47-7412a31004fc/dev-165832819b769900/cmd/req"}
- subscribe_raw im/v1/275a7dc9-91de-40a2-8d47-7412a31004fc/dev-165832819b769900/config: subscribe_result {"granted":false,"reason_code":135,"topic":"im/v1/275a7dc9-91de-40a2-8d47-7412a31004fc/dev-165832819b769900/config"}
- subscribe_raw im/v1/275a7dc9-91de-40a2-8d47-7412a31004fc/#: subscribe_result {"granted":false,"reason_code":135,"topic":"im/v1/275a7dc9-91de-40a2-8d47-7412a31004fc/#"}
- subscribe_raw im/v1/275a7dc9-91de-40a2-8d47-7412a31004fc/+/cmd/req: subscribe_result {"granted":false,"reason_code":135,"topic":"im/v1/275a7dc9-91de-40a2-8d47-7412a31004fc/+/cmd/req"}
- subscribe_raw im/v1/275a7dc9-91de-40a2-8d47-7412a31004fc/dev-e1c58215a88b991d/#: subscribe_result {"granted":false,"reason_code":135,"topic":"im/v1/275a7dc9-91de-40a2-8d47-7412a31004fc/dev-e1c58215a88b991d/#"}
- subscribe_raw #: subscribe_result {"granted":false,"reason_code":135,"topic":"#"}
- subscribe_raw $SYS/#: subscribe_result {"granted":false,"reason_code":135,"topic":"$SYS/#"}
- subscribe_raw $share/bridge/im/v1/#: subscribe_result {"granted":false,"reason_code":135,"topic":"$share/bridge/im/v1/#"}
- subscribe_raw im/v1/275a7dc9-91de-40a2-8d47-7412a31004fc/dev-e1c58215a88b991d/telemetry: subscribe_result {"granted":false,"reason_code":135,"topic":"im/v1/275a7dc9-91de-40a2-8d47-7412a31004fc/dev-e1c58215a88b991d/telemetry"}

### C-ACL-3 Retained publish on telemetry - pass

*Criterion:* rejected

| Measurement | Value |
|---|---|
| outcome | disconnected |
| outcome events (retained) | disconnected |

- DUT dev-732809f2c280ff4a (esp32-host fw 1.0.0 code 10000, se_type software), bootstrap serial d722be561e72b17f6f114ca11d937344
- enrolled {"cert_serial_hex":"0cec08521c94c3309cdc054c4a9dbd01","not_after":1795466736,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- publish_raw im/v1/275a7dc9-91de-40a2-8d47-7412a31004fc/dev-732809f2c280ff4a/telemetry retain=true: first event disconnected {"reason":"broker","reason_code":135}; publish_result (none); policy authz allowed=false
- publish_raw im/v1/275a7dc9-91de-40a2-8d47-7412a31004fc/dev-732809f2c280ff4a/events retain=true: first event disconnected {"reason":"broker","reason_code":135}; publish_result (none); policy authz allowed=false

### C-OTA-1 Unsigned image - n/a

*Criterion:* `ota_state{state=rejected}`; active slot unchanged

**Reason:** the real PKI with its in-memory store issues trust bundles without tenant_cmd_pubkey / fw_signing_pubkeys (no API provisions a tenant policy), so devices must and do reject every downlink and update


### C-OTA-2 Tampered image (1 byte flipped, valid manifest) - n/a

*Criterion:* `ota_state{state=rejected, error=image_hash}`

**Reason:** the real PKI with its in-memory store issues trust bundles without tenant_cmd_pubkey / fw_signing_pubkeys (no API provisions a tenant policy), so devices must and do reject every downlink and update


### C-OTA-3 Manifest signed by an untrusted key - n/a

*Criterion:* rejected

**Reason:** the real PKI with its in-memory store issues trust bundles without tenant_cmd_pubkey / fw_signing_pubkeys (no API provisions a tenant policy), so devices must and do reject every downlink and update


### C-OTA-4 Downgrade (`version_code` not greater) - n/a

*Criterion:* rejected

**Reason:** the real PKI with its in-memory store issues trust bundles without tenant_cmd_pubkey / fw_signing_pubkeys (no API provisions a tenant policy), so devices must and do reject every downlink and update


### C-OTA-5 Valid update applies and is marked healthy - n/a

*Criterion:* `rebooted{reason=ota_apply}`, new `version_code`, `ota_state=success`

**Reason:** the real PKI with its in-memory store issues trust bundles without tenant_cmd_pubkey / fw_signing_pubkeys (no API provisions a tenant policy), so devices must and do reject every downlink and update


### C-OTA-6 Update that fails its health check rolls back - n/a

*Criterion:* `rebooted{reason=rollback}`, previous slot active, `ota_state=rolled_back`

**Reason:** the real PKI with its in-memory store issues trust bundles without tenant_cmd_pubkey / fw_signing_pubkeys (no API provisions a tenant policy), so devices must and do reject every downlink and update


### C-OTA-7 Delta update - n/a

*Criterion:* applied image hash equals full image hash

**Reason:** the real PKI with its in-memory store issues trust bundles without tenant_cmd_pubkey / fw_signing_pubkeys (no API provisions a tenant policy), so devices must and do reject every downlink and update


### C-RPL-1 Replayed command (same `seq`) - n/a

*Criterion:* `message_rejected{code=ENV_REPLAY}`; command not executed twice

**Reason:** the real PKI with its in-memory store issues trust bundles without tenant_cmd_pubkey / fw_signing_pubkeys (no API provisions a tenant policy), so devices must and do reject every downlink and update


### C-RPL-2 Command with stale timestamp - n/a

*Criterion:* `message_rejected{code=ENV_TS_SKEW}`

**Reason:** the real PKI with its in-memory store issues trust bundles without tenant_cmd_pubkey / fw_signing_pubkeys (no API provisions a tenant policy), so devices must and do reject every downlink and update


### C-RPL-3 Command signed by a non-tenant key - n/a

*Criterion:* `message_rejected{code=COSE_SIGNATURE}`

**Reason:** the real PKI with its in-memory store issues trust bundles without tenant_cmd_pubkey / fw_signing_pubkeys (no API provisions a tenant policy), so devices must and do reject every downlink and update


### C-RPL-4 Device `seq` strictly increases across reboot - pass

*Criterion:* `status.seq_out` after reboot > before

| Measurement | Value |
|---|---|
| seq_out_before | 5 |
| seq_out_after | 18 |
| last_seq_sent_before | 4 |
| first_seq_sent_after | 18 |

- DUT dev-64c5f405b4af7277 (esp32-host fw 1.0.0 code 10000, se_type software), bootstrap serial 5ce84d164b4ca628b19474682a71bf78
- enrolled {"cert_serial_hex":"0e3720205d77dd3af61787ac8d07273e","not_after":1795466740,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- rebooted {"active_slot":"ota_0","reason":"requested","version_code":10000}
- telemetry seqs on the wire: [2, 18]

### C-OFF-1 Offline buffering and resync - pass

*Criterion:* telemetry sent while `net_down` is delivered after `net_up`, in order, no gaps, `buffer_flushed`

| Measurement | Value |
|---|---|
| buffered_and_flushed | 25 |
| telemetry_on_wire | 32 |

- DUT dev-03be2490d4224dab (esp32-host fw 1.0.0 code 10000, se_type software), bootstrap serial 68ab284300f4c89e34a1dc068e7f9041
- enrolled {"cert_serial_hex":"dc496a2fabc26de5def5b00696bb0de1","not_after":1795466740,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- net_down -> disconnected {"reason":"network","reason_code":0}
- offline send_telemetry 25 -> {"first_seq":4,"last_seq":28}, status.buffered=25
- net_up -> buffer_flushed {"count":25,"first_seq":4,"last_seq":28}
- telemetry seqs on the wire (32): [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33]

### C-CFG-1 Encrypted config delivery - n/a

*Criterion:* DUT applies config; retained broker copy is ciphertext only

**Reason:** the real PKI with its in-memory store issues trust bundles without tenant_cmd_pubkey / fw_signing_pubkeys (no API provisions a tenant policy), so devices must and do reject every downlink and update


### C-HOOK-1 Release build has no control channel - n/a

*Criterion:* release `agent-rs` exits non-zero on `--dut`

**Reason:** C-HOOK-1 is defined for the agent-rs release binary. On ESP32 the channel is excluded at build time: the prod profile forces CONFIG_IRONMESH_DUT_CONTROL=n (checked by device/esp32/tools/check_prod_config.py in CI); the esp32-host shim and the hil profile are test builds by definition

