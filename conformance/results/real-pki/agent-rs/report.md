# IronMesh conformance report: `agent-rs`

| | |
|---|---|
| Run started | 2026-11-09T20:43:15.397666Z |
| Duration | 68 s |
| Git commit | `8904ed970ffcb9fbbf516fb6cd9b1d79c7509427 (working tree modified)` |
| Cloud mode | hermetic + real PKI |
| Host | MUSTAFAGOMAA (windows x86_64) |
| tenant_id | a93c5393-cb7f-4179-810e-2a40f05dad44 |
| run_dir | C:\Users\mgoma\Desktop\Security Assignments\IoT-Security-Framework\conformance\target\runs\agent-rs-1794256995 |
| policy_service | C:\Users\mgoma\Desktop\Security Assignments\IoT-Security-Framework\conformance\target\bin\policy.exe (sha256 2965de8111b46a59) |
| signing_keys | test-vector keys from C:\Users\mgoma\Desktop\Security Assignments\IoT-Security-Framework\libs\python\ironmesh-wire\tests\keys |
| dut_binary | C:\Users\mgoma\Desktop\Security Assignments\IoT-Security-Framework\conformance\target\duts\agent-rs-dut\debug\ironmesh-agent.exe (sha256 ac3501f8013546ad) |
| release_binary | C:\Users\mgoma\Desktop\Security Assignments\IoT-Security-Framework\conformance\target\duts\agent-rs-release\release\ironmesh-agent.exe (sha256 1ddff3aeeb44f9dd) |
| pki_service | target/bin/pki.exe (sha256 a66e8ce986730a79): real PKI is the enrollment authority |
| product | gateway-rpi |
| reconnect_backoff_clock_scale | 0.02 |
| ota_health_timeout_s | 15 |

**Result: 15 passed, 0 failed, 12 not applicable, 0 errors** (of 27).

| Case | Title | Verdict | Measured | Time |
|---|---|---|---|---|
| C-TLS-1 | mTLS handshake with valid operational cert | pass | tls_version: TLSv1.3, alpn mqtt | 1.8 s |
| C-TLS-2 | Broker presents cert from an unpinned CA (rogue broker) | pass |  | 0.7 s |
| C-TLS-3 | Broker offers TLS 1.2 only | pass |  | 0.5 s |
| C-TLS-4 | Session resumption on reconnect | pass | broker_observed_resumed: true | 0.5 s |
| C-TLS-5 | Bounded reconnect backoff | pass | attempts_observed: 13, max gap 5.671 s | 18.6 s |
| C-ENR-1 | Zero-touch enrollment with attestation | pass |  | 0.3 s |
| C-ENR-2 | Enrollment refused for quarantined device | pass | http_status: 403 | 0.2 s |
| C-ROT-1 | Certificate rotation (`renew`) keeps identity, changes key and serial | pass |  | 0.4 s |
| C-ROT-2 | Automatic rotation at 50 % lifetime (short-lived test certs) | n/a |  | 0.2 s |
| C-REV-1 | Revocation reaction time | pass | denied p50 0.009 s, p95 0.028 s, max 0.028 s | 36.3 s |
| C-ACL-1 | Publish to another device's topic | pass |  | 1.7 s |
| C-ACL-2 | Subscribe to another device's command topic or wildcard | pass |  | 0.3 s |
| C-ACL-3 | Retained publish on telemetry | pass |  | 1.0 s |
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
| C-RPL-4 | Device `seq` strictly increases across reboot | pass | seq_out 5 -> 6 | 0.4 s |
| C-OFF-1 | Offline buffering and resync | pass |  | 1.4 s |
| C-CFG-1 | Encrypted config delivery | n/a |  | 0.0 s |
| C-HOOK-1 | Release build has no control channel | pass | exit_code: 2 | 0.2 s |

## Revocation reaction time (C-REV-1)

Path: harness PKI revokes the certificate (CRL regenerated) and pushes the signed event to the **real** policy service (`POST /internal/v1/revocations`, bearer + `X-IronMesh-Signature` HMAC) -> policy deny-lists the device and calls the broker's EMQX management API `DELETE /api/v5/clients/{id}` -> session dropped -> the DUT's reconnect is refused by the real authn hook.

| Interval | Value |
|---|---|
| iterations | 20 |
| revoke -> policy 202 | p50 0.004 s, p95 0.015 s, max 0.015 s |
| revoke -> kick (EMQX API) | p50 0.004 s, p95 0.015 s, max 0.015 s |
| revoke -> broker disconnect | p50 0.004 s, p95 0.015 s, max 0.015 s |
| revoke -> DUT disconnected event | p50 0.006 s, p95 0.016 s, max 0.016 s |
| revoke -> reconnect denied (end to end) | p50 0.009 s, p95 0.028 s, max 0.028 s |

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

- DUT dev-ca651ed022a5d3b0 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 68acec9fb211ae41acbc3a22f17da374
- connected {"alpn":"mqtt","broker":"127.0.0.1:54113","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- broker handshake: version Some("TLSv1.3"), alpn Some("mqtt"), client cert serial Some("654fd4dd41f6be9adc39af8dccb30dc1")
- CONNECT: client id = CN, clean_start=false, session_expiry=Some(604800), keep_alive=60, receive_maximum=Some(32); policy authn allow=true

### C-TLS-2 Broker presents cert from an unpinned CA (rogue broker) - pass

*Criterion:* `connect_failed{reason=tls_pin_mismatch}`; no CONNECT packet observed

| Measurement | Value |
|---|---|
| RogueUnknownCa: connect_failed.reason | tls_pin_mismatch |
| RogueUnknownCa: CONNECT packets observed | 0 |
| Rogue: connect_failed.reason | tls_pin_mismatch |
| Rogue: CONNECT packets observed | 0 |

- DUT dev-07650205a984ba69 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 7bb0f11d1da2452d81d530e01f625922
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

- DUT dev-ba751802b0bf57cb (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 440ab7a297f0d7d9df25219f5536bfcd
- broker mode Tls12Only: connect_failed {"detail":"received fatal alert: ProtocolVersion","reason":"tls_handshake"}
- broker-side handshakes in mode Tls12Only: ["ok=false version=None error=Some(\"peer is incompatible: Tls12NotOfferedOrEnabled\")"]

### C-TLS-4 Session resumption on reconnect - pass

*Criterion:* second `connected.resumed=true` (where the target supports tickets)

| Measurement | Value |
|---|---|
| dut_reported_resumed | true |
| broker_observed_resumed | true |
| session_present | true |

- DUT dev-d0f0c76cf0f5c201 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial a0785ea7ca82605703a662abc1936a82
- enrolled {"cert_serial_hex":"7adc360ae9bae5e781e6efc55f8de72d","not_after":1795466601,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:54113","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- second connected {"alpn":"mqtt","broker":"127.0.0.1:54113","resumed":true,"session_present":true,"tls_version":"TLSv1.3"}

### C-TLS-5 Bounded reconnect backoff - pass

*Criterion:* reconnect attempts follow base 1 s, factor 2, cap 300 s, full jitter (verified on attempt timestamps with clock scaling)

| Measurement | Value |
|---|---|
| clock_scale | 0.02 |
| attempts_observed | 13 |
| max_gap_s | 5.671 |
| capped_gaps_checked | 4 |

- DUT dev-0c952310512eddeb (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 97dba8e48fa7d1c3d68042d006d3b4b2
- enrolled {"cert_serial_hex":"40e2cd49e69b14e79ef0280c2fb52619","not_after":1795466602,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:54113","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- connect_failed reasons (first 3): ["not_authorized", "not_authorized", "not_authorized"]; status.state=backoff observed: true
- gap_k <= min(300, 2^k) x scale [s]: 0.002<=0.020, 0.020<=0.040, 0.006<=0.080, 0.081<=0.160, 0.065<=0.320, 0.095<=0.640, 0.034<=1.280, 0.083<=2.560, 1.980<=5.120, 3.650<=6.000, 3.357<=6.000, 3.166<=6.000, 5.671<=6.000

### C-ENR-1 Zero-touch enrollment with attestation - pass

*Criterion:* `enrolled`; harness verifies attestation, CSR CN, fresh key

| Measurement | Value |
|---|---|
| issued_serial | 8092445c5a2d76070902d7a04c3b128e |
| attestation_verified_by | services/pki EST handler (real PKI) |

- DUT dev-6ec4012d8d11535a (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial d4afc59b0cfcd14e31bb5eb291f1b6ec
- enrolled {"cert_serial_hex":"8092445c5a2d76070902d7a04c3b128e","not_after":1795466620,"se_type":"software"}
- issued by the real PKI: subject O=IronMesh, OU=assurance:software + OU=a93c5393-cb7f-4179-810e-2a40f05dad44, CN=dev-6ec4012d8d11535a, issuer O=IronMesh, CN=IronMesh Device CA, SAN ["urn:ironmesh:tenant:a93c5393-cb7f-4179-810e-2a40f05dad44:device:dev-6ec4012d8d11535a"]
- PKI record: {"assurance_level":"software","device_id":"dev-6ec4012d8d11535a","issuer":"IronMesh Device CA","kind":"operational","not_after":"2026-11-23T20:43:40Z","not_before":"2026-11-09T20:43:40Z","serial":"8092445c5a2d76070902d7a04c3b128e","status":"valid","tenant_id":"a93c5393-cb7f-4179-810e-2a40f05dad44"}
- **warning:** a fresh, never-enrolled device reports status.state="offline" (DUT_PROTOCOL: unprovisioned = no usable certificate)

### C-ENR-2 Enrollment refused for quarantined device - pass

*Criterion:* `enroll_failed{http_status=403}`

| Measurement | Value |
|---|---|
| http_status | 403 |

- DUT dev-f4154cc425935a09 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial e22f7c6eb5b1583d35b72733424e07cd
- enroll_failed {"http_status":403,"reason":"device lifecycle state \"quarantined\" does not permit enrollment"}

### C-ROT-1 Certificate rotation (`renew`) keeps identity, changes key and serial - pass

*Criterion:* `cert_renewed`, new serial, new SPKI, reconnect succeeds

| Measurement | Value |
|---|---|
| old_serial | 2e51102126a30bd571a36542a8931cb0 |
| new_serial | 367a46d496b780c2a05a60456637e464 |
| spki_changed | true |
| reconnected_automatically | true |

- DUT dev-d123b009ad3999b1 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 6a2b9bc037ebd02cad435caf46c1881f
- enrolled {"cert_serial_hex":"2e51102126a30bd571a36542a8931cb0","not_after":1795466621,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:54113","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- cert_renewed {"new_serial_hex":"367a46d496b780c2a05a60456637e464","not_after":1795466621,"old_serial_hex":"2e51102126a30bd571a36542a8931cb0"}
- telemetry seq 3 verified with the renewed key (kid 367a46d496b780c2a05a60456637e464)

### C-ROT-2 Automatic rotation at 50 % lifetime (short-lived test certs) - n/a

*Criterion:* `cert_renewed` without an explicit `renew`

**Reason:** short-lived operational certificates (the real PKI bounds PKI_OPERATIONAL_CERT_TTL to 168h-720h) needs the in-process EST server (the real PKI handles EST in this run)

- DUT dev-01738c879da768c7 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 725b82182c6f4c0cc398d3cea93e5486

### C-REV-1 Revocation reaction time - pass

*Criterion:* revoke -> broker disconnect -> DUT cannot reconnect with the revoked cert, measured < 10 s

| Measurement | Value |
|---|---|
| iterations | 20 |
| revoke -> policy 202 | p50 0.004 s, p95 0.015 s, max 0.015 s |
| revoke -> kick (EMQX API) | p50 0.004 s, p95 0.015 s, max 0.015 s |
| revoke -> broker disconnect | p50 0.004 s, p95 0.015 s, max 0.015 s |
| revoke -> DUT disconnected event | p50 0.006 s, p95 0.016 s, max 0.016 s |
| revoke -> reconnect denied (end to end) | p50 0.009 s, p95 0.028 s, max 0.028 s |

- DUT dev-801e60f6fbac04d1 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial f3e3672e94acc792a7c586ce240e4c06
- enrolled {"cert_serial_hex":"e64b80956dff4064d30e1a5e6244f98d","not_after":1795466621,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:54113","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- revocation path: real PKI POST /v1/certificates/{serial}/revoke (ES256 JWT) -> PKI publisher -> real policy -> EMQX API kick
- DUT disconnected {"reason":"broker DISCONNECT 0x98 ","reason_code":152} then connect_failed {"detail":"CONNACK reason 0x87 ","reason":"not_authorized"}
- reconnect with revoked serial Some("e64b80956dff4064d30e1a5e6244f98d") answered CONNACK 0x87 by the policy authn hook
- DUT dev-7bd211f17bcf3ab5 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial bacdd538be75b7d90b14ae3e68fcccb6
- enrolled {"cert_serial_hex":"a4ba8343e52d19d17d181ce62fa0e26a","not_after":1795466623,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:54113","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-49bf855894ac4d2c (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 870ac213312d9366df4436727344c3f8
- enrolled {"cert_serial_hex":"8c34cdfb22d0c768d543f9a3c3906b72","not_after":1795466625,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:54113","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-bf2c75878f9b2c3f (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 4a4d1f7bbba20944217e1abea10243bd
- enrolled {"cert_serial_hex":"6080142846b4a0878597b730dcbe3c75","not_after":1795466627,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:54113","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-9734309a2047624a (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 9f675d38ba4f55c8e9df9407db211572
- enrolled {"cert_serial_hex":"e86601fe145e72bdfdc40fc9f891b0d8","not_after":1795466629,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:54113","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-c1a2f226d29d833e (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 8b1f508bd6a84d2590c14c60dffa092c
- enrolled {"cert_serial_hex":"da6725c33481ceb6bc9bf74b9d51c5cd","not_after":1795466630,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:54113","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-6bcd744de00d0b3f (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 7d5d052b36fb4c497124fedaa911cfee
- enrolled {"cert_serial_hex":"066821465190185df5fa407c69cd4b21","not_after":1795466632,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:54113","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-8ded8efde3150140 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 3a2a2f6ff9f3dcd25bc7e2c5e9428d05
- enrolled {"cert_serial_hex":"68375727efec94c88a4f423f933f73f8","not_after":1795466634,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:54113","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-01881f1c773c854c (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 3bb8653b967292ab0342aae3284e3548
- enrolled {"cert_serial_hex":"e697f5f1f2c36b47be68ef612fb89bf6","not_after":1795466636,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:54113","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-928bbf61da73e441 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial dea06565b4ae72a6ff222d78c6a3e5fc
- enrolled {"cert_serial_hex":"3b4f897cdda32ef1e9ffd3175a1012a3","not_after":1795466638,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:54113","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-b99d87141c80cce4 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 50ee9d3aee335f36d6971d605e2c78ad
- enrolled {"cert_serial_hex":"d25cb8ef465c28290ea5d05e705d1c0e","not_after":1795466639,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:54113","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-6bf0fd5c569b2fc7 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial b69c108106b32cdf651f802692391e13
- enrolled {"cert_serial_hex":"a8bba60bd3ad76d70d71b7fbd494c032","not_after":1795466641,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:54113","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-312206af05a05eb8 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 204e1623c377bdf68c3fa48c10949368
- enrolled {"cert_serial_hex":"285dec73ca2c65802d795607d73e16a2","not_after":1795466643,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:54113","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-1a9c0a1c9b35d5e8 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 955f0691a7175ab505470a19e63fc4d5
- enrolled {"cert_serial_hex":"4f9097ef3b66a8875284935b0afe8125","not_after":1795466645,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:54113","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-8b2eb46f99678cce (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial cc05c3628db4166f34c8b736ea570f75
- enrolled {"cert_serial_hex":"e8cff1d3e7a24d09f84e8bff1de46f77","not_after":1795466647,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:54113","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-286b664ae76b9859 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 0c3bf08851f4e3a22f7ebb897a74ec0b
- enrolled {"cert_serial_hex":"b6fbc1790ef419820a7bcf58e36de5f0","not_after":1795466649,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:54113","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-8b6d4bb9ca1e97ed (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 6685b39c4593a17f1f7a698ed7870ade
- enrolled {"cert_serial_hex":"7917ce886d59af3197d138459aafc84f","not_after":1795466650,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:54113","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-27648d408d829997 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial d80c2cd65bcc535a812ebdfeb209ed16
- enrolled {"cert_serial_hex":"c01fcfab31d561a8c81599c10f8f3170","not_after":1795466652,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:54113","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-dccba30745cb30ff (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial d97d2b04697fe7492e3a8cc5b701ddfe
- enrolled {"cert_serial_hex":"2288e1b584c8e4bab0841a981b4b2be4","not_after":1795466654,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:54113","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- DUT dev-f579633cd125f51b (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial c9de2dda5bde1d170be0eecb7eb441f6
- enrolled {"cert_serial_hex":"5f237aa1e3c1382fb1cb90b4215b82e5","not_after":1795466656,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:54113","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- policy /metrics: ironmesh_kick_total{result=ok} +20, ironmesh_revocation_latency_seconds count 20 sum 0.050 s (mean 0.003 s, revoked_at -> kick)
- policy log: {"ts":"2026-11-09T22:44:16.3989034+02:00","level":"info","msg":"revoked session kicked","service":"policy","device_id":"dev-f579633cd125f51b","tenant_id":"a93c5393-cb7f-4179-810e-2a40f05dad44","event_id":"c59ac3f3-eb6d-47d7-a6c6-5760fba03a2

### C-ACL-1 Publish to another device's topic - pass

*Criterion:* `publish_result.ok=false` (or disconnect) and harness subscriber receives nothing

| Measurement | Value |
|---|---|
| outcome im/v1/a93c5393-cb7f-4179-810e-2a40f05dad44/dev-4b395aa2ce902276/telemetry | disconnected |
| outcome im/v1/a93c5393-cb7f-4179-810e-2a40f05dad44/dev-4b395aa2ce902276/cmd/ack | disconnected |
| outcome im/v1/c8e7d493-9e27-4a00-b929-5323be93a47e/dev-2275f3deaf513052/telemetry | disconnected |
| outcome im/v1/a93c5393-cb7f-4179-810e-2a40f05dad44/dev-2275f3deaf513052/cmd/req | disconnected |

- DUT dev-2275f3deaf513052 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 1bb38a29e11b8598fafd113245b2bcc4
- enrolled {"cert_serial_hex":"52ad660f7e16b6d0c7f3742f01030465","not_after":1795466658,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:54113","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- publish_raw im/v1/a93c5393-cb7f-4179-810e-2a40f05dad44/dev-4b395aa2ce902276/telemetry retain=false: first event publish_result {"ok":false,"reason_code":128,"topic":"im/v1/a93c5393-cb7f-4179-810e-2a40f05dad44/dev-4b395aa2ce902276/telemetry"}; publish_result {"ok":false,"reason_code":128,"topic":"im/v1/a93c5393-cb7f-4179-810e-2a40f05dad44/dev-4b395aa2ce902276/telemetry"}; policy authz allowed=false
- publish_raw im/v1/a93c5393-cb7f-4179-810e-2a40f05dad44/dev-4b395aa2ce902276/cmd/ack retain=false: first event publish_result {"ok":false,"reason_code":128,"topic":"im/v1/a93c5393-cb7f-4179-810e-2a40f05dad44/dev-4b395aa2ce902276/cmd/ack"}; publish_result {"ok":false,"reason_code":128,"topic":"im/v1/a93c5393-cb7f-4179-810e-2a40f05dad44/dev-4b395aa2ce902276/cmd/ack"}; policy authz allowed=false
- publish_raw im/v1/c8e7d493-9e27-4a00-b929-5323be93a47e/dev-2275f3deaf513052/telemetry retain=false: first event disconnected {"reason":"broker DISCONNECT 0x87 ","reason_code":135}; publish_result {"ok":false,"reason_code":128,"topic":"im/v1/c8e7d493-9e27-4a00-b929-5323be93a47e/dev-2275f3deaf513052/telemetry"}; policy authz allowed=false
- publish_raw im/v1/a93c5393-cb7f-4179-810e-2a40f05dad44/dev-2275f3deaf513052/cmd/req retain=false: first event publish_result {"ok":false,"reason_code":128,"topic":"im/v1/a93c5393-cb7f-4179-810e-2a40f05dad44/dev-2275f3deaf513052/cmd/req"}; publish_result {"ok":false,"reason_code":128,"topic":"im/v1/a93c5393-cb7f-4179-810e-2a40f05dad44/dev-2275f3deaf513052/cmd/req"}; policy authz allowed=false

### C-ACL-2 Subscribe to another device's command topic or wildcard - pass

*Criterion:* `subscribe_result.granted=false`

| Measurement | Value |
|---|---|
| reason_code im/v1/a93c5393-cb7f-4179-810e-2a40f05dad44/dev-4a33a686b7af995d/cmd/req | 135 |
| reason_code im/v1/a93c5393-cb7f-4179-810e-2a40f05dad44/dev-4a33a686b7af995d/config | 135 |
| reason_code im/v1/a93c5393-cb7f-4179-810e-2a40f05dad44/# | 135 |
| reason_code im/v1/a93c5393-cb7f-4179-810e-2a40f05dad44/+/cmd/req | 135 |
| reason_code im/v1/a93c5393-cb7f-4179-810e-2a40f05dad44/dev-3f2299487105a000/# | 135 |
| reason_code # | 135 |
| reason_code $SYS/# | 135 |
| reason_code $share/bridge/im/v1/# | 135 |
| reason_code im/v1/a93c5393-cb7f-4179-810e-2a40f05dad44/dev-3f2299487105a000/telemetry | 135 |

- DUT dev-3f2299487105a000 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 3450f63ed5a35ee656e32a37a07c224c
- enrolled {"cert_serial_hex":"aa0143513c080170ea17c0101714ad85","not_after":1795466659,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:54113","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- subscribe_raw im/v1/a93c5393-cb7f-4179-810e-2a40f05dad44/dev-4a33a686b7af995d/cmd/req: subscribe_result {"granted":false,"reason_code":135,"topic":"im/v1/a93c5393-cb7f-4179-810e-2a40f05dad44/dev-4a33a686b7af995d/cmd/req"}
- subscribe_raw im/v1/a93c5393-cb7f-4179-810e-2a40f05dad44/dev-4a33a686b7af995d/config: subscribe_result {"granted":false,"reason_code":135,"topic":"im/v1/a93c5393-cb7f-4179-810e-2a40f05dad44/dev-4a33a686b7af995d/config"}
- subscribe_raw im/v1/a93c5393-cb7f-4179-810e-2a40f05dad44/#: subscribe_result {"granted":false,"reason_code":135,"topic":"im/v1/a93c5393-cb7f-4179-810e-2a40f05dad44/#"}
- subscribe_raw im/v1/a93c5393-cb7f-4179-810e-2a40f05dad44/+/cmd/req: subscribe_result {"granted":false,"reason_code":135,"topic":"im/v1/a93c5393-cb7f-4179-810e-2a40f05dad44/+/cmd/req"}
- subscribe_raw im/v1/a93c5393-cb7f-4179-810e-2a40f05dad44/dev-3f2299487105a000/#: subscribe_result {"granted":false,"reason_code":135,"topic":"im/v1/a93c5393-cb7f-4179-810e-2a40f05dad44/dev-3f2299487105a000/#"}
- subscribe_raw #: subscribe_result {"granted":false,"reason_code":135,"topic":"#"}
- subscribe_raw $SYS/#: subscribe_result {"granted":false,"reason_code":135,"topic":"$SYS/#"}
- subscribe_raw $share/bridge/im/v1/#: subscribe_result {"granted":false,"reason_code":135,"topic":"$share/bridge/im/v1/#"}
- subscribe_raw im/v1/a93c5393-cb7f-4179-810e-2a40f05dad44/dev-3f2299487105a000/telemetry: subscribe_result {"granted":false,"reason_code":135,"topic":"im/v1/a93c5393-cb7f-4179-810e-2a40f05dad44/dev-3f2299487105a000/telemetry"}

### C-ACL-3 Retained publish on telemetry - pass

*Criterion:* rejected

| Measurement | Value |
|---|---|
| outcome | disconnected |
| outcome events (retained) | disconnected |

- DUT dev-1c785b3bb7d8c525 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 5eec35a98c1f844dcc857c2eb3445177
- enrolled {"cert_serial_hex":"f72c5e05eceaa65da8b17b93b78fc3f2","not_after":1795466660,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:54113","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- publish_raw im/v1/a93c5393-cb7f-4179-810e-2a40f05dad44/dev-1c785b3bb7d8c525/telemetry retain=true: first event publish_result {"ok":false,"reason_code":128,"topic":"im/v1/a93c5393-cb7f-4179-810e-2a40f05dad44/dev-1c785b3bb7d8c525/telemetry"}; publish_result {"ok":false,"reason_code":128,"topic":"im/v1/a93c5393-cb7f-4179-810e-2a40f05dad44/dev-1c785b3bb7d8c525/telemetry"}; policy authz allowed=false
- publish_raw im/v1/a93c5393-cb7f-4179-810e-2a40f05dad44/dev-1c785b3bb7d8c525/events retain=true: first event publish_result {"ok":false,"reason_code":128,"topic":"im/v1/a93c5393-cb7f-4179-810e-2a40f05dad44/dev-1c785b3bb7d8c525/events"}; publish_result {"ok":false,"reason_code":128,"topic":"im/v1/a93c5393-cb7f-4179-810e-2a40f05dad44/dev-1c785b3bb7d8c525/events"}; policy authz allowed=false

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
| seq_out_after | 6 |
| last_seq_sent_before | 4 |
| first_seq_sent_after | 6 |

- DUT dev-58fe0dfa5e47389d (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial 51c55466dd8bc6d4e82b83ada74a9ca6
- enrolled {"cert_serial_hex":"4cd18d8973212658a23014977559dcf6","not_after":1795466661,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:54113","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- rebooted {"active_slot":"a","reason":"requested","version_code":100}
- telemetry seqs on the wire: [2, 3, 4, 6]

### C-OFF-1 Offline buffering and resync - pass

*Criterion:* telemetry sent while `net_down` is delivered after `net_up`, in order, no gaps, `buffer_flushed`

| Measurement | Value |
|---|---|
| buffered_and_flushed | 25 |
| telemetry_on_wire | 32 |

- DUT dev-c4b6d7c31bc2a763 (agent-rs fw 1.0.0 code 100, se_type software), bootstrap serial c41cb0db32de3061efb950e01da13730
- enrolled {"cert_serial_hex":"2748423189f8fc38248a3db4c6735b8a","not_after":1795466661,"se_type":"software"}; connected {"alpn":"mqtt","broker":"127.0.0.1:54113","resumed":false,"session_present":false,"tls_version":"TLSv1.3"}
- net_down -> disconnected {"reason":"network down","reason_code":128}
- offline send_telemetry 25 -> {"first_seq":4,"last_seq":28}, status.buffered=25
- net_up -> buffer_flushed {"count":25,"first_seq":4,"last_seq":28}
- telemetry seqs on the wire (32): [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33]

### C-CFG-1 Encrypted config delivery - n/a

*Criterion:* DUT applies config; retained broker copy is ciphertext only

**Reason:** the real PKI with its in-memory store issues trust bundles without tenant_cmd_pubkey / fw_signing_pubkeys (no API provisions a tenant policy), so devices must and do reject every downlink and update


### C-HOOK-1 Release build has no control channel - pass

*Criterion:* release `agent-rs` exits non-zero on `--dut`

| Measurement | Value |
|---|---|
| exit_code | 2 |

- C:\Users\mgoma\Desktop\Security Assignments\IoT-Security-Framework\conformance\target\duts\agent-rs-release\release\ironmesh-agent.exe --dut -> exit Some(2); stderr: ironmesh-agent: the DUT control channel is not compiled into this build (cargo feature `dut-control`); refusing --dut
