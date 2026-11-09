# Device-Under-Test Control Protocol

The conformance suite drives every firmware target through this protocol. It is implemented by:

| Target           | Transport                                   | Build gate                                   |
|------------------|---------------------------------------------|----------------------------------------------|
| `agent-rs`       | stdin/stdout of `ironmesh-agent --dut`      | cargo feature `dut-control`                  |
| `esp32-host`     | stdin/stdout of the ESP32 protocol core host shim | always on (host build only)            |
| `esp32-hil`      | USB-Serial/JTAG, lines prefixed `@@IM `     | Kconfig `CONFIG_IRONMESH_DUT_CONTROL` (`hil` profile only) |

The control channel is a **test hook**. It is compiled out of release builds: the Rust release
pipeline builds without `dut-control`, and the ESP32 `prod` profile forces
`CONFIG_IRONMESH_DUT_CONTROL=n` (checked by `device/esp32/tools/check_prod_config.py` in CI). A
conformance test asserts that a release `agent-rs` binary rejects `--dut`.

## Framing

* One JSON object per line, UTF-8, `\n` terminated, max 64 KiB per line.
* On serial, every protocol line is prefixed with `@@IM ` so it can be separated from log output.
* Requests: `{"id": <u64>, "op": "<name>", "args": {...}}`.
* Responses: `{"id": <same>, "ok": true, "result": {...}}` or
  `{"id": <same>, "ok": false, "error": {"code": "<code>", "message": "..."}}`.
* Asynchronous events (no `id`): `{"event": "<name>", "at_ms": <monotonic ms>, "data": {...}}`.
* The DUT must answer every request within 5 s (operations that take longer return immediately and
  report completion through events).

## Operations

| op               | args                                              | result |
|------------------|---------------------------------------------------|--------|
| `hello`          | -                                                 | `{target, fw_version, fw_version_code, se_type, device_id, tenant_id, protocol_version: 1}` |
| `status`         | -                                                 | `{state, cert_serial_hex, cert_not_after, seq_out, buffered, active_slot, pending_slot, version_code, connected_broker}` with `state` in `unprovisioned, enrolling, connecting, connected, offline, backoff, rebooting` |
| `enroll`         | -                                                 | `{}`; emits `enrolled` or `enroll_failed` |
| `renew`          | -                                                 | `{}`; forces `simplereenroll` now; emits `cert_renewed` or `renew_failed` |
| `connect`        | -                                                 | `{}`; emits `connected` or `connect_failed` |
| `disconnect`     | -                                                 | `{}` |
| `net_down`       | -                                                 | `{}`; simulates link loss (no packets leave or arrive) |
| `net_up`         | -                                                 | `{}` |
| `send_telemetry` | `{count: u32}`                                    | `{first_seq, last_seq}`; buffered if offline |
| `publish_raw`    | `{topic, payload_b64, qos, retain}`               | `{}`; publishes bytes verbatim (ACL tests); emits `publish_result` |
| `subscribe_raw`  | `{topic}`                                         | `{}`; emits `subscribe_result {topic, granted: bool, reason_code}` |
| `ota_slots`      | -                                                 | `{active_slot, pending_slot, slots: [{name, version, version_code, sha256_hex, state}]}` |
| `reboot`         | -                                                 | `{}`; emits `rebooted` after restart |
| `rejections`     | `{since_ms?}`                                     | `{items: [{at_ms, code, topic, detail}]}` (wire error codes from `device/common/WIRE_FORMAT.md`) |
| `set_clock`      | `{unix_s}`                                        | `{}`; host targets only (timestamp-skew tests) |

Error codes for failed operations: `unsupported`, `busy`, `invalid_args`, `not_provisioned`,
`internal`.

## Events

| event              | data |
|--------------------|------|
| `enrolled`         | `{cert_serial_hex, not_after, se_type}` (`not_after` and every other timestamp field are Unix seconds) |
| `enroll_failed`    | `{http_status, reason}` |
| `cert_renewed`     | `{old_serial_hex, new_serial_hex, not_after}` |
| `renew_failed`     | `{http_status, reason}` |
| `connected`        | `{broker, tls_version, alpn, session_present, resumed}` |
| `connect_failed`   | `{reason}` where reason in `tls_pin_mismatch, tls_handshake, cert_rejected, not_authorized, network, timeout` |
| `disconnected`     | `{reason, reason_code}` |
| `publish_result`   | `{topic, ok, reason_code}` |
| `subscribe_result` | `{topic, granted, reason_code}` |
| `message_rejected` | `{topic, code}` (inbound message failed COSE/replay/skew/schema checks) |
| `command_executed` | `{cmd_id, status}` |
| `ota_state`        | `{campaign_id, state, error}` (state names per contract §5 OtaStatus; `error` is one of `unsigned`, `signature`, `untrusted_key`, `image_hash`, `downgrade`, `product`, `image_size`, `delta`, `health_check`, `download`, or empty) |
| `rebooted`         | `{active_slot, version_code, reason}` where reason in `requested, ota_apply, rollback, watchdog` |
| `buffer_flushed`   | `{count, first_seq, last_seq}` |

## Conformance cases (all targets)

| ID      | Case                                                                 | Pass criterion |
|---------|----------------------------------------------------------------------|----------------|
| C-TLS-1 | mTLS handshake with valid operational cert                           | `connected` with `tls_version=TLSv1.3`, `alpn=mqtt` |
| C-TLS-2 | Broker presents cert from an unpinned CA (rogue broker)              | `connect_failed{reason=tls_pin_mismatch}`; no CONNECT packet observed |
| C-TLS-3 | Broker offers TLS 1.2 only                                           | `connect_failed{reason=tls_handshake}` |
| C-TLS-4 | Session resumption on reconnect                                      | second `connected.resumed=true` (where the target supports tickets) |
| C-TLS-5 | Bounded reconnect backoff                                            | reconnect attempts follow base 1 s, factor 2, cap 300 s, full jitter (verified on attempt timestamps with clock scaling) |
| C-ENR-1 | Zero-touch enrollment with attestation                               | `enrolled`; harness verifies attestation, CSR CN, fresh key |
| C-ENR-2 | Enrollment refused for quarantined device                            | `enroll_failed{http_status=403}` |
| C-ROT-1 | Certificate rotation (`renew`) keeps identity, changes key and serial | `cert_renewed`, new serial, new SPKI, reconnect succeeds |
| C-ROT-2 | Automatic rotation at 50 % lifetime (short-lived test certs)         | `cert_renewed` without an explicit `renew` |
| C-REV-1 | Revocation reaction time                                             | revoke -> broker disconnect -> DUT cannot reconnect with the revoked cert, measured < 10 s |
| C-REV-2 | Single-certificate revocation refuses the serial, renewed certificate admitted | after `renew`, the superseded serial (single-certificate revocation, `device_deny=false`) is refused at CONNECT (policy reason `revoked_serial`) while the renewed certificate is admitted and its session is not kicked; a single-certificate revocation of the current serial refuses the device's own reconnect by serial within 10 s; the device id is never deny-listed |
| C-ACL-1 | Publish to another device's topic                                    | `publish_result.ok=false` (or disconnect) and harness subscriber receives nothing |
| C-ACL-2 | Subscribe to another device's command topic or wildcard              | `subscribe_result.granted=false` |
| C-ACL-3 | Retained publish on telemetry                                        | rejected |
| C-OTA-1 | Unsigned image                                                       | `ota_state{state=rejected}`; active slot unchanged |
| C-OTA-2 | Tampered image (1 byte flipped, valid manifest)                      | `ota_state{state=rejected, error=image_hash}` |
| C-OTA-3 | Manifest signed by an untrusted key                                  | rejected |
| C-OTA-4 | Downgrade (`version_code` not greater)                               | rejected |
| C-OTA-5 | Valid update applies and is marked healthy                           | `rebooted{reason=ota_apply}`, new `version_code`, `ota_state=success` |
| C-OTA-6 | Update that fails its health check rolls back                        | `rebooted{reason=rollback}`, previous slot active, `ota_state=rolled_back` |
| C-OTA-7 | Delta update                                                         | applied image hash equals full image hash |
| C-RPL-1 | Replayed command (same `seq`)                                        | `message_rejected{code=ENV_REPLAY}`; command not executed twice |
| C-RPL-2 | Command with stale timestamp                                         | `message_rejected{code=ENV_TS_SKEW}` |
| C-RPL-3 | Command signed by a non-tenant key                                   | `message_rejected{code=COSE_SIGNATURE}` |
| C-RPL-4 | Device `seq` strictly increases across reboot                        | `status.seq_out` after reboot > before |
| C-OFF-1 | Offline buffering and resync                                         | telemetry sent while `net_down` is delivered after `net_up`, in order, no gaps, `buffer_flushed` |
| C-CFG-1 | Encrypted config delivery                                            | DUT applies config; retained broker copy is ciphertext only |
| C-HOOK-1| Release build has no control channel                                 | release `agent-rs` exits non-zero on `--dut` |
