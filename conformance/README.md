# IronMesh device conformance suite

One suite, run unchanged against every firmware target through the DUT control protocol
([`DUT_PROTOCOL.md`](DUT_PROTOCOL.md)). It implements every case of the protocol's case table
(C-TLS-1..5, C-ENR-1..2, C-ROT-1..2, C-REV-1..2, C-ACL-1..3, C-OTA-1..7, C-RPL-1..4, C-OFF-1,
C-CFG-1, C-HOOK-1) and writes JUnit XML, a Markdown report with the measured values and a
machine-readable `results.json` per target, plus a cross-target [`results/SUMMARY.md`](results/SUMMARY.md).

Binding specifications: [`docs/DESIGN_CONTRACT.md`](../docs/DESIGN_CONTRACT.md),
[`device/common/WIRE_FORMAT.md`](../device/common/WIRE_FORMAT.md),
[`docs/API_CONTRACT.md`](../docs/API_CONTRACT.md) §4 and the DUT protocol.

```sh
cd conformance
cargo run --release -- run --target agent-rs              # results/agent-rs/{junit.xml,report.md,results.json}
cargo run --release -- run --target esp32-host            # results/esp32-host/...
cargo run --release -- run --target agent-rs --cases 'C-OTA-*,C-REV-1' --junit out.xml --report out.md
cargo run --release -- summary                            # regenerate results/SUMMARY.md
cargo run --release -- list                               # the case table
```

Missing binaries are built on first use (disable with `--no-build`): the policy service with
`go build ./services/policy/cmd/policy`, `ironmesh-agent` with `--features dut-control` (DUT) and in
`--release` without it (C-HOOK-1), and `im-dut-shim`. Everything is built into
`conformance/target/`, never into the device or service trees; `ironmesh-conformance build` builds
all of them, including the real PKI binaries for `--pki-bin`. Requirements: Rust stable, Go (on
Windows `C:\Program Files\Go\bin\go.exe` is used when `go` is not on `PATH`), MSVC for the ESP32 C
core. No Docker, no EMQX, no Postgres.

## Load test

`ironmesh-conformance load` runs N simulated devices (default 10 000) against the same hermetic
cloud and the real policy service. The devices run in a separate fleet process, built on the
agent-rs device stack. The command measures throughput, latency, policy decisions, errors and
CPU/RSS per process, and writes the results to `loadtest/results/`. The broker double runs in load
mode for this command: no observation log, topic-indexed routing and a keep-alive hook pool. See
[`../loadtest/README.md`](../loadtest/README.md) and [`../loadtest/REPORT.md`](../loadtest/REPORT.md).

## Architecture

```mermaid
flowchart LR
  subgraph suite["ironmesh-conformance (one process)"]
    cases["cases/*\nC-TLS ... C-HOOK"]
    dut["dut::Dut\n(line protocol, events)"]
    subgraph cloud["harness: hermetic cloud"]
      pki["TestPki (rcgen)\nRoot P-384, Factory P-384,\nDevice P-256, Services P-256,\nrogue CAs, bundle key"]
      est["EST server (RFC 7030)\n+ attestation verification\n+ X-IronMesh-Bundle"]
      broker["MQTT 5 broker double\nTLS 1.3 + mTLS + ALPN mqtt\nmodes: rogue CA, TLS 1.2,\nrefuse, PUBACK drop, session drop"]
      mgmt["EMQX management API\nDELETE /api/v5/clients/{id}"]
      reg["registry double\nlifecycle + manufacture record\nCRL distribution point"]
      art["HTTPS artifact server\n(OTA images / patches, Range)"]
      ota["artifact builder\nunsigned / tampered / untrusted /\ndowngrade / delta / valid"]
    end
  end
  policy["REAL policy service\n(go build ./services/policy/cmd/policy)\nsubprocess, temp state dir"]
  realpki["optional: REAL PKI service\n(--pki-bin, pkictl ceremony)"]
  agent["agent-rs\nironmesh-agent --dut"]
  shim["esp32-host\nim-dut-shim (real-network mode)\nESP32 C core"]
  hil["esp32-hil\nserial @@IM"]

  cases --> dut
  cases --> cloud
  dut -- stdin/stdout --> agent
  dut -- stdin/stdout --> shim
  dut -- serial --> hil
  agent & shim & hil -- "EST over TLS (mTLS)" --> est
  agent & shim & hil -- "MQTT 5 / TLS 1.3 / mTLS" --> broker
  agent & shim & hil -- HTTPS --> art
  broker -- "POST /emqx/authn (cert_pem + cert_serial), /emqx/authz\n(EMQX templates)" --> policy
  policy -- "GET /internal/v1/devices/{id}/lifecycle" --> reg
  policy -- "GET /crl/device-ca.crl (5 s)" --> reg
  cases -- "revoke: signed POST /internal/v1/revocations\n(bearer + X-IronMesh-Signature HMAC, device_deny)" --> policy
  cases -- "GET /v1/revocations\n(single-use ES256 JWT)" --> policy
  policy -- "kick" --> mgmt
  mgmt --> broker
  realpki -. "replaces EST + CA,\npublisher -> policy" .-> policy
```

| Path | What |
|------|------|
| `src/harness/pki.rs` | Contract §2 hierarchy with rcgen, certificate profiles mirroring `services/pki/internal/ca` (CN/OU/O, SAN URI, KU/EKU, CRL DP, AIA OCSP, 128-bit serials, `assurance:software` OU, bootstrap OU), rogue CAs, CRL, persistence for HIL |
| `src/harness/est.rs` | EST: `cacerts`, `csrattrs`, `ironmesh/nonce`, `simpleenroll`, `simplereenroll` with the checks of `services/pki/internal/est/handler.go`; records every request |
| `src/harness/broker.rs` | MQTT 5 broker double; every decision delegated to the real policy service; EMQX management API |
| `src/harness/policy.rs` | Policy subprocess (Device / Services CA files, JWT key, `POLICY_REQUIRE_CERT_SERIAL`), EMQX hook client, PKI event publisher (revocations with `device_deny`, `device_release`; HMAC-SHA256 + bearer), management API client, `/metrics` reader |
| `src/harness/jwt.rs` | ES256 service JWTs minted per request (`iss`/`sub`/`aud`/`iat`/`exp`/`jti`, 60 s), as the services mint them for each other |
| `src/harness/registry.rs` | Registry internal endpoints of API_CONTRACT §1.12 (lifecycle, PKI device lookup, assurance, `enrolled` with validation / `404` / `409`), admin `release` (§1.2) and the CRL distribution point |
| `src/harness/ota.rs`, `downlink.rs`, `keys.rs` | Manifests / signatures / IMDELTA1 patches, tenant-signed downlinks, HPKE Config wrap, uplink verification, test-vector keys |
| `src/harness/realpki.rs` | `--pki-bin`: real `pkictl` ceremony (CAs, bundle key, broker / artifact server / `svc-registry` / `svc-ota` certificates) + real `pki` service as the enrollment authority; tenant policy provisioned through its tenant-policy API |
| `src/harness/stack.rs` | `--stack`: the same cases against a real deployment |
| `src/dut/` | `Dut` handle, line-protocol transport (`link.rs`, stdio and `@@IM ` serial framing), launchers per target |
| `src/cases/` | One module per case family |
| `src/report/` | JUnit, Markdown report, SUMMARY |
| `src/load/` | Load test: orchestrator, fleet process, uplink verifier, sampler, statistics, report |

### Design decisions

* **Real policy service, faithful broker double.** The broker double renders the EMQX HTTP
  authn/authz request bodies exactly like `services/policy/deploy/emqx/emqx.conf` (strings for
  `qos`/`retain`, nested and flat `client_attrs`, `X-IronMesh-Hook-Token`, username = certificate
  CN, and in every authn call `cert_pem` = the PEM of the presented client certificate and
  `cert_serial` = its serial, as `mqtt.client_attrs_init` would set it from the TLS peer
  certificate) and implements `deny_action = disconnect`, `max_qos_allowed = 1`, retained
  messages, `clean_start=false` sessions and `DELETE /api/v5/clients/{clientid}` with HTTP basic
  auth. The policy service runs with its hardened defaults: `POLICY_REQUIRE_CERT_SERIAL=true`,
  `POLICY_DEVICE_CA_FILE` (Device CA) and `POLICY_SERVICES_CA_FILE` (Services CA) set, so every
  CONNECT is checked for issuer and revoked serial; `POLICY_JWT_PUBLIC_KEY_PEM` with single-use
  `jti` for the management API, which the harness calls with a freshly minted token per request
  (each run records that a replayed token is refused). Every CONNECT, PUBLISH and SUBSCRIBE in
  every case is therefore decided by the real Rego policy and the real revocation cache.
  Downlinks are published as `svc-registry`, whose CONNECT is authenticated once with a Services
  CA client certificate (`cert_pem` + `cert_serial`), and are authorized by the policy too
  (retained Config only works because the policy allows it).
* **Revocation events like the PKI publisher.** The harness's in-process authority sends the
  PKI's wire body: `{event_id, serial, device_id, tenant_id, reason, revoked_at, device_deny}`,
  `device_deny=false` for single-certificate revocations and `true` for revoke-all (quarantine),
  and `{event_id, event: "device_release", device_id, tenant_id, released_at}` for releases; the
  CRL carries the revocation reason.
* **C-REV-1 traverses the production code.** Revoke = CRL regenerated + the PKI publisher's request
  (`POST /internal/v1/revocations`, JSON event in the Go field order, `Authorization: Bearer`,
  `X-IronMesh-Signature: sha256=<hex HMAC-SHA256(body)>`, `X-IronMesh-Event-ID`) to the real policy
  service, which updates its cache and calls the EMQX management API on the broker double, which
  drops the session; the DUT's reconnect is refused by the real authn hook. The suite measures
  revoke -> policy 202, -> kick call, -> broker disconnect, -> DUT `disconnected`, -> first
  denied CONNECT, over 20 iterations (fresh device each), p50/p95/max, and asserts < 10 s.
* **Why the default EST server is in-process, and what `--pki-bin` adds.** The real PKI runs with
  the in-memory store and the file KMS (`pkictl` ceremony in a temp dir, see `realpki.rs`).
  Before any device enrolls the harness provisions the tenant policy through the PKI
  tenant-policy API the way the owning services do: `PUT /v1/tenants/{t}/command-key` and
  `/enrollment` as `svc-registry`, `PUT /v1/tenants/{t}/firmware-keys` as `svc-ota` (Services CA
  client certificates issued by the ceremony's `pkictl issue-server`, plus a single-use ES256 JWT
  whose `sub` names the same service). The PKI's bundles then carry the harness's command key and
  firmware key, so the downlink and OTA cases apply; the artifact server presents a certificate
  from the real Services CA. `PKI_SUPERSEDE_GRACE` is 5 s so the PKI's own supersede-on-renewal
  revocation is observed in C-REV-2. The remaining limit: `PKI_OPERATIONAL_CERT_TTL` is bounded to
  168h-720h, so C-ROT-2 cannot use short-lived certificates and stays `not_applicable` there. The
  in-process EST server mirrors the PKI's checks for the default run.
* **The wire code of the Rust agent is reused** (`ironmesh-agent` as a path dependency, default
  features off) for CBOR/COSE/envelopes/manifests/deltas/HPKE/MQTT codec. To make sure a bug there
  cannot hide, the harness unit tests reproduce the published deterministic vectors
  (`manifest_signed.json`, `envelope_command_ack.json`) byte for byte with the harness builders and
  keys, and every uplink the cases rely on is verified with the certificate key the broker saw.
* **Keys.** Tenant command key and firmware keys are the public test-vector keys of
  `libs/python/ironmesh-wire/tests/keys/` (so artifacts can be re-checked with the Python
  reference). C-RPL-3 forges with a random non-tenant key.
* **Fresh device per case** (and per C-REV-1 iteration): the policy's revocation deny list is
  persistent and keyed by device id, so cases never influence each other.
* **DUT configuration.** agent-rs gets `ota.base_url` (the artifact server) and
  `ota.allowed_hosts` (its host) besides the EST pins; the esp32-host shim gets `--est-pin` (the
  Services CA SPKI) and `--ota-host` (the artifact host), in hermetic, real-PKI and `--stack` runs
  (with `artifact_base_url` from the stack configuration).
* **Health-failing update (C-OTA-6).** The image is valid; the broker refuses every CONNECT of the
  new boot (CONNACK 0x88), so the contract health check (MQTT connected + telemetry acked within
  the deadline) cannot pass and the device must roll back by itself. agent-rs is configured with
  `ota.health_timeout_s = 15`; the ESP32 core has a fixed 120 s (`IM_OTA_HEALTH_TIMEOUT_MS`), so
  the case takes about 2 minutes there.
* **Clock scaling (C-TLS-5).** agent-rs runs with `mqtt.backoff_scale = 0.02` (base 20 ms, cap
  6 s), which lets the suite verify the cap; the ESP32 core has no scaling, so the bound, the
  growth and the jitter are verified over real-time attempts and the report states that the cap
  was not reached.
* **Resumption semantics (C-TLS-4).** agent-rs must report `resumed=true` and the broker must see a
  resumed handshake; for ESP32 targets the criterion is "ticket offered": the broker-side resumed
  handshake decides, the DUT flag is informational.

## How each case works

| Case | Procedure (fresh device, enroll + connect unless noted) | Cross-checks on the wire |
|------|------|------|
| C-TLS-1 | `connect` | broker: TLS 1.3, ALPN `mqtt`, operational cert presented, CONNECT client id = CN, policy authn allow; session parameters vs contract §4 (warnings) |
| C-TLS-2 | broker serves a rogue-CA certificate; `connect`; repeated with a rogue CA that impersonates the Services CA name | no CONNECT reached the broker; handshake failure logged |
| C-TLS-3 | broker offers TLS 1.2 only | no CONNECT |
| C-TLS-4 | `disconnect`, `connect` | broker-side resumed handshake; `session_present` |
| C-TLS-5 | broker refuses CONNECT (0x88) and drops the session; collect `connect_failed.at_ms` | gap_k <= min(300, 2^k) x scale (+ tolerance), growth, full jitter, cap (scaled targets) |
| C-ENR-1 | `enroll` | EST: bootstrap client cert, attestation kid = bootstrap serial, signature by the bootstrap key, nonce single use, CSR CN/OU, fresh key, se_type, issued serial / notAfter = event |
| C-ENR-2 | registry lifecycle `quarantined`, `enroll` | EST answered 403, nothing issued |
| C-ROT-1 | `renew` | `simplereenroll` with the operational cert, new serial, new SPKI, same CN; broker session with the new cert; telemetry kid = new serial and verifies with the new key |
| C-ROT-2 | 40 s certificates, wait | renewal at 50-60 % of the lifetime (EST timestamp), reconnect |
| C-REV-1 | revoke (real policy path above), 20 iterations | kick, broker disconnect, denied CONNECT, no re-admission; policy `/metrics` and log |
| C-REV-2 | `renew` (A -> B, DUT session on B); A revoked as `superseded`, `device_deny=false` (real PKI: its own supersede after `PKI_SUPERSEDE_GRACE`); then B revoked as `affiliationChanged`, `device_deny=false` | B session not kicked (policy log "kick skipped"); CONNECT presenting A (the certificate the DUT presented earlier, rendered as EMQX renders it) denied `revoked_serial`; DUT reconnect with B admitted; after B's revocation: kick, the DUT's own reconnect presenting B refused (`revoked_serial`) within 10 s, no re-admission; `ironmesh_auth_failures_total{reason="revoked"}` unchanged (device id never deny-listed); policy `GET /v1/revocations` entries |
| C-ACL-1 | `publish_raw` to another device / tenant / own downlink topic | policy authz denied, session dropped (`deny_action = disconnect`), nothing routed; own telemetry accepted |
| C-ACL-2 | `subscribe_raw` to foreign / wildcard / `$SYS` / shared / own uplink filters | every filter denied by the policy; own `cmd/req` granted |
| C-ACL-3 | retained `publish_raw` on own telemetry (and events) | denied, nothing retained |
| C-OTA-1..4 | OtaNotify with unsigned / tampered / untrusted-key / downgrade artifact | final `ota_state`, error code, slots unchanged, no reboot, signed OtaStatus uplinks |
| C-OTA-5 | valid update | `rebooted{ota_apply}`, `success`, new version code, active slot hash = image hash, signed OtaStatus success with fw_hash |
| C-OTA-6 | valid update, broker refuses the new boot | `rebooted{rollback}`, previous slot and version active, `rolled_back` |
| C-OTA-7 | IMDELTA1 patch from the running (factory) image | applied slot hash = full image hash; patch size |
| C-RPL-1 | command, then the same bytes again | `ENV_REPLAY`, executed once, one CommandAck echoing cmd_id + nonce |
| C-RPL-2 | command with ts = now - 400 s (and + 400 s) | `ENV_TS_SKEW`, not executed |
| C-RPL-3 | command signed by a non-tenant key, then the genuine command with the same seq | `COSE_SIGNATURE`; the genuine one is executed (store not advanced by the forgery) |
| C-RPL-4 | telemetry, `status`, `reboot`, `status`, telemetry | `seq_out` after > before; first seq after reboot > last before; wire seqs strictly increasing |
| C-OFF-1 | `net_down`, 25 telemetry, `net_up`; then a broker-side session drop | nothing leaves while down, `buffer_flushed` range, all seqs verified, in order, no gaps |
| C-CFG-1 | Config (tenant-signed, HPKE to the cert key) published retained | no rejection; the same ciphertext again -> `ENV_REPLAY` (proves it was applied); retained copy is a COSE_Encrypt0 without plaintext; a config for another key -> `HPKE_OPEN` |
| C-HOOK-1 | run the release `ironmesh-agent --dut` | exit status != 0, no protocol answer (n/a for ESP32 targets, with the reason) |

Verdicts: `pass`, `FAIL` (the DUT did not meet the criterion; the reason names what was
observed), `n/a` (not applicable to the target or mode - always with a written reason), `ERROR`
(harness problem). Deviations from the contract that are outside a case's pass criterion are
reported as **warnings**, never as failures. Every DUT protocol violation (unparsable lines, events
without `at_ms`, answers slower than 5 s) is reported as a warning of the case.

## Running in CI

* **Hermetic job** (Linux or Windows runner, no services): `cargo run --release -- run --target
  agent-rs` and `--target esp32-host`; publish `results/*/junit.xml`. Exit status is 1 when any case
  failed or errored.
* **Real PKI interop job**: `ironmesh-conformance build` then `run --target <t> --pki-bin
  conformance/target/bin/pki --results-dir conformance/results/real-pki`. Every case except
  C-ROT-2 (certificate TTL bounds) and C-HOOK-1 on ESP32 applies.
* **Stack job** (docker-compose / Helm with EMQX): `run --target agent-rs --stack https://<host>
  --stack-config stack.toml`. The config gives the registry URL and API key, the PKI port, the
  devices' factory anchors (`anchors_pem`), the bundle public key, `pkictl` + `pki_ca_dir` (factory
  issuance; passphrase in `PKI_FILE_KMS_PASSPHRASE`), a Services CA client certificate for the PKI
  management API and for `svc-registry` MQTT publishes, optionally a P-256 `svc_jwt_key` (its
  public key in `PKI_MGMT_JWT_PUBLIC_KEY_FILE`; every PKI management request then carries a fresh
  single-use JWT), and optionally the stack's test tenant / firmware key seeds and an artifact
  directory + base URL. Secrets can come from
  `IRONMESH_STACK_*` variables (see `src/harness/stack.rs`). Cases that need broker-side fault
  injection or observation (C-TLS-2/3/5, C-REV-1 timing, C-ACL, C-OFF-1, C-OTA-6) report `n/a` in
  this mode; this mode is compiled and its configuration unit-tested here but was not run against
  EMQX (not available on the development host).
* **HIL job**: a board built with the `hil` profile, provisioned from a persistent harness PKI:
  1. `ironmesh-conformance export-pki --out hil-pki` (CAs, keys, `anchors.pem`, `est-pin.hex`,
     `bundle.pub.hex`); bake anchors, pin, bundle key and the EST host/port into the HIL firmware
     and issue its bootstrap certificate from `hil-pki/factory-ca.*`.
  2. `hil.toml`: `port`, `bootstrap_cert`, `pki_dir = "hil-pki"`, `advertise_host` (the runner's
     LAN address), `est_port`, optional `se_type` (default `atecc608`), `baud`.
  3. `run --target esp32-hil --hil-config hil.toml` (binds `0.0.0.0`).
  One physical board keeps its device id across cases, so run C-REV-1 last with
  `--rev-iterations 1` (the policy deny list is per device). The serial framing and the transport
  are unit-tested with a fake serial pair (`src/dut/esp32_hil.rs`); the board itself only runs in
  the HIL job.

## Adding a target

1. Implement the DUT protocol in the firmware (test builds only).
2. Add a launcher in `src/dut/` that provisions a fresh device (factory identity, bootstrap
   certificate from `Cloud::issue_bootstrap`, manufacture record via `Cloud::register_device`),
   starts it against `Cloud::endpoints()` and returns `Dut::attach(...)`.
3. Describe it with a `TargetProfile` (product, clock control, resumption semantics, backoff clock
   scale, OTA health deadline, a side-effect-free command, the factory image if the harness knows
   it, a release binary for C-HOOK-1).
4. Add it to `Target`, `Launcher` and the CLI. No case changes: cases branch only on the profile.

## Quality

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test        # harness unit tests: broker topic filters, policy hook/revocation signer (RFC 4231 HMAC vectors,
                  # PKI publisher request shapes incl. device_deny and device_release), service JWTs (fresh jti, lifetime),
                  # registry double enrolled/release routes, PKI profiles + persistence, artifact builder variants, manifest and
                  # command vectors reproduced byte for byte, HPKE config round trip, line framing (stdio and @@IM serial
                  # over a fake serial pair), backoff analysis, JUnit rendering, stack config
cargo test --release -- --ignored authn_certificate_check_cost --nocapture   # cost of the CONNECT certificate checks in the real policy service
```
