# IronMesh Linux device agent (`agent-rs`)

The Linux gateway agent and the virtual fleet simulator of IronMesh. Binding specifications:
[`docs/DESIGN_CONTRACT.md`](../../docs/DESIGN_CONTRACT.md),
[`device/common/WIRE_FORMAT.md`](../common/WIRE_FORMAT.md),
[`device/common/DELTA_FORMAT.md`](../common/DELTA_FORMAT.md) and
[`conformance/DUT_PROTOCOL.md`](../../conformance/DUT_PROTOCOL.md). The wire code is byte-compatible
with the Python reference (`libs/python/ironmesh-wire`) and passes every file in
[`device/common/vectors/`](../common/vectors/README.md).

## Binaries

| Binary            | Purpose |
|-------------------|---------|
| `ironmesh-agent`  | systemd service: enrollment, pinned MQTT 5 session, telemetry, commands, shadow, encrypted config, A/B OTA. Also `--factory`, `--install-bootstrap`, `--boot-status`, `--rollback`, `--dut` (feature `dut-control` only). |
| `ironmesh-fleet`  | Virtual fleet: `provision` identities + bootstrap CSRs, `run` N devices (default 500) in one process with staggered enrollment and optional `--anomalous k` misbehaving devices, `bench` memory footprint without network. |

## Module map

| Module | Responsibility |
|--------|----------------|
| `wire::cbor` | Canonical CBOR encoder, strict decoder (size 64 KiB, depth 16, tags 16/18/98), diagnostic-notation parser for the vectors |
| `wire::cose` | COSE_Sign1 (ES256/EdDSA), COSE_Sign (Ed25519 + ML-DSA-65), COSE_Encrypt0 (A256GCM + HPKE header `-70000`) |
| `wire::envelope` | Typed bodies 1-10, `encode`, the 11-step `decode` of WIRE_FORMAT §3.6 (per-type downlink replay streams, retained-type timestamp rule), `ReplayStore` |
| `wire::manifest` | Manifest codec, `verify_manifest` (Ed25519 always, ML-DSA-65 when `require_pq`), `accept_image` / `accept_patch` |
| `wire::delta` | IMDELTA1 streaming applier (bounded memory: one op + one block), reference encoder |
| `wire::hpke` | RFC 9180 DHKEM(P-256)/HKDF-SHA256/AES-128-GCM with an abstract recipient (TPM / TEE ECDH) and Config wrap/unwrap |
| `wire::attestation` | Type-10 attestation builder, server-side verifier, `TPMS_ATTEST` parser |
| `wire::error` | `ErrorCode` 1:1 with WIRE_FORMAT §8 / DELTA_FORMAT §6 |
| `identity` | `IdentityProvider` trait; `software` (AES-256-GCM at rest, HKDF from a 0600 machine secret [+ OS keyring]), `tpm` (feature `tpm`), `optee` (feature `optee`) |
| `tls` | TLS 1.3-only rustls config, `PinnedVerifier` (webpki chain + hostname with only SPKI-pinned anchors), identity-backed client key, connect-failure classification |
| `est` | RFC 7030 client (`cacerts`, nonce, `simpleenroll`/`simplereenroll` + `X-IronMesh-Attestation`), certs-only PKCS#7 decoder (`der`), `X-IronMesh-Bundle` verification, renewal schedule |
| `enroll` | Enrollment/rotation orchestration and the on-disk credential store (crash-safe key promotion) |
| `mqtt` | Self-written, fuzzed MQTT 5 codec and async client (clean_start=false, 7-day session expiry, receive max 32, keep-alive 60 s, user property `traceparent`), backoff 1 s x2 cap 300 s full jitter |
| `buffer` | Persistent offline ring buffer (10 000 records, CRC per record, torn-tail recovery, compaction) |
| `telemetry` | `sysinfo` collector, `auth.log` / `journalctl` failed-login counter, firmware hash |
| `ota` | A/B slots, `BootControl` (`FileBootControl`, `FwSetenvBootControl` for U-Boot/RAUC), resumable HTTPS download, anti-rollback floor, delta apply, staging |
| `commands`, `shadow`, `config` | Command execution with expiry and 256-key persisted idempotency; desired/reported state; encrypted config |
| `agent` | Supervisor state machine, uplink signing + buffering, inbound verification/dispatch, renewal task, health gate (MQTT + telemetry PUBACK within 120 s, else rollback) |
| `dut` | DUT control protocol over stdio (feature `dut-control`) |
| `fleet` | Simulator devices, telemetry models, anomalies, provisioning, bench |
| `logging` | JSON logs with `ts, level, service, trace_id, span_id, tenant_id, device_id, msg`; W3C trace context |

`#![forbid(unsafe_code)]` holds for the whole crate (the TPM/TEE FFI lives inside `tss-esapi` /
`optee-teec`); `clippy::unwrap_used`, `expect_used` and `panic` are denied outside tests.

## Building and testing

```sh
cargo build --release                                 # agent + fleet, software identity
cargo test --features dut-control                     # unit, vectors, e2e, DUT, fleet, CLI
cargo test                                            # same, plus the release C-HOOK-1 check
cargo clippy --all-targets --features dut-control -- -D warnings
cargo fmt --check
cargo llvm-cov --features dut-control --summary-only
```

Feature flags: `pq` (default, ML-DSA-65 verify via RustCrypto `ml-dsa`), `tpm`, `optee`, `keyring`,
`dut-control` (never in release builds; `--dut` exits with status 2 otherwise).

### Platform support

* `tpm` needs `libtss2-esys` (tpm2-tss) and `optee` needs `libteec` at build time, so they are
  built in Linux CI only: `cargo check --features tpm` and `cross build --target
  aarch64-unknown-linux-gnu --features tpm|optee` (see `Cross.toml`). They are written against
  tss-esapi 7.x / optee-teec 0.9 and run their FFI context on a dedicated worker thread.
* Cross-compile for a Pi: `cross build --release --target aarch64-unknown-linux-gnu --features tpm`.

### The end-to-end tests

`tests/support` contains in-process doubles of the backend: a test PKI (rcgen: Root, Services,
Device, Factory and a rogue CA), an EST server (axum over rustls, mandatory client auth, nonce
store, attestation verification, issuance from the CSR, `X-IronMesh-Bundle`), an HTTPS artifact
store with `Range`, and an MQTT 5 broker (ACLs per the contract topic table, retained-topic rule,
injection, TLS 1.2-only and rogue-certificate modes). `tests/e2e.rs` proves enrollment, pinned TLS
1.3 + ALPN, session resumption, rotation (manual and at 50 % lifetime), quarantine refusal,
rogue-CA and TLS 1.2 rejection, replay / skew / signature / type rejection, idempotency, ACL
probes, offline buffering with in-order resync, encrypted config, shadow, OTA tamper / untrusted
key / unsigned / downgrade rejection, delta update with health gate, and rollback.

## Provisioning and operation

```sh
# factory station, on the device (key never leaves it)
ironmesh-agent --config /etc/ironmesh/agent.toml --factory --device-id dev-... --tenant-id ... > bootstrap.csr
pkictl issue-bootstrap --csr bootstrap.csr --out bootstrap.crt
ironmesh-agent --config /etc/ironmesh/agent.toml --install-bootstrap bootstrap.crt
systemctl enable --now ironmesh-agent
ironmesh-agent --boot-status          # A/B slots, boot_count, pending update
```

`packaging/ironmesh-agent.service` (strict sandbox: `ProtectSystem=strict`, `NoNewPrivileges`,
empty capability set, `@system-service` syscall filter, only `/var/lib/ironmesh` writable) runs the
agent; `OnFailure=ironmesh-rollback.service` abandons a pending slot that does not start.
`packaging/agent.toml.example` documents every setting; any key can be overridden with
`IRONMESH_<SECTION>_<KEY>`, and `IRONMESH_PQ_REQUIRED=1` makes ML-DSA-65 mandatory.

## Fleet simulator demo

```sh
ironmesh-fleet provision --out fleet --count 500 --tenant <tenant-uuid>
for d in fleet/dev-*; do pkictl issue-bootstrap --csr $d/bootstrap.csr.pem --out $d/bootstrap.crt; done
ironmesh-fleet run --dir fleet --config fleet.toml --anomalous 5      # [pki]/[mqtt]/[telemetry] as for the agent
ironmesh-fleet bench --count 10000                                    # memory footprint, no network
docker build -t ironmesh-fleet .                                      # distroless image
```

Anomalies (round robin over the `--anomalous` devices): `auth_burst`, `beaconing` (1 s period,
50x upload), `topic_violation` (publishes to another device's topic), `fw_hash_change`.
Footprint measured here: ~148 KiB RSS per connected device in the 60-device integration test
(debug build, including the in-process EST server and broker state), ~6 KiB per device for the
network-free bench state.

## Fuzzing

`fuzz/` holds cargo-fuzz targets for every parser that sees untrusted bytes (`cbor_decode`,
`cose_sign1_decode`, `cose_sign_decode`, `cose_encrypt0_decode`, `envelope_decode`,
`manifest_decode`, `delta_apply`, `mqtt_decode`, `pkcs7_decode`, `bundle_decode`), seed corpora
derived from the vectors (`python fuzz/make_corpus.py`) and `fuzz/run_all.sh`. Results:
[`fuzz/RESULTS.md`](fuzz/RESULTS.md).
