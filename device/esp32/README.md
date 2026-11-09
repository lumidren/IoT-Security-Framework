# IronMesh ESP32 firmware

Firmware for the `esp32-atecc` and `esp32-sw` targets of [HARDWARE_SETUP.md](../../HARDWARE_SETUP.md),
implementing [docs/DESIGN_CONTRACT.md](../../docs/DESIGN_CONTRACT.md),
[WIRE_FORMAT.md](../common/WIRE_FORMAT.md), [DELTA_FORMAT.md](../common/DELTA_FORMAT.md) and the DUT
control protocol of [conformance/DUT_PROTOCOL.md](../../conformance/DUT_PROTOCOL.md). ESP-IDF **v5.3.x**.

```
components/im_core/          portable C99 protocol core - no ESP-IDF dependency, built and tested on the host
components/im_platform_esp/  ESP-IDF platform layer (mbedTLS/libsodium crypto, ATECC608B, NVS, TLS, EST, MQTT, OTA)
main/                        app_main: tasks, bounded event queue, Kconfig menu "IronMesh"
host/core-tests/             Rust crate: compiles im_core with MSVC/clang, Rust crypto provider, vector + unit tests
host/dut-shim/               `esp32-host` DUT: the C core behind DUT_PROTOCOL.md over stdio
host/fuzz/                   cargo-fuzz targets for every C parser + RESULTS.md
tools/                       check_prod_config.py, factory_provision.py, sign_and_package.py
```

## Security architecture in one paragraph

All protocol decisions - strict canonical CBOR, COSE profiles, the §3.6 envelope check order,
per-stream replay windows (`<tenant kid>/<type>` downlink, device kid uplink) persisted in
encrypted NVS, ±300 s timestamp skew (future-only for retained types 4/7/9), tenant binding,
HPKE config unwrap, manifest signature + anti-rollback + product + size/hash acceptance, the
streaming IMDELTA1 applier, the OTA A/B state machine with a 120 s health check, the offline
ring buffer, command idempotency and the MQTT topic ACL - live in `im_core`, a single-threaded,
allocation-free C99 library with bounded buffers and recursion only up to the CBOR depth limit
(16). It performs no cryptography itself: everything goes through `im_crypto.h`, and private-key
operations go through an `im_identity_t` so the key can stay in the ATECC608B.

## Build profiles

| Profile | Command | Keys | Secure Boot | Flash encryption | Console / logs | DUT channel |
|---------|---------|------|-------------|------------------|----------------|-------------|
| dev  | `idf.py -DSDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.defaults.dev" build`  | software (encrypted NVS, HMAC scheme) | off | off | UART, INFO | off |
| hil  | `idf.py -DSDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.defaults.hil" build`  | ATECC608B | v2, development | development | USB-Serial/JTAG, WARN | **on** (`@@IM `) |
| prod | `idf.py -DSDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.defaults.prod" build` | ATECC608B | v2 (RSA-PSS; ECDSA on ECDSA-only chips) | **release** | none, `LOG_LEVEL_NONE` | off (forced) |

CI runs `python tools/check_prod_config.py` (and `--sdkconfig build/sdkconfig` on the generated
config): it fails if production enables a console, the DUT channel, debug paths/logging or
software keys, or disables Secure Boot, release-mode flash encryption, ROM-download/JTAG lockdown,
anti-rollback, rollback, NVS encryption or the strong stack protector.

Flash (dev): `idf.py -p PORT flash monitor`. Release artifacts:
`python tools/sign_and_package.py build/ironmesh_esp32.bin --key fw_ed25519.pem [--base old.bin]`
writes `image.bin`, `manifest.cbor`, `manifest.sig` (COSE_Sign, Ed25519) and optionally an
IMDELTA1 patch, using the Python reference wire library; it re-verifies its own output.
`version.txt` holds the semver (line 1) and the monotonic `version_code` (line 2).

## eFuses - read this before touching a production board

**Burning eFuses is irreversible.** `tools/factory_provision.py --profile prod` prints every
eFuse it is about to burn (Secure Boot digest, `SECURE_BOOT_EN`, flash-encryption counter in
release mode, `DIS_DOWNLOAD_MODE`, `DIS_USB_JTAG`/`DIS_PAD_JTAG`/`SOFT_DIS_JTAG`, ...), verifies
the bootloader signature with the production Secure Boot key *before* burning anything
(HARDWARE_SETUP.md §5), and does nothing without `--yes-i-understand` (default is a dry run).
After release-mode flash encryption and disabled download mode, a board can only be updated by
signed OTA. Use the `hil` profile (development modes) for anything that must stay re-flashable.

Anti-rollback has two layers: the manifest `version_code` (`MF_ROLLBACK`, any granularity) and
the ESP32 eFuse secure version (`CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK`, burned by
`esp_ota_mark_app_valid_cancel_rollback` after a healthy boot). The eFuse field has only 16-32
one-time bits, so it is bumped per *security epoch* (`CONFIG_BOOTLOADER_APP_SECURE_VERSION`), not
per release; `ota_ab.c` refuses an image whose `secure_version` is below the eFuse value.

## ATECC608B vs. encrypted-NVS keys (assurance)

| | ATECC608B (`atecc608`, hardware) | Encrypted NVS (`software`) |
|-|-|-|
| key generation | in the chip (`atcab_genkey` into the inactive operational slot 2/3; slot 0 bootstrap, locked) | on the device, mbedTLS (same slot numbering: three NVS keys) |
| key at rest | never leaves the chip, no read path in the slot config (`atecc_config.h`) | NVS encrypted with an eFuse HMAC key (S3) or the flash-encrypted `nvs_keys` partition |
| runtime exposure | only signatures / ECDH results reach the MCU | key is in RAM while used; code execution on the MCU = key compromise |
| contract §10 | allowed by default | tenant policy `allow_software_keys`, **off** in the prod profile |

The ESP32 Digital Signature peripheral (`esp_ds`) is RSA-only and cannot hold the contract's
P-256 key, so the software build uses mbedTLS with the encrypted-NVS key.

## Crypto provider

`im_crypto_mbedtls.c`: mbedTLS 3.6 (hardware SHA/AES/MPI) for SHA-256, HKDF, ECDSA P-256,
AES-GCM, point validation; **libsodium** (`espressif/libsodium`) for Ed25519, because the mbedTLS
3.6 shipped with IDF 5.3 has no Ed25519 (neither legacy nor PSA builtin driver). There is no
ML-DSA-65 backend on the ESP32: `IRONMESH_REQUIRE_PQ` would reject every update with
`MLDSA_NOT_AVAILABLE`, and hybrid manifests are verified on their mandatory Ed25519 signature
(WIRE_FORMAT.md §6.3 step 5). The host build verifies ML-DSA-65 (RustCrypto `ml-dsa`).

## TLS, EST and MQTT

`im_tls.c` is an `esp_transport` on mbedTLS: TLS 1.3 only, ALPN `mqtt`, server SAN = broker
host, and trust anchors = exactly the CA certificates (from EST `/cacerts`) whose SPKI SHA-256 is
pinned in the trust bundle - a rogue CA fails with `tls_pin_mismatch` before any MQTT byte.
TLS 1.3 tickets are cached for resumption. It exists because esp-tls' secure-element hook is
hard-wired to ATECC slot 0 (the bootstrap key). esp-mqtt v5 runs over it with
`clean_start=false`, 7-day session expiry, receive maximum 32, keep-alive 60 s; reconnects use the
agent's backoff (1 s, x2, cap 300 s, full jitter). The EST client speaks HTTP/1.1 over the same
transport.

### Key slots and renewal

Slot 0 is the bootstrap key; slots 2 and 3 alternate as the operational key
(`atecc_config.h`; the software key store uses the same numbering). The selection is a pure
im_core function, `im_keyslot_plan()`, host-tested in `host/core-tests/tests/keyslot.rs`:

| situation | TLS client key + attestation signer | EST op | new key goes to |
|-----------|-------------------------------------|--------|-----------------|
| never enrolled | slot 0 + bootstrap cert | `simpleenroll` | slot 2 |
| operational cert valid (renewal at 50 %) | active slot + operational cert | `simplereenroll` | inactive slot |
| operational cert expired | slot 0 + bootstrap cert | `simpleenroll` | inactive slot |

The commit point is a single NVS blob `id_rec` = (active slot, operational cert DER, CRC-32),
written with one `nvs_set_blob` + `nvs_commit` only after the leaf certificate was received and
checked to certify the new key. Before that write nothing about the live identity changes, so a
failed enrollment or a power loss at any step keeps the old slot/cert pair.

## Offline buffer

`im_ringbuf.c` over the `storage` partition: 512-byte slots with CRC-32, sector erase drops the
oldest undelivered records, torn writes are skipped on mount, delivery acks are a NOR bit-clear
of one header byte. That ack scheme is incompatible with ciphertext, so `storage` is **not**
flash-encrypted: records are ES256-signed envelopes (integrity and origin protected) and
telemetry is not secret. 1 MiB = 2048 records on 8 MiB parts; use 4 MiB on 16 MiB modules for the
contract's 10 000 messages.

## Host test strategy (what is verified here)

ESP-IDF is not installed on the development host, so the split is deliberate:

* `host/core-tests` compiles **every `components/im_core/*.c`** with MSVC `/W4 /WX /sdl /std:c11`
  (clang/gcc: `-std=c99 -Wextra -Werror -Wshadow -Wconversion`) and links a Rust `im_crypto.h`
  provider. `cargo test` runs all 18 vector files of `device/common/vectors/` through the C code
  (byte-identical reproduction of every deterministic vector, every rejection code) plus unit
  tests for the MQTT codec/session, ring buffer on simulated NOR flash, the OTA state machine
  (valid/tampered/downgrade/untrusted/unsigned/rollback/delta), replay store, JSON, base64,
  command cache, and an ABI check of every mirrored struct.
* `host/dut-shim` is the `esp32-host` DUT target: the C agent + DUT dispatcher over stdio, with
  Rust supplying only crypto, transport bytes (in-process simulated broker/EST, or rustls TLS 1.3
  to a real stack) and simulated flash/NVS/A-B slots. Its tests run the DUT_PROTOCOL.md cases that
  need no network: ENR-1/2, ROT-1/2, ACL-1/2/3, OTA-1..7, RPL-1..4, OFF-1, CFG-1, REV-1, TLS-4/5.
  **This validates the protocol core, not the ESP32's radio, esp-tls/mbedTLS, esp-mqtt, the
  ATECC driver or the bootloader** - those are covered by the HIL job on real hardware.
* `host/fuzz`: seven cargo-fuzz targets over the C parsers (MSVC ASan + SanitizerCoverage);
  results in `host/fuzz/RESULTS.md`.

```sh
cd host && cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings
cd fuzz && python gen_corpus.py && SECS=60 bash run_all.sh
```

Everything under `components/im_platform_esp/`, `main/`, the CMake/Kconfig/sdkconfig files and
the partition table is written against the ESP-IDF v5.3 API but **was not compiled** on the
authoring host; the HIL workflow builds it.
