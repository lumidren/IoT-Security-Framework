# Hardware Setup

This guide covers the two reference device targets, the secure elements they use, the factory
provisioning station, and the self-hosted GitHub Actions runner that drives hardware-in-the-loop
(HIL) conformance testing.

## 1. Reference hardware

| Target            | Board                                   | Secure element            | Firmware         |
|-------------------|-----------------------------------------|---------------------------|------------------|
| `esp32-atecc`     | ESP32-WROOM-32E / ESP32-S3-WROOM-1      | Microchip ATECC608B (I2C) | `device/esp32`   |
| `esp32-sw`        | Any ESP32 / ESP32-S3 dev kit            | none (encrypted NVS)      | `device/esp32`   |
| `linux-tpm`       | Raspberry Pi 4/5 + Infineon OPTIGA TPM SLB 9670 (SPI) or any x86_64 with fTPM | TPM 2.0 | `device/agent-rs` |
| `linux-optee`     | STM32MP157 / i.MX8 with OP-TEE          | OP-TEE TA                 | `device/agent-rs` |
| `linux-sw`        | Any Linux host                          | none (file/keyring)       | `device/agent-rs` |

Software-key targets are **lower assurance** (contract §10); production tenants should keep
`allow_software_keys` disabled.

### 1.1 ESP32 + ATECC608B wiring

| ATECC608B pin | ESP32 pin (default, configurable in `menuconfig -> IronMesh -> Secure element`) |
|---------------|------------------------------------------------------------------|
| VCC           | 3V3                                                              |
| GND           | GND                                                              |
| SDA           | GPIO 21                                                          |
| SCL           | GPIO 22                                                          |

Use 4.7 kOhm pull-ups on SDA/SCL if your module does not include them. I2C address default
`0x6A` for ATECC608B-TNGTLS (Trust&GO) and `0x60` for blank parts (`0xC0` 8-bit). Trust&GO
parts come pre-provisioned with a Microchip-signed device certificate; IronMesh **does not** use that
chain. We use slot 0 for the bootstrap key (locked at the factory) and slot 2 for the operational
key (regenerated at every enrollment). The ATECC configuration zone used by IronMesh is in
`device/esp32/components/im_identity/atecc_config.h` and is applied once by the factory tool.

### 1.2 Raspberry Pi + TPM

1. Enable SPI and the TPM overlay in `/boot/firmware/config.txt`:
   ```
   dtparam=spi=on
   dtoverlay=tpm-slb9670
   ```
2. Reboot, verify `/dev/tpmrm0` exists, install `tpm2-tools tpm2-abrmd libtss2-dev`.
3. Create the agent user and give it access: `usermod -aG tss ironmesh`.
4. The agent creates a persistent primary key under the Owner hierarchy at handle `0x81010001`
   (configurable `IRONMESH_TPM_PRIMARY_HANDLE`), the identity key as a child, and an Attestation Key
   (AK) at `0x81010002` used for quotes over PCRs 0, 2, 4, 7.

## 2. Toolchains

### 2.1 ESP-IDF

* ESP-IDF **v5.3.x** (`git clone -b v5.3.2 --recursive https://github.com/espressif/esp-idf.git`).
* Run `install.sh esp32,esp32s3` then `. export.sh`.
* Components pulled by the IDF component manager (`device/esp32/main/idf_component.yml`):
  `espressif/esp-cryptoauthlib`, `espressif/esp_secure_cert_mgr`, `espressif/mdns` is **not** used.
* Build profiles:
  * `idf.py -DSDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.defaults.dev" build` — software keys
    allowed, UART console on, Secure Boot off (for bring-up only).
  * `idf.py -DSDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.defaults.prod" build` — Secure Boot v2,
    flash encryption (release mode), JTAG disabled by eFuse, UART console and `esp_log` output off,
    anti-rollback enabled with secure version from `version.txt`.

**Burning eFuses is irreversible.** The production profile is applied by
`device/esp32/tools/factory_provision.py --profile prod`, which prints every eFuse it is about to
burn and requires `--yes-i-understand`.

### 2.2 Rust agent

* Rust stable (see `device/agent-rs/rust-toolchain.toml`), `cargo-fuzz` + nightly for fuzzing.
* Cross-compile for Pi: `cargo build --release --target aarch64-unknown-linux-gnu --features tpm`
  (needs `libtss2-dev` for the target; `cross` configuration in `Cross.toml`).
* Features: `tpm` (tss-esapi), `optee` (optee-teec), default `software`.

## 3. Factory provisioning station

The factory flow produces a **bootstrap certificate** per device and records the device in the
Registry as `manufactured`. It runs `scripts/factory/provision_device.py` against a Factory CA
instance of the PKI service (`pkictl issue-bootstrap`).

1. Station operator authenticates to the Registry with a factory-scoped API key (RBAC role
   `factory`) and the PKI with a Services CA client cert `svc-factory`.
2. For each unit:
   * ESP32 + ATECC608: flash the factory image, the firmware generates the bootstrap key in slot 0 and
     prints a CSR over USB; the station submits the CSR (`--csr`), receives the bootstrap cert and the
     PKI bundle public key, writes them into `esp_secure_cert` partition, locks slot 0, then flashes
     the production image and burns the production eFuses.
   * Raspberry Pi + TPM: the agent in `--factory` mode creates the TPM identity key and AK, prints the
     CSR and AK public key; the station submits both; the AK certificate issued by the PKI is stored in
     `/var/lib/ironmesh/ak.crt`.
   * Software-key devices: the station generates the key on the device via `agent --factory --software`
     (never on the station) and stores it encrypted at rest.
3. The station calls `POST /v1/devices` on the Registry with `{device_id, tenant_id, product,
   hw_revision, se_type, bootstrap_serial}` -> state `manufactured`.
4. Device id and bootstrap serial are printed on the unit label (QR) for RMA tracking.

The Factory CA private key lives in the factory HSM (SoftHSM2 in the compose demo). Only the factory
station host can reach the PKI's `issue-bootstrap` endpoint (NetworkPolicy + client cert allowlist).

## 4. Hardware-in-the-loop CI runner

The HIL job (`.github/workflows/hil.yml`) runs on a self-hosted runner labelled
`[self-hosted, linux, hil, esp32]` with an ESP32-S3 + ATECC608B attached over USB, and executes:
build release firmware -> flash -> start a local IronMesh stack (compose) -> run the conformance
suite against the real board -> upload serial logs and JUnit results.

### 4.1 Runner host

* Ubuntu 24.04 LTS (x86_64 or arm64), 4 vCPU, 8 GiB RAM, 60 GiB disk, Docker Engine 27+.
* Create user `hil` in groups `docker`, `dialout`, `plugdev`.
* Install ESP-IDF v5.3.x under `/opt/esp-idf` and `esptool` (`pip install esptool`).
* udev rule so the board is always `/dev/ttyESP32`:
  ```
  # /etc/udev/rules.d/99-ironmesh-hil.rules
  SUBSYSTEM=="tty", ATTRS{idVendor}=="303a", ATTRS{idProduct}=="1001", SYMLINK+="ttyESP32", MODE="0660", GROUP="dialout"
  ```
  (`303a:1001` is the ESP32-S3 USB-Serial/JTAG; use `10c4:ea60` for CP2102 boards.)
* Register the runner:
  ```bash
  mkdir -p /opt/actions-runner && cd /opt/actions-runner
  curl -fsSL -o runner.tar.gz https://github.com/actions/runner/releases/download/v2.321.0/actions-runner-linux-x64-2.321.0.tar.gz
  echo "<sha256 from the release page>  runner.tar.gz" | sha256sum -c
  tar xzf runner.tar.gz
  ./config.sh --url https://github.com/lumidren/IoT-Security-Framework \
     --token <registration token from Settings -> Actions -> Runners> \
     --labels self-hosted,linux,hil,esp32 --name hil-esp32-01 --unattended --ephemeral
  sudo ./svc.sh install hil && sudo ./svc.sh start
  ```
  Use `--ephemeral` so each job gets a clean runner process. The runner must only run jobs from
  this repository (Settings -> Actions -> Runner groups -> restrict to selected repositories), and
  `hil.yml` is restricted to `workflow_dispatch` and pushes to `main`, never to pull requests from
  forks.
* Environment file `/opt/actions-runner/.env`:
  ```
  IDF_PATH=/opt/esp-idf
  IRONMESH_HIL_PORT=/dev/ttyESP32
  IRONMESH_HIL_BAUD=921600
  IRONMESH_HIL_TARGET=esp32s3
  ```

### 4.2 Board preparation

Flash the **development** bootloader once by hand with Secure Boot v2 enabled in *development*
mode (`CONFIG_SECURE_BOOT_V2_ENABLED=y` without `CONFIG_SECURE_BOOT_INSECURE`), using a dedicated
HIL signing key `device/esp32/keys/hil_secure_boot_signing_key.pem` (stored as a GitHub secret
`HIL_SECURE_BOOT_KEY`, never committed). Flash encryption is left in development mode on the HIL
board so it can be re-flashed. The job writes a fresh bootstrap cert into the `esp_secure_cert`
partition before each run, so the board enrolls from scratch each time.

### 4.3 What the HIL job asserts

The same conformance suite as the Rust agent (`conformance/`), with the board as the device under
test: mTLS handshake with pinning, EST enrollment with ATECC attestation, cert rotation, revocation
reaction time (< 10 s), ACL enforcement, OTA signature rejection (unsigned and tampered images),
A/B rollback after an image that fails its health check, replay rejection, offline buffering and
resync after Wi-Fi is cut (the runner toggles a USB-controlled relay on the board's Wi-Fi antenna
switch, or uses `hostapd_cli` to deauth the device from the runner's test access point).

### 4.4 Test access point

The runner hosts a Wi-Fi AP with `hostapd` (`conformance/hil/hostapd.conf`) on a USB Wi-Fi
adapter so the board's network can be controlled: SSID `ironmesh-hil`, WPA2-PSK from the secret
`HIL_WIFI_PSK`, `dnsmasq` for DHCP, and `nftables` rules that redirect `pki.ironmesh.local` and
`mqtt.ironmesh.local` to the compose stack on the runner.

## 5. Safety and handling

* Never ship a unit whose production eFuses were burned before Secure Boot signing keys were
  verified; the factory tool refuses to burn `SECURE_BOOT_EN` unless it has verified the bootloader
  signature with the production key.
* Keep the HIL board physically isolated from production networks; its certificates belong to a
  dedicated `hil` tenant.
* RMA: decommission the device in the Registry (`decommissioned` is terminal) which revokes every
  certificate; the ATECC608 keys cannot be extracted, so the physical part can be destroyed or reused
  after a fresh factory provisioning under a new device id.
