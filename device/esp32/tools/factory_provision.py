#!/usr/bin/env python3
"""Factory provisioning of an IronMesh ESP32 (HARDWARE_SETUP.md section 3). IRREVERSIBLE.

Orchestrates esptool / espsecure / espefuse (pip install esptool>=4.7):

  1. reads the chip (esptool chip_id) and the current eFuse summary,
  2. writes the esp_secure_cert partition: bootstrap certificate (issued by the Factory CA for
     the CSR the factory image printed), the Factory CA certificate (initial EST trust anchor)
     and the PKI bundle Ed25519 public key (TLV USER_DATA_1),
  3. writes NVS seed values (device_id, tenant_id and, with --est-pin, the factory EST SPKI
     pins `est_pins` used before the first trust bundle - threat model T-29) into the encrypted
     NVS partition,
  4. for --profile prod|hil: verifies the bootloader signature with the production (or HIL)
     Secure Boot public key BEFORE anything is burned, prints EVERY eFuse it is about to burn,
     and burns them only with --yes-i-understand.

Without --yes-i-understand the tool is a dry run: it prints the exact commands and changes
nothing. The ATECC608B configuration zone (components/im_platform_esp/atecc_config.h) is
written and locked by the factory firmware image on the device, not by this script.

    python tools/factory_provision.py --port /dev/ttyUSB0 --chip esp32s3 --profile prod \
        --bootloader build/bootloader/bootloader.bin --secure-boot-pubkey prod_sb_pub.pem \
        --bootstrap-cert dev-....pem --factory-ca factory-ca.pem --bundle-pubkey <64 hex> \
        --device-id dev-8f3a1c2b9d4e5f60 --tenant-id 7e4b1a9c-... [--yes-i-understand]
"""

from __future__ import annotations

import argparse
import re
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

# eFuses per chip and profile. (name, value) pairs for espefuse burn_efuse; keys are handled
# by burn_key / burn_key_digest below. Reviewed against ESP-IDF v5.3 security docs.
EFUSES = {
    "esp32": {
        "prod": [
            ("FLASH_CRYPT_CNT", "127"),       # flash encryption, release (all bits set)
            ("FLASH_CRYPT_CONFIG", "0xF"),
            ("ABS_DONE_1", "1"),              # Secure Boot v2 enable
            ("JTAG_DISABLE", "1"),
            ("DISABLE_DL_ENCRYPT", "1"),
            ("DISABLE_DL_DECRYPT", "1"),
            ("DISABLE_DL_CACHE", "1"),
            ("UART_DOWNLOAD_DIS", "1"),       # ROM download mode off (ECO3+)
            ("CONSOLE_DEBUG_DISABLE", "1"),
        ],
        "hil": [
            ("ABS_DONE_1", "1"),
            ("FLASH_CRYPT_CNT", "1"),         # development mode: re-flashable
        ],
    },
    "esp32s3": {
        "prod": [
            ("SPI_BOOT_CRYPT_CNT", "7"),      # flash encryption, release
            ("SECURE_BOOT_EN", "1"),
            ("SECURE_BOOT_AGGRESSIVE_REVOKE", "1"),
            ("DIS_DOWNLOAD_MANUAL_ENCRYPT", "1"),
            ("DIS_DOWNLOAD_ICACHE", "1"),
            ("DIS_DOWNLOAD_DCACHE", "1"),
            ("DIS_USB_JTAG", "1"),
            ("DIS_PAD_JTAG", "1"),
            ("SOFT_DIS_JTAG", "7"),
            ("DIS_DIRECT_BOOT", "1"),
            ("DIS_DOWNLOAD_MODE", "1"),       # = CONFIG_SECURE_DISABLE_ROM_DL_MODE
            ("DIS_USB_SERIAL_JTAG_ROM_PRINT", "1"),
            ("DIS_USB_OTG_DOWNLOAD_MODE", "1"),
        ],
        "hil": [
            ("SECURE_BOOT_EN", "1"),
            ("SPI_BOOT_CRYPT_CNT", "1"),      # development mode
        ],
    },
}

UUID4 = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
DEVICE = re.compile(r"^dev-[0-9a-f]{16}$")


def run(cmd: list[str], execute: bool) -> str:
    print("  $ " + " ".join(shlex.quote(c) for c in cmd))
    if not execute:
        return ""
    res = subprocess.run(cmd, check=True, capture_output=True, text=True)
    return res.stdout


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", required=True)
    ap.add_argument("--chip", choices=sorted(EFUSES), required=True)
    ap.add_argument("--profile", choices=["dev", "hil", "prod"], required=True)
    ap.add_argument("--bootloader", type=Path, help="signed bootloader.bin (hil/prod)")
    ap.add_argument("--secure-boot-pubkey", type=Path, help="Secure Boot v2 public key PEM (hil/prod)")
    ap.add_argument("--flash-key", type=Path, help="flash encryption key (default: generated on-chip)")
    ap.add_argument("--hmac-key", type=Path, help="NVS HMAC key for chips with the HMAC peripheral")
    ap.add_argument("--bootstrap-cert", type=Path, required=True)
    ap.add_argument("--factory-ca", type=Path, required=True)
    ap.add_argument("--bundle-pubkey", required=True, help="PKI bundle Ed25519 key, 64 hex chars")
    ap.add_argument("--est-pin", action="append", default=[],
                    help="SHA-256 of the PKI (Services) CA SubjectPublicKeyInfo, 64 hex chars; "
                         "repeatable (max 4). Without it the device pins the esp_secure_cert CA.")
    ap.add_argument("--device-id", required=True)
    ap.add_argument("--tenant-id", required=True)
    ap.add_argument("--yes-i-understand", action="store_true",
                    help="really write flash and BURN eFUSES (irreversible)")
    a = ap.parse_args(argv)

    if not DEVICE.match(a.device_id) or not UUID4.match(a.tenant_id):
        ap.error("device id must be dev-<16 hex>, tenant id a lower-case UUIDv4")
    if not re.fullmatch(r"[0-9a-f]{64}", a.bundle_pubkey):
        ap.error("--bundle-pubkey must be 64 lower-case hex characters")
    if len(a.est_pin) > 4 or not all(re.fullmatch(r"[0-9a-f]{64}", p) for p in a.est_pin):
        ap.error("--est-pin must be 64 lower-case hex characters (at most 4)")
    if a.profile != "dev" and (a.bootloader is None or a.secure_boot_pubkey is None):
        ap.error("hil/prod need --bootloader and --secure-boot-pubkey")
    execute = a.yes_i_understand
    if not execute:
        print("DRY RUN - nothing will be written or burned (add --yes-i-understand).")

    print(f"[1/4] chip and current eFuses ({a.chip} on {a.port})")
    run(["esptool.py", "--chip", a.chip, "--port", a.port, "chip_id"], execute)
    run(["espefuse.py", "--chip", a.chip, "--port", a.port, "summary"], execute)

    print("[2/4] esp_secure_cert partition (bootstrap cert, Factory CA, bundle key)")
    with tempfile.TemporaryDirectory() as tmp:
        key_bin = Path(tmp) / "bundle_pubkey.bin"
        key_bin.write_bytes(bytes.fromhex(a.bundle_pubkey))
        run(["configure_esp_secure_cert.py", "-p", a.port, "--target_chip", a.chip,
             "--keep_ds_data_on_host", "--skip_flash",
             "--device-cert", str(a.bootstrap_cert), "--ca-cert", str(a.factory_ca),
             "--priv_key_algo", "ECDSA", "256", "--sec_cert_type", "cust_flash_tlv",
             "--user-data-1", str(key_bin)], execute)
        print("[3/4] NVS seed (device_id, tenant_id, est_pins)")
        csv = Path(tmp) / "nvs.csv"
        pins = f"est_pins,data,hex2bin,{''.join(a.est_pin)}\n" if a.est_pin else ""
        csv.write_text("key,type,encoding,value\nironmesh,namespace,,\n"
                       f"device_id,data,string,{a.device_id}\ntenant_id,data,string,{a.tenant_id}\n"
                       + pins)
        run(["python", "-m", "esp_idf_nvs_partition_gen", "encrypt", str(csv),
             str(Path(tmp) / "nvs.bin"), "0x6000", "--keygen", "--keyfile", "nvs_keys.bin"], execute)

    print(f"[4/4] security eFuses for profile '{a.profile}'")
    if a.profile == "dev":
        print("  dev profile: no eFuses are burned (software keys, no Secure Boot).")
        return 0
    # HARDWARE_SETUP.md section 5: never burn SECURE_BOOT_EN before the bootloader signature
    # verified with the production key.
    print("  verifying the bootloader signature with the Secure Boot public key first:")
    run(["espsecure.py", "verify_signature", "--version", "2", "--keyfile",
         str(a.secure_boot_pubkey), str(a.bootloader)], True)  # read-only, always executed
    plan = list(EFUSES[a.chip][a.profile])
    keys = [("BLOCK_KEY0" if a.chip != "esp32" else "secure_boot_v2", "SECURE_BOOT_DIGEST0",
             str(a.secure_boot_pubkey), "burn_key_digest")]
    if a.flash_key:
        keys.append(("BLOCK_KEY1" if a.chip != "esp32" else "flash_encryption",
                     "XTS_AES_128_KEY", str(a.flash_key), "burn_key"))
    if a.hmac_key and a.chip != "esp32":
        keys.append(("BLOCK_KEY2", "HMAC_UP", str(a.hmac_key), "burn_key"))
    print("  THE FOLLOWING eFUSES WILL BE BURNED (one-time programmable, cannot be undone):")
    for name, value in plan:
        print(f"    {name:34s} = {value}")
    for block, purpose, path, how in keys:
        print(f"    {block:34s} <- {purpose} ({how} {path})")
    print("  + SECURE_VERSION is advanced only by the firmware (esp_ota_mark_app_valid_...).")
    if not execute:
        print("DRY RUN complete.")
        return 0
    for block, purpose, path, how in keys:
        if how == "burn_key_digest" and a.chip == "esp32":
            run(["espefuse.py", "--chip", a.chip, "--port", a.port, "--do-not-confirm",
                 "burn_key_digest", path], True)
        elif how == "burn_key_digest":
            run(["espefuse.py", "--chip", a.chip, "--port", a.port, "--do-not-confirm",
                 "burn_key_digest", block, path, purpose], True)
        else:
            run(["espefuse.py", "--chip", a.chip, "--port", a.port, "--do-not-confirm",
                 "burn_key", block, path, purpose], True)
    args = []
    for name, value in plan:
        args += [name, value]
    run(["espefuse.py", "--chip", a.chip, "--port", a.port, "--do-not-confirm", "burn_efuse", *args], True)
    run(["espefuse.py", "--chip", a.chip, "--port", a.port, "summary"], True)
    print("done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
