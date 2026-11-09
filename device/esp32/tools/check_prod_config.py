#!/usr/bin/env python3
"""CI gate for the ESP32 production profile (conformance/DUT_PROTOCOL.md "C-HOOK-1" for ESP32).

Fails (exit 1) if sdkconfig.defaults(+.prod) - or a generated sdkconfig given with --sdkconfig -
enables a console, the DUT control channel, debug paths or logging, or disables Secure Boot,
flash encryption (release mode), ROM-download/JTAG lockdown or anti-rollback.

    python tools/check_prod_config.py                  # defaults files
    python tools/check_prod_config.py --sdkconfig build/sdkconfig
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]

# option -> required value ("y", "n", or a literal string/number)
REQUIRED = {
    "CONFIG_IRONMESH_DUT_CONTROL": "n",
    "CONFIG_SECURE_BOOT": "y",
    "CONFIG_SECURE_BOOT_V2_ENABLED": "y",
    "CONFIG_SECURE_BOOT_INSECURE": "n",
    "CONFIG_SECURE_BOOT_ALLOW_JTAG": "n",
    "CONFIG_SECURE_BOOT_ALLOW_ROM_BASIC": "n",
    "CONFIG_SECURE_FLASH_ENC_ENABLED": "y",
    "CONFIG_SECURE_FLASH_ENCRYPTION_MODE_RELEASE": "y",
    "CONFIG_SECURE_FLASH_UART_BOOTLOADER_ALLOW_ENC": "n",
    "CONFIG_SECURE_FLASH_UART_BOOTLOADER_ALLOW_DEC": "n",
    "CONFIG_SECURE_FLASH_UART_BOOTLOADER_ALLOW_CACHE": "n",
    "CONFIG_SECURE_DISABLE_ROM_DL_MODE": "y",
    "CONFIG_ESP_CONSOLE_NONE": "y",
    "CONFIG_LOG_DEFAULT_LEVEL_NONE": "y",
    "CONFIG_BOOTLOADER_LOG_LEVEL_NONE": "y",
    "CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK": "y",
    "CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE": "y",
    "CONFIG_COMPILER_STACK_CHECK_MODE_STRONG": "y",
    "CONFIG_NVS_ENCRYPTION": "y",
    "CONFIG_IRONMESH_SE_ATECC608": "y",
}

# options that must never be enabled in production
FORBIDDEN_Y = [
    "CONFIG_ESP_CONSOLE_UART_DEFAULT",
    "CONFIG_ESP_CONSOLE_UART",
    "CONFIG_ESP_CONSOLE_USB_CDC",
    "CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG",
    "CONFIG_SECURE_FLASH_ENCRYPTION_MODE_DEVELOPMENT",
    "CONFIG_SECURE_ENABLE_SECURE_ROM_DL_MODE",
    "CONFIG_ESP_DEBUG_OCDAWARE",
    "CONFIG_ESP_GDBSTUB_ENABLED",
    "CONFIG_ESP_SYSTEM_GDBSTUB_RUNTIME",
    "CONFIG_ESP_SYSTEM_PANIC_GDBSTUB",
    "CONFIG_APPTRACE_ENABLE",
    "CONFIG_IRONMESH_SE_SOFTWARE",
    "CONFIG_LOG_DEFAULT_LEVEL_INFO",
    "CONFIG_LOG_DEFAULT_LEVEL_DEBUG",
    "CONFIG_LOG_DEFAULT_LEVEL_VERBOSE",
    "CONFIG_LOG_DEFAULT_LEVEL_WARN",
    "CONFIG_LOG_DEFAULT_LEVEL_ERROR",
]

LINE = re.compile(r"^(CONFIG_[A-Z0-9_]+)=(.*)$")
UNSET = re.compile(r"^# (CONFIG_[A-Z0-9_]+) is not set$")


def parse(paths: list[pathlib.Path]) -> dict[str, str]:
    """Later files override earlier ones, like SDKCONFIG_DEFAULTS="a;b"."""
    cfg: dict[str, str] = {}
    for p in paths:
        for raw in p.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            m = LINE.match(line)
            if m:
                cfg[m.group(1)] = m.group(2).strip().strip('"')
                continue
            m = UNSET.match(line)
            if m:
                cfg[m.group(1)] = "n"
    return cfg


def check(cfg: dict[str, str]) -> list[str]:
    problems = []
    for key, want in REQUIRED.items():
        have = cfg.get(key, "n")
        if have != want:
            problems.append(f"{key} must be {want} (is {have})")
    for key in FORBIDDEN_Y:
        if cfg.get(key) == "y":
            problems.append(f"{key} must not be enabled in production")
    return problems


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sdkconfig", type=pathlib.Path, help="generated sdkconfig to check instead")
    ap.add_argument("--defaults", nargs="*", type=pathlib.Path,
                    default=[ROOT / "sdkconfig.defaults", ROOT / "sdkconfig.defaults.prod"])
    args = ap.parse_args(argv)
    paths = [args.sdkconfig] if args.sdkconfig else args.defaults
    for p in paths:
        if not p.is_file():
            print(f"check_prod_config: missing {p}", file=sys.stderr)
            return 2
    problems = check(parse(paths))
    if problems:
        print("check_prod_config: production profile REJECTED:", file=sys.stderr)
        for pr in problems:
            print(f"  - {pr}", file=sys.stderr)
        return 1
    print(f"check_prod_config: OK ({', '.join(p.name for p in paths)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
