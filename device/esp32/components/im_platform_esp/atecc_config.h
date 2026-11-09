/*
 * ATECC608B configuration-zone layout used by IronMesh (HARDWARE_SETUP.md section 1.1).
 * Applied ONCE by the factory station (tools/factory_provision.py writes these bytes with
 * atcab_write_config_zone and then locks the configuration zone - irreversible).
 *
 *   slot 0  bootstrap key   P-256 private, ExtSign only (no ECDH), never readable,
 *                           generated on-chip at the factory, then the slot is locked
 *   slot 2  operational key P-256 private, ExtSign + ECDH (HPKE config unwrap), GenKey
 *                           allowed so every enrollment creates a fresh key (atcab_genkey)
 *   slot 8  general data    certificate cache (not secret)
 *
 * Private keys are never exported: there is no ReadKey/encrypted-read path for slots 0 and 2.
 * Values follow the ATECC608B datasheet (DS40001977) SlotConfig/KeyConfig bit layout; verify
 * them with Microchip Trust Platform Design Suite before burning a production lot.
 */
#pragma once

#include <stdint.h>

#define IM_ATECC_SLOT_BOOTSTRAP 0u
#define IM_ATECC_SLOT_OPERATIONAL 2u
#define IM_ATECC_SLOT_CERT_CACHE 8u

/* SlotConfig (little-endian 16-bit, config zone bytes 20..51) */
/* ReadKey=0b0001 (external sign), IsSecret=1, WriteConfig=0b0010 (GenKey) */
#define IM_ATECC_SLOTCFG_BOOTSTRAP 0x2081u
/* ReadKey=0b0101 (external sign + ECDH, shared secret returned in clear), IsSecret=1,
 * WriteConfig=0b0010 (GenKey permitted after the data zone is locked) */
#define IM_ATECC_SLOTCFG_OPERATIONAL 0x2085u
/* clear read/write data slot */
#define IM_ATECC_SLOTCFG_DATA 0x0000u

/* KeyConfig (config zone bytes 96..127) */
/* Private=1, PubInfo=1, KeyType=P256 (0b100), Lockable=1 */
#define IM_ATECC_KEYCFG_BOOTSTRAP 0x0033u
/* Private=1, PubInfo=1, KeyType=P256, not lockable (re-generated at every enrollment) */
#define IM_ATECC_KEYCFG_OPERATIONAL 0x0013u
/* KeyType=0b111 (not an ECC key), Lockable=1 */
#define IM_ATECC_KEYCFG_DATA 0x003Cu

#define IM_ATECC_CFG_SLOTCONFIG_OFFSET 20u
#define IM_ATECC_CFG_KEYCONFIG_OFFSET 96u
