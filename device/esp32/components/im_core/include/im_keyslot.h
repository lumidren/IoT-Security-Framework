/*
 * IronMesh protocol core - device key-slot selection for enrollment and renewal (pure logic).
 *
 * Slots (ATECC608B layout in components/im_platform_esp/atecc_config.h; the software key store
 * mirrors the same numbering with three NVS keys):
 *   0      bootstrap key (Factory CA certificate), first enrollment and post-expiry fallback only
 *   2, 3   alternating operational keys; exactly one is "active" (holds the key of the current
 *          operational certificate), the other is the renewal target
 *
 * Renewal (operational certificate still valid): generate the new key in the INACTIVE slot,
 * authenticate TLS and sign the attestation with the ACTIVE operational key (the TLS client key,
 * contract section 3), simplereenroll. Only after the new certificate has been received is the
 * identity record (active slot + certificate) rewritten - in ONE key-value write, so a power loss
 * at any earlier point leaves the old slot/cert pair in force.
 * Expired (or never enrolled): TLS + attestation with the bootstrap key/cert, simpleenroll, new
 * key in the slot that is not active.
 */
#ifndef IM_KEYSLOT_H
#define IM_KEYSLOT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "im_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define IM_SLOT_BOOTSTRAP 0u
#define IM_SLOT_OP_A 2u
#define IM_SLOT_OP_B 3u
#define IM_KEYSLOT_CERT_MAX 2048u
#define IM_KEYSLOT_RECORD_MAX (12u + IM_KEYSLOT_CERT_MAX)

typedef struct {
    uint8_t tls_slot;    /* key for TLS client auth AND the attestation signature */
    bool bootstrap_cert; /* present the bootstrap certificate (else the operational one) */
    bool reenroll;       /* simplereenroll (true) or simpleenroll (false) */
    uint8_t new_slot;    /* slot for the freshly generated key (CSR subject key) */
} im_keyslot_plan_t;

/* True when the operational certificate may still be used: enrolled and now < not_after. */
bool im_keyslot_operational_valid(uint8_t active_slot, bool provisioned, uint64_t now,
                                  uint64_t not_after);
/* The operational slot that is not active (IM_SLOT_OP_A when none is active). */
uint8_t im_keyslot_inactive(uint8_t active_slot);
/* active_slot: 0 (none yet), 2 or 3; anything else is IM_ERR_ARG. */
im_err_t im_keyslot_plan(uint8_t active_slot, bool provisioned, uint64_t now, uint64_t not_after,
                         im_keyslot_plan_t *plan);

/* Identity record persisted as ONE key-value blob (atomic replace):
 *   "IMKS" | version 1 | active slot | cert length (u16 BE) | cert DER | CRC-32 (BE)
 * A record that fails any check is reported as IM_ERR_STORAGE (treated as "not enrolled"). */
im_err_t im_keyslot_record_encode(uint8_t active_slot, const uint8_t *cert, size_t cert_len,
                                  uint8_t *out, size_t cap, size_t *out_len);
im_err_t im_keyslot_record_decode(const uint8_t *rec, size_t len, uint8_t *active_slot,
                                  const uint8_t **cert, size_t *cert_len);

#ifdef __cplusplus
}
#endif

#endif /* IM_KEYSLOT_H */
