/*
 * IronMesh protocol core - key-slot selection and the atomic identity record (see im_keyslot.h).
 */
#include "im_keyslot.h"

#include <string.h>

#include "im_ringbuf.h" /* im_crc32 */

static bool op_slot(uint8_t s)
{
    return s == IM_SLOT_OP_A || s == IM_SLOT_OP_B;
}

bool im_keyslot_operational_valid(uint8_t active_slot, bool provisioned, uint64_t now,
                                  uint64_t not_after)
{
    return provisioned && op_slot(active_slot) && now < not_after;
}

uint8_t im_keyslot_inactive(uint8_t active_slot)
{
    return active_slot == IM_SLOT_OP_A ? IM_SLOT_OP_B : IM_SLOT_OP_A;
}

im_err_t im_keyslot_plan(uint8_t active_slot, bool provisioned, uint64_t now, uint64_t not_after,
                         im_keyslot_plan_t *plan)
{
    if (plan == NULL || (active_slot != IM_SLOT_BOOTSTRAP && !op_slot(active_slot))) {
        return IM_ERR_ARG;
    }
    plan->new_slot = im_keyslot_inactive(active_slot);
    if (im_keyslot_operational_valid(active_slot, provisioned, now, not_after)) {
        plan->tls_slot = active_slot;
        plan->bootstrap_cert = false;
        plan->reenroll = true;
    } else {
        /* first enrollment, or the operational certificate expired: Factory CA path */
        plan->tls_slot = IM_SLOT_BOOTSTRAP;
        plan->bootstrap_cert = true;
        plan->reenroll = false;
    }
    return IM_OK;
}

im_err_t im_keyslot_record_encode(uint8_t active_slot, const uint8_t *cert, size_t cert_len,
                                  uint8_t *out, size_t cap, size_t *out_len)
{
    uint32_t crc;
    size_t n = 8u + cert_len;
    if (!op_slot(active_slot) || cert == NULL || cert_len == 0 ||
        cert_len > IM_KEYSLOT_CERT_MAX || out == NULL || out_len == NULL) {
        return IM_ERR_ARG;
    }
    if (cap < n + 4u) {
        return IM_ERR_BUFFER;
    }
    memcpy(out, "IMKS", 4);
    out[4] = 1;
    out[5] = active_slot;
    out[6] = (uint8_t)(cert_len >> 8);
    out[7] = (uint8_t)cert_len;
    memcpy(out + 8, cert, cert_len);
    crc = im_crc32(0, out, n);
    out[n] = (uint8_t)(crc >> 24);
    out[n + 1] = (uint8_t)(crc >> 16);
    out[n + 2] = (uint8_t)(crc >> 8);
    out[n + 3] = (uint8_t)crc;
    *out_len = n + 4u;
    return IM_OK;
}

im_err_t im_keyslot_record_decode(const uint8_t *rec, size_t len, uint8_t *active_slot,
                                  const uint8_t **cert, size_t *cert_len)
{
    size_t cl;
    uint32_t crc;
    if (rec == NULL || active_slot == NULL || cert == NULL || cert_len == NULL) {
        return IM_ERR_ARG;
    }
    if (len < 12u || memcmp(rec, "IMKS", 4) != 0 || rec[4] != 1 || !op_slot(rec[5])) {
        return IM_ERR_STORAGE;
    }
    cl = ((size_t)rec[6] << 8) | rec[7];
    if (cl == 0 || cl > IM_KEYSLOT_CERT_MAX || len != 12u + cl) {
        return IM_ERR_STORAGE;
    }
    crc = ((uint32_t)rec[8 + cl] << 24) | ((uint32_t)rec[9 + cl] << 16) |
          ((uint32_t)rec[10 + cl] << 8) | rec[11 + cl];
    if (crc != im_crc32(0, rec, 8u + cl)) {
        return IM_ERR_STORAGE;
    }
    *active_slot = rec[5];
    *cert = rec + 8;
    *cert_len = cl;
    return IM_OK;
}
