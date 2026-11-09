/*
 * IronMesh protocol core - persistent offline ring buffer (contract §4 "offline buffering") over
 * a NOR-flash style storage callback (erase sets 0xFF; writes may only clear bits).
 *
 * Layout: the region is divided into fixed-size slots (slot_size divides sector_size). Each slot
 * holds one record: 16-byte header + payload.
 *   [0..1] magic "IM"   [2] ack (0xFF pending, 0x00 delivered - not covered by the CRC)
 *   [3] version 1       [4..7] record id (u32 BE, increasing, serial arithmetic)
 *   [8..9] payload length (u16 BE)  [10..11] 0xFFFF  [12..15] CRC-32 of bytes 3..11 + payload
 * Records are written sequentially; entering a sector erases it first, dropping the oldest
 * undelivered records in it (overwrite-oldest policy, counted in `dropped`). A torn write leaves
 * a slot whose CRC fails; recovery skips it. RAM use is the struct only (no index).
 */
#ifndef IM_RINGBUF_H
#define IM_RINGBUF_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "im_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define IM_RB_HDR 16u

typedef struct {
    im_err_t (*read)(void *ctx, uint32_t off, uint8_t *buf, size_t len);
    im_err_t (*write)(void *ctx, uint32_t off, const uint8_t *data, size_t len);
    im_err_t (*erase)(void *ctx, uint32_t off, size_t len); /* sector aligned */
    void *ctx;
    uint32_t size;        /* bytes, multiple of sector_size */
    uint32_t sector_size; /* e.g. 4096 */
} im_storage_t;

typedef struct {
    im_storage_t st;
    uint32_t slot_size;
    uint32_t nslots;
    uint32_t head;      /* next slot to write */
    uint32_t tail;      /* oldest pending candidate */
    uint32_t next_id;
    uint32_t count;     /* pending records */
    uint32_t dropped;   /* overwritten before delivery */
    bool tail_valid;
} im_ringbuf_t;

/* Mount: scans the region and recovers head/tail/count. slot_size >= 64 and divides the sector. */
im_err_t im_rb_init(im_ringbuf_t *rb, const im_storage_t *st, uint32_t slot_size);
/* Erase everything. */
im_err_t im_rb_format(im_ringbuf_t *rb);
uint32_t im_rb_max_payload(const im_ringbuf_t *rb);
/* Append (IM_ERR_BUFFER if len > max payload). */
im_err_t im_rb_push(im_ringbuf_t *rb, const uint8_t *data, size_t len);
/* Oldest pending record (IM_ERR_EMPTY when none). */
im_err_t im_rb_peek(im_ringbuf_t *rb, uint8_t *buf, size_t cap, size_t *len, uint32_t *id);
/* Mark the oldest pending record delivered. */
im_err_t im_rb_pop(im_ringbuf_t *rb);
uint32_t im_rb_count(const im_ringbuf_t *rb);

uint32_t im_crc32(uint32_t crc, const uint8_t *p, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* IM_RINGBUF_H */
