/*
 * IronMesh protocol core - persistent offline ring buffer (see im_ringbuf.h).
 */
#include "im_ringbuf.h"

#include <string.h>

#define ACK_PENDING 0xFFu
#define ACK_DONE 0x00u
#define REC_VERSION 1u
#define SLOT_MIN 64u
#define SLOT_MAX 4096u

uint32_t im_crc32(uint32_t crc, const uint8_t *p, size_t n)
{
    crc = ~crc;
    for (size_t i = 0; i < n; i++) {
        crc ^= p[i];
        for (unsigned k = 0; k < 8u; k++) {
            crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
        }
    }
    return ~crc;
}

static bool serial_gt(uint32_t a, uint32_t b)
{
    return a != b && (uint32_t)(a - b) < 0x80000000u;
}

static uint32_t be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

typedef struct {
    bool valid;
    bool pending;
    bool blank;
    uint32_t id;
    uint16_t len;
} slot_t;

static im_err_t slot_info(const im_ringbuf_t *rb, uint32_t i, slot_t *s)
{
    uint8_t h[IM_RB_HDR];
    uint8_t chunk[64];
    uint32_t off = i * rb->slot_size;
    uint32_t crc;
    uint32_t done = 0;
    bool blank = true;

    memset(s, 0, sizeof *s);
    IM_TRY(rb->st.read(rb->st.ctx, off, h, sizeof h));
    for (unsigned k = 0; k < IM_RB_HDR; k++) {
        blank = blank && h[k] == 0xFFu;
    }
    s->blank = blank;
    if (h[0] != 'I' || h[1] != 'M' || h[3] != REC_VERSION || h[10] != 0xFFu || h[11] != 0xFFu) {
        return IM_OK;
    }
    s->len = (uint16_t)((h[8] << 8) | h[9]);
    if (s->len > rb->slot_size - IM_RB_HDR) {
        return IM_OK;
    }
    crc = im_crc32(0, h + 3, 9);
    while (done < s->len) {
        uint32_t n = s->len - done < sizeof chunk ? s->len - done : (uint32_t)sizeof chunk;
        IM_TRY(rb->st.read(rb->st.ctx, off + IM_RB_HDR + done, chunk, n));
        crc = im_crc32(crc, chunk, n);
        done += n;
    }
    if (crc != be32(h + 12)) {
        return IM_OK;
    }
    s->valid = true;
    s->pending = h[2] == ACK_PENDING;
    s->id = be32(h + 4);
    return IM_OK;
}

static uint32_t per_sector(const im_ringbuf_t *rb)
{
    return rb->st.sector_size / rb->slot_size;
}

im_err_t im_rb_init(im_ringbuf_t *rb, const im_storage_t *st, uint32_t slot_size)
{
    bool any = false;
    bool have_min = false;
    uint32_t max_id = 0;
    uint32_t max_pos = 0;
    uint32_t min_id = 0;
    uint32_t min_pos = 0;

    if (rb == NULL || st == NULL || st->read == NULL || st->write == NULL || st->erase == NULL ||
        slot_size < SLOT_MIN || slot_size > SLOT_MAX || st->sector_size == 0 ||
        st->sector_size % slot_size != 0 || st->size == 0 || st->size % st->sector_size != 0) {
        return IM_ERR_ARG;
    }
    memset(rb, 0, sizeof *rb);
    rb->st = *st;
    rb->slot_size = slot_size;
    rb->nslots = st->size / slot_size;
    for (uint32_t i = 0; i < rb->nslots; i++) {
        slot_t s;
        IM_TRY(slot_info(rb, i, &s));
        if (!s.valid) {
            continue;
        }
        if (!any || serial_gt(s.id, max_id)) {
            max_id = s.id;
            max_pos = i;
        }
        any = true;
        if (s.pending) {
            if (!have_min || serial_gt(min_id, s.id)) {
                min_id = s.id;
                min_pos = i;
            }
            have_min = true;
            rb->count++;
        }
    }
    rb->head = any ? (max_pos + 1u) % rb->nslots : 0;
    rb->next_id = any ? max_id + 1u : 1u;
    rb->tail = have_min ? min_pos : rb->head;
    rb->tail_valid = have_min;
    /* skip slots inside the current sector that are not blank (torn writes) */
    while (rb->head % per_sector(rb) != 0) {
        slot_t s;
        IM_TRY(slot_info(rb, rb->head, &s));
        if (s.blank) {
            break;
        }
        rb->head = (rb->head + 1u) % rb->nslots;
    }
    return IM_OK;
}

im_err_t im_rb_format(im_ringbuf_t *rb)
{
    IM_TRY(rb->st.erase(rb->st.ctx, 0, rb->st.size));
    rb->head = 0;
    rb->tail = 0;
    rb->tail_valid = false;
    rb->count = 0;
    rb->next_id = 1;
    return IM_OK;
}

uint32_t im_rb_max_payload(const im_ringbuf_t *rb)
{
    uint32_t m = rb->slot_size - IM_RB_HDR;
    return m > 0xFFFFu ? 0xFFFFu : m;
}

uint32_t im_rb_count(const im_ringbuf_t *rb)
{
    return rb->count;
}

im_err_t im_rb_push(im_ringbuf_t *rb, const uint8_t *data, size_t len)
{
    uint8_t h[IM_RB_HDR];
    uint32_t crc;
    uint32_t off;
    if (rb == NULL || (data == NULL && len != 0)) {
        return IM_ERR_ARG;
    }
    if (len > im_rb_max_payload(rb)) {
        return IM_ERR_BUFFER;
    }
    if (rb->head % per_sector(rb) == 0) {
        uint32_t first = rb->head;
        for (uint32_t k = 0; k < per_sector(rb); k++) {
            slot_t s;
            IM_TRY(slot_info(rb, first + k, &s));
            if (s.valid && s.pending) {
                rb->count--;
                rb->dropped++;
            }
        }
        IM_TRY(rb->st.erase(rb->st.ctx, first * rb->slot_size, rb->st.sector_size));
        /* the oldest surviving records start right after the erased sector */
        if (rb->tail >= first && rb->tail < first + per_sector(rb)) {
            rb->tail = (first + per_sector(rb)) % rb->nslots;
        }
        if (rb->count == 0) {
            rb->tail_valid = false;
        }
    }
    h[0] = 'I';
    h[1] = 'M';
    h[2] = ACK_PENDING;
    h[3] = REC_VERSION;
    h[4] = (uint8_t)(rb->next_id >> 24);
    h[5] = (uint8_t)(rb->next_id >> 16);
    h[6] = (uint8_t)(rb->next_id >> 8);
    h[7] = (uint8_t)rb->next_id;
    h[8] = (uint8_t)(len >> 8);
    h[9] = (uint8_t)len;
    h[10] = 0xFFu;
    h[11] = 0xFFu;
    crc = im_crc32(0, h + 3, 9);
    crc = im_crc32(crc, data, len);
    h[12] = (uint8_t)(crc >> 24);
    h[13] = (uint8_t)(crc >> 16);
    h[14] = (uint8_t)(crc >> 8);
    h[15] = (uint8_t)crc;
    off = rb->head * rb->slot_size;
    IM_TRY(rb->st.write(rb->st.ctx, off + IM_RB_HDR, data, len));
    IM_TRY(rb->st.write(rb->st.ctx, off, h, sizeof h));
    if (!rb->tail_valid) {
        rb->tail = rb->head;
        rb->tail_valid = true;
    }
    rb->head = (rb->head + 1u) % rb->nslots;
    rb->next_id++;
    rb->count++;
    return IM_OK;
}

static im_err_t locate_tail(im_ringbuf_t *rb, slot_t *s)
{
    if (rb->count == 0) {
        return IM_ERR_EMPTY;
    }
    for (uint32_t k = 0; k < rb->nslots; k++) {
        IM_TRY(slot_info(rb, rb->tail, s));
        if (s->valid && s->pending) {
            rb->tail_valid = true;
            return IM_OK;
        }
        rb->tail = (rb->tail + 1u) % rb->nslots;
    }
    rb->count = 0; /* inconsistent count: storage changed underneath */
    return IM_ERR_EMPTY;
}

im_err_t im_rb_peek(im_ringbuf_t *rb, uint8_t *buf, size_t cap, size_t *len, uint32_t *id)
{
    slot_t s;
    if (rb == NULL) {
        return IM_ERR_ARG;
    }
    IM_TRY(locate_tail(rb, &s));
    if (buf == NULL || cap < s.len) {
        return IM_ERR_BUFFER;
    }
    IM_TRY(rb->st.read(rb->st.ctx, rb->tail * rb->slot_size + IM_RB_HDR, buf, s.len));
    if (len != NULL) {
        *len = s.len;
    }
    if (id != NULL) {
        *id = s.id;
    }
    return IM_OK;
}

im_err_t im_rb_pop(im_ringbuf_t *rb)
{
    slot_t s;
    uint8_t ack = ACK_DONE;
    if (rb == NULL) {
        return IM_ERR_ARG;
    }
    IM_TRY(locate_tail(rb, &s));
    IM_TRY(rb->st.write(rb->st.ctx, rb->tail * rb->slot_size + 2u, &ack, 1));
    rb->count--;
    rb->tail = (rb->tail + 1u) % rb->nslots;
    if (rb->count == 0) {
        rb->tail_valid = false;
        rb->tail = rb->head;
    }
    return IM_OK;
}
