/*
 * IronMesh protocol core - IMDELTA1 streaming applier. State machine equivalent to
 * ironmesh_wire/delta.py DeltaApplier (same error for every malformed patch), without buffering
 * literals.
 */
#include "im_delta.h"

#include <string.h>

enum { ST_OP = 0, ST_COPY_ARGS, ST_LIT_LEN, ST_LIT_DATA };

static const uint8_t k_magic[8] = {'I', 'M', 'D', 'E', 'L', 'T', 'A', '1'};

static uint64_t be(const uint8_t *p, unsigned n)
{
    uint64_t v = 0;
    for (unsigned i = 0; i < n; i++) {
        v = (v << 8) | p[i];
    }
    return v;
}

im_err_t im_delta_init(im_delta_t *d, const im_delta_io_t *io, uint64_t base_size,
                       uint64_t max_target_size, uint8_t *work, size_t work_len)
{
    if (d == NULL || io == NULL || io->read_base == NULL || io->write == NULL || work == NULL ||
        work_len < 64u) {
        return IM_ERR_ARG;
    }
    memset(d, 0, sizeof *d);
    d->io = *io;
    d->base_size = base_size;
    d->max_target_size = max_target_size ? max_target_size : IM_DELTA_DEFAULT_MAX_TARGET;
    d->work = work;
    d->work_len = work_len;
    d->st = ST_OP;
    return IM_OK;
}

static im_err_t fail(im_delta_t *d, im_err_t e)
{
    if (d->err == IM_OK) {
        d->err = e;
    }
    if (d->hashing) {
        im_crypto_sha256_free(&d->out_hash);
        d->hashing = false;
    }
    return d->err;
}

static im_err_t read_base(im_delta_t *d, uint64_t off, size_t len)
{
    im_err_t e = d->io.read_base(d->io.ctx, off, d->work, len);
    return e == IM_OK ? IM_OK : IM_ERR_DELTA_BOUNDS;
}

static im_err_t start(im_delta_t *d)
{
    im_sha256_ctx_t h;
    uint8_t digest[32];
    uint64_t off = 0;
    uint64_t base_size;
    if (memcmp(d->hdr, k_magic, 8) != 0) {
        return IM_ERR_DELTA_MAGIC;
    }
    if (be(d->hdr + 8, 4) != IM_DELTA_BLOCK) {
        return IM_ERR_DELTA_BLOCK_SIZE;
    }
    base_size = be(d->hdr + 12, 8);
    memcpy(d->base_sha256, d->hdr + 20, 32);
    memcpy(d->target_sha256, d->hdr + 52, 32);
    d->target_size = be(d->hdr + 84, 8);
    if (base_size != d->base_size) {
        return IM_ERR_DELTA_BASE_SIZE;
    }
    if (d->target_size > d->max_target_size) {
        return IM_ERR_DELTA_TOO_LARGE;
    }
    /* hash the whole base before producing any output */
    IM_TRY(im_crypto_sha256_init(&h));
    while (off < base_size) {
        uint64_t left = base_size - off;
        size_t n = left < d->work_len ? (size_t)left : d->work_len;
        im_err_t e = read_base(d, off, n);
        if (e == IM_OK) {
            e = im_crypto_sha256_update(&h, d->work, n);
        }
        if (e != IM_OK) {
            im_crypto_sha256_free(&h);
            return e;
        }
        off += n;
    }
    IM_TRY(im_crypto_sha256_finish(&h, digest));
    if (!im_ct_equal(digest, d->base_sha256, 32)) {
        return IM_ERR_DELTA_BASE_HASH;
    }
    IM_TRY(im_crypto_sha256_init(&d->out_hash));
    d->hashing = true;
    d->have_header = true;
    return IM_OK;
}

static im_err_t emit(im_delta_t *d, const uint8_t *p, size_t n)
{
    IM_TRY(d->io.write(d->io.ctx, d->produced, p, n));
    IM_TRY(im_crypto_sha256_update(&d->out_hash, p, n));
    d->produced += n;
    return IM_OK;
}

static im_err_t do_copy(im_delta_t *d, uint32_t idx)
{
    uint64_t start_off = (uint64_t)idx * IM_DELTA_BLOCK;
    uint64_t done = 0;
    bool overflow;
    if (start_off + IM_DELTA_BLOCK > d->base_size) {
        return IM_ERR_DELTA_BOUNDS;
    }
    overflow = d->produced + IM_DELTA_BLOCK > d->target_size;
    /* the reference reads the block before the overflow check: a failing read wins */
    while (done < IM_DELTA_BLOCK) {
        size_t n = (IM_DELTA_BLOCK - done) < d->work_len ? (size_t)(IM_DELTA_BLOCK - done)
                                                          : d->work_len;
        IM_TRY(read_base(d, start_off + done, n));
        if (!overflow) {
            IM_TRY(emit(d, d->work, n));
        }
        done += n;
    }
    return overflow ? IM_ERR_DELTA_OVERFLOW : IM_OK;
}

static im_err_t do_end(im_delta_t *d)
{
    uint8_t digest[32];
    if (d->produced != d->target_size) {
        return IM_ERR_DELTA_SHORT;
    }
    d->hashing = false;
    IM_TRY(im_crypto_sha256_finish(&d->out_hash, digest));
    if (!im_ct_equal(digest, d->target_sha256, 32)) {
        return IM_ERR_DELTA_TARGET_HASH;
    }
    d->done = true;
    return IM_OK;
}

static im_err_t process(im_delta_t *d, const uint8_t *p, size_t len)
{
    size_t i = 0;
    if (!d->have_header) {
        size_t take = IM_DELTA_HEADER_LEN - d->hdr_have;
        if (take > len) {
            take = len;
        }
        memcpy(d->hdr + d->hdr_have, p, take);
        d->hdr_have += take;
        i = take;
        if (d->hdr_have < IM_DELTA_HEADER_LEN) {
            return IM_OK;
        }
        IM_TRY(start(d));
    }
    while (i < len) {
        if (d->done) {
            return IM_ERR_DELTA_TRAILING;
        }
        switch (d->st) {
        case ST_OP: {
            uint8_t op = p[i++];
            if (op == 0x01u) {
                d->st = ST_COPY_ARGS;
                d->op_have = 0;
            } else if (op == 0x02u) {
                d->st = ST_LIT_LEN;
                d->op_have = 0;
            } else if (op == 0x03u) {
                IM_TRY(do_end(d));
            } else {
                return IM_ERR_DELTA_OP;
            }
            break;
        }
        case ST_COPY_ARGS:
            d->opbuf[d->op_have++] = p[i++];
            if (d->op_have == 4u) {
                d->st = ST_OP;
                IM_TRY(do_copy(d, (uint32_t)be(d->opbuf, 4)));
            }
            break;
        case ST_LIT_LEN:
            d->opbuf[d->op_have++] = p[i++];
            if (d->op_have == 2u) {
                uint32_t n = (uint32_t)be(d->opbuf, 2);
                if (n == 0) {
                    return IM_ERR_DELTA_LITERAL_LEN;
                }
                d->lit_remaining = n;
                d->lit_overflow = d->produced + n > d->target_size;
                d->st = ST_LIT_DATA;
            }
            break;
        default: { /* ST_LIT_DATA */
            size_t n = len - i;
            if (n > d->lit_remaining) {
                n = d->lit_remaining;
            }
            if (!d->lit_overflow) {
                IM_TRY(emit(d, p + i, n));
            }
            i += n;
            d->lit_remaining -= (uint32_t)n;
            if (d->lit_remaining == 0) {
                d->st = ST_OP;
                if (d->lit_overflow) {
                    return IM_ERR_DELTA_OVERFLOW;
                }
            }
            break;
        }
        }
    }
    return IM_OK;
}

im_err_t im_delta_feed(im_delta_t *d, const uint8_t *data, size_t len)
{
    im_err_t e;
    if (d == NULL || (data == NULL && len != 0)) {
        return IM_ERR_ARG;
    }
    if (d->err != IM_OK) {
        return d->err;
    }
    if (len == 0) {
        return IM_OK;
    }
    e = process(d, data, len);
    return e == IM_OK ? IM_OK : fail(d, e);
}

im_err_t im_delta_finish(im_delta_t *d)
{
    if (d == NULL) {
        return IM_ERR_ARG;
    }
    if (d->err != IM_OK) {
        return d->err;
    }
    if (!d->have_header || !d->done) {
        if (!d->have_header || d->st != ST_OP) {
            return fail(d, IM_ERR_DELTA_TRUNCATED);
        }
        return fail(d, IM_ERR_DELTA_MISSING_END);
    }
    return IM_OK;
}

void im_delta_abort(im_delta_t *d)
{
    if (d != NULL && d->hashing) {
        im_crypto_sha256_free(&d->out_hash);
        d->hashing = false;
    }
}

size_t im_delta_ctx_size(void)
{
    return sizeof(im_delta_t);
}
