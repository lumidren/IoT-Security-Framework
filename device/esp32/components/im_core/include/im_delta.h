/*
 * IronMesh protocol core - IMDELTA1 streaming applier (DELTA_FORMAT.md §4).
 *
 * Fixed RAM budget: the applier state (~250 bytes incl. a SHA-256 context) plus one caller
 * supplied work buffer (any size >= 64 bytes; 4096 is natural for flash) through which the base
 * image is hashed and COPY blocks are streamed. LITERAL data is streamed straight to the writer as
 * it arrives, so the largest literal (65535 bytes) is never buffered. Output goes through a flash
 * writer callback at increasing offsets; the caller must not mark the slot bootable unless
 * im_delta_finish() returned IM_OK.
 */
#ifndef IM_DELTA_H
#define IM_DELTA_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "im_crypto.h"
#include "im_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define IM_DELTA_BLOCK 4096u
#define IM_DELTA_HEADER_LEN 92u
#define IM_DELTA_DEFAULT_MAX_TARGET (1ull << 30)

typedef struct {
    /* Random access read of the base (running) image; must fill exactly len bytes or fail. */
    im_err_t (*read_base)(void *ctx, uint64_t off, uint8_t *buf, size_t len);
    /* Sequential write of target bytes at off. */
    im_err_t (*write)(void *ctx, uint64_t off, const uint8_t *data, size_t len);
    void *ctx;
} im_delta_io_t;

typedef struct {
    /* configuration */
    im_delta_io_t io;
    uint64_t base_size;
    uint64_t max_target_size;
    uint8_t *work;
    size_t work_len;
    /* parsed header */
    bool have_header;
    uint64_t target_size;
    uint8_t base_sha256[32];
    uint8_t target_sha256[32];
    /* state */
    uint8_t hdr[IM_DELTA_HEADER_LEN];
    size_t hdr_have;
    int st;
    uint8_t opbuf[4];
    size_t op_have;
    uint32_t lit_remaining;
    bool lit_overflow;
    uint64_t produced;
    bool done;
    bool hashing;
    im_err_t err;
    im_sha256_ctx_t out_hash;
} im_delta_t;

/* max_target_size 0 means IM_DELTA_DEFAULT_MAX_TARGET (firmware should pass its slot size). */
im_err_t im_delta_init(im_delta_t *d, const im_delta_io_t *io, uint64_t base_size,
                       uint64_t max_target_size, uint8_t *work, size_t work_len);
/* Feed patch bytes in any chunking. Errors are sticky. */
im_err_t im_delta_feed(im_delta_t *d, const uint8_t *data, size_t len);
/* End of patch: IM_OK only after a clean END with matching size and hash. */
im_err_t im_delta_finish(im_delta_t *d);
/* sizeof(im_delta_t), for hosts that allocate the context opaquely (FFI). */
size_t im_delta_ctx_size(void);
/* Release resources after an error or when abandoning the patch. */
void im_delta_abort(im_delta_t *d);

#ifdef __cplusplus
}
#endif

#endif /* IM_DELTA_H */
