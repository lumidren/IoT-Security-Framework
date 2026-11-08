# IronMesh Block-Delta Format (`IMDELTA1`)

Normative specification of the firmware delta-patch format referenced by
[`docs/DESIGN_CONTRACT.md`](../../docs/DESIGN_CONTRACT.md) §6. The reference implementation is
`libs/python/ironmesh-wire/src/ironmesh_wire/delta.py`; the conformance vectors are the
`device/common/vectors/delta_*.json` files. The key words MUST / MUST NOT / SHOULD are to be read as
in RFC 2119.

## 1. Overview

A patch transforms a **base** image (the firmware currently running) into a **target** image. It is
a fixed 92-byte header followed by a sequence of operations terminated by `END`. All multi-byte
integers are **big-endian**. The block size is fixed at **4096 bytes**. A patch is only ever applied
after its manifest has been verified (contract §6); the format nevertheless carries its own hashes
so that an applier can validate the base before writing and the result before marking a slot
`pending`.

Design goals: trivially streamable (the applier needs the header, then one op at a time), bounded
memory (one 4 KiB block plus the largest literal), no dependency on compression libraries, and no
ambiguity (every patch has exactly one valid interpretation; every deviation has a defined error).

## 2. Header (92 bytes)

| Offset | Size | Field           | Value / rule                                                   |
|-------:|-----:|-----------------|----------------------------------------------------------------|
| 0      | 8    | `magic`         | ASCII `IMDELTA1` = `49 4d 44 45 4c 54 41 31`                    |
| 8      | 4    | `block_size`    | u32, MUST be `4096` (`00 00 10 00`)                             |
| 12     | 8    | `base_size`     | u64, byte length of the base image                             |
| 20     | 32   | `base_sha256`   | SHA-256 of the entire base image                               |
| 52     | 32   | `target_sha256` | SHA-256 of the entire target image                             |
| 84     | 8    | `target_size`   | u64, byte length of the target image                           |

Python struct layout: `">8sIQ32s32sQ"`.

## 3. Operations

Operations follow the header back to back. Each begins with a one-byte opcode.

| Opcode | Name      | Encoding                                | Output                                                             |
|-------:|-----------|-----------------------------------------|--------------------------------------------------------------------|
| `0x01` | `COPY`    | `01` + u32 `old_block_index`            | `base[idx*4096 : idx*4096 + 4096]` - exactly 4096 bytes             |
| `0x02` | `LITERAL` | `02` + u16 `len` + `len` bytes          | the `len` bytes verbatim; `1 <= len <= 65535`                      |
| `0x03` | `END`     | `03`                                    | nothing; MUST be the last byte of the patch                        |

Rules:

* `COPY` copies a **full** block only: `(old_block_index + 1) * 4096 <= base_size` MUST hold. A
  partial last block of the base can never be a `COPY` source.
* `LITERAL` with `len = 0` is invalid.
* Output is produced in order; the concatenation of all op outputs MUST have exactly `target_size`
  bytes and hash to `target_sha256`.
* No bytes may follow `END`. A patch without `END` is invalid even if the output is already complete.

## 4. Applying a patch (normative algorithm)

Given the base image (random-access reader plus its byte length `L`) and the patch stream:

1. Read 92 bytes. Fewer available at end of input -> `DELTA_TRUNCATED`.
2. `magic != "IMDELTA1"` -> `DELTA_MAGIC`. `block_size != 4096` -> `DELTA_BLOCK_SIZE`.
3. `base_size != L` -> `DELTA_BASE_SIZE`.
4. `target_size` larger than the applier's configured limit (reference: 1 GiB) -> `DELTA_TOO_LARGE`.
5. Hash the whole base image; mismatch with `base_sha256` -> `DELTA_BASE_HASH`. (This happens
   before any output is produced.)
6. Loop over ops. Before executing an op, if the input ends inside the op -> `DELTA_TRUNCATED`
   (when the whole patch has been consumed) or wait for more bytes (streaming).
   * unknown opcode -> `DELTA_OP`
   * `COPY` with `(idx + 1) * 4096 > base_size` -> `DELTA_BOUNDS`; a short read from the base
     reader is also `DELTA_BOUNDS`
   * `LITERAL` with `len == 0` -> `DELTA_LITERAL_LEN`
   * any op whose output would make `produced > target_size` -> `DELTA_OVERFLOW` (checked before
     the bytes are emitted)
   * `END` with `produced != target_size` -> `DELTA_SHORT`; with `SHA-256(output) != target_sha256`
     -> `DELTA_TARGET_HASH`
7. After `END`, any further byte -> `DELTA_TRAILING`.
8. Input exhausted on an op boundary without `END` -> `DELTA_MISSING_END`.

Output MAY be streamed to flash as it is produced, but the slot MUST NOT be marked bootable until
step 6's `END` checks have passed. The reference `DeltaApplier` implements exactly this state
machine and accepts the patch in arbitrary chunk sizes (vectors are exercised with chunk sizes 1 to
whole-patch).

## 5. Reference encoder (`make_delta`)

Any encoder producing a patch that satisfies §3 is conformant; the vectors' `patch_hex` values were
produced by this algorithm, and an implementation that follows it reproduces them byte-for-byte:

1. Index every **full** 4096-byte block of the base by `SHA-256(block)`; on duplicate hashes keep
   the lowest index (first occurrence wins).
2. Write the header (§2).
3. For each target block at offset `0, 4096, 8192, ...`:
   * if the block is exactly 4096 bytes and its hash is in the index **and** the indexed base block
     is bytewise equal, emit `COPY <index>`;
   * otherwise emit `LITERAL <len> <bytes>` (the partial last block is always a literal).
4. Emit `END`.

Literal runs are not merged; the maximum literal the reference encoder emits is 4096 bytes.

## 6. Limits and error codes

| Code                | Meaning                                                     |
|---------------------|-------------------------------------------------------------|
| `DELTA_MAGIC`       | header magic is not `IMDELTA1`                              |
| `DELTA_BLOCK_SIZE`  | header block size is not 4096                               |
| `DELTA_TRUNCATED`   | patch ends inside the header or inside an op                |
| `DELTA_BASE_SIZE`   | header `base_size` differs from the actual base image size  |
| `DELTA_BASE_HASH`   | base image hash mismatch (wrong base, or corrupted header)  |
| `DELTA_TOO_LARGE`   | `target_size` exceeds the applier's limit                   |
| `DELTA_OP`          | unknown opcode                                              |
| `DELTA_BOUNDS`      | `COPY` outside the base image / short read                  |
| `DELTA_LITERAL_LEN` | `LITERAL` length 0                                          |
| `DELTA_OVERFLOW`    | output would exceed `target_size`                           |
| `DELTA_SHORT`       | `END` reached before `target_size` bytes were produced      |
| `DELTA_TARGET_HASH` | output hash differs from `target_sha256`                    |
| `DELTA_MISSING_END` | patch ended without `END`                                   |
| `DELTA_TRAILING`    | bytes after `END`                                           |

`u16`/`u32`/`u64` field widths are hard limits of the format. The reference applier additionally
limits `target_size` to 1 GiB (configurable); firmware appliers SHOULD use their slot size.

## 7. Examples (from the vectors)

`delta_both_empty.json`: base and target both empty. The patch is the 92-byte header followed by
`03`:

```
49 4d 44 45 4c 54 41 31                          magic "IMDELTA1"
00 00 10 00                                      block_size 4096
00 00 00 00 00 00 00 00                          base_size 0
e3 b0 c4 42 98 fc 1c 14 9a fb f4 c8 99 6f b9 24  base_sha256 = SHA-256("")
27 ae 41 e4 64 9b 93 4c a4 95 99 1b 78 52 b8 55
e3 b0 c4 42 98 fc 1c 14 9a fb f4 c8 99 6f b9 24  target_sha256 = SHA-256("")
27 ae 41 e4 64 9b 93 4c a4 95 99 1b 78 52 b8 55
00 00 00 00 00 00 00 00                          target_size 0
03                                               END
```

`delta_small_change.json`: base = 3 full blocks + 100-byte tail, target = block 0, a modified block
1, block 2, the same tail. Ops: `01 00000000` (COPY 0), `02 1000 <4096 bytes>` (LITERAL), `01
00000002` (COPY 2), `02 0064 <100 bytes>` (LITERAL), `03`.

`delta_invalid.json` lists corrupted patches with the error code each MUST produce.

## 8. Relationship to the manifest and the OTA flow

The manifest (`WIRE_FORMAT.md` §6) carries `delta = {1: base_sha256, 2: patch_sha256, 3:
patch_size}` and `OtaNotify.delta_from = base_sha256`. Before applying, the device checks (pure
function `accept_patch`): the manifest has a delta (`MF_NO_DELTA`), `delta.base_sha256` equals the
hash of its running image (`DELTA_BASE_HASH`), the downloaded patch has `patch_size` bytes
(`MF_SIZE_MISMATCH`) and hashes to `patch_sha256` (`MF_HASH_MISMATCH`). The header's `base_sha256`
MUST equal the manifest's `delta.base_sha256` and the header's `target_sha256`/`target_size` MUST
equal the manifest's `image_sha256`/`image_size`; after applying, the device runs the normal
`accept_image` checks on the produced image before marking the slot `pending`.
