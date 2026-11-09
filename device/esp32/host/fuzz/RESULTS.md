# Fuzzing results - ESP32 protocol core (`components/im_core`)

Date: 2026-11-09. Host: Windows 11 (build 26200), x86_64, MSVC 14.38 (`cl` 19.38), Rust nightly
(`cargo-fuzz` 0.13.2, `libfuzzer-sys` 0.4). Each target ran **60 s** (7 targets in parallel,
`SECS=60 bash run_all.sh`), seeded from `corpus/<target>/` (generated from
`device/common/vectors/` by `gen_corpus.py`).

| Target            | C code exercised                                                     | Execs      | exec/s | Coverage features (start -> end) | Corpus (seed -> end) | Crashes |
|-------------------|----------------------------------------------------------------------|-----------:|-------:|---------------------------------:|---------------------:|--------:|
| `cbor_decode`     | strict validator, reader, canonical re-encoder (round-trip asserted)  | 3,362,811  | 55,128 | 1402 -> 1540                     | 305 -> 384           | 0       |
| `cose_decode`     | Sign1 / Sign / Encrypt0 parsers, Sign1 verify path                    | 2,382,584  | 39,058 | 541 -> 1288                      | 20 -> 425            | 0       |
| `envelope_decode` | full §3.6 decode (resolver, replay store, skew), payload/bodies, HPKE config unwrap | 977,834 | 16,030 | 949 -> 1806            | 39 -> 459            | 0       |
| `manifest_decode` | manifest decoder, COSE_Sign verify (+PQ branch), acceptance rules     | 2,221,919  | 36,424 | 424 -> 1288                      | 4 -> 402             | 0       |
| `delta_apply`     | IMDELTA1 streaming applier (chunking, work-buffer sizes, header fix-up) | 383,200  | 6,281  | 143 -> 289                       | 15 -> 71             | 0       |
| `mqtt_decode`     | MQTT 5 framer/decoder, client session state machine                  | 1,468,128  | 24,067 | 223 -> 1187                      | 12 -> 400            | 0       |
| `dut_json`        | DUT JSON parser/accessors, base64, JSON writer (output re-parsed)     | 1,874,752  | 30,733 | 386 -> 1666                      | 8 -> 480             | 0       |

**Total: 12.7 M executions, no crash, no ASan report, no assertion failure, no timeout/OOM.**
Invariants asserted inside the targets: canonical CBOR round trip, parsed signature/kid sizes,
`min_version_code <= version_code` on every accepted manifest, delta writes strictly sequential
and never beyond `max_target_size`, PUBLISH payload inside the frame, JSON root token spans the
whole token array, and the JSON writer only ever emits parseable JSON.

## Instrumentation (and why `cargo fuzz run` is not used directly on Windows)

* The **C core** is compiled by `core-tests/build.rs` (feature `fuzz`) with
  `/fsanitize=address /fsanitize-coverage=inline-8bit-counters /fsanitize-coverage=edge
  /fsanitize-coverage=trace-cmp` (all supported by cl 19.38) and linked with `libsancov.lib`
  (MSVC's glue that registers the counters with libFuzzer) and the MSVC ASan runtime
  (`clang_rt.asan_dynamic-x86_64`). The counter count printed by libFuzzer (`Loaded 1 modules`)
  is the C core only.
* The **Rust harness is not instrumented** (`RUSTFLAGS=--cfg fuzzing`): on
  `x86_64-pc-windows-msvc`
  1. rustc's ASan runtime and MSVC's in one process abort with `Interception failure`;
  2. rustc's sancov adds PC tables, MSVC's does not, and libFuzzer refuses the mismatch
     ("size of coverage PC tables does not match");
  3. rustc's `inline-8bit-counters` fail on some crates with
     `LLVM ERROR: Associative COMDAT symbol ... is not a key for its COMDAT`.
  The harness is a thin, safe-Rust FFI driver, so nothing of value is lost.
* MSVC 14.38's ASan needs `ASAN_WIN_CONTINUE_ON_INTERCEPTION_FAILURE=1` on this Windows build
  (it fails to hook a ucrt function at startup). ASan was confirmed live on this host with a
  deliberate heap overflow compiled the same way (`ERROR: AddressSanitizer: heap-buffer-overflow`).
* On Linux (clang), `cargo +nightly fuzz run <target>` works unchanged; `build.rs` then uses
  `-fsanitize=address,fuzzer-no-link`.

## Reproduce

```sh
cd device/esp32/host/fuzz
python gen_corpus.py          # (re)create corpus/<target>/ from the vectors
SECS=60 bash run_all.sh       # Windows/MSVC; logs in logs/, findings in artifacts/
# Linux:
cargo +nightly fuzz run cbor_decode corpus/cbor_decode -- -max_total_time=60
```

## Bugs found while building the tests (fixed before fuzzing)

The unit/conformance tests (not the fuzzer) found one real defect: after the ring buffer wrapped
and erased the sector holding the oldest record, the cached tail pointed at the slot that had just
been rewritten with the *newest* record, so the flush order broke after wrap-around
(`im_ringbuf.c`, fixed: the tail moves past an erased sector). The fuzzers found nothing in the
60 s budget; longer runs (hours) are recommended in CI on Linux.
