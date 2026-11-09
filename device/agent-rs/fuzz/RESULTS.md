# Fuzzing results

Host: Windows 11, `x86_64-pc-windows-msvc`, `cargo-fuzz 0.13.2`, nightly `cargo 1.101.0-nightly
(2026-10-27)`, libFuzzer with AddressSanitizer (the default `cargo fuzz` sanitizer).
Command: `SECS=60 fuzz/run_all.sh` (= `cargo +nightly fuzz run <target> corpus/<target> --
-max_total_time=60 -rss_limit_mb=2048` per target). Seed corpora: `python fuzz/make_corpus.py`
(derived from `device/common/vectors/` plus signed bundles, certs-only PKCS#7 and MQTT packets).

| Target                 | What it drives                                                        | Executions (60 s) | cov / ft     | Crashes |
|------------------------|-----------------------------------------------------------------------|------------------:|--------------|--------:|
| `cbor_decode`          | strict decoder; asserts accepted input re-encodes byte-identically     | 508 142           | 468 / 2278   | 0 |
| `cose_sign1_decode`    | Sign1 parse + Sig_structure + verify                                  | 544 652           | 566 / 1498   | 0 |
| `cose_sign_decode`     | COSE_Sign parse + per-signature Sig_structure                         | 602 072           | 471 / 1484   | 0 |
| `cose_encrypt0_decode` | Encrypt0 parse, HPKE decap, both AEAD layers (`unwrap_config`)        | 338 009           | 928 / 1829   | 0 |
| `envelope_decode`      | payload decoder + full 11-step `decode` with key resolver/replay store | 281 050           | 1069 / 2090  | 0 |
| `manifest_decode`      | manifest decoder + `verify_manifest` (with and without `require_pq`)   | 235 064           | 636 / 1554   | 0 |
| `delta_apply`          | streaming IMDELTA1 applier with fuzzer-chosen chunking and base       | 267 766           | 259 / 620    | 0 |
| `mqtt_decode`          | packet stream decoder; asserts encode/decode round trip               | 1 151 879         | 751 / 2668   | 0 |
| `pkcs7_decode`         | certs-only SignedData decoder + X.509 parse + base64 body decoding    | 326 043           | 1969 / 5019  | 0 |
| `bundle_decode`        | `X-IronMesh-Bundle` signature path + payload decoder                  | 114 879           | 1268 / 2525  | 0 |

No crashes, leaks, timeouts or OOMs were found, so no crashing inputs had to be added to the
corpus. The corpora grown during the run are kept in `corpus/<target>/`.

## Running libFuzzer on Windows/MSVC

`cargo fuzz` works on this host, with two environment adjustments (nothing installed):

1. The MSVC ASan runtime must be on `PATH`, otherwise the target exits with
   `STATUS_DLL_NOT_FOUND (0xc0000135)`:
   `PATH="C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.38.33130\bin\Hostx64\x64;$PATH"`.
2. ASan's interception of some Windows heap functions fails with this MSVC/LLVM combination
   (`AddressSanitizer: CHECK failed: interception_win.cpp:171 ... Interception failure`); set
   `ASAN_WIN_CONTINUE_ON_INTERCEPTION_FAILURE=1`.
3. `cargo fuzz run -s none` (no sanitizer) does **not** link on MSVC (`unresolved external symbol
   __stop___sancov_pcs`), so keep the default ASan build.

On Linux CI no environment is needed: `SECS=600 fuzz/run_all.sh` for the nightly job.
