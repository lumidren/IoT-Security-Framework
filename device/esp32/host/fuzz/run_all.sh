#!/usr/bin/env bash
# Build and run every fuzz target for $SECS seconds (default 60) on Windows/MSVC.
#
# Why not plain `cargo fuzz run`: on x86_64-pc-windows-msvc (a) rustc's ASan runtime and MSVC's
# cannot share a process, (b) MSVC /fsanitize-coverage emits no PC tables while rustc's sancov
# does (libFuzzer rejects the mix), and (c) rustc's inline-8bit-counters hit an LLVM COMDAT error
# on some crates. So only the C core is instrumented (MSVC /fsanitize=address +
# /fsanitize-coverage=inline-8bit-counters,edge,trace-cmp via core-tests' `fuzz` feature) and
# the Rust harness is built with --cfg fuzzing only. On Linux, `cargo fuzz run <target>` works
# unchanged (build.rs then uses clang -fsanitize=address,fuzzer-no-link).
set -euo pipefail
cd "$(dirname "$0")"
SECS="${SECS:-60}"
MSVC_BIN="${MSVC_BIN:-/c/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/MSVC/14.38.33130/bin/HostX64/x64}"
export PATH="$MSVC_BIN:$PATH"                 # clang_rt.asan_dynamic-x86_64.dll
export ASAN_WIN_CONTINUE_ON_INTERCEPTION_FAILURE=1  # MSVC 14.38 ASan vs. Windows 11 26200 ucrt
export RUSTFLAGS="--cfg fuzzing -Cdebug-assertions -Coverflow-checks -Clink-arg=/include:main"
cargo +nightly build --release --target x86_64-pc-windows-msvc --target-dir target-msvc
BIN=target-msvc/x86_64-pc-windows-msvc/release
TARGETS="cbor_decode cose_decode envelope_decode manifest_decode delta_apply mqtt_decode dut_json"
mkdir -p logs work artifacts
for t in $TARGETS; do
  mkdir -p "work/$t" "artifacts/$t"
  "$BIN/$t.exe" -max_total_time="$SECS" -max_len=16384 -print_final_stats=1 \
      -artifact_prefix="artifacts/$t/" "work/$t" "corpus/$t" > "logs/$t.log" 2>&1 &
done
wait
for t in $TARGETS; do
  echo "== $t"; grep -E "Loaded|INITED|DONE|ERROR|SUMMARY|stat::number_of_executed_units|stat::peak_rss" "logs/$t.log" || true
  ls "artifacts/$t" 2>/dev/null | sed 's/^/   artifact: /'
done
