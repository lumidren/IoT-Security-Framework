#!/usr/bin/env bash
# Run every fuzz target for $SECS seconds (default 60) and summarise into logs/summary.txt.
# On Windows/MSVC: put the MSVC ASan runtime on PATH and set ASAN_WIN_CONTINUE_ON_INTERCEPTION_FAILURE=1
# (see RESULTS.md). On Linux no environment is needed.
set -u
cd "$(dirname "$0")"
SECS="${SECS:-60}"
TARGETS="${TARGETS:-cbor_decode cose_sign1_decode cose_sign_decode cose_encrypt0_decode envelope_decode manifest_decode delta_apply mqtt_decode pkcs7_decode bundle_decode}"
mkdir -p logs
: > logs/summary.txt
for t in $TARGETS; do
  mkdir -p "corpus/$t" "artifacts/$t"
  cargo +nightly fuzz run "$t" "corpus/$t" -- -max_total_time="$SECS" -rss_limit_mb=2048 > "logs/$t.log" 2>&1
  rc=$?
  runs=$(grep -Eo "Done [0-9]+ runs in [0-9]+ second" "logs/$t.log" | tail -1)
  cov=$(grep -Eo "cov: [0-9]+ ft: [0-9]+" "logs/$t.log" | tail -1)
  crashes=$(ls "artifacts/$t" 2>/dev/null | wc -l)
  echo "$t rc=$rc ${runs:-no-summary} ${cov} artifacts=$crashes" >> logs/summary.txt
done
cat logs/summary.txt
