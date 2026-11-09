#!/usr/bin/env python3
"""Post-deploy SLO gate against Prometheus (deploy.yml canary analysis).

Evaluates the recording rules of observability/prometheus/rules/ironmesh.rules.yml:

* ``ironmesh:http_error_ratio:5m``                 max over jobs  <= --max-error-ratio (0.01)
* ``ironmesh:revocation_latency_seconds:p99_5m``   max            <= --max-revocation-p99 (10 s,
  the DESIGN_CONTRACT.md section 2 budget)

A missing series (no traffic yet) counts as healthy unless ``--require-data`` is set. The check
is repeated ``--samples`` times ``--interval`` seconds apart and every sample must pass.

Usage: ``python scripts/ci/slo_check.py --prometheus http://127.0.0.1:9090 [--samples 5]``
Only the standard library is used.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.parse
import urllib.request

CHECKS = (
    ("http error ratio", "max(ironmesh:http_error_ratio:5m)", "max_error_ratio"),
    ("revocation latency p99 (s)", "max(ironmesh:revocation_latency_seconds:p99_5m)", "max_revocation_p99"),
)


def query(base: str, expr: str) -> float | None:
    url = f"{base.rstrip('/')}/api/v1/query?" + urllib.parse.urlencode({"query": expr})
    with urllib.request.urlopen(url, timeout=15) as resp:  # noqa: S310 - operator-supplied URL
        body = json.load(resp)
    if body.get("status") != "success":
        raise RuntimeError(f"prometheus error for {expr!r}: {body}")
    result = body["data"]["result"]
    if not result:
        return None
    value = float(result[0]["value"][1])
    return None if value != value else value  # NaN = no data


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--prometheus", required=True)
    parser.add_argument("--max-error-ratio", type=float, default=0.01)
    parser.add_argument("--max-revocation-p99", type=float, default=10.0)
    parser.add_argument("--samples", type=int, default=5)
    parser.add_argument("--interval", type=float, default=60.0)
    parser.add_argument("--require-data", action="store_true")
    args = parser.parse_args()

    failed = False
    for i in range(args.samples):
        for name, expr, limit_attr in CHECKS:
            limit = getattr(args, limit_attr)
            value = query(args.prometheus, expr)
            if value is None:
                ok = not args.require_data
                print(f"sample {i + 1}: {name}: no data ({'ok' if ok else 'FAIL'})")
            else:
                ok = value <= limit
                print(f"sample {i + 1}: {name}: {value:.4f} (limit {limit}) {'ok' if ok else 'FAIL'}")
            failed |= not ok
        if failed:
            break
        if i + 1 < args.samples:
            time.sleep(args.interval)
    if failed:
        print("SLO check failed", file=sys.stderr)
        return 1
    print("SLO check passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
