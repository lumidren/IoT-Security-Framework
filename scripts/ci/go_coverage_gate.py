#!/usr/bin/env python3
"""Statement-coverage gate for a Go cover profile, restricted to selected packages.

    go test ./... -race -covermode=atomic -coverprofile=coverage.out
    python scripts/ci/go_coverage_gate.py coverage.out --min 90 --include /internal/

Blocks are de-duplicated (a block reported by several test binaries counts once, covered if any
run covered it). Prints per-package coverage and exits 1 when the aggregate of the included
packages is below ``--min`` percent. ``--exclude`` drops packages such as test helpers.
"""

from __future__ import annotations

import argparse
import sys
from collections import defaultdict
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("profile", type=Path)
    parser.add_argument("--min", type=float, default=90.0, help="minimum percent (default 90)")
    parser.add_argument("--include", action="append", default=None, help="path substring to include (repeatable; default /internal/)")
    parser.add_argument("--exclude", action="append", default=[], help="path substring to exclude (repeatable)")
    args = parser.parse_args()
    include = args.include or ["/internal/"]

    blocks: dict[str, tuple[int, bool]] = {}
    for line in args.profile.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("mode:"):
            continue
        try:
            location, stmts, count = line.rsplit(" ", 2)
            n, hit = int(stmts), int(count) > 0
        except ValueError:
            print(f"go_coverage_gate: malformed line: {line!r}", file=sys.stderr)
            return 2
        path = location.split(":", 1)[0]
        if not any(s in path for s in include) or any(s in path for s in args.exclude):
            continue
        prev = blocks.get(location)
        blocks[location] = (n, hit or (prev[1] if prev else False))

    per_pkg: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for location, (n, hit) in blocks.items():
        pkg = location.split(":", 1)[0].rsplit("/", 1)[0]
        per_pkg[pkg][0] += n
        per_pkg[pkg][1] += n if hit else 0

    total = sum(v[0] for v in per_pkg.values())
    covered = sum(v[1] for v in per_pkg.values())
    if total == 0:
        print("go_coverage_gate: no statements matched --include", file=sys.stderr)
        return 2
    for pkg in sorted(per_pkg):
        t, c = per_pkg[pkg]
        print(f"{100.0 * c / t:6.1f}%  {pkg}")
    pct = 100.0 * covered / total
    print(f"total {pct:.2f}% of {total} statements (minimum {args.min:.1f}%)")
    if pct + 1e-9 < args.min:
        print(f"go_coverage_gate: coverage {pct:.2f}% is below {args.min:.1f}%", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
