"""Command-line interface: ``python -m ironmesh_wire {vectors,delta} ...``."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__, delta, vectors
from .errors import WireError


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ironmesh-wire", description="IronMesh wire-format reference tools"
    )
    parser.add_argument("--version", action="version", version=f"ironmesh-wire {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    vec = sub.add_parser("vectors", help="generate the deterministic test-vector JSON files")
    vec.add_argument("--out", type=Path, required=True, help="output directory")
    vec.add_argument(
        "--keys",
        type=Path,
        default=None,
        help="directory with the fixed test keys (default: <checkout>/tests/keys)",
    )

    dlt = sub.add_parser("delta", help="make or apply an IronMesh block-delta patch")
    dlt_sub = dlt.add_subparsers(dest="delta_command", required=True)
    make = dlt_sub.add_parser("make", help="make a patch: OLD NEW PATCH")
    make.add_argument("old", type=Path)
    make.add_argument("new", type=Path)
    make.add_argument("patch", type=Path)
    apply = dlt_sub.add_parser("apply", help="apply a patch: OLD PATCH OUT")
    apply.add_argument("old", type=Path)
    apply.add_argument("patch", type=Path)
    apply.add_argument("out", type=Path)
    info = dlt_sub.add_parser("info", help="print header and op statistics of a patch")
    info.add_argument("patch", type=Path)
    return parser


def _cmd_vectors(args: argparse.Namespace) -> int:
    keys_dir: Path = args.keys if args.keys is not None else vectors.default_keys_dir()
    if not keys_dir.is_dir():
        print(f"error: test key directory not found: {keys_dir} (use --keys)", file=sys.stderr)
        return 2
    written = vectors.generate_all(args.out, vectors.TestKeys.load(keys_dir))
    for path in written:
        print(path)
    print(f"wrote {len(written)} vector files to {args.out}")
    return 0


def _cmd_delta(args: argparse.Namespace) -> int:
    if args.delta_command == "make":
        patch = delta.make_delta(args.old.read_bytes(), args.new.read_bytes())
        args.patch.write_bytes(patch)
        _, copies, literal_bytes = delta.inspect_delta(patch)
        print(f"wrote {len(patch)} bytes ({copies} COPY ops, {literal_bytes} literal bytes)")
        return 0
    if args.delta_command == "apply":
        new = delta.apply_delta(args.old.read_bytes(), args.patch.read_bytes())
        args.out.write_bytes(new)
        print(f"wrote {len(new)} bytes")
        return 0
    header, copies, literal_bytes = delta.inspect_delta(args.patch.read_bytes())
    print(f"block_size:    {header.block_size}")
    print(f"base_size:     {header.base_size}")
    print(f"base_sha256:   {header.base_sha256.hex()}")
    print(f"target_size:   {header.target_size}")
    print(f"target_sha256: {header.target_sha256.hex()}")
    print(f"copy_ops:      {copies}")
    print(f"literal_bytes: {literal_bytes}")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.command == "vectors":
            return _cmd_vectors(args)
        return _cmd_delta(args)
    except WireError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
