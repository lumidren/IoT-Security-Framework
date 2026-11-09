#!/usr/bin/env python3
"""Resolve ``path::symbol`` code references in the security documents.

THREAT_MODEL.md, COMPLIANCE_MATRIX.md and ARCHITECTURE.md cite the code that
implements each mitigation or control as a backticked reference of the form ``path::symbol``
(for example ``services/pki/internal/est/handler.go::rejectReusedKey``).  This
script checks those references against the repository and, on request, rewrites
them to ``path:line (symbol)`` so a reviewer can jump straight to the line.

Backticked bare repository paths (``device/esp32/partitions.csv``,
``sbom/README.md``) are checked too: a token whose first segment is an existing
top-level entry of the repository, or a root-level ``UPPERCASE.md`` name, must
exist as a file or directory.  Bare paths are never rewritten.

Modes
-----
--check     (default) verify every reference, print a report, change nothing.
--rewrite   additionally rewrite resolved references in place.  Unresolved
            references are left untouched.  Already-resolved references are
            re-resolved so line numbers stay fresh after refactors.
--file F    scan F instead of the default set (THREAT_MODEL.md,
            COMPLIANCE_MATRIX.md, ARCHITECTURE.md); repeatable.

Exit status
-----------
0  every reference resolved (or --strict not given)
1  --strict given and at least one reference is unresolved or a bare path
   does not exist
2  usage error (markdown file or repository root missing)

Only the Python standard library is used.  Python 3.8 or newer.
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# A reference is backticked, the path contains at least one "." or "/" (so Rust
# paths such as `std::fs` are not mistaken for file references) and the symbol
# runs to the closing backtick.  Symbols may contain spaces (Markdown headings,
# bold terms, config keys).
_PATH = r"(?P<path>(?=[^`:]*[./])[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*)"
UNRESOLVED_RE = re.compile(r"`" + _PATH + r"::(?P<symbol>[^`]+?)`")
RESOLVED_RE = re.compile(r"`" + _PATH + r":(?P<line>\d+) \((?P<symbol>[^`]+?)\)`")
# Any other backticked token that looks like a repository path.
BARE_RE = re.compile(r"`(?P<path>\.?[A-Za-z0-9_-][A-Za-z0-9_./-]*)`")
ROOT_DOC_RE = re.compile(r"^[A-Z][A-Z0-9_]*\.md$")

DEFAULT_FILES = ["THREAT_MODEL.md", "COMPLIANCE_MATRIX.md", "ARCHITECTURE.md"]

STATUS_OK = "RESOLVED"
STATUS_PARTIAL = "RESOLVED (last segment)"
STATUS_NO_FILE = "MISSING FILE"
STATUS_NO_SYMBOL = "SYMBOL NOT FOUND"
STATUS_PATH_OK = "PATH EXISTS"
STATUS_NO_PATH = "MISSING PATH"


def _definition_patterns(ext: str, name: str) -> List[re.Pattern]:
    """Regexes that match a *definition* of ``name`` for the given extension."""
    n = re.escape(name)
    common: List[re.Pattern] = []  # comments never count as definitions
    table = {
        ".go": [
            re.compile(r"^\s*func\s+(?:\([^)]*\)\s*)?" + n + r"\b"),
            re.compile(r"^\s*(?:type|var|const)\s+" + n + r"\b"),
            re.compile(r"^\s*" + n + r"\s*:?=\s"),
        ],
        ".rs": [
            re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?(?:fn|struct|enum|trait|const|static|mod|type|macro_rules!)\s+" + n + r"\b"),
            re.compile(r"^\s*impl\b.*\b" + n + r"\b"),
        ],
        ".py": [
            re.compile(r"^\s*(?:async\s+def|def|class)\s+" + n + r"\b"),
            re.compile(r"^\s*" + n + r"\s*(?::\s*[A-Za-z_\[\], .]+)?=\s"),
        ],
        ".c": [
            re.compile(r"^\s*(?:[A-Za-z_][\w\s\*]*?\s+\*?)" + n + r"\s*\("),
            re.compile(r"^\s*#\s*define\s+" + n + r"\b"),
        ],
        ".h": [
            re.compile(r"^\s*(?:[A-Za-z_][\w\s\*]*?\s+\*?)" + n + r"\s*\("),
            re.compile(r"^\s*#\s*define\s+" + n + r"\b"),
        ],
        ".rego": [
            re.compile(r"^\s*(?:default\s+)?" + n + r"\b"),
        ],
        ".sql": [
            re.compile(r"^\s*.*\b" + n + r"\b", re.IGNORECASE),
        ],
        ".md": [
            re.compile(r"^\s*#{1,6}\s+.*" + n),
            re.compile(r"\*\*" + n + r"\*\*"),
        ],
        ".ts": [
            re.compile(r"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?(?:function|class|const|let|var|interface|type|enum)\s+" + n + r"\b"),
        ],
        ".tsx": [
            re.compile(r"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?(?:function|class|const|let|var|interface|type|enum)\s+" + n + r"\b"),
        ],
        ".tf": [
            re.compile(r"^\s*(?:resource|data)\s+\"[^\"]*\"\s+\"" + n + r"\""),
            re.compile(r"^\s*(?:module|variable|output)\s+\"" + n + r"\""),
            re.compile(r"^\s*" + n + r"\s*=\s"),
        ],
    }
    generic = [
        re.compile(r"^\s*" + n + r"\s*$"),            # whole line, e.g. a YAML `name: x` entry
        re.compile(r"^\s*" + n + r"\s*[:=]"),          # yaml / conf / toml / csv keys
        re.compile(r"^\s*CONFIG_[A-Z0-9_]*" + n + r"\b"),  # sdkconfig keys
    ]
    return table.get(ext, []) + generic + common


def _score(line: str, name: str, ext: str) -> int:
    for pat in _definition_patterns(ext, name):
        if pat.search(line):
            return 3
    idx = line.find(name)
    if idx >= 0:
        tail = line[idx + len(name):idx + len(name) + 2].lstrip()
        if tail[:1] in ("(", "=", ":", "{", "<"):
            return 2
        return 1
    return 0


def _strip_call(symbol: str) -> str:
    symbol = symbol.strip()
    if symbol.endswith("()"):
        symbol = symbol[:-2]
    return symbol


def _candidates(symbol: str) -> List[Tuple[str, bool]]:
    """Return (needle, is_partial) pairs to try, most specific first."""
    full = _strip_call(symbol)
    out = [(full, False)]
    for sep in ("::", "."):
        if sep in full:
            last = full.rsplit(sep, 1)[-1]
            if last and last != full:
                out.append((last, True))
    return out


def find_symbol(lines: List[str], symbol: str, ext: str) -> Tuple[Optional[int], bool]:
    """Return (1-based line, partial) for the best match of ``symbol``."""
    for needle, partial in _candidates(symbol):
        best_line, best_score = None, 0
        for i, line in enumerate(lines, 1):
            if needle not in line:
                continue
            s = _score(line, needle, ext)
            if s > best_score:
                best_line, best_score = i, s
                if s == 3:
                    break
        if best_line is not None:
            return best_line, partial
        # Case-insensitive fallback for prose-like files (Markdown, SQL, conf).
        lowered = needle.lower()
        for i, line in enumerate(lines, 1):
            if lowered in line.lower():
                return i, partial
    return None, False


class Resolver:
    def __init__(self, root: Path) -> None:
        self.root = root
        self._cache: Dict[str, Optional[List[str]]] = {}

    def _read(self, rel: str) -> Optional[List[str]]:
        if rel in self._cache:
            return self._cache[rel]
        target = (self.root / rel)
        try:
            target_resolved = target.resolve()
            root_resolved = self.root.resolve()
            if root_resolved not in target_resolved.parents and target_resolved != root_resolved:
                self._cache[rel] = None
                return None
            if not target_resolved.is_file():
                self._cache[rel] = None
                return None
            text = target_resolved.read_text(encoding="utf-8", errors="replace")
        except OSError:
            self._cache[rel] = None
            return None
        lines = text.splitlines()
        self._cache[rel] = lines
        return lines

    def is_repo_path(self, token: str) -> bool:
        """True when ``token`` should be checked as a bare repository path."""
        if "/" not in token:
            return bool(ROOT_DOC_RE.match(token))
        first = token.split("/", 1)[0]
        return bool(first) and first not in (".", "..") and (self.root / first).exists()

    def path_exists(self, rel: str) -> bool:
        target = self.root / rel.rstrip("/")
        try:
            target_resolved = target.resolve()
        except OSError:
            return False
        root_resolved = self.root.resolve()
        if root_resolved not in target_resolved.parents and target_resolved != root_resolved:
            return False
        return target_resolved.exists()

    def resolve(self, rel: str, symbol: str) -> Tuple[str, Optional[int]]:
        lines = self._read(rel)
        if lines is None:
            return STATUS_NO_FILE, None
        ext = os.path.splitext(rel)[1].lower()
        line, partial = find_symbol(lines, symbol, ext)
        if line is None:
            return STATUS_NO_SYMBOL, None
        return (STATUS_PARTIAL if partial else STATUS_OK), line


def scan(text: str, resolver: Optional["Resolver"] = None) -> List[dict]:
    """Collect every reference in ``text`` with its span and current form."""
    refs: List[dict] = []
    if resolver is not None:
        for m in BARE_RE.finditer(text):
            token = m.group("path")
            if resolver.is_repo_path(token):
                refs.append({"span": m.span(), "path": token, "symbol": "",
                             "line": None, "form": "path"})
    for m in UNRESOLVED_RE.finditer(text):
        refs.append({"span": m.span(), "path": m.group("path"), "symbol": m.group("symbol"),
                     "line": None, "form": "unresolved"})
    for m in RESOLVED_RE.finditer(text):
        refs.append({"span": m.span(), "path": m.group("path"), "symbol": m.group("symbol"),
                     "line": int(m.group("line")), "form": "resolved"})
    refs.sort(key=lambda r: r["span"][0])
    return refs


def line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def process_file(md_path: Path, resolver: Resolver, rewrite: bool) -> Tuple[List[dict], bool]:
    text = md_path.read_text(encoding="utf-8")
    refs = scan(text, resolver)
    report: List[dict] = []
    pieces: List[str] = []
    cursor = 0
    changed = False
    for ref in refs:
        if ref["form"] == "path":
            ok = resolver.path_exists(ref["path"])
            report.append({
                "file": str(md_path),
                "md_line": line_of(text, ref["span"][0]),
                "path": ref["path"],
                "symbol": "",
                "status": STATUS_PATH_OK if ok else STATUS_NO_PATH,
                "line": 0 if ok else None,
            })
            continue
        status, line = resolver.resolve(ref["path"], ref["symbol"])
        entry = {
            "file": str(md_path),
            "md_line": line_of(text, ref["span"][0]),
            "path": ref["path"],
            "symbol": ref["symbol"],
            "status": status,
            "line": line,
        }
        report.append(entry)
        if rewrite and line is not None:
            start, end = ref["span"]
            replacement = "`{}:{} ({})`".format(ref["path"], line, ref["symbol"])
            if text[start:end] != replacement:
                pieces.append(text[cursor:start])
                pieces.append(replacement)
                cursor = end
                changed = True
    if rewrite and changed:
        pieces.append(text[cursor:])
        new_text = "".join(pieces)
        tmp = md_path.with_suffix(md_path.suffix + ".tmp")
        tmp.write_text(new_text, encoding="utf-8", newline="\n")
        os.replace(tmp, md_path)
    return report, changed


def _label(r: dict) -> str:
    if r["status"] in (STATUS_PATH_OK, STATUS_NO_PATH):
        return r["path"]
    return r["path"] + "::" + r["symbol"]


def print_report(report: List[dict], quiet: bool) -> None:
    width = max([len(_label(r)) for r in report] + [10])
    for r in report:
        if quiet and r["status"] in (STATUS_OK, STATUS_PARTIAL, STATUS_PATH_OK):
            continue
        ref = _label(r)
        where = "" if not r["line"] else " -> {}:{}".format(r["path"], r["line"])
        print("  [{:<23}] L{:<5} {:<{w}}{}".format(r["status"], r["md_line"], ref, where, w=width))


def main(argv: Optional[List[str]] = None) -> int:
    here = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="report only (default)")
    mode.add_argument("--rewrite", action="store_true", help="rewrite resolved references in place")
    parser.add_argument("--root", default=str(here.parent), help="repository root (default: parent of scripts/)")
    parser.add_argument("--file", action="append", default=None,
                        help="markdown file to scan, relative to root "
                             "(default: THREAT_MODEL.md, COMPLIANCE_MATRIX.md, ARCHITECTURE.md); repeatable")
    parser.add_argument("--strict", action="store_true", help="exit 1 if any reference is unresolved")
    parser.add_argument("--json", action="store_true", help="emit a JSON report instead of text")
    parser.add_argument("--quiet", action="store_true", help="only list unresolved references and the summary")
    args = parser.parse_args(argv)

    root = Path(args.root)
    if not root.is_dir():
        print("error: repository root not found: {}".format(root), file=sys.stderr)
        return 2
    files = args.file or DEFAULT_FILES
    md_paths = [root / f for f in files]
    missing = [p for p in md_paths if not p.is_file()]
    if missing:
        for p in missing:
            print("error: markdown file not found: {}".format(p), file=sys.stderr)
        return 2

    resolver = Resolver(root)
    full_report: List[dict] = []
    any_changed = False
    for md in md_paths:
        report, changed = process_file(md, resolver, rewrite=args.rewrite)
        full_report.extend(report)
        any_changed = any_changed or changed

    paths = [r for r in full_report if r["status"] in (STATUS_PATH_OK, STATUS_NO_PATH)]
    symbols = [r for r in full_report if r["status"] not in (STATUS_PATH_OK, STATUS_NO_PATH)]
    resolved = [r for r in symbols if r["line"] is not None]
    unresolved = [r for r in symbols if r["line"] is None]
    no_file = [r for r in unresolved if r["status"] == STATUS_NO_FILE]
    no_symbol = [r for r in unresolved if r["status"] == STATUS_NO_SYMBOL]
    no_path = [r for r in paths if r["status"] == STATUS_NO_PATH]

    if args.json:
        json.dump({
            "mode": "rewrite" if args.rewrite else "check",
            "root": str(root),
            "files": [str(p) for p in md_paths],
            "total": len(symbols),
            "resolved": len(resolved),
            "unresolved": len(unresolved),
            "missing_file": len(no_file),
            "symbol_not_found": len(no_symbol),
            "bare_paths": len(paths),
            "missing_paths": len(no_path),
            "rewritten": any_changed,
            "references": full_report,
        }, sys.stdout, indent=2)
        print()
    else:
        print("resolve_threat_refs: {} mode, root={}".format("rewrite" if args.rewrite else "check", root))
        print_report(full_report, quiet=args.quiet)
        print()
        print("summary: {} references, {} resolved, {} unresolved ({} missing file, {} symbol not found); "
              "{} bare paths, {} missing".format(
                  len(symbols), len(resolved), len(unresolved), len(no_file), len(no_symbol),
                  len(paths), len(no_path)))
        if args.rewrite:
            print("rewrite: {}".format("file(s) updated" if any_changed else "nothing to change"))

    if args.strict and (unresolved or no_path):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
