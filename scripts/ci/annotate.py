#!/usr/bin/env python3
"""Turn tool reports into GitHub Actions annotations so CI failures are readable without logs.

    annotate.py bandit REPORT.json [--prefix DIR]
    annotate.py gosec REPORT.json [--prefix DIR]
    annotate.py cargo-deny REPORT.jsonl
    annotate.py lines LOGFILE PATTERN [--title TITLE]

Paths in the reports are relative to the tool's working directory; --prefix makes them
repository-relative so the annotation lands on the right file. GitHub keeps at most 10 error
annotations per step, so every tool first gets one summary annotation listing all findings,
followed by per-finding annotations for the first few. Always exits 0: the calling step keeps
the tool's own exit status.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import PurePosixPath

ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
PER_FINDING = 8


def _esc(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _path(prefix: str, path: str) -> str:
    workspace = os.environ.get("GITHUB_WORKSPACE", "")
    if workspace and path.startswith(workspace):
        return path[len(workspace) :].lstrip("/")
    path = path.replace("\\", "/").removeprefix("./")
    return str(PurePosixPath(prefix) / path) if prefix else path


def _emit(tool: str, findings: list[tuple[str, str, str, str]]) -> None:
    """findings: (file, line, title, message)."""
    if not findings:
        return
    summary = "\n".join(f"{f}:{ln} {t}: {m}" for f, ln, t, m in findings)
    print(f"::error title={tool}: {len(findings)} finding(s)::{_esc(summary[:60000])}")
    for f, ln, t, m in findings[:PER_FINDING]:
        loc = f"file={f}," if f else ""
        loc += f"line={ln}," if ln else ""
        print(f"::error {loc}title={t}::{_esc(m[:3000])}")


def bandit(report: str, prefix: str) -> None:
    with open(report, encoding="utf-8") as fh:
        data = json.load(fh)
    findings = [
        (
            _path(prefix, r["filename"]),
            str(r.get("line_number", 1)),
            f"bandit {r.get('test_id')} {r.get('issue_severity')}/{r.get('issue_confidence')}",
            r.get("issue_text", ""),
        )
        for r in data.get("results", [])
    ]
    _emit("bandit", findings)
    for e in data.get("errors", []):
        print(f"::warning title=bandit error::{_esc(json.dumps(e))}")


def gosec(report: str, prefix: str) -> None:
    with open(report, encoding="utf-8") as fh:
        data = json.load(fh)
    findings = [
        (
            _path(prefix, i.get("file", "")),
            str(i.get("line", "1")).split("-")[0],
            f"gosec {i.get('rule_id')} {i.get('severity')}/{i.get('confidence')}",
            f"{i.get('details', '')} | {i.get('code', '').strip()[:300]}",
        )
        for i in data.get("Issues") or []
    ]
    _emit("gosec", findings)
    for f, errs in (data.get("Golang errors") or {}).items():
        print(f"::warning title=gosec load error::{_esc(f + ': ' + json.dumps(errs))}")


def cargo_deny(report: str, prefix: str) -> None:
    del prefix
    findings: list[tuple[str, str, str, str]] = []
    with open(report, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            raw = ANSI.sub("", raw).strip()
            if not raw:
                continue
            try:
                entry = json.loads(raw)
            except json.JSONDecodeError:
                if "error" in raw.lower():
                    findings.append(("", "", "cargo deny", raw))
                continue
            fields = entry.get("fields", {}) if isinstance(entry, dict) else {}
            if str(fields.get("severity", "")).lower() != "error":
                continue
            krates = sorted(
                {
                    f"{g['Krate']['name']} {g['Krate']['version']}"
                    for g in fields.get("graphs", [])
                    if isinstance(g, dict) and "Krate" in g
                }
            )
            msg = f"[{fields.get('code', '')}] {fields.get('message', '')}"
            if krates:
                msg += " -- " + ", ".join(krates)
            for label in fields.get("labels", [])[:3]:
                msg += f"\n{label.get('message', '')}: {label.get('span', '')}"
            findings.append(("", "", f"cargo deny {fields.get('code', '')}", msg))
    _emit("cargo deny", findings)


def lines(log: str, pattern: str, title: str) -> None:
    rx = re.compile(pattern)
    with open(log, encoding="utf-8", errors="replace") as fh:
        hits = [ANSI.sub("", ln).rstrip() for ln in fh]
    _emit(title, [("", "", title, ln) for ln in hits if rx.search(ln)])


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("bandit", "gosec", "cargo-deny"):
        p = sub.add_parser(name)
        p.add_argument("report")
        p.add_argument("--prefix", default="")
    p = sub.add_parser("lines")
    p.add_argument("log")
    p.add_argument("pattern")
    p.add_argument("--title", default="ci")
    args = ap.parse_args()
    try:
        if args.cmd == "bandit":
            bandit(args.report, args.prefix)
        elif args.cmd == "gosec":
            gosec(args.report, args.prefix)
        elif args.cmd == "cargo-deny":
            cargo_deny(args.report, args.prefix)
        else:
            lines(args.log, args.pattern, args.title)
    except (OSError, ValueError) as exc:
        print(f"::warning title=annotate.py::{_esc(str(exc))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
