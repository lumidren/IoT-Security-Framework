#!/usr/bin/env python3
"""Turn tool reports into GitHub Actions annotations so CI failures are readable without logs.

    annotate.py bandit REPORT.json [--prefix DIR]
    annotate.py junit REPORT.xml [--prefix DIR]
    annotate.py gosec REPORT.json [--prefix DIR]
    annotate.py cargo-deny REPORT.jsonl
    annotate.py lines LOGFILE PATTERN [--title TITLE]

Paths in the reports are relative to the tool's working directory; --prefix makes them
repository-relative so the annotation lands on the right file. Always exits 0: the calling step
keeps the tool's own exit status.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET  # noqa: S405 - parses CI-produced JUnit reports only
from pathlib import PurePosixPath


def _esc(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _path(prefix: str, path: str) -> str:
    path = path.replace("\\", "/").removeprefix("./")
    return str(PurePosixPath(prefix) / path) if prefix else path


def bandit(report: str, prefix: str) -> None:
    with open(report, encoding="utf-8") as fh:
        data = json.load(fh)
    for r in data.get("results", []):
        title = f"bandit {r.get('test_id')} {r.get('issue_severity')}/{r.get('issue_confidence')}"
        print(
            f"::error file={_path(prefix, r['filename'])},line={r.get('line_number', 1)},"
            f"title={title}::{_esc(r.get('issue_text', ''))}"
        )
    for e in data.get("errors", []):
        print(f"::warning title=bandit error::{_esc(json.dumps(e))}")


def junit(report: str, prefix: str) -> None:
    root = ET.parse(report).getroot()  # noqa: S314 - trusted, locally generated file
    for case in root.iter("testcase"):
        for kind in ("failure", "error"):
            node = case.find(kind)
            if node is None:
                continue
            name = f"{case.get('classname', '')}::{case.get('name', '')}"
            body = (node.get("message") or "") + "\n" + (node.text or "")
            file_attr = case.get("file")
            loc = f"file={_path(prefix, file_attr)}," if file_attr else ""
            line = case.get("line")
            loc += f"line={int(line) + 1}," if line and line.isdigit() else ""
            print(f"::error {loc}title=pytest {kind} {name[:120]}::{_esc(body.strip()[:3000])}")


def gosec(report: str, prefix: str) -> None:
    import os

    workspace = os.environ.get("GITHUB_WORKSPACE", "")
    with open(report, encoding="utf-8") as fh:
        data = json.load(fh)
    for i in data.get("Issues") or []:
        path = i.get("file", "")
        if workspace and path.startswith(workspace):
            path = path[len(workspace) :].lstrip("/")
        else:
            path = _path(prefix, path)
        line = str(i.get("line", "1")).split("-")[0]
        title = f"gosec {i.get('rule_id')} {i.get('severity')}/{i.get('confidence')}"
        print(f"::error file={path},line={line},title={title}::{_esc(i.get('details', ''))}")
    for f, errs in (data.get("Golang errors") or {}).items():
        print(f"::warning title=gosec load error::{_esc(f + ': ' + json.dumps(errs))}")


def cargo_deny(report: str, prefix: str) -> None:
    del prefix
    with open(report, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            raw = raw.strip()
            if not raw:
                continue
            try:
                entry = json.loads(raw)
            except json.JSONDecodeError:
                if "error" in raw.lower():
                    print(f"::error title=cargo deny::{_esc(raw)}")
                continue
            fields = entry.get("fields", {}) if isinstance(entry, dict) else {}
            if fields.get("severity") not in ("error", "Error"):
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
            print(f"::error title=cargo deny {fields.get('code', '')}::{_esc(msg)}")


def lines(log: str, pattern: str, title: str) -> None:
    rx = re.compile(pattern)
    with open(log, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if rx.search(line):
                print(f"::error title={title}::{_esc(line.rstrip())}")


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("bandit", "junit", "gosec", "cargo-deny"):
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
        elif args.cmd == "junit":
            junit(args.report, args.prefix)
        elif args.cmd == "gosec":
            gosec(args.report, args.prefix)
        elif args.cmd == "cargo-deny":
            cargo_deny(args.report, args.prefix)
        else:
            lines(args.log, args.pattern, args.title)
    except (OSError, ValueError, ET.ParseError) as exc:
        print(f"::warning title=annotate.py::{_esc(str(exc))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
