#!/usr/bin/env python3
"""Lint the Grafana dashboards and check the Helm copy of the Prometheus rules.

* every ``observability/grafana/dashboards/*.json`` parses, has a unique ``uid`` and ``title``,
  unique panel ids, and only references provisioned datasource uids (``prometheus``, ``tempo``)
  or template variables;
* ``deploy/helm/ironmesh/rules/ironmesh.rules.yml`` is byte-identical to
  ``observability/prometheus/rules/ironmesh.rules.yml`` (the chart embeds it verbatim).

Usage: ``python scripts/ci/check_observability.py [--root .]``
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import yaml

DATASOURCE_UIDS = {"prometheus", "tempo", "-- Grafana --", "grafana"}


def panels(node: dict[str, Any]) -> Iterator[dict[str, Any]]:
    for panel in node.get("panels", []) or []:
        yield panel
        yield from panels(panel)


def datasource_uids(node: Any) -> Iterator[str]:
    if isinstance(node, dict):
        ds = node.get("datasource")
        if isinstance(ds, dict) and isinstance(ds.get("uid"), str):
            yield ds["uid"]
        elif isinstance(ds, str):
            yield ds
        for value in node.values():
            yield from datasource_uids(value)
    elif isinstance(node, list):
        for value in node:
            yield from datasource_uids(value)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", default=str(Path(__file__).resolve().parents[2]))
    root = Path(parser.parse_args().root)
    errors: list[str] = []

    provisioned = yaml.safe_load((root / "observability/grafana/provisioning/datasources/datasources.yaml").read_text(encoding="utf-8"))
    known = DATASOURCE_UIDS | {d["uid"] for d in provisioned.get("datasources", [])}

    uids: dict[str, str] = {}
    files = sorted((root / "observability/grafana/dashboards").glob("*.json"))
    if not files:
        errors.append("no dashboards found")
    for path in files:
        try:
            dash = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            errors.append(f"{path.name}: invalid JSON: {exc}")
            continue
        uid, title = dash.get("uid"), dash.get("title")
        if not uid or not title:
            errors.append(f"{path.name}: missing uid or title")
        elif uid in uids:
            errors.append(f"{path.name}: uid {uid} already used by {uids[uid]}")
        else:
            uids[uid] = path.name
        ids = [p.get("id") for p in panels(dash) if "id" in p]
        dupes = {i for i in ids if ids.count(i) > 1}
        if dupes:
            errors.append(f"{path.name}: duplicate panel ids {sorted(dupes)}")
        for ds in set(datasource_uids(dash)):
            if ds not in known and not ds.startswith("$"):
                errors.append(f"{path.name}: unknown datasource {ds!r}")
        print(f"ok   {path.name} ({len(ids)} panels)")

    a = root / "observability/prometheus/rules/ironmesh.rules.yml"
    b = root / "deploy/helm/ironmesh/rules/ironmesh.rules.yml"
    if a.read_bytes() != b.read_bytes():
        errors.append(f"{b} differs from {a}")
    yaml.safe_load(a.read_text(encoding="utf-8"))

    for e in errors:
        print(f"ERROR {e}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
