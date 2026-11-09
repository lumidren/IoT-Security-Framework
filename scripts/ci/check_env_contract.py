#!/usr/bin/env python3
"""Cross-check deployment environment variable names against the services' settings modules.

Sources of truth (the code, never the docs):

* Go:     ``services/{pki,policy,bridge}/internal/config/config.go`` plus direct
          ``os.Getenv("X")`` / ``os.LookupEnv("X")`` calls in ``cmd/`` and ``internal/``
* Python: the pydantic ``Settings`` class of ``services/registry/app/settings.py``,
          ``services/ota/src/ironmesh_ota/settings.py`` and
          ``services/anomaly/src/ironmesh_anomaly/config.py`` (env_prefix + field names,
          ``validation_alias``), plus ``os.environ`` lookups in the package (migrations)
* Console: ``process.env.X`` and env-name string literals in ``console/src`` and
          ``console/next.config.ts`` plus the Next.js / Auth.js runtime variables

Checked deployments:

* ``deploy/docker/docker-compose.yml`` (``environment`` of every IronMesh service container)
* ``deploy/helm/ironmesh/values*.yaml`` (``services.<name>.config`` keys and ``secretKeys``)
* ``deploy/k8s/base/services/*.yaml`` ConfigMaps and the dev overlay's ``secretGenerator``

Exit status 1 lists every name a deployment sets that the code never reads.
Usage: ``python scripts/ci/check_env_contract.py [--root .] [--verbose]``
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
from collections.abc import Iterable
from pathlib import Path

import yaml

# Variables consumed by SDKs / runtimes rather than by IronMesh code.
COMMON = {
    "OTEL_SERVICE_NAME",
    "OTEL_EXPORTER_OTLP_ENDPOINT",
    "OTEL_EXPORTER_OTLP_PROTOCOL",
    "OTEL_RESOURCE_ATTRIBUTES",
    "OTEL_TRACES_SAMPLER",
    "OTEL_TRACES_SAMPLER_ARG",
    "POD_NAME",
    "POD_NAMESPACE",
    "NODE_NAME",
    "POD_IP",
    "TMPDIR",
}
PYTHON_RUNTIME = {"PYTHONUNBUFFERED", "PYTHONDONTWRITEBYTECODE", "PATH"}
EXTRA = {
    # uvicorn --forwarded-allow-ips in services/registry/Dockerfile CMD
    "registry": {"FORWARDED_ALLOW_IPS"},
    # Next.js standalone server and Auth.js v5 read these directly.
    "console": {"NODE_ENV", "PORT", "HOSTNAME", "NEXT_TELEMETRY_DISABLED", "AUTH_SECRET", "AUTH_URL", "AUTH_TRUST_HOST"},
}

GO_CALL = re.compile(r'\b(?:get|dur|duration|boolean|integer|list)\(\s*"([A-Z][A-Z0-9_]+)"')
GO_GETENV = re.compile(r'os\.(?:Getenv|LookupEnv)\(\s*"([A-Z][A-Z0-9_]+)"\)')
PY_ENVIRON = re.compile(r'os\.environ(?:\.get)?[\[(]\s*["\']([A-Z][A-Z0-9_]+)["\']')
TS_PROCESS_ENV = re.compile(r'process\.env(?:\.([A-Z][A-Z0-9_]+)|\[\s*["\']([A-Z][A-Z0-9_]+)["\']\s*\])')
TS_LITERAL = re.compile(r"""['"]((?:CONSOLE|AUTH|NEXT_PUBLIC|REGISTRY|OTA|ANOMALY|POLICY)_[A-Z0-9_]+|MAP_TILE_ORIGINS|NEXT_DIST_DIR)['"]""")


def go_names(service_dir: Path) -> set[str]:
    names: set[str] = set()
    for path in service_dir.rglob("*.go"):
        if path.name.endswith("_test.go") or "testutil" in path.parts:
            continue
        text = path.read_text(encoding="utf-8")
        if path.parent.name == "config":
            names.update(GO_CALL.findall(text))
        names.update(GO_GETENV.findall(text))
    return names


def _literal(node: ast.AST) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def pydantic_names(settings_file: Path) -> set[str]:
    tree = ast.parse(settings_file.read_text(encoding="utf-8"))
    for cls in (n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "Settings"):
        prefix = ""
        fields: list[tuple[str, str | None]] = []
        for stmt in cls.body:
            if isinstance(stmt, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "model_config" for t in stmt.targets):
                call = stmt.value
                if isinstance(call, ast.Call):
                    for kw in call.keywords:
                        if kw.arg == "env_prefix":
                            prefix = _literal(kw.value) or ""
            elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                alias = None
                if isinstance(stmt.value, ast.Call):
                    for kw in stmt.value.keywords:
                        if kw.arg in ("validation_alias", "alias"):
                            alias = _literal(kw.value)
                fields.append((stmt.target.id, alias))
        return {alias or (prefix + name).upper() for name, alias in fields if name != "model_config"}
    raise SystemExit(f"no Settings class in {settings_file}")


def python_environ_names(package_dirs: Iterable[Path]) -> set[str]:
    names: set[str] = set()
    for root in package_dirs:
        for path in root.rglob("*.py"):
            if "tests" in path.parts:
                continue
            names.update(PY_ENVIRON.findall(path.read_text(encoding="utf-8")))
    return names


def console_names(console: Path) -> set[str]:
    names: set[str] = set()
    files = [p for p in (console / "src").rglob("*.ts*") if ".test." not in p.name]
    files.append(console / "next.config.ts")
    for path in files:
        text = path.read_text(encoding="utf-8")
        for a, b in TS_PROCESS_ENV.findall(text):
            names.add(a or b)
        names.update(TS_LITERAL.findall(text))
    return names


def contract(root: Path) -> dict[str, set[str]]:
    svc = root / "services"
    c = {
        "pki": go_names(svc / "pki"),
        "policy": go_names(svc / "policy"),
        "bridge": go_names(svc / "bridge"),
        "registry": pydantic_names(svc / "registry/app/settings.py")
        | python_environ_names([svc / "registry/app", svc / "registry/migrations"]),
        "ota": pydantic_names(svc / "ota/src/ironmesh_ota/settings.py") | python_environ_names([svc / "ota/src"]),
        "anomaly": pydantic_names(svc / "anomaly/src/ironmesh_anomaly/config.py")
        | python_environ_names([svc / "anomaly/src"]),
        "console": console_names(root / "console"),
    }
    for name in c:
        c[name] |= COMMON | EXTRA.get(name, set())
        if name in ("registry", "ota", "anomaly"):
            c[name] |= PYTHON_RUNTIME
    return c


# compose service -> settings module
COMPOSE_SERVICES = {
    "pki": "pki",
    "policy": "policy",
    "bridge": "bridge",
    "registry": "registry",
    "registry-migrate": "registry",
    "registry-seed": "registry",
    "ota": "ota",
    "ota-migrate": "ota",
    "anomaly": "anomaly",
    "console": "console",
}


def compose_findings(root: Path, c: dict[str, set[str]]) -> list[str]:
    path = root / "deploy/docker/docker-compose.yml"
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    out = []
    for svc_name, module in COMPOSE_SERVICES.items():
        svc = doc["services"].get(svc_name)
        if svc is None:
            out.append(f"{path}: service {svc_name} missing")
            continue
        env = svc.get("environment") or {}
        keys = env.keys() if isinstance(env, dict) else [e.split("=", 1)[0] for e in env]
        for key in keys:
            if key not in c[module]:
                out.append(f"compose {svc_name}: {key} is not read by {module}")
    return out


def helm_findings(root: Path, c: dict[str, set[str]]) -> list[str]:
    out = []
    for path in sorted((root / "deploy/helm/ironmesh").glob("values*.yaml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for name, svc in (doc.get("services") or {}).items():
            if name not in c:
                continue
            for key in (svc.get("config") or {}):
                if key not in c[name]:
                    out.append(f"{path.name} services.{name}.config: {key} is not read by {name}")
            for key in svc.get("secretKeys") or []:
                if key not in c[name]:
                    out.append(f"{path.name} services.{name}.secretKeys: {key} is not read by {name}")
            for item in svc.get("extraEnv") or []:
                if isinstance(item, dict) and item.get("name") not in c[name]:
                    out.append(f"{path.name} services.{name}.extraEnv: {item.get('name')} is not read by {name}")
    return out


def kustomize_findings(root: Path, c: dict[str, set[str]]) -> list[str]:
    out = []
    for path in sorted((root / "deploy/k8s/base/services").glob("*.yaml")):
        name = path.stem
        for doc in yaml.safe_load_all(path.read_text(encoding="utf-8")):
            if doc and doc.get("kind") == "ConfigMap":
                for key in doc.get("data") or {}:
                    if key not in c.get(name, set()):
                        out.append(f"k8s {path.name} ConfigMap {doc['metadata']['name']}: {key} is not read by {name}")
    overlay = root / "deploy/k8s/overlays/dev/kustomization.yaml"
    doc = yaml.safe_load(overlay.read_text(encoding="utf-8"))
    for gen in doc.get("secretGenerator") or []:
        svc = gen["name"].removesuffix("-secret")
        if svc not in c or not gen["name"].endswith("-secret"):
            continue
        for literal in gen.get("literals") or []:
            key = literal.split("=", 1)[0]
            if key not in c[svc]:
                out.append(f"k8s overlay secret {gen['name']}: {key} is not read by {svc}")
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", default=str(Path(__file__).resolve().parents[2]))
    parser.add_argument("--verbose", action="store_true", help="print the names read by each service")
    args = parser.parse_args()
    root = Path(args.root)
    c = contract(root)
    if args.verbose:
        for name, names in sorted(c.items()):
            print(f"{name}: {' '.join(sorted(names))}\n")
    findings = compose_findings(root, c) + helm_findings(root, c) + kustomize_findings(root, c)
    for f in findings:
        print(f"ERROR {f}")
    print(f"env contract: {len(findings)} finding(s)")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
