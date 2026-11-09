"""IronMesh compose demo driver (runs inside the compose network, see deploy/docker).

Executed by the ``seed`` and ``demo-tools`` services with the OTA image's Python environment
(httpx is a dependency of that image), so the host needs nothing but Docker. Every call goes
through the public contract (docs/API_CONTRACT.md) with an OIDC access token from the local
Keycloak demo realm. The PKI tenant policy is never written here: the registry (the only holder
of tenant command keys) pushes the command key and ``allow_software_keys``, the OTA service pushes
its firmware signing keys (API_CONTRACT §5). ``seed`` only reads the policy back
(``GET /v1/tenants/{t}/policy`` over mTLS with the svc-ota identity) and waits until both keys are
there, so the fleet never enrolls with an incomplete trust bundle.

Subcommands::

    seed             register the virtual fleet (factory flow), upload the baseline firmware so
                     the OTA service publishes its keys, wait for the PKI tenant policy
    campaign         upload a demo firmware image and start a 1% -> 10% -> 100% campaign
    wait-active N    wait until N fleet devices are active in the registry
    wait-quarantine  wait until the anomaly engine has auto-quarantined a device
    status           print a short fleet / campaign / alert summary
    harness-secrets  print JSON for the conformance --stack harness: a fresh registry API key
                     (role admin: factory + operator) and the tenant id. The tenant command key
                     stays KMS-wrapped inside the registry, so ``tenant_key_seed_hex`` is empty
                     and the harness skips the cases that need to sign downlinks itself.

Configuration comes from the environment set in docker-compose.yml (IRONMESH_*).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import ssl
import sys
import time
from pathlib import Path
from typing import Any

import httpx

TIMEOUT = httpx.Timeout(30.0, connect=10.0)


def env(name: str, default: str | None = None) -> str:
    value = os.environ.get(name, default)
    if value is None or value == "":
        sys.exit(f"demo: {name} is not set")
    return value


def log(msg: str) -> None:
    print(f"{time.strftime('%H:%M:%S')} demo: {msg}", flush=True)


# --- authentication ---------------------------------------------------------------------------


class Session:
    """OIDC password grant against the demo realm (client ``ironmesh-cli``), refreshed on expiry."""

    def __init__(self) -> None:
        self.http = httpx.Client(timeout=TIMEOUT)
        self._token: str | None = None
        self._expires = 0.0

    def token(self) -> str:
        if self._token and time.time() < self._expires - 60:
            return self._token
        deadline = time.time() + 300
        while True:
            try:
                resp = self.http.post(
                    env("IRONMESH_TOKEN_URL"),
                    data={
                        "grant_type": "password",
                        "client_id": "ironmesh-cli",
                        "username": env("IRONMESH_DEMO_USER", "demo"),
                        "password": env("IRONMESH_DEMO_PASSWORD"),
                        "scope": "openid",
                    },
                )
                if resp.status_code == 200:
                    body = resp.json()
                    self._token = str(body["access_token"])
                    self._expires = time.time() + float(body.get("expires_in", 300))
                    return self._token
                reason = f"HTTP {resp.status_code}"
            except httpx.HTTPError as exc:
                reason = str(exc)
            if time.time() > deadline:
                sys.exit(f"demo: cannot obtain an access token ({reason})")
            time.sleep(3)

    def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        headers = dict(kwargs.pop("headers", {}) or {})
        headers["Authorization"] = f"Bearer {self.token()}"
        for attempt in range(5):
            try:
                resp = self.http.request(method, url, headers=headers, **kwargs)
            except httpx.TransportError:
                if attempt == 4:
                    raise
                time.sleep(2)
                continue
            if resp.status_code in (502, 503, 504) and attempt < 4:
                time.sleep(2)
                continue
            return resp
        raise RuntimeError("unreachable")


def check(resp: httpx.Response, *ok: int) -> Any:
    if resp.status_code not in ok:
        sys.exit(f"demo: {resp.request.method} {resp.request.url} -> {resp.status_code}: {resp.text[:500]}")
    return resp.json() if resp.content else None


# --- seed -------------------------------------------------------------------------------------


def fleet_devices() -> list[tuple[str, str]]:
    """(device_id, bootstrap serial hex) for every identity with a factory bootstrap cert."""
    root = Path(env("IRONMESH_FLEET_DIR", "/fleet"))
    index = json.loads((root / "fleet.json").read_text(encoding="utf-8"))
    out: list[tuple[str, str]] = []
    for device_id in index["devices"]:
        record = root / device_id / "factory" / f"{device_id}.record.json"
        if not record.is_file():
            sys.exit(f"demo: {record} missing (did pki-init issue the bootstrap certificates?)")
        out.append((device_id, str(json.loads(record.read_text(encoding="utf-8"))["Serial"]).lower()))
    return out


def firmware_pubkeys(s: Session) -> list[bytes]:
    keys = check(s.request("GET", f"{env('IRONMESH_OTA_URL')}/v1/signing-keys"), 200)
    out = [base64.b64decode(k["public_key_b64"]) for k in keys if k.get("algorithm") == "Ed25519"]
    if not out:
        sys.exit("demo: the OTA service lists no Ed25519 signing key")
    return out


def demo_image(version: str) -> bytes:
    """Deterministic demo image bytes, so the hash is reproducible for a given version."""
    seed = hashlib.sha256(f"ironmesh-demo-firmware:{version}".encode()).digest()
    return b"".join(hashlib.sha256(seed + i.to_bytes(4, "big")).digest() for i in range(8192))


def upload_baseline_firmware(s: Session) -> None:
    """Upload the version the fleet already runs (fleet.toml: 1.0.0 / code 1), once.

    The OTA service pushes its firmware signing keys to the PKI for every tenant that has firmware
    (its key-sync outbox is keyed on the first stored image), so this is what puts
    ``firmware_keys_b64`` into the tenant policy before the fleet enrolls.
    """
    product = env("IRONMESH_FLEET_PRODUCT", "fleet-sim")
    metadata = {
        "product": product,
        "version": "1.0.0",
        "version_code": 1,
        "notes": "IronMesh quickstart baseline image (the version the virtual fleet reports)",
        "severity": "normal",
    }
    resp = s.request(
        "POST",
        f"{env('IRONMESH_OTA_URL')}/v1/firmware",
        files={"image": ("firmware.bin", demo_image("1.0.0"), "application/octet-stream")},
        data={"metadata": json.dumps(metadata)},
    )
    if resp.status_code == 409:
        log(f"baseline firmware {product}/1.0.0 already uploaded")
        return
    fw = check(resp, 201)
    log(f"baseline firmware {fw['product']}/{fw['version']} uploaded (key {fw['signing_key_id']})")


def pki_client() -> httpx.Client:
    """mTLS client for the PKI management API with the Services CA identity in IRONMESH_PKI_TLS_DIR."""
    tls_dir = Path(env("IRONMESH_PKI_TLS_DIR", "/etc/ironmesh/tls"))
    ctx = ssl.create_default_context(cafile=str(tls_dir / "ca.crt"))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(str(tls_dir / "tls.crt"), str(tls_dir / "tls.key"))
    return httpx.Client(base_url=env("IRONMESH_PKI_URL"), verify=ctx, timeout=TIMEOUT)


def wait_pki_tenant_policy(tenant: str, fw_pubs: list[bytes], timeout_s: float = 300.0) -> dict[str, Any]:
    """Poll GET /v1/tenants/{t}/policy until the registry's command key and the OTA firmware keys
    are both present (and software keys are allowed for the simulated fleet)."""
    want_fw = {base64.b64encode(k).decode() for k in fw_pubs}
    deadline = time.time() + timeout_s
    with pki_client() as pki:
        while True:
            try:
                resp = pki.get(f"/v1/tenants/{tenant}/policy")
                if resp.status_code == 200:
                    pol = resp.json()
                    have_fw = set(pol.get("firmware_keys_b64") or [])
                    missing = []
                    if not pol.get("command_key_b64"):
                        missing.append("command key (registry)")
                    if not want_fw <= have_fw:
                        missing.append("firmware keys (ota)")
                    if not pol.get("allow_software_keys"):
                        missing.append("allow_software_keys (registry)")
                    if not missing:
                        return dict(pol)
                    reason = "waiting for " + ", ".join(missing)
                elif resp.status_code == 404:
                    reason = "no tenant policy yet"
                else:
                    reason = f"HTTP {resp.status_code}: {resp.text[:200]}"
            except httpx.HTTPError as exc:
                reason = str(exc)
            if time.time() > deadline:
                sys.exit(f"demo: PKI tenant policy incomplete after {int(timeout_s)}s ({reason})")
            log(f"PKI tenant policy: {reason}")
            time.sleep(3)


def cmd_seed(_: argparse.Namespace) -> None:
    s = Session()
    registry = env("IRONMESH_REGISTRY_URL")
    tenant = env("IRONMESH_TENANT_ID")
    product = env("IRONMESH_FLEET_PRODUCT", "fleet-sim")

    me = check(s.request("GET", f"{registry}/v1/tenants/me"), 200)
    if me["id"] != tenant:
        sys.exit(f"demo: token tenant {me['id']} != IRONMESH_TENANT_ID {tenant}")
    log(f"tenant {tenant} present (allow_software_keys={me['settings'].get('allow_software_keys')})")

    created = existing = 0
    for device_id, serial in fleet_devices():
        resp = s.request(
            "POST",
            f"{registry}/v1/devices",
            json={
                "id": device_id,
                "product": product,
                "hw_revision": "sim-1",
                "se_type": "software",
                "bootstrap_serial_hex": serial,
                "tags": {"sim": "fleet"},
            },
        )
        if resp.status_code == 201:
            created += 1
        elif resp.status_code == 409:
            existing += 1
        else:
            check(resp, 201, 409)
    log(f"factory registration: {created} created, {existing} already registered")

    upload_baseline_firmware(s)
    fw_pubs = firmware_pubkeys(s)
    pol = wait_pki_tenant_policy(tenant, fw_pubs)
    cmd_pub = base64.b64decode(pol["command_key_b64"])
    log(
        "PKI tenant policy: software keys allowed, command key "
        f"{hashlib.sha256(cmd_pub).hexdigest()[:16]}... (registry), "
        f"{len(pol.get('firmware_keys_b64') or [])} firmware key(s) (ota)"
    )


# --- campaign ---------------------------------------------------------------------------------


def cmd_campaign(args: argparse.Namespace) -> None:
    s = Session()
    ota = env("IRONMESH_OTA_URL")
    product = env("IRONMESH_FLEET_PRODUCT", "fleet-sim")
    version_code = int(time.time())
    version = f"1.1.{version_code}"
    image = demo_image(version)
    metadata = {
        "product": product,
        "version": version,
        "version_code": version_code,
        "notes": "IronMesh quickstart demo image",
        "severity": "normal",
    }
    fw = check(
        s.request(
            "POST",
            f"{ota}/v1/firmware",
            files={"image": ("firmware.bin", image, "application/octet-stream")},
            data={"metadata": json.dumps(metadata)},
        ),
        201,
    )
    log(f"firmware {fw['product']}/{fw['version']} uploaded and signed (key {fw['signing_key_id']})")

    dwell = int(args.dwell_s)
    body = {
        "name": f"quickstart {version}",
        "firmware_id": fw["id"],
        "target": {"groups": [], "device_ids": [], "tags": {"sim": "fleet"}},
        "delta": False,
        "severity": "normal",
        "stages": [
            {"percent": 1, "dwell_s": dwell, "max_failure_rate": 0.05},
            {"percent": 10, "dwell_s": dwell, "max_failure_rate": 0.05},
            {"percent": 100, "dwell_s": 0, "max_failure_rate": 0.05},
        ],
    }
    camp = check(
        s.request("POST", f"{ota}/v1/campaigns", json=body, headers={"Idempotency-Key": f"qs-{version_code}"}),
        201,
    )
    started = check(
        s.request("POST", f"{ota}/v1/campaigns/{camp['id']}/start", headers={"Idempotency-Key": f"qs-start-{version_code}"}),
        200,
    )
    log(f"campaign {camp['id']} {started['state']} (stages 1% -> 10% -> 100%, dwell {dwell}s)")
    print(camp["id"])


# --- waits and status -------------------------------------------------------------------------


def count_devices(s: Session, state: str) -> int:
    registry = env("IRONMESH_REGISTRY_URL")
    total, cursor = 0, None
    while True:
        params = {"state": state, "tag": "sim:fleet", "limit": "200"}
        if cursor:
            params["cursor"] = cursor
        page = check(s.request("GET", f"{registry}/v1/devices", params=params), 200)
        total += len(page["items"])
        cursor = page.get("next_cursor")
        if not cursor:
            return total


def cmd_wait_active(args: argparse.Namespace) -> None:
    s = Session()
    deadline = time.time() + float(args.timeout_s)
    while True:
        active = count_devices(s, "active")
        log(f"{active}/{args.count} fleet devices active")
        if active >= int(args.count):
            return
        if time.time() > deadline:
            sys.exit("demo: timed out waiting for the fleet to enroll")
        time.sleep(10)


def cmd_wait_quarantine(args: argparse.Namespace) -> None:
    s = Session()
    anomaly = env("IRONMESH_ANOMALY_URL")
    deadline = time.time() + float(args.timeout_s)
    while True:
        page = check(s.request("GET", f"{anomaly}/v1/quarantine", params={"limit": "50"}), 200)
        auto = [q for q in page.get("items", []) if q.get("by") == "auto"]
        if auto:
            for q in auto:
                log(f"auto-quarantined {q['device_id']} at {q['quarantined_at']}: {q['reason']}")
            return
        if time.time() > deadline:
            sys.exit("demo: timed out waiting for an automatic quarantine")
        log("waiting for the anomaly engine to quarantine the misbehaving device")
        time.sleep(10)


def cmd_status(_: argparse.Namespace) -> None:
    s = Session()
    summary = check(s.request("GET", f"{env('IRONMESH_REGISTRY_URL')}/v1/fleet/summary"), 200)
    campaigns = check(s.request("GET", f"{env('IRONMESH_OTA_URL')}/v1/campaigns", params={"limit": "5"}), 200)
    alerts = check(s.request("GET", f"{env('IRONMESH_ANOMALY_URL')}/v1/alerts", params={"limit": "5"}), 200)
    print(
        json.dumps(
            {
                "devices_total": summary.get("devices_total"),
                "by_state": summary.get("by_state"),
                "connected": summary.get("connected"),
                "campaigns": [
                    {"id": c["id"], "state": c["state"], "stage": c.get("current_stage")}
                    for c in campaigns.get("items", [])
                ],
                "alerts": [
                    {"device_id": a["device_id"], "rule": a["rule"], "severity": a["severity"], "state": a["state"]}
                    for a in alerts.get("items", [])
                ],
            },
            indent=2,
        )
    )


def cmd_harness_secrets(_: argparse.Namespace) -> None:
    s = Session()
    created = check(
        s.request(
            "POST",
            f"{env('IRONMESH_REGISTRY_URL')}/v1/api-keys",
            json={"name": f"conformance-{int(time.time())}", "role": "admin"},
        ),
        201,
    )
    # The tenant command key never leaves the registry (KMS-wrapped, the only downlink signer),
    # so no seed is exported: an empty value keeps the JSON shape the HIL workflow parses and
    # makes the conformance harness skip the cases that sign downlinks themselves.
    print(json.dumps({"registry_token": created["secret"], "tenant_key_seed_hex": "", "tenant_id": env("IRONMESH_TENANT_ID")}))


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="demo.py", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("seed").set_defaults(fn=cmd_seed)
    p = sub.add_parser("campaign")
    p.add_argument("--dwell-s", default=os.environ.get("IRONMESH_DEMO_DWELL_S", "30"))
    p.set_defaults(fn=cmd_campaign)
    p = sub.add_parser("wait-active")
    p.add_argument("count", nargs="?", default=os.environ.get("IRONMESH_FLEET_COUNT", "500"))
    p.add_argument("--timeout-s", default="900")
    p.set_defaults(fn=cmd_wait_active)
    p = sub.add_parser("wait-quarantine")
    p.add_argument("--timeout-s", default="900")
    p.set_defaults(fn=cmd_wait_quarantine)
    sub.add_parser("status").set_defaults(fn=cmd_status)
    sub.add_parser("harness-secrets").set_defaults(fn=cmd_harness_secrets)
    args = parser.parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
