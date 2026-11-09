"""IronMesh compose demo driver (runs inside the compose network, see deploy/docker).

Executed by the ``seed`` and ``demo-tools`` services with the OTA image's Python environment
(httpx, asyncpg and cryptography are dependencies of that image), so the host needs nothing but
Docker. Every call goes through the public contract (docs/API_CONTRACT.md) with an OIDC access
token from the local Keycloak demo realm, except the PKI tenant policy, which the PKI service has
no API for yet and is therefore written to its ``tenant_policies`` table as the schema owner.

Subcommands::

    seed             register the virtual fleet (factory flow) and the PKI tenant policy
    campaign         upload a demo firmware image and start a 1% -> 10% -> 100% campaign
    wait-active N    wait until N fleet devices are active in the registry
    wait-quarantine  wait until the anomaly engine has auto-quarantined a device
    status           print a short fleet / campaign / alert summary
    harness-secrets  print JSON for the conformance --stack harness: a fresh registry API key
                     (role admin: factory + operator) and the tenant command key seed (hex)

Configuration comes from the environment set in docker-compose.yml (IRONMESH_*).
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import os
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


def tenant_command_pubkey() -> bytes:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    pem = Path(env("IRONMESH_TENANT_KEY_FILE")).read_bytes()
    key = serialization.load_pem_private_key(pem, password=env("OTA_TENANT_KEYS_PASSPHRASE").encode())
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        sys.exit("demo: tenant command key is not Ed25519")
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def firmware_pubkeys(s: Session) -> list[bytes]:
    keys = check(s.request("GET", f"{env('IRONMESH_OTA_URL')}/v1/signing-keys"), 200)
    out = [base64.b64decode(k["public_key_b64"]) for k in keys if k.get("algorithm") == "Ed25519"]
    if not out:
        sys.exit("demo: the OTA service lists no Ed25519 signing key")
    return out


async def upsert_pki_tenant_policy(tenant: str, cmd_pub: bytes, fw_pubs: list[bytes]) -> None:
    import asyncpg

    conn = await asyncpg.connect(env("IRONMESH_PKI_DSN"))
    try:
        await conn.execute(
            """
            INSERT INTO tenant_policies (tenant_id, allow_software_keys, tenant_cmd_pubkey,
                                         fw_signing_pubkeys, broker_host, broker_port, updated_at)
            VALUES ($1::uuid, true, $2, $3, $4, $5, now())
            ON CONFLICT (tenant_id) DO UPDATE SET
                allow_software_keys = EXCLUDED.allow_software_keys,
                tenant_cmd_pubkey = EXCLUDED.tenant_cmd_pubkey,
                fw_signing_pubkeys = EXCLUDED.fw_signing_pubkeys,
                broker_host = EXCLUDED.broker_host,
                broker_port = EXCLUDED.broker_port,
                updated_at = now()
            """,
            tenant,
            cmd_pub,
            fw_pubs,
            env("IRONMESH_BROKER_HOST", "emqx"),
            int(env("IRONMESH_BROKER_PORT", "8883")),
        )
    finally:
        await conn.close()


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

    cmd_pub = tenant_command_pubkey()
    fw_pubs = firmware_pubkeys(s)
    asyncio.run(upsert_pki_tenant_policy(tenant, cmd_pub, fw_pubs))
    log(
        "PKI tenant policy: software keys allowed, tenant_cmd_pubkey "
        f"{hashlib.sha256(cmd_pub).hexdigest()[:16]}…, {len(fw_pubs)} firmware key(s)"
    )


# --- campaign ---------------------------------------------------------------------------------


def cmd_campaign(args: argparse.Namespace) -> None:
    s = Session()
    ota = env("IRONMESH_OTA_URL")
    product = env("IRONMESH_FLEET_PRODUCT", "fleet-sim")
    version_code = int(time.time())
    version = f"1.1.{version_code}"
    # Demo image: deterministic bytes so the hash is reproducible for a given version_code.
    seed = hashlib.sha256(f"ironmesh-demo-firmware:{version}".encode()).digest()
    image = b"".join(hashlib.sha256(seed + i.to_bytes(4, "big")).digest() for i in range(8192))
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
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    s = Session()
    created = check(
        s.request(
            "POST",
            f"{env('IRONMESH_REGISTRY_URL')}/v1/api-keys",
            json={"name": f"conformance-{int(time.time())}", "role": "admin"},
        ),
        201,
    )
    pem = Path(env("IRONMESH_TENANT_KEY_FILE")).read_bytes()
    key = serialization.load_pem_private_key(pem, password=env("OTA_TENANT_KEYS_PASSPHRASE").encode())
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        sys.exit("demo: tenant command key is not Ed25519")
    seed = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    print(json.dumps({"registry_token": created["secret"], "tenant_key_seed_hex": seed.hex(), "tenant_id": env("IRONMESH_TENANT_ID")}))


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
