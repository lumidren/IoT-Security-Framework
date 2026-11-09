"""Development key tool.

``python -m ironmesh_ota.keytool init --out keyring.json [--mldsa]``
``python -m ironmesh_ota.keytool rotate --file keyring.json --algorithm Ed25519``
``python -m ironmesh_ota.keytool list --file keyring.json``

The passphrase is read from ``OTA_SIGNING_PASSPHRASE``; it is never accepted on the command line
so it cannot leak into shell history. Production key rings are wrapped with KMS instead
(``signing.kms_wrap_keyring``). After a rotation the restarted service pushes the new public key
set to the PKI tenant policy (``services/key_sync.py``). Tenant command keys are held and used
only by the registry.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from . import signing


def _passphrase(var: str) -> bytes:
    value = os.environ.get(var)
    if not value:
        raise SystemExit(f"{var} must be set")
    return value.encode()


def _write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(data)
    tmp.replace(path)
    path.chmod(0o600)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ironmesh-ota-keytool")
    sub = parser.add_subparsers(dest="command", required=True)
    p_init = sub.add_parser("init", help="create a new encrypted key ring")
    p_init.add_argument("--out", type=Path, required=True)
    p_init.add_argument("--mldsa", action="store_true", help="also create an ML-DSA-65 key")
    p_rot = sub.add_parser("rotate", help="add a new active key; old keys stay trusted")
    p_rot.add_argument("--file", type=Path, required=True)
    p_rot.add_argument(
        "--algorithm", choices=[signing.ED25519, signing.ML_DSA_65], default=signing.ED25519
    )
    p_list = sub.add_parser("list", help="print key ids")
    p_list.add_argument("--file", type=Path, required=True)
    args = parser.parse_args(argv)

    passphrase = _passphrase("OTA_SIGNING_PASSPHRASE")
    if args.command == "init":
        entries = signing.new_keyring_entries(with_mldsa=args.mldsa)
        _write(args.out, signing.encrypt_keyring(signing.keyring_document(entries), passphrase))
        path = args.out
    else:
        path = args.file
        plaintext = signing.decrypt_keyring(path.read_bytes(), passphrase)
        if args.command == "rotate":
            entries = signing.rotate_entries(
                signing.entries_from_plaintext(plaintext), args.algorithm
            )
            _write(path, signing.encrypt_keyring(signing.keyring_document(entries), passphrase))
    signer = signing.load_file_signer(path, passphrase)
    for info in signer.list_keys():
        flag = "active" if info.active else "trusted"
        print(f"{info.key_id}  {info.algorithm:9}  {flag}  {info.created_at.isoformat()}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
