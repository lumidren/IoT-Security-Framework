# ironmesh-wire

Reference implementation of the IronMesh wire format (`docs/DESIGN_CONTRACT.md` §1, §3, §5, §6) and
generator of the conformance vectors in `device/common/vectors/`. The byte-level specification that
the Rust (`device/agent-rs`) and C (`device/esp32`) implementations follow lives in
`device/common/WIRE_FORMAT.md` and `device/common/DELTA_FORMAT.md`; this package is the executable
form of those documents.

| Module                    | Contents                                                                 |
|---------------------------|--------------------------------------------------------------------------|
| `ironmesh_wire.cbor`      | canonical CBOR encoder (RFC 8949 §4.2.1) and strict decoder               |
| `ironmesh_wire.cose`      | COSE_Sign1 (ES256/EdDSA), COSE_Sign (Ed25519 + ML-DSA-65), COSE_Encrypt0  |
| `ironmesh_wire.envelope`  | `{1 seq, 2 ts, 3 type, 4 body, 5 nonce}` envelope, all ten bodies, replay |
| `ironmesh_wire.manifest`  | firmware manifest, hybrid signing/verification, `accept_image()`          |
| `ironmesh_wire.delta`     | `IMDELTA1` block-delta encoder and streaming applier                      |
| `ironmesh_wire.attestation` | attestation envelope (type 10), `Tpm2Evidence`, `TPMS_ATTEST` parsing   |
| `ironmesh_wire.hpke`      | HPKE base mode (RFC 9180) and the Config key wrap                         |
| `ironmesh_wire.ids`       | identifier validators, key ids, MQTT topic builder/parser                 |
| `ironmesh_wire.vectors`   | deterministic test-vector generator                                       |

## Development

```sh
python -m venv .venv                      # repo root; 64-bit CPython 3.12
.venv/Scripts/python -m pip install -e "libs/python/ironmesh-wire[dev]"
cd libs/python/ironmesh-wire
ruff check . && ruff format --check . && mypy
pytest --cov=ironmesh_wire --cov-report=term-missing
python -m ironmesh_wire vectors --out ../../../device/common/vectors
python -m ironmesh_wire delta make old.bin new.bin patch.imdelta
python -m ironmesh_wire delta apply old.bin patch.imdelta out.bin
```

Runtime dependency: `cryptography` only (ML-DSA-65 is provided by its OpenSSL 3.5 backend).
`cbor2` and `pyhpke` are development dependencies used as independent oracles in the test suite.

## Test keys

`tests/keys/` holds fixed, **public** test keys (P-256 device/attacker keys, Ed25519 tenant and
firmware keys, an ML-DSA-65 seed). They exist so that vectors are reproducible; never use them for
anything else.
