"""IronMesh reference wire-format library.

Modules:

* :mod:`ironmesh_wire.cbor` - canonical CBOR encoder and strict decoder
* :mod:`ironmesh_wire.cose` - COSE_Sign1 / COSE_Sign / COSE_Encrypt0 profiles
* :mod:`ironmesh_wire.envelope` - message envelope, bodies, signing and verification
* :mod:`ironmesh_wire.manifest` - firmware manifest, hybrid signatures, acceptance rules
* :mod:`ironmesh_wire.delta` - block-delta format
* :mod:`ironmesh_wire.attestation` - attestation envelope and TPM evidence
* :mod:`ironmesh_wire.hpke` - HPKE base mode and the Config key wrap
* :mod:`ironmesh_wire.ids` - identifiers, key ids and MQTT topics
* :mod:`ironmesh_wire.vectors` - deterministic test-vector generator
"""

from __future__ import annotations

from . import attestation, cbor, cose, delta, envelope, errors, hpke, ids, manifest, mldsa
from .constants import AckStatus, Direction, EventSeverity, MessageType, OtaState, SeType
from .errors import WireError

__version__ = "0.1.0"

__all__ = [
    "AckStatus",
    "Direction",
    "EventSeverity",
    "MessageType",
    "OtaState",
    "SeType",
    "WireError",
    "__version__",
    "attestation",
    "cbor",
    "cose",
    "delta",
    "envelope",
    "errors",
    "hpke",
    "ids",
    "manifest",
    "mldsa",
]
