"""Outgoing service-to-service HTTP: ES256 service JWTs (``aud=<service>``) over mTLS.

Every request gets a freshly minted token (new random ``jti``, ``iat`` = now, ``exp`` = now +
60 s): the PKI, policy and registry accept each ``jti`` only once, so tokens are never cached.
"""

from __future__ import annotations

import ssl
import time
import uuid
from pathlib import Path

import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from ..settings import Settings

TOKEN_LIFETIME_S = 60


class ServiceTokenMinter:
    def __init__(
        self, key: ec.EllipticCurvePrivateKey, issuer: str, kid: str | None = None
    ) -> None:
        if not isinstance(key.curve, ec.SECP256R1):
            raise ValueError("service tokens are ES256 (P-256)")
        self._key = key
        self._issuer = issuer
        self._kid = kid

    @classmethod
    def from_file(cls, path: Path, issuer: str) -> ServiceTokenMinter:
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise ValueError("service token key must be an EC P-256 key")
        return cls(key, issuer)

    def mint(self, audience: str, now: float | None = None) -> str:
        """A fresh single-use token for one request to ``audience`` (never cached)."""
        current = time.time() if now is None else now
        iat = int(current)
        exp = iat + TOKEN_LIFETIME_S
        headers = {"kid": self._kid} if self._kid else None
        return jwt.encode(
            {
                "iss": self._issuer,
                "sub": self._issuer,
                "aud": audience,
                "iat": iat,
                "exp": exp,
                "jti": str(uuid.uuid4()),
            },
            self._key,
            algorithm="ES256",
            headers=headers,
        )


def build_http_client(settings: Settings, base_url: str) -> httpx.AsyncClient:
    verify: ssl.SSLContext | bool = True
    if settings.tls_ca_file is not None:
        ctx = ssl.create_default_context(cafile=str(settings.tls_ca_file))
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        if settings.tls_cert_file is not None and settings.tls_key_file is not None:
            ctx.load_cert_chain(str(settings.tls_cert_file), str(settings.tls_key_file))
        verify = ctx
    return httpx.AsyncClient(base_url=base_url, verify=verify, timeout=settings.http_timeout_s)
