"""API authentication: OIDC bearer JWTs (JWKS or a pinned public key) and tenant RBAC.

* ``aud`` must contain ``ironmesh-api``; ``iss`` must match when configured; ``exp``/``nbf``/``iat``
  are enforced with a small leeway; only asymmetric algorithms are accepted (``alg=none`` and HMAC
  algorithms are rejected so a public key can never be used as an HMAC secret).
* The tenant is the ``tenant_id`` claim. ``platform_admin`` users may act in another tenant with
  ``X-IronMesh-Tenant`` (with the ``admin`` role there); such requests are flagged for audit.
* Role hierarchy per tenant: ``viewer < operator < admin < owner``; ``factory`` has no access to
  the anomaly API.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

import httpx
import jwt
from fastapi import Depends, HTTPException, Request
from jwt import PyJWKClient

from ironmesh_wire import ids

ROLE_RANK: Final = {"viewer": 0, "operator": 1, "admin": 2, "owner": 3}
ASYMMETRIC_ALGS: Final = frozenset(
    {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}
)
PLATFORM_ADMIN: Final = "platform_admin"
TENANT_HEADER: Final = "X-IronMesh-Tenant"


class AuthError(Exception):
    def __init__(self, status: int, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail


@dataclass(frozen=True, slots=True)
class Principal:
    subject: str
    name: str
    tenant_id: str
    role: str
    platform_admin: bool = False
    impersonating: bool = False

    @property
    def actor_id(self) -> str:
        return self.subject

    def has_role(self, minimum: str) -> bool:
        return ROLE_RANK.get(self.role, -1) >= ROLE_RANK[minimum]


type KeyResolver = Callable[[str], Awaitable[Any]]


class TokenVerifier:
    def __init__(
        self,
        *,
        audience: str,
        issuer: str | None,
        algorithms: Sequence[str],
        key_resolver: KeyResolver,
        leeway_s: int = 30,
    ) -> None:
        algs = [a for a in algorithms if a in ASYMMETRIC_ALGS]
        if not algs:
            raise ValueError("at least one asymmetric JWT algorithm is required")
        self._audience, self._issuer, self._algs = audience, issuer, algs
        self._resolve, self._leeway = key_resolver, leeway_s

    @classmethod
    def from_public_key(cls, pem: bytes | str, **kwargs: Any) -> TokenVerifier:
        from cryptography.hazmat.primitives.serialization import load_pem_public_key

        key = load_pem_public_key(pem.encode() if isinstance(pem, str) else pem)

        async def resolve(_: str) -> Any:
            return key

        return cls(key_resolver=resolve, **kwargs)

    @classmethod
    def from_jwks(cls, url: str, **kwargs: Any) -> TokenVerifier:
        client = PyJWKClient(url, cache_keys=True, lifespan=300)

        async def resolve(token: str) -> Any:
            signing_key = await asyncio.to_thread(client.get_signing_key_from_jwt, token)
            return signing_key.key

        return cls(key_resolver=resolve, **kwargs)

    @classmethod
    def from_issuer(cls, **kwargs: Any) -> TokenVerifier:
        """JWKS URL from the ``issuer``'s OIDC discovery document (resolved on first use)."""
        issuer: str = kwargs["issuer"]
        clients: list[PyJWKClient] = []

        def discover() -> PyJWKClient:
            url = issuer.rstrip("/") + "/.well-known/openid-configuration"
            resp = httpx.get(url, timeout=5.0, follow_redirects=False)
            resp.raise_for_status()
            jwks_uri = resp.json().get("jwks_uri")
            if not isinstance(jwks_uri, str) or not jwks_uri.startswith(("https://", "http://")):
                raise AuthError(503, "issuer discovery returned no jwks_uri")
            return PyJWKClient(jwks_uri, cache_keys=True, lifespan=300)

        async def resolve(token: str) -> Any:
            if not clients:
                clients.append(await asyncio.to_thread(discover))
            signing_key = await asyncio.to_thread(clients[0].get_signing_key_from_jwt, token)
            return signing_key.key

        return cls(key_resolver=resolve, **kwargs)

    async def verify(self, token: str) -> dict[str, Any]:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise AuthError(401, "malformed token") from exc
        if header.get("alg") not in self._algs:
            raise AuthError(401, "token algorithm not allowed")
        try:
            key = await self._resolve(token)
            claims: dict[str, Any] = jwt.decode(
                token,
                key,
                algorithms=self._algs,
                audience=self._audience,
                issuer=self._issuer,
                leeway=self._leeway,
                options={"require": ["exp", "iat", "sub", "aud"]},
            )
        except jwt.PyJWTError as exc:
            raise AuthError(401, f"invalid token: {type(exc).__name__}") from exc
        except httpx.HTTPError as exc:
            raise AuthError(503, "identity provider unavailable") from exc
        return claims


def _roles(claims: dict[str, Any]) -> list[str]:
    raw = claims.get("roles", claims.get("role", []))
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, list):
        return [r for r in raw if isinstance(r, str)]
    return []


def principal_from_claims(claims: dict[str, Any], header_tenant: str | None) -> Principal:
    roles = _roles(claims)
    platform = PLATFORM_ADMIN in roles or PLATFORM_ADMIN in (claims.get("platform_roles") or [])
    tenant_roles = [r for r in roles if r in ROLE_RANK]
    role = max(tenant_roles, key=lambda r: ROLE_RANK[r]) if tenant_roles else "none"
    tenant = claims.get("tenant_id")
    impersonating = False
    if header_tenant:
        if not ids.is_tenant_id(header_tenant):
            raise AuthError(422, f"{TENANT_HEADER} must be a tenant UUID")
        if header_tenant != tenant:
            if not platform:
                raise AuthError(403, f"{TENANT_HEADER} requires the platform_admin role")
            tenant, role, impersonating = header_tenant, "admin", True
    if not isinstance(tenant, str) or not ids.is_tenant_id(tenant):
        raise AuthError(403, "token carries no tenant")
    if platform and role == "none":
        role = "admin"
    return Principal(
        subject=str(claims["sub"]),
        name=str(claims.get("name") or claims.get("preferred_username") or claims["sub"]),
        tenant_id=tenant,
        role=role,
        platform_admin=platform,
        impersonating=impersonating,
    )


async def authenticate(request: Request) -> Principal:
    verifier: TokenVerifier | None = getattr(request.app.state, "verifier", None)
    if verifier is None:
        raise HTTPException(503, "authentication is not configured")
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(401, "missing bearer token", headers={"WWW-Authenticate": "Bearer"})
    if token.startswith("imk_"):
        raise HTTPException(
            401, "API keys are verified by the registry; use an OIDC access token here"
        )
    try:
        claims = await verifier.verify(token)
        principal = principal_from_claims(claims, request.headers.get(TENANT_HEADER))
    except AuthError as exc:
        headers = {"WWW-Authenticate": "Bearer"} if exc.status == 401 else None
        raise HTTPException(exc.status, exc.detail, headers=headers) from exc
    if principal.role not in ROLE_RANK:
        raise HTTPException(403, "no anomaly role in this tenant")
    request.state.principal = principal
    return principal


def require(minimum: str) -> Callable[..., Awaitable[Principal]]:
    async def dependency(principal: Principal = Depends(authenticate)) -> Principal:  # noqa: B008
        if not principal.has_role(minimum):
            raise HTTPException(403, f"requires role {minimum}")
        return principal

    return dependency


def build_verifier(
    *,
    audience: str,
    issuer: str | None,
    algorithms: Sequence[str],
    jwks_url: str | None,
    public_key_file: str | None,
    leeway_s: int,
) -> TokenVerifier | None:
    kwargs: dict[str, Any] = {
        "audience": audience,
        "issuer": issuer,
        "algorithms": algorithms,
        "leeway_s": leeway_s,
    }
    if public_key_file:
        return TokenVerifier.from_public_key(Path(public_key_file).read_bytes(), **kwargs)
    if jwks_url:
        return TokenVerifier.from_jwks(jwks_url, **kwargs)
    if issuer:
        return TokenVerifier.from_issuer(**kwargs)
    return None
