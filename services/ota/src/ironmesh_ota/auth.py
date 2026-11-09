"""Authentication and RBAC (API_CONTRACT §0).

* Public API: ``Authorization: Bearer <OIDC access token>`` verified against the IdP JWKS with
  ``aud`` containing ``ironmesh-api``. Tenant from the ``tenant_id`` claim, role from ``role`` (or
  the highest of ``roles``). ``platform_admin`` (in ``platform_roles`` or ``roles``) may act in
  another tenant via ``X-IronMesh-Tenant``; that is flagged on the principal and audited.
* Internal API: ES256 service JWTs (``aud=ota``, ``iat``/``exp``/``jti``, at most 5 minutes,
  each ``jti`` single use per instance) from an allow-listed caller.
"""

from __future__ import annotations

import asyncio
import hmac
import threading
import time
import uuid
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Final, Protocol

import jwt
from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes
from fastapi import Request

from ironmesh_wire import ids

from .domain import ROLE_RANK, Actor, Role
from .problems import Problem

PLATFORM_ADMIN: Final = "platform_admin"
TENANT_HEADER: Final = "X-IronMesh-Tenant"
MAX_SERVICE_TOKEN_LIFETIME_S: Final = 300
LEEWAY_S: Final = 30


@dataclass(frozen=True)
class Principal:
    tenant_id: uuid.UUID
    role: Role
    actor: Actor
    platform_admin: bool = False
    cross_tenant: bool = False
    ip: str | None = None
    request_id: str | None = None

    def has(self, minimum: Role) -> bool:
        return ROLE_RANK[self.role] >= ROLE_RANK[minimum]


@dataclass(frozen=True)
class ServicePrincipal:
    name: str
    ip: str | None = None
    request_id: str | None = None

    @property
    def actor(self) -> Actor:
        return Actor("service", self.name, self.name)


class TokenVerifier(Protocol):
    async def verify(self, token: str) -> dict[str, Any]: ...


class StaticKeyTokenVerifier:
    """Verifies JWTs against a fixed set of public keys (tests, dev, service keys from disk)."""

    def __init__(
        self,
        keys: Iterable[PublicKeyTypes],
        *,
        audience: str,
        issuer: str | None = None,
        algorithms: Iterable[str] = ("ES256", "RS256", "EdDSA"),
    ) -> None:
        self._keys = list(keys)
        self._audience = audience
        self._issuer = issuer
        self._algorithms = list(algorithms)

    async def verify(self, token: str) -> dict[str, Any]:
        last: Exception | None = None
        for key in self._keys:
            try:
                return jwt.decode(
                    token,
                    key=key,  # type: ignore[arg-type]
                    algorithms=self._algorithms,
                    audience=self._audience,
                    issuer=self._issuer,
                    leeway=LEEWAY_S,
                    options={"require": ["exp", "iat"]},
                )
            except jwt.InvalidSignatureError as exc:
                last = exc
                continue
        raise jwt.InvalidTokenError("no trusted key verifies the token") from last


class JwksTokenVerifier:
    """OIDC access-token verification against the IdP JWKS (keys cached by PyJWT)."""

    def __init__(
        self, jwks_url: str, *, audience: str, issuer: str | None, algorithms: Iterable[str]
    ) -> None:
        self._client = jwt.PyJWKClient(jwks_url, cache_keys=True, lifespan=300)
        self._audience = audience
        self._issuer = issuer
        self._algorithms = list(algorithms)

    def _verify_sync(self, token: str) -> dict[str, Any]:
        key = self._client.get_signing_key_from_jwt(token)
        return jwt.decode(
            token,
            key=key.key,
            algorithms=self._algorithms,
            audience=self._audience,
            issuer=self._issuer,
            leeway=LEEWAY_S,
            options={"require": ["exp", "iat"]},
        )

    async def verify(self, token: str) -> dict[str, Any]:  # pragma: no cover - network I/O
        return await asyncio.to_thread(self._verify_sync, token)


def _bearer(request: Request) -> str:
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise Problem(401, "missing bearer token", headers={"WWW-Authenticate": "Bearer"})
    return token.strip()


def _role_from_claims(claims: Mapping[str, Any]) -> Role:
    candidates: list[str] = []
    if isinstance(claims.get("role"), str):
        candidates.append(claims["role"])
    roles = claims.get("roles")
    if isinstance(roles, list):
        candidates.extend(r for r in roles if isinstance(r, str))
    valid = [Role(r) for r in candidates if r in Role._value2member_map_]
    if not valid:
        raise Problem(403, "token carries no IronMesh tenant role")
    return max(valid, key=lambda r: ROLE_RANK[r])


def principal_from_claims(
    claims: Mapping[str, Any], tenant_header: str | None, *, ip: str | None, request_id: str | None
) -> Principal:
    platform_roles = claims.get("platform_roles")
    roles = claims.get("roles")
    platform_admin = (isinstance(platform_roles, list) and PLATFORM_ADMIN in platform_roles) or (
        isinstance(roles, list) and PLATFORM_ADMIN in roles
    )
    home = claims.get("tenant_id")
    subject = claims.get("sub")
    if not isinstance(subject, str) or not subject:
        raise Problem(401, "token has no subject")
    name = claims.get("name") or claims.get("email")
    actor_type = "api_key" if claims.get("token_use") == "api_key" else "user"
    actor = Actor(actor_type, subject, name if isinstance(name, str) else None)

    if tenant_header is not None:
        if not ids.is_tenant_id(tenant_header):
            raise Problem(400, f"{TENANT_HEADER} must be a lower-case UUIDv4")
        if tenant_header != home:
            if not platform_admin:
                raise Problem(403, f"{TENANT_HEADER} requires the platform_admin role")
            return Principal(
                uuid.UUID(tenant_header), Role.OWNER, actor, True, True, ip, request_id
            )
    if not isinstance(home, str) or not ids.is_tenant_id(home):
        raise Problem(403, "token has no valid tenant_id claim")
    return Principal(
        uuid.UUID(home), _role_from_claims(claims), actor, platform_admin, False, ip, request_id
    )


def _request_meta(request: Request) -> tuple[str | None, str]:
    ip = request.client.host if request.client else None
    request_id = request.headers.get("x-request-id") or str(uuid.uuid4())
    return ip, request_id[:128]


async def authenticate(request: Request, verifier: TokenVerifier) -> Principal:
    token = _bearer(request)
    if token.startswith("imk_"):
        raise Problem(401, "API keys are verified by the registry; use an access token here")
    try:
        claims = await verifier.verify(token)
    except jwt.PyJWTError as exc:
        raise Problem(
            401, f"invalid token: {type(exc).__name__}", headers={"WWW-Authenticate": "Bearer"}
        ) from exc
    ip, request_id = _request_meta(request)
    return principal_from_claims(
        claims, request.headers.get(TENANT_HEADER.lower()), ip=ip, request_id=request_id
    )


class JtiReplayCache:
    """Bounded in-memory set of used service-JWT ids (single use per instance).

    An id is remembered until its token's ``exp`` plus the verification leeway (afterwards the
    token is rejected as expired anyway). When full, expired ids are dropped first, then the
    oldest.
    """

    def __init__(self, max_entries: int = 100_000) -> None:
        self.max_entries = max(1, max_entries)
        self._seen: dict[str, float] = {}  # key -> forget-after (unix time), insertion ordered
        self._lock = threading.Lock()

    def __len__(self) -> int:
        return len(self._seen)

    def use(self, key: str, forget_after: float, now: float | None = None) -> bool:
        """Record ``key``; ``False`` when it was already used and has not expired."""
        current = time.time() if now is None else now
        with self._lock:
            seen = self._seen.get(key)
            if seen is not None and seen > current:
                return False
            self._seen.pop(key, None)
            if len(self._seen) >= self.max_entries:
                for k in [k for k, exp in self._seen.items() if exp <= current]:
                    del self._seen[k]
                while len(self._seen) >= self.max_entries:
                    del self._seen[next(iter(self._seen))]
            self._seen[key] = forget_after
            return True


async def authenticate_service(
    request: Request,
    verifier: TokenVerifier | None,
    allowed: Iterable[str],
    static_token: str | None = None,
    replay: JtiReplayCache | None = None,
) -> ServicePrincipal:
    """ES256 service JWT (preferred) or the shared ``OTA_INTERNAL_TOKEN`` bearer.

    Service JWTs must carry integer ``iat``/``exp`` at most 5 minutes apart and a ``jti``; with
    ``replay`` every ``jti`` (per issuer) is accepted once on this instance.
    """
    token = _bearer(request)
    if static_token and hmac.compare_digest(token.encode(), static_token.encode()):
        ip, request_id = _request_meta(request)
        caller = request.headers.get("x-ironmesh-service", "internal")[:64]
        return ServicePrincipal(caller, ip, request_id)
    if verifier is None:
        raise Problem(401, "invalid internal credentials")
    try:
        claims = await verifier.verify(token)
    except jwt.PyJWTError as exc:
        raise Problem(401, f"invalid service token: {type(exc).__name__}") from exc
    iat, exp = claims.get("iat"), claims.get("exp")
    if (
        not isinstance(iat, int)
        or not isinstance(exp, int)
        or (exp - iat > MAX_SERVICE_TOKEN_LIFETIME_S)
    ):
        raise Problem(401, "service tokens must live at most 5 minutes")
    jti = claims.get("jti")
    if not isinstance(jti, str) or not jti or len(jti) > 128:
        raise Problem(401, "service tokens must carry a jti")
    issuer = claims.get("iss") or claims.get("sub")
    if replay is not None and not replay.use(f"{issuer}\x00{jti}", exp + LEEWAY_S):
        raise Problem(401, "service token already used (jti replay)")
    name = claims.get("sub") or claims.get("iss")
    if not isinstance(name, str) or name not in set(allowed):
        raise Problem(403, "calling service is not allowed on this endpoint")
    ip, request_id = _request_meta(request)
    return ServicePrincipal(name, ip, request_id)


def require_role(
    minimum: Role, resolve: Callable[[Request], Awaitable[Principal]]
) -> Callable[[Request], Awaitable[Principal]]:
    async def dependency(request: Request) -> Principal:
        principal = await resolve(request)
        if not principal.has(minimum):
            raise Problem(403, f"requires role {minimum.value} or higher")
        return principal

    return dependency
