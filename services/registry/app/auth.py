"""Authentication (OIDC bearer JWTs, ``imk_`` API keys, service JWTs) and RBAC.

* OIDC access tokens are verified against the IdP JWKS (cached, refreshed on unknown ``kid``):
  signature, ``iss``, ``aud`` containing ``ironmesh-api``, ``exp``/``nbf``/``iat``. Only
  asymmetric algorithms from the allow-list are accepted (never ``none``/``HS*``).
* The tenant comes from the ``tenant_id`` claim. ``platform_admin`` users may send
  ``X-IronMesh-Tenant`` to act in another tenant; every such request is audited.
* API keys (``imk_...``) are stored as SHA-256 hashes and carry a role and optional scopes.
* ``/internal/*`` requires an ES256 service JWT with ``aud=registry``, ``iat``/``exp``/``jti``,
  a lifetime of at most five minutes and an unused ``jti`` (single use per instance), signed by a
  key pinned per calling service. Outgoing service JWTs are minted fresh for every request.
"""

from __future__ import annotations

import asyncio
import hashlib
import secrets
import threading
import time
import uuid
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field, replace
from typing import Any, Final, Protocol

import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .problems import ProblemError, forbidden, unauthorized

ROLES: Final = ("owner", "admin", "operator", "viewer", "factory")
ROLE_RANK: Final[dict[str, int]] = {
    "viewer": 0,
    "factory": 0,
    "operator": 1,
    "admin": 2,
    "owner": 3,
}
API_KEY_PREFIX: Final = "imk_"
PLATFORM_ADMIN: Final = "platform_admin"
TENANT_HEADER: Final = "X-IronMesh-Tenant"
SERVICE_JWT_MAX_LIFETIME: Final = 300
SERVICE_JWT_MINT_LIFETIME: Final = 60


@dataclass(frozen=True, slots=True)
class Permission:
    name: str
    min_role: str
    scope: str
    also: tuple[str, ...] = ()


def _p(name: str, min_role: str, scope: str, also: tuple[str, ...] = ()) -> Permission:
    return Permission(name, min_role, scope, also)


PERMISSIONS: Final[dict[str, Permission]] = {
    p.name: p
    for p in (
        _p("tenant.read", "viewer", "tenant:read"),
        _p("tenant.settings", "admin", "tenant:write"),
        _p("device.read", "viewer", "devices:read"),
        _p("device.create", "admin", "devices:write", also=("factory",)),
        _p("device.edit", "operator", "devices:write"),
        _p("device.quarantine", "operator", "devices:lifecycle"),
        _p("device.release", "admin", "devices:lifecycle"),
        _p("device.decommission", "admin", "devices:lifecycle"),
        _p("twin.read", "viewer", "twin:read"),
        _p("twin.write", "operator", "twin:write"),
        _p("command.read", "viewer", "commands:read"),
        _p("command.send", "operator", "commands:write"),
        _p("config.read", "viewer", "config:read"),
        _p("config.write", "admin", "config:write"),
        _p("group.read", "viewer", "groups:read"),
        _p("group.write", "operator", "groups:write"),
        _p("group.delete", "admin", "groups:write"),
        _p("provisioning.read", "viewer", "provisioning:read"),
        _p("provisioning.review", "operator", "provisioning:write"),
        _p("fleet.read", "viewer", "fleet:read"),
        _p("audit.read", "viewer", "audit:read"),
        _p("audit.export", "admin", "audit:export"),
        _p("audit.verify", "admin", "audit:export"),
        _p("users.read", "admin", "users:read"),
        _p("users.role", "owner", "users:write"),
        _p("apikeys.manage", "admin", "apikeys:write"),
        _p("ws.connect", "viewer", "ws:connect"),
    )
}

ALL_SCOPES: Final = frozenset(p.scope for p in PERMISSIONS.values())


@dataclass(frozen=True, slots=True)
class Principal:
    tenant_id: str
    actor_type: str  # user | api_key | service | system
    actor_id: str
    name: str | None = None
    role: str | None = None
    email: str | None = None
    scopes: frozenset[str] | None = None  # None: everything the role allows
    platform_admin: bool = False
    impersonating: bool = False
    home_tenant_id: str | None = None
    ip: str | None = None
    request_id: str | None = None

    @property
    def display(self) -> str:
        return f"{self.actor_type}:{self.actor_id}"

    def with_request(self, ip: str | None, request_id: str | None) -> Principal:
        return replace(self, ip=ip, request_id=request_id)


SYSTEM = Principal(tenant_id="", actor_type="system", actor_id="registry", name="registry")


def role_allows(role: str | None, perm: Permission) -> bool:
    if role is None or role not in ROLE_RANK:
        return False
    if role in perm.also:
        return True
    if role == "factory":  # side role: only what it is explicitly granted, plus viewer reads
        return ROLE_RANK[perm.min_role] == 0
    return ROLE_RANK[role] >= ROLE_RANK[perm.min_role]


def allowed(principal: Principal, permission: str) -> bool:
    perm = PERMISSIONS[permission]
    if principal.actor_type in ("service", "system"):
        return True
    if not role_allows(principal.role, perm):
        return False
    return principal.scopes is None or perm.scope in principal.scopes


def check(principal: Principal, permission: str) -> None:
    if not allowed(principal, permission):
        raise forbidden(f"{permission} requires role {PERMISSIONS[permission].min_role}")


def role_at_most(granter: str | None, role: str) -> bool:
    """A principal may only grant roles up to its own rank (factory only by admins+)."""
    if granter is None:
        return False
    if role == "factory":
        return ROLE_RANK.get(granter, -1) >= ROLE_RANK["admin"]
    return ROLE_RANK.get(granter, -1) >= ROLE_RANK[role]


# ------------------------------------------------------------------------------------------------
# API keys
# ------------------------------------------------------------------------------------------------


def generate_api_key() -> tuple[str, str, bytes]:
    """Returns ``(secret, display_prefix, sha256)``."""
    secret = API_KEY_PREFIX + secrets.token_urlsafe(32)
    return secret, secret[:12], hash_api_key(secret)


def hash_api_key(secret: str) -> bytes:
    return hashlib.sha256(secret.encode()).digest()


# ------------------------------------------------------------------------------------------------
# OIDC
# ------------------------------------------------------------------------------------------------


class JwksSource(Protocol):
    async def get(self, kid: str | None, *, refresh: bool = False) -> Mapping[str, Any] | None: ...


class StaticJwks:
    def __init__(self, jwks: Mapping[str, Any]) -> None:
        self.jwks = jwks

    async def get(self, kid: str | None, *, refresh: bool = False) -> Mapping[str, Any] | None:
        return _select_key(self.jwks, kid)


def _select_key(jwks: Mapping[str, Any], kid: str | None) -> Mapping[str, Any] | None:
    keys = [k for k in jwks.get("keys", []) if isinstance(k, dict)]
    if kid is None:
        return keys[0] if len(keys) == 1 else None
    return next((k for k in keys if k.get("kid") == kid), None)


class HttpJwks:
    """Fetches ``jwks_uri`` (discovered from the issuer if not configured) with a TTL cache."""

    def __init__(
        self,
        issuer: str,
        jwks_url: str | None,
        client: httpx.AsyncClient,
        ttl: float = 600.0,
        min_refresh_interval: float = 30.0,
    ) -> None:
        self.issuer = issuer.rstrip("/")
        self.jwks_url = jwks_url
        self.client = client
        self.ttl = ttl
        self.min_refresh_interval = min_refresh_interval
        self._jwks: Mapping[str, Any] = {}
        self._fetched_at = 0.0
        self._lock = asyncio.Lock()

    async def _refresh(self) -> None:
        if self.jwks_url is None:
            disc = await self.client.get(f"{self.issuer}/.well-known/openid-configuration")
            disc.raise_for_status()
            self.jwks_url = str(disc.json()["jwks_uri"])
        resp = await self.client.get(self.jwks_url)
        resp.raise_for_status()
        self._jwks = resp.json()
        self._fetched_at = time.monotonic()

    async def get(self, kid: str | None, *, refresh: bool = False) -> Mapping[str, Any] | None:
        async with self._lock:
            age = time.monotonic() - self._fetched_at
            stale = not self._jwks or age > self.ttl
            if stale or (refresh and age > self.min_refresh_interval):
                try:
                    await self._refresh()
                except (httpx.HTTPError, KeyError, ValueError) as exc:
                    if not self._jwks:
                        raise ProblemError(503, "identity provider keys unavailable") from exc
        return _select_key(self._jwks, kid)


@dataclass(slots=True)
class OidcConfig:
    issuer: str
    audience: str
    algorithms: list[str]
    tenant_claim: str = "tenant_id"
    role_claim: str = "role"
    platform_roles_claim: str = "platform_roles"
    leeway: int = 30


@dataclass(frozen=True, slots=True)
class OidcIdentity:
    subject: str
    tenant_id: str | None
    email: str
    name: str | None
    role: str | None
    platform_admin: bool


ASYMMETRIC: Final = frozenset(
    {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}
)


def _claim_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str)]
    return []


class OidcVerifier:
    def __init__(self, config: OidcConfig, jwks: JwksSource) -> None:
        self.config = config
        self.jwks = jwks
        self.algorithms = [a for a in config.algorithms if a in ASYMMETRIC]

    async def verify(self, token: str) -> OidcIdentity:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise unauthorized("malformed token") from exc
        alg = header.get("alg")
        if alg not in self.algorithms:
            raise unauthorized("token algorithm not allowed")
        kid = header.get("kid")
        jwk = await self.jwks.get(kid) or await self.jwks.get(kid, refresh=True)
        if jwk is None:
            raise unauthorized("unknown signing key")
        try:
            key = jwt.PyJWK(dict(jwk), algorithm=alg).key
            claims: dict[str, Any] = jwt.decode(
                token,
                key,
                algorithms=[alg],
                audience=self.config.audience,
                issuer=self.config.issuer,
                leeway=self.config.leeway,
                options={"require": ["exp", "iat", "sub", "iss", "aud"]},
            )
        except jwt.PyJWTError as exc:
            raise unauthorized(f"invalid token: {exc}") from exc
        roles = _claim_list(claims.get(self.config.role_claim))
        role = max(
            (r for r in roles if r in ROLE_RANK and r != "factory"),
            key=lambda r: ROLE_RANK[r],
            default="factory" if "factory" in roles else None,
        )
        platform = PLATFORM_ADMIN in _claim_list(claims.get(self.config.platform_roles_claim))
        tenant = claims.get(self.config.tenant_claim)
        return OidcIdentity(
            subject=str(claims["sub"]),
            tenant_id=_uuid_or_none(tenant),
            email=str(claims.get("email") or claims["sub"]),
            name=claims.get("name") if isinstance(claims.get("name"), str) else None,
            role=role,
            platform_admin=platform,
        )


def _uuid_or_none(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        return None
    return str(parsed)


def parse_tenant_header(value: str) -> str:
    tenant = _uuid_or_none(value)
    if tenant is None:
        raise ProblemError(400, f"{TENANT_HEADER} must be a tenant UUID")
    return tenant


# ------------------------------------------------------------------------------------------------
# Service JWTs (ES256, aud=<service>, <= 5 min)
# ------------------------------------------------------------------------------------------------


class JtiReplayCache:
    """Bounded in-memory set of used service-JWT ids (single use per instance).

    Each id is remembered until its token's ``exp`` plus the verification leeway, after which the
    token would be rejected as expired anyway. When the cache is full, expired ids are dropped
    first, then the oldest ones.
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


@dataclass(slots=True)
class ServiceJwtVerifier:
    """ES256 service JWTs: ``iss`` names a trusted caller, ``aud`` this service, ``iat``/``exp``/
    ``jti`` required, lifetime at most 5 minutes, and (with ``replay``) every ``jti`` single use."""

    audience: str
    trusted: dict[str, ec.EllipticCurvePublicKey] = field(default_factory=dict)
    leeway: int = 30
    replay: JtiReplayCache | None = field(default_factory=JtiReplayCache)

    @classmethod
    def from_pem(
        cls,
        audience: str,
        pems: Mapping[str, str],
        *,
        single_use: bool = True,
        replay_cache_size: int = 100_000,
    ) -> ServiceJwtVerifier:
        keys: dict[str, ec.EllipticCurvePublicKey] = {}
        for name, pem in pems.items():
            key = serialization.load_pem_public_key(pem.encode())
            if not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name != "secp256r1":
                raise ValueError(f"service key for {name} must be a P-256 public key")
            keys[name] = key
        replay = JtiReplayCache(replay_cache_size) if single_use else None
        return cls(audience=audience, trusted=keys, replay=replay)

    def verify(self, token: str) -> str:
        try:
            header = jwt.get_unverified_header(token)
            unverified = jwt.decode(token, options={"verify_signature": False})
        except jwt.PyJWTError as exc:
            raise unauthorized("malformed service token") from exc
        if header.get("alg") != "ES256":
            raise unauthorized("service tokens must be ES256")
        service = unverified.get("iss")
        if not isinstance(service, str) or service not in self.trusted:
            raise unauthorized("unknown calling service")
        try:
            claims = jwt.decode(
                token,
                self.trusted[service],
                algorithms=["ES256"],
                audience=self.audience,
                issuer=service,
                leeway=self.leeway,
                options={"require": ["exp", "iat", "iss", "aud", "jti"]},
            )
        except jwt.PyJWTError as exc:
            raise unauthorized(f"invalid service token: {exc}") from exc
        iat, exp, jti = claims["iat"], claims["exp"], claims["jti"]
        if not isinstance(iat, int) or not isinstance(exp, int):
            raise unauthorized("service token iat/exp must be integers")
        if exp - iat > SERVICE_JWT_MAX_LIFETIME:
            raise unauthorized("service token lifetime exceeds 5 minutes")
        if not isinstance(jti, str) or not jti or len(jti) > 128:
            raise unauthorized("service token jti must be a non-empty string")
        if self.replay is not None and not self.replay.use(
            f"{service}\x00{jti}", exp + self.leeway
        ):
            raise unauthorized("service token already used (jti replay)")
        return service


class ServiceTokenMinter:
    """Mints the registry's own ES256 service JWTs for calls to PKI / OTA.

    Every call returns a fresh token (new random ``jti``, ``iat`` = now, ``exp`` = now + 60 s):
    the receivers accept each ``jti`` once, so tokens are never cached or reused.
    """

    def __init__(self, issuer: str, key: ec.EllipticCurvePrivateKey | None) -> None:
        self.issuer = issuer
        self.key = key

    @classmethod
    def from_file(cls, issuer: str, path: str | None) -> ServiceTokenMinter:
        if not path:
            return cls(issuer, None)
        with open(path, "rb") as fh:
            key = serialization.load_pem_private_key(fh.read(), password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise ValueError("service JWT key must be an EC P-256 private key")
        return cls(issuer, key)

    def token(self, audience: str) -> str | None:
        """A fresh single-use service JWT for one request to ``audience``."""
        if self.key is None:
            return None
        now = int(time.time())
        claims = {
            "iss": self.issuer,
            "sub": self.issuer,
            "aud": audience,
            "iat": now,
            "exp": now + SERVICE_JWT_MINT_LIFETIME,
            "jti": str(uuid.uuid4()),
        }
        return jwt.encode(claims, self.key, algorithm="ES256")


def bearer_token(authorization: str | None) -> str | None:
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()


type Authenticator = Callable[[str], Awaitable[Principal]]
