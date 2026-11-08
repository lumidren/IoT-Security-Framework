"""FastAPI dependencies: application context, authentication, authorization."""

from __future__ import annotations

import hmac
import time
from collections.abc import Awaitable, Callable
from dataclasses import replace
from datetime import timedelta

from fastapi import Request

from ..auth import (
    API_KEY_PREFIX,
    PERMISSIONS,
    TENANT_HEADER,
    Principal,
    allowed,
    bearer_token,
    hash_api_key,
    parse_tenant_header,
)
from ..context import AppContext
from ..domain import UserRecord
from ..problems import forbidden, not_found, unauthorized

USER_CACHE_SECONDS = 15.0
LOGIN_TOUCH = timedelta(minutes=5)
KEY_TOUCH_SECONDS = 60.0
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def get_ctx(request: Request) -> AppContext:
    ctx: AppContext = request.app.state.ctx
    return ctx


def _origin(request: Request) -> tuple[str | None, str | None]:
    ip = request.client.host if request.client else None
    return ip, getattr(request.state, "request_id", None)


async def _api_key_principal(ctx: AppContext, token: str, request: Request) -> Principal:
    rec = await ctx.repo.lookup_api_key(hash_api_key(token))
    now = ctx.clock()
    if rec is None or rec.revoked_at is not None or (rec.expires_at and rec.expires_at <= now):
        raise unauthorized("invalid or expired API key")
    header = request.headers.get(TENANT_HEADER)
    if header and parse_tenant_header(header) != rec.tenant_id:
        raise forbidden(f"{TENANT_HEADER} is not allowed for API keys")
    last = ctx.key_touch.get(rec.id, 0.0)
    if time.monotonic() - last > KEY_TOUCH_SECONDS:
        ctx.key_touch[rec.id] = time.monotonic()
        async with ctx.repo.tenant(rec.tenant_id) as tx:
            current = await tx.get_api_key(rec.id)
            if current is not None:
                current.last_used_at = now
                await tx.save_api_key(current)
    ip, rid = _origin(request)
    return Principal(
        tenant_id=rec.tenant_id,
        actor_type="api_key",
        actor_id=rec.id,
        name=rec.name,
        role=rec.role,
        scopes=frozenset(rec.scopes) if rec.scopes else None,
        ip=ip,
        request_id=rid,
    )


async def _user_role(
    ctx: AppContext,
    tenant_id: str,
    subject: str,
    email: str,
    name: str | None,
    claim_role: str | None,
    p: Principal,
) -> str:
    key = (tenant_id, subject)
    hit = ctx.user_cache.get(key)
    if hit is not None and time.monotonic() - hit[0] < USER_CACHE_SECONDS:
        return hit[1]
    async with ctx.unit(p, tenant_id) as u:
        if await u.tx.get_tenant() is None:
            raise forbidden("tenant is not provisioned in the registry")
        user = await u.tx.get_user(subject)
        now = u.now()
        if user is None:
            user = UserRecord(
                tenant_id=tenant_id,
                id=subject,
                email=email,
                name=name,
                role=claim_role or "viewer",
                created_at=now,
                last_login_at=now,
            )
            await u.tx.save_user(user)
            await u.audit("user.provisioned", "user", subject, {"role": user.role, "email": email})
        elif user.last_login_at is None or now - user.last_login_at > LOGIN_TOUCH:
            user.last_login_at, user.email, user.name = now, email, name or user.name
            await u.tx.save_user(user)
    ctx.user_cache[key] = (time.monotonic(), user.role)
    return user.role


async def current_principal(request: Request) -> Principal:
    ctx = get_ctx(request)
    token = bearer_token(request.headers.get("authorization"))
    if token is None:
        raise unauthorized()
    if token.startswith(API_KEY_PREFIX):
        return await _api_key_principal(ctx, token, request)
    ident = await ctx.oidc.verify(token)
    ip, rid = _origin(request)
    header = request.headers.get(TENANT_HEADER)
    if header:
        target = parse_tenant_header(header)
        if target != ident.tenant_id:
            if not ident.platform_admin:
                raise forbidden(f"{TENANT_HEADER} requires the platform_admin role")
            p = Principal(
                tenant_id=target,
                actor_type="user",
                actor_id=ident.subject,
                name=ident.name,
                role="owner",
                email=ident.email,
                platform_admin=True,
                impersonating=True,
                home_tenant_id=ident.tenant_id,
                ip=ip,
                request_id=rid,
            )
            async with ctx.unit(p) as u:
                if await u.tx.get_tenant() is None:
                    raise not_found("tenant")
                await u.audit(
                    "platform_admin.tenant_access",
                    "tenant",
                    target,
                    {
                        "method": request.method,
                        "path": request.url.path,
                        "home_tenant_id": ident.tenant_id,
                    },
                )
            return p
    if ident.tenant_id is None:
        raise forbidden("token carries no tenant_id claim")
    base = Principal(
        tenant_id=ident.tenant_id,
        actor_type="user",
        actor_id=ident.subject,
        name=ident.name,
        email=ident.email,
        platform_admin=ident.platform_admin,
        ip=ip,
        request_id=rid,
    )
    role = await _user_role(
        ctx, ident.tenant_id, ident.subject, ident.email, ident.name, ident.role, base
    )
    return replace(base, role=role)


def require(permission: str) -> Callable[[Request], Awaitable[Principal]]:
    if permission not in PERMISSIONS:
        raise KeyError(permission)

    async def dependency(request: Request) -> Principal:
        principal = await current_principal(request)
        if not allowed(principal, permission):
            if request.method not in SAFE_METHODS:
                ctx = get_ctx(request)
                async with ctx.unit(principal) as u:
                    await u.audit(
                        "authz.denied",
                        "endpoint",
                        request.url.path,
                        {
                            "permission": permission,
                            "method": request.method,
                            "role": principal.role,
                        },
                        outcome="failure",
                    )
            perm = PERMISSIONS[permission]
            raise forbidden(f"{permission} requires role {perm.min_role} or higher")
        return principal

    dependency.__name__ = f"require_{permission.replace('.', '_')}"
    return dependency


def internal(*services: str) -> Callable[[Request], Awaitable[Principal]]:
    """Service authentication for ``/internal/*``: ES256 service JWT (aud=registry) or the
    shared ``REGISTRY_INTERNAL_TOKEN`` used by the PKI and policy deployments."""

    async def dependency(request: Request) -> Principal:
        ctx = get_ctx(request)
        token = bearer_token(request.headers.get("authorization"))
        if token is None:
            raise unauthorized("service credentials required")
        shared = ctx.settings.internal_token
        if shared is not None and hmac.compare_digest(
            token.encode(), shared.get_secret_value().encode()
        ):
            service = "internal"
        else:
            service = ctx.service_jwt.verify(token)
            if services and service not in services:
                raise forbidden(f"service {service} may not call this endpoint")
        ip, rid = _origin(request)
        return Principal(
            tenant_id="",
            actor_type="service",
            actor_id=service,
            name=service,
            ip=ip,
            request_id=rid,
        )

    return dependency
