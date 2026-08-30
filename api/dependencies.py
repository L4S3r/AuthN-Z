"""
Auth N&Z - API Dependencies & Shared Services (api/dependencies.py)
-------------------------------------------------------------------
Provides singleton service instances, authentication guards, cookie managers,
and contextual request dependencies for FastAPI domain routers.
"""

from typing import Any, Dict, List, Optional, Set, Tuple
from datetime import datetime, timezone
import hashlib
import json
import os
import secrets
import logging
from fastapi import Depends, HTTPException, Header, Request, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from config import settings
from exceptions import (
    AuthNZException,
    InvalidTokenException,
    TokenExpiredException,
    TokenRevokedException,
    PermissionDeniedException,
)
from password_hasher import concretePasswordHasher
from user_repository import concreteUserRepository
from workspace_repository import WorkspaceRepository
from session_store import concreteSessionStore
from token_service import concreteTokenService
from mfa_provider import concreteMFAProvider
from audit_logger import AuditLogger
from device_trust_service import DeviceTrustService
from oauth_provider import OAuthManager
from email_service import EmailService
from authenticator import Authenticator
from permission_evaluator import PermissionEvaluator
from task_repository import TaskRepository

from webauthn_service import WebAuthnService

logger = logging.getLogger("auth_nz.dependencies")

# =============================================================================
# Core Engine Singletons
# =============================================================================
sess_store = concreteSessionStore()
hasher = concretePasswordHasher()
user_repo = concreteUserRepository(redis_client=getattr(sess_store, "r", None))
ws_repo = WorkspaceRepository()
token_svc = concreteTokenService(redis_client=getattr(sess_store, "r", None))
mfa_prov = concreteMFAProvider()
audit_log = AuditLogger()
device_trust_svc = DeviceTrustService()
oauth_mgr = OAuthManager(redis_client=getattr(sess_store, "r", None))
oauth_provision_hook: Optional[Any] = None
task_repo = TaskRepository()
email_svc = EmailService(audit_logger=audit_log)
webauthn_svc = WebAuthnService(redis_client=getattr(sess_store, "r", None))

auth = Authenticator(
    user_repo=user_repo,
    hasher=hasher,
    token_service=token_svc,
    session_store=sess_store,
    mfa_provider=mfa_prov,
    device_trust_service=device_trust_svc,
)

perm_eval = PermissionEvaluator(user_repo=user_repo, workspace_repo=ws_repo)

# Security bearer scheme
security = HTTPBearer(auto_error=False)


def get_cookie_domain_and_tls(request: Request) -> Tuple[Optional[str], bool]:
    """Determine cookie domain and TLS security configuration based on environment, settings, and request host."""
    # 1. Resolve host and protocol based on proxy trust setting
    if settings.TRUSTED_PROXY_HEADERS:
        host = (request.headers.get("x-forwarded-host") or request.headers.get("host") or request.url.hostname or "").lower().split(":")[0]
        proto = (request.headers.get("x-forwarded-proto") or request.url.scheme or "").lower()
    else:
        host = (request.headers.get("host") or request.url.hostname or "").lower().split(":")[0]
        proto = (request.url.scheme or "").lower()

    # 2. Determine TLS requirement
    if settings.COOKIE_SECURE is not None:
        is_https = settings.COOKIE_SECURE
    else:
        is_https = proto == "https" or request.url.scheme == "https"

    # 3. Explicit configured cookie domain takes precedence
    if settings.COOKIE_DOMAIN:
        return settings.COOKIE_DOMAIN, is_https

    # 4. If accessing via localhost / 127.0.0.1 / local IPs, use host-only cookies without forcing TLS
    if host in ("localhost", "127.0.0.1", "0.0.0.0", "testserver") or host.endswith(".local"):
        return None, is_https

    # 5. Default domain matching fallback
    if host.endswith(".l4s3r.site") or host == "l4s3r.site":
        return ".l4s3r.site", is_https

    return None, is_https


def set_auth_cookies(
    response: Response,
    request: Request,
    access_token: str,
    refresh_token: Optional[str] = None,
    csrf_token: Optional[str] = None,
) -> None:
    """Set secure, scoped httpOnly cookies for access and refresh tokens, plus an anti-CSRF token."""
    domain, is_https = get_cookie_domain_and_tls(request)

    # 1. Set Access Token Cookie (15 min TTL, path=/)
    response.set_cookie(
        key="access_token",
        value=access_token,
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        httponly=True,
        samesite="lax",
        secure=is_https,
        domain=domain,
        path="/",
    )

    # 2. Set Refresh Token Cookie (7 day TTL, scoped to path=/auth)
    if refresh_token:
        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400,
            httponly=True,
            samesite="lax",
            secure=is_https,
            domain=domain,
            path="/auth",
        )

    # 3. Set Anti-CSRF Token Cookie (readable by frontend client)
    if not csrf_token:
        csrf_token = secrets.token_urlsafe(32)
    response.set_cookie(
        key="csrf_token",
        value=csrf_token,
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400,
        httponly=False,
        samesite="lax",
        secure=is_https,
        domain=domain,
        path="/",
    )


def clear_auth_cookies(response: Response, request: Request) -> None:
    """Clear all authentication and session cookies across all domain and path scopes."""
    domain, is_https = get_cookie_domain_and_tls(request)

    for key, path in [
        ("access_token", "/"),
        ("refresh_token", "/auth"),
        ("refresh_token", "/"),
        ("csrf_token", "/"),
    ]:
        response.delete_cookie(
            key=key,
            domain=domain,
            path=path,
            samesite="lax",
            secure=is_https,
        )
        response.delete_cookie(
            key=key,
            path=path,
            samesite="lax",
            secure=is_https,
        )


def set_trusted_device_cookie(response: Response, request: Request, raw_token: str) -> None:
    """Set scoped HttpOnly trusted device cookie with path=/auth."""
    domain, is_https = get_cookie_domain_and_tls(request)

    # Clear legacy path="/" cookie
    response.delete_cookie(key="trusted_device", domain=domain, path="/", samesite="lax", secure=is_https)
    response.delete_cookie(key="trusted_device", path="/", samesite="lax", secure=is_https)

    response.set_cookie(
        key="trusted_device",
        value=raw_token,
        max_age=30 * 86400,
        httponly=True,
        samesite="lax",
        secure=is_https,
        domain=domain,
        path="/auth",
    )


def clear_trusted_device_cookie(response: Response, request: Request) -> None:
    """Clear trusted device cookie across all domain and path scopes."""
    domain, is_https = get_cookie_domain_and_tls(request)

    response.delete_cookie(key="trusted_device", domain=domain, path="/auth", samesite="lax", secure=is_https)
    response.delete_cookie(key="trusted_device", path="/auth", samesite="lax", secure=is_https)
    if domain:
        response.delete_cookie(key="trusted_device", domain=domain, path="/", samesite="lax", secure=is_https)
    response.delete_cookie(key="trusted_device", path="/", samesite="lax", secure=is_https)


_in_memory_rate_limits: Dict[str, Tuple[int, float]] = {}


def check_rate_limit(key: str, max_requests: int, window_seconds: int) -> bool:
    """
    Return True if under rate limit, False if threshold exceeded.
    Uses Redis sliding-window TTL counters when available, with an in-memory
    sliding-window fallback and architectural warning when Redis is unreachable.
    """
    if sess_store and getattr(sess_store, "r", None):
        try:
            rate_key = f"rate_limit:{key}"
            current = sess_store.r.incr(rate_key)
            if current == 1:
                sess_store.r.expire(rate_key, window_seconds)
            return current <= max_requests
        except Exception as exc:
            logger.warning(
                "Redis rate limit check failed (%s); falling back to in-memory rate limiter for key '%s'.",
                exc,
                key,
            )

    # In-memory sliding-window fallback
    now = datetime.now(timezone.utc).timestamp()

    # Periodic cleanup if cache grows large
    if len(_in_memory_rate_limits) > 5000:
        expired_keys = [k for k, (_, reset_ts) in _in_memory_rate_limits.items() if now >= reset_ts]
        for k in expired_keys:
            _in_memory_rate_limits.pop(k, None)

    entry = _in_memory_rate_limits.get(key)
    if entry is not None:
        count, reset_ts = entry
        if now < reset_ts:
            count += 1
            _in_memory_rate_limits[key] = (count, reset_ts)
            return count <= max_requests

    _in_memory_rate_limits[key] = (1, now + window_seconds)
    return 1 <= max_requests


# =============================================================================
# Authentication & Principal Guards
# =============================================================================
async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> Dict[str, Any]:
    """Extract and validate Bearer token from httpOnly cookie or Authorization header."""
    token: Optional[str] = None

    # 1. Prefer explicit Authorization: Bearer header
    if credentials and credentials.credentials:
        token = credentials.credentials.strip()
    if not token:
        auth_hdr = request.headers.get("authorization")
        if auth_hdr and auth_hdr.lower().startswith("bearer "):
            token = auth_hdr[7:].strip()

    # 2. Fallback to access_token httpOnly cookie
    if not token:
        cookie_token = request.cookies.get("access_token")
        if cookie_token:
            token = str(cookie_token).strip().strip('"').strip("'")

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization token (access_token cookie or Bearer token required).",
            headers={"WWW-Authenticate": "Bearer"},
        )

    res = await auth.authenticate_token(token)
    if res["status"] != "SUCCESS":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired token: {res.get('reason')}",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return res


# =============================================================================
# HTTP Caching & Conditional 304 Helpers (Phase 4.4)
# =============================================================================
def generate_etag(data: Any) -> str:
    """Generate a stable deterministic ETag hash for JSON-serializable payloads."""
    serialized = json.dumps(data, sort_keys=True, default=str)
    return f'W/"{hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:16]}"'


def handle_conditional_response(
    request: Request,
    response: Response,
    payload: Dict[str, Any],
    max_age: Optional[int] = None,
    stale_while_revalidate: Optional[int] = None,
) -> Any:
    """
    Apply ETag and Cache-Control headers, returning a 304 Not Modified response
    if the incoming If-None-Match header matches the computed ETag.
    """
    etag = generate_etag(payload)
    age = max_age if max_age is not None else getattr(settings, "HTTP_CACHE_MAX_AGE", 60)
    swr = (
        stale_while_revalidate
        if stale_while_revalidate is not None
        else getattr(settings, "HTTP_CACHE_STALE_WHILE_REVALIDATE", 300)
    )

    response.headers["ETag"] = etag
    response.headers["Cache-Control"] = f"private, max-age={age}, stale-while-revalidate={swr}"

    if_none_match = request.headers.get("if-none-match")
    if if_none_match:
        candidates = [t.strip() for t in if_none_match.split(",")]
        if etag in candidates or "*" in candidates:
            return Response(
                status_code=status.HTTP_304_NOT_MODIFIED,
                headers={
                    "ETag": etag,
                    "Cache-Control": f"private, max-age={age}, stale-while-revalidate={swr}",
                },
            )

    return payload
