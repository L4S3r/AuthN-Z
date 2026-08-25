"""
Auth N&Z - API Dependencies & Shared Services (api/dependencies.py)
-------------------------------------------------------------------
Provides singleton service instances, authentication guards, cookie managers,
and contextual request dependencies for FastAPI domain routers.
"""

from typing import Any, Dict, List, Optional, Set, Tuple
from datetime import datetime, timezone
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
hasher = concretePasswordHasher()
user_repo = concreteUserRepository()
ws_repo = WorkspaceRepository()
sess_store = concreteSessionStore()
token_svc = concreteTokenService(redis_client=getattr(sess_store, "r", None))
mfa_prov = concreteMFAProvider()
audit_log = AuditLogger()
device_trust_svc = DeviceTrustService()
oauth_mgr = OAuthManager(redis_client=getattr(sess_store, "r", None))
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


# =============================================================================
# Cookie & Transport Utilities
# =============================================================================
def get_cookie_domain_and_tls(request: Request) -> Tuple[Optional[str], bool]:
    """Determine cookie domain and TLS security configuration based on environment and headers."""
    if settings.is_production:
        is_https = True
        domain = ".l4s3r.site"
    else:
        proto = (request.headers.get("x-forwarded-proto") or "").lower()
        is_https = request.url.scheme == "https" or proto == "https"
        domain = None
    return domain, is_https


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


def check_rate_limit(key: str, max_requests: int, window_seconds: int) -> bool:
    """Return True if under rate limit, False if threshold exceeded."""
    if sess_store and getattr(sess_store, "r", None):
        try:
            rate_key = f"rate_limit:{key}"
            current = sess_store.r.incr(rate_key)
            if current == 1:
                sess_store.r.expire(rate_key, window_seconds)
            return current <= max_requests
        except Exception:
            return True
    return True


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
