"""
Phase 1 Modularization & Exception Handling Unit Tests (tests/test_phase1_modularization.py)
--------------------------------------------------------------------------------------------
Validates:
1. Centralized configuration parsing, defaults, and helper properties.
2. Custom domain exception hierarchy and RFC 7807 problem details serialization.
3. Modular FastAPI router route registration and OpenAPI schema generation.
"""

import pytest
from fastapi.testclient import TestClient

from config import AuthNZSettings, settings
from exceptions import (
    AuthNZException,
    InvalidCredentialsException,
    AccountLockedException,
    MFARequiredException,
    TokenRevokedException,
    TokenExpiredException,
    PermissionDeniedException,
    WorkspaceNotFoundException,
    ConflictException,
    RateLimitExceededException,
)
from server import app


def test_settings_configuration_and_helpers():
    """Verify settings properties, defaults, and URL assemblies."""
    custom_settings = AuthNZSettings(
        ENVIRONMENT="development",
        DATABASE_URL=None,
        TEST_DATABASE_URL=None,
        JWT_SECRET_KEY="0123456789abcdef0123456789abcdef",
        POSTGRES_USER="test_user",
        POSTGRES_PASSWORD="test_password",
        POSTGRES_HOST="127.0.0.1",
        POSTGRES_PORT="5432",
        POSTGRES_DB="test_db",
    )

    assert custom_settings.is_testing is False
    assert custom_settings.is_production is False
    assert custom_settings.get_jwt_secret() == "0123456789abcdef0123456789abcdef"
    db_url = custom_settings.get_database_url()
    assert "postgresql+asyncpg://" in db_url
    assert "test_user:test_password@127.0.0.1:5432/test_db" in db_url


def test_domain_exceptions_to_dict():
    """Verify domain exception serialization to RFC 7807 problem details."""
    exc1 = InvalidCredentialsException()
    assert exc1.status_code == 401
    assert exc1.code == "INVALID_CREDENTIALS"
    assert exc1.to_dict()["title"] == "Invalid Credentials"

    exc2 = AccountLockedException(retry_after_seconds=600)
    assert exc2.status_code == 423
    assert exc2.code == "ACCOUNT_LOCKED"
    assert exc2.extra["retry_after_seconds"] == 600
    assert exc2.headers["Retry-After"] == "600"

    exc3 = MFARequiredException(challenge_id="ch_123", user_id="u_456")
    assert exc3.status_code == 403
    assert exc3.code == "MFA_REQUIRED"
    assert exc3.extra["challenge_id"] == "ch_123"
    assert exc3.extra["user_id"] == "u_456"

    exc4 = PermissionDeniedException(required_permission="tasks:delete", required_role="admin")
    assert exc4.status_code == 403
    assert exc4.extra["required_permission"] == "tasks:delete"
    assert exc4.extra["required_role"] == "admin"

    exc5 = WorkspaceNotFoundException(workspace_id="ws_999")
    assert exc5.status_code == 404
    assert "ws_999" in exc5.detail


def test_server_root_health_and_router_mounts():
    """Verify root health check probe and OpenAPI route registration across all domain modules."""
    client = TestClient(app)
    res = client.get("/")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "HEALTHY"
    assert data["service"] == "Auth N&Z Gateway"

    # Verify OpenAPI contains paths from all domain routers
    openapi_schema = app.openapi()
    paths = set(openapi_schema.get("paths", {}).keys())

    expected_paths = [
        "/",
        "/auth/register",
        "/admin/users",
        "/auth/login",
        "/auth/refresh",
        "/auth/logout",
        "/auth/forgot-password",
        "/auth/verify-reset-token",
        "/auth/reset-password",
        "/auth/me",
        "/auth/mfa/setup",
        "/auth/mfa/verify-setup",
        "/auth/mfa/disable",
        "/auth/mfa/complete",
        "/auth/trusted-devices",
        "/workspaces",
        "/team/members",
        "/auth/oauth/providers",
        "/audit/logs",
        "/notifications",
        "/tasks",
    ]

    for expected in expected_paths:
        assert expected in paths, f"Route '{expected}' not found in OpenAPI schema paths: {paths}"


def test_cors_origin_narrowing_and_rejection():
    """Verify that only authorized l4s3r.site and project-specific Vercel origins are accepted by CORS."""
    client = TestClient(app)

    # 1. Authorized origin: l4s3r.site domain
    res_valid1 = client.options("/", headers={"Origin": "https://auth-api.l4s3r.site", "Access-Control-Request-Method": "GET"})
    assert res_valid1.headers.get("access-control-allow-origin") == "https://auth-api.l4s3r.site"

    # 2. Authorized origin: project-specific Vercel preview
    res_valid2 = client.options("/", headers={"Origin": "https://l4s3r-tasks-preview.vercel.app", "Access-Control-Request-Method": "GET"})
    assert res_valid2.headers.get("access-control-allow-origin") == "https://l4s3r-tasks-preview.vercel.app"

    # 3. Unauthorized origin: arbitrary third-party *.vercel.app deployment MUST BE REJECTED
    res_evil = client.options("/", headers={"Origin": "https://evil-attacker.vercel.app", "Access-Control-Request-Method": "GET"})
    assert "access-control-allow-origin" not in res_evil.headers

    # 4. Unauthorized origin: random external domain MUST BE REJECTED
    res_random = client.options("/", headers={"Origin": "https://malicious-site.com", "Access-Control-Request-Method": "GET"})
    assert "access-control-allow-origin" not in res_random.headers


def test_rate_limiter_in_memory_fallback():
    """Verify rate limiter fallback operates in-memory when Redis is unavailable."""
    from api.dependencies import check_rate_limit, _in_memory_rate_limits

    test_key = "test_user_rate_limit_key_123"
    _in_memory_rate_limits.pop(test_key, None)

    # Allow 3 requests in a 10-second window
    assert check_rate_limit(test_key, max_requests=3, window_seconds=10) is True
    assert check_rate_limit(test_key, max_requests=3, window_seconds=10) is True
    assert check_rate_limit(test_key, max_requests=3, window_seconds=10) is True

    # 4th request must be rate limited (blocked)
    assert check_rate_limit(test_key, max_requests=3, window_seconds=10) is False
