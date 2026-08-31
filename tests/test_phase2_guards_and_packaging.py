"""
Phase 2 Guards & Packaging Unit Tests (tests/test_phase2_guards_and_packaging.py)
--------------------------------------------------------------------------------
Validates:
1. Top-level package exports from the 'auth_nz' root module.
2. Declarative FastAPI dependency guards (require_auth, require_role, require_permission).
3. CurrentUser and CurrentWorkspace domain models.
"""

from typing import Dict
from unittest.mock import AsyncMock, MagicMock
import pytest
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.testclient import TestClient

import auth_nz
from auth_nz import (
    CurrentUser,
    CurrentWorkspace,
    require_auth,
    require_role,
    require_permission,
    PermissionDeniedException,
    TokenService,
)


def test_top_level_package_exports():
    """Verify all key facades, guards, models, and exceptions are cleanly exported."""
    expected_exports = [
        "Authenticator",
        "PasswordHasher",
        "TokenService",
        "MFAProvider",
        "DeviceTrustService",
        "SessionStore",
        "PermissionEvaluator",
        "AuditLogger",
        "UserRepository",
        "WorkspaceRepository",
        "OAuthManager",
        "EmailService",
        "settings",
        "AuthNZSettings",
        "api_router",
        "CurrentUser",
        "CurrentWorkspace",
        "require_auth",
        "require_role",
        "require_permission",
        "get_current_workspace",
        "register_exception_handlers",
        "AuthNZException",
        "InvalidCredentialsException",
        "AccountLockedException",
        "MFARequiredException",
    ]
    for symbol in expected_exports:
        assert hasattr(auth_nz, symbol), f"Symbol '{symbol}' not exported from auth_nz root module."


def test_current_user_and_workspace_models():
    """Verify CurrentUser and CurrentWorkspace model validation and helper accessors."""
    user = CurrentUser(
        id="usr_12345",
        username="laser_dev",
        email="dev@l4s3r.site",
        roles=["developer", "editor"],
        metadata={"department": "Security", "clearance": 3},
        workspace_id="ws_main",
        claims={"sub": "usr_12345", "type": "access"},
    )

    assert user.id == "usr_12345"
    assert user.clearance == 3
    assert user.department == "Security"
    assert "developer" in user.roles

    ws = CurrentWorkspace(
        id="ws_main",
        name="Main Ops",
        slug="main-ops",
        role="editor",
    )
    assert ws.slug == "main-ops"
    assert ws.role == "editor"


@pytest.mark.asyncio
async def test_require_auth_guard_behavior():
    """Test require_auth guard when token is missing or valid."""
    auth_guard = require_auth(auto_error=True)

    # Mock request without token
    mock_request = MagicMock(spec=Request)
    mock_request.headers = {}
    mock_request.cookies = {}

    with pytest.raises(HTTPException) as exc_info:
        await auth_guard(request=mock_request, credentials=None)
    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_require_role_guard_hierarchy():
    """Test require_role guard enforces role hierarchy and throws PermissionDeniedException on violation."""
    role_guard = require_role("admin")

    mock_request = MagicMock(spec=Request)
    mock_request.path_params = {}
    mock_request.query_params = {}
    mock_request.headers = {}

    # Viewer attempting admin action
    viewer_user = CurrentUser(
        id="u_viewer",
        username="viewer",
        email="viewer@example.com",
        roles=["viewer"],
        metadata={},
    )

    # When role check evaluates to False
    with pytest.raises(PermissionDeniedException) as exc_info:
        await role_guard(request=mock_request, current_user=viewer_user)
    assert exc_info.value.status_code == 403
    assert "admin" in exc_info.value.extra.get("required_role", "")


def test_example_task_tracker_app_routes():
    """Verify that the example task tracker app boots and exposes all secured consumer routes."""
    from examples.task_tracker_app.main import app as demo_app
    client = TestClient(demo_app)

    # 1. Unauthenticated request to /app/profile should be blocked by require_auth()
    res = client.get("/app/profile")
    assert res.status_code == 401

    # 2. Verify OpenAPI schema contains both Auth N&Z gateway and consumer app routes
    openapi = demo_app.openapi()
    paths = openapi.get("paths", {})
    assert "/app/profile" in paths
    assert "/app/tasks" in paths
    assert "/app/tasks/{task_id}" in paths
    assert "/auth/login" in paths
    assert "/workspaces" in paths


def test_automated_version_consistency_across_codebase():
    """Verify that versioning is automatically synchronized from pyproject.toml across all package modules and gateway servers."""
    import re
    from pathlib import Path
    import __init__ as root_module
    from server import app as gateway_app

    pyproject_path = Path(__file__).parent.parent / "pyproject.toml"
    assert pyproject_path.exists(), "pyproject.toml not found"
    match = re.search(r'^version\s*=\s*"([^"]+)"', pyproject_path.read_text(encoding="utf-8"), re.MULTILINE)
    assert match is not None, "Could not parse version from pyproject.toml"
    pyproject_version = match.group(1)

    # 1. auth_nz package __version__
    assert auth_nz.__version__ == pyproject_version, f"auth_nz.__version__ ({auth_nz.__version__}) != pyproject.toml ({pyproject_version})"
    
    # 2. Root module __version__
    assert root_module.__version__ == pyproject_version, f"root __version__ ({root_module.__version__}) != pyproject.toml ({pyproject_version})"

    # 3. FastAPI Gateway app version
    assert gateway_app.version == pyproject_version, f"FastAPI app.version ({gateway_app.version}) != pyproject.toml ({pyproject_version})"

