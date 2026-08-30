"""
Tests for Auth N&Z Adapter Framework & Extensibility
=====================================================
Validates:
1. AuthNZUserMixin with custom application User models (BYOU pattern).
2. create_authnz_router with selective feature toggles and modular endpoint mounting.
3. configure_authnz and AuthNZ class configuration.
4. auth_nz package namespace imports and submodules (models, routers, guards, adapter).
5. Task tracker backwards compatibility on standalone / mini-server mode.
"""

import pytest
import uuid
from typing import Optional
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import String, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

import auth_nz
from auth_nz.models import Base as DefaultBase, AuthNZUserMixin
from default_user import User as DefaultUser
from auth_nz.routers import (
    create_authnz_router,
    auth_router,
    mfa_router,
    webauthn_router,
    task_router,
    api_router,
)
from auth_nz.adapter import configure_authnz, AuthNZ
from auth_nz.guards import CurrentUser, require_auth, require_permission
from user_repository import UserRepository


class CustomBase(DeclarativeBase):
    pass


class CustomCompanyUser(CustomBase, AuthNZUserMixin):
    """Host project's custom User model with project-specific columns."""
    __tablename__ = "custom_company_users"

    company_name: Mapped[str] = mapped_column(String(100), default="Acme Corp", server_default="Acme Corp")
    stripe_customer_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)


def test_authnz_user_mixin_with_custom_model():
    """Verify that a host app can define its own User model inheriting AuthNZUserMixin."""
    custom_user = CustomCompanyUser(
        id=uuid.uuid4(),
        username="custom_alice",
        email="alice@acme.com",
        hashed_password="$argon2id$v=19$m=65536,t=3,p=4$fakehash",
        roles=["developer"],
        metadata_={"department": "Engineering"},
        company_name="Acme Global",
        stripe_customer_id="cus_12345",
    )

    assert custom_user.username == "custom_alice"
    assert custom_user.company_name == "Acme Global"
    assert custom_user.stripe_customer_id == "cus_12345"
    assert "developer" in custom_user.roles

    # Verify formatting via UserRepository
    formatted = UserRepository._format_user(custom_user)
    assert formatted["id"] == str(custom_user.id)
    assert formatted["username"] == "custom_alice"
    assert formatted["email"] == "alice@acme.com"
    assert formatted["roles"] == ["developer"]
    assert formatted["metadata"] == {"department": "Engineering"}


def test_create_authnz_router_selective_toggles():
    """Verify that create_authnz_router only mounts routes specified in feature flags."""
    # 1. Auth-only router (no workspaces, no tasks, no webauthn, no oauth)
    auth_only_router = create_authnz_router(
        enable_auth=True,
        enable_mfa=False,
        enable_webauthn=False,
        enable_device_trust=False,
        enable_workspaces=False,
        enable_team=False,
        enable_oauth=False,
        enable_audit=False,
        enable_notifications=False,
        enable_websockets=False,
        enable_health=False,
        enable_policies=False,
        enable_tasks=False,
    )

    app1 = FastAPI()
    app1.include_router(auth_only_router)

    paths1 = set(app1.openapi().get("paths", {}).keys())
    assert "/auth/login" in paths1
    assert "/auth/register" in paths1
    assert "/auth/mfa/setup" not in paths1
    assert "/workspaces" not in paths1
    assert "/tasks" not in paths1
    assert "/auth/webauthn/register/options" not in paths1

    # 2. MFA + WebAuthn + Tasks router (e.g. mini-server)
    mini_server_router = create_authnz_router(
        enable_auth=True,
        enable_mfa=True,
        enable_webauthn=True,
        enable_tasks=True,
        enable_workspaces=True,
    )

    app2 = FastAPI()
    app2.include_router(mini_server_router)

    paths2 = set(app2.openapi().get("paths", {}).keys())
    assert "/auth/login" in paths2
    assert "/auth/mfa/setup" in paths2
    assert "/auth/webauthn/register/options" in paths2
    assert "/workspaces" in paths2
    assert "/tasks" in paths2


def test_authnz_adapter_class_and_configure_helper():
    """Verify configure_authnz and AuthNZ class configuration API."""
    custom_jwt_secret = "test_custom_secret_key_9876543210_abcdef"

    # Configure via helper
    configure_authnz(
        jwt_secret_key=custom_jwt_secret,
        access_token_expire_minutes=45,
    )

    from config import settings
    import api.dependencies as deps
    assert settings.JWT_SECRET_KEY == custom_jwt_secret
    assert deps.token_svc.secret_key == custom_jwt_secret

    # Configure via AuthNZ class
    adapter = AuthNZ(
        jwt_secret_key="another_secret_key_1122334455_xyz",
    )
    assert settings.JWT_SECRET_KEY == "another_secret_key_1122334455_xyz"

    custom_router = adapter.create_router(
        enable_auth=True,
        enable_mfa=True,
        enable_tasks=False,
    )
    test_app = FastAPI()
    test_app.include_router(custom_router)
    paths = set(test_app.openapi().get("paths", {}).keys())
    assert "/auth/login" in paths
    assert "/tasks" not in paths


def test_submodule_package_exports():
    """Verify all public symbols are importable from auth_nz and its submodules."""
    assert hasattr(auth_nz, "AuthNZUserMixin")
    assert hasattr(auth_nz, "configure_authnz")
    assert hasattr(auth_nz, "create_authnz_router")
    assert hasattr(auth_nz, "AuthNZ")
    assert hasattr(auth_nz, "AuthNZAdapter")
    assert hasattr(auth_nz, "require_auth")
    assert hasattr(auth_nz, "require_permission")
    assert hasattr(auth_nz, "require_role")
    assert hasattr(auth_nz, "CurrentUser")
    assert hasattr(auth_nz, "CurrentWorkspace")
    assert hasattr(auth_nz, "api_router")
    assert hasattr(auth_nz, "auth_router")
    assert hasattr(auth_nz, "mfa_router")
    assert hasattr(auth_nz, "webauthn_router")
    assert hasattr(auth_nz, "task_router")
    assert auth_nz.__version__ == "1.1.3"


def test_byou_oauth_provision_hook_registration():
    """Verify that configure_authnz accepts and registers host oauth_provision_hook."""
    dummy_hook = lambda profile, ip: {"status": "PENDING_APPROVAL", "detail": "Test pending"}
    auth_nz.configure_authnz(oauth_provision_hook=dummy_hook)
    import api.dependencies as deps
    assert deps.oauth_provision_hook == dummy_hook


def test_default_api_router_backwards_compatibility():
    """Verify that default api_router still mounts all core + mini-server task routes."""
    app = FastAPI()
    app.include_router(api_router)

    paths = set(app.openapi().get("paths", {}).keys())
    assert "/auth/login" in paths
    assert "/auth/mfa/setup" in paths
    assert "/auth/webauthn/register/options" in paths
    assert "/workspaces" in paths
    assert "/tasks" in paths
    assert "/health" in paths


def test_model_separation_and_byou_isolation():
    """Verify that models.py, default_user.py, and workspace_models.py are properly separated."""
    import models
    import default_user
    import workspace_models
    import auth_nz.models

    # models.py core exports
    assert hasattr(models, "Base")
    assert hasattr(models, "AuthNZUserMixin")
    assert hasattr(models, "PasswordResetToken")
    assert hasattr(models, "TrustedDevice")

    # default_user.py exports
    assert hasattr(default_user, "User")
    assert issubclass(default_user.User, models.Base)
    assert issubclass(default_user.User, models.AuthNZUserMixin)

    # workspace_models.py exports
    assert hasattr(workspace_models, "Workspace")
    assert hasattr(workspace_models, "WorkspaceMember")
    assert hasattr(workspace_models, "Task")
    assert hasattr(workspace_models, "TeamMember")
    assert hasattr(workspace_models, "AuditLog")
    assert hasattr(workspace_models, "Notification")

    # auth_nz.models public BYOU surface
    assert hasattr(auth_nz.models, "Base")
    assert hasattr(auth_nz.models, "AuthNZUserMixin")
    assert hasattr(auth_nz.models, "PasswordResetToken")
    assert hasattr(auth_nz.models, "TrustedDevice")

