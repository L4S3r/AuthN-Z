"""
Auth N&Z - Package Module (auth_nz/__init__.py)
-----------------------------------------------
Exports the full public IAM SDK, Adapter Framework, Models, and Routers.
"""

import re
from pathlib import Path

def _resolve_version() -> str:
    try:
        pyproject_file = Path(__file__).parent.parent / "pyproject.toml"
        if pyproject_file.exists():
            match = re.search(r'^version\s*=\s*"([^"]+)"', pyproject_file.read_text(encoding="utf-8"), re.MULTILINE)
            if match:
                return match.group(1)
    except Exception:
        pass
    try:
        from importlib.metadata import version as _pkg_version
        return _pkg_version("l4s3r-authnz")
    except Exception:
        pass
    return "1.2.0"

__version__ = _resolve_version()

# Models & Mixins
from models import (
    Base,
    AuthNZUserMixin,
    PasswordResetToken,
    TrustedDevice,
)
from default_user import User
from workspace_models import (
    Workspace,
    WorkspaceMember,
    Task,
    TeamMember,
    AuditLog,
    Notification,
)

# Adapter & Configuration
from adapter import (
    configure_authnz,
    AuthNZ,
    AuthNZAdapter,
)

# Guards & Dependency Injection
from guards import (
    CurrentUser,
    CurrentWorkspace,
    require_auth,
    require_role,
    require_permission,
    get_current_workspace,
)

# Exceptions & Error Handlers
from exceptions import (
    AuthNZException,
    InvalidCredentialsException,
    AccountLockedException,
    MFARequiredException,
    TokenRevokedException,
    TokenExpiredException,
    InvalidTokenException,
    PermissionDeniedException,
    ResourceNotFoundException,
    WorkspaceNotFoundException,
    ConflictException,
    RateLimitExceededException,
    WebAuthnVerificationException,
    WebAuthnCloneDetectedException,
    register_exception_handlers,
)

# Configuration & Database
from config import settings, AuthNZSettings
from database import get_engine, get_session_factory, get_db_session

# Services & Cryptography
from authenticator import Authenticator, abstractAuthenticator
from password_hasher import PasswordHasher, abstractPasswordHasher
from token_service import TokenService, abstractTokenService
from mfa_provider import MFAProvider, abstractMFAProvider
from device_trust_service import DeviceTrustService
from session_store import SessionStore, abstractSessionStore
from permission_evaluator import PermissionEvaluator
from audit_logger import AuditLogger
from user_repository import UserRepository, abstractUserRepository
from workspace_repository import WorkspaceRepository
from oauth_provider import OAuthManager
from email_service import EmailService
from webauthn_service import WebAuthnService
from metrics import MetricsCollector, metrics_collector
from opa_client import OPAClient
from policy_engine import DeclarativePolicyEngine, DistributedPolicyManager

# Routers & Router Factory
from api.router import (
    api_router,
    create_authnz_router,
    auth_router,
    mfa_router,
    webauthn_router,
    device_trust_router,
    workspace_router,
    team_router,
    oauth_router,
    audit_router,
    notification_router,
    websocket_router,
    task_router,
    health_router,
    policy_router,
)

__all__ = [
    "__version__",
    # Adapter & Configuration
    "configure_authnz",
    "AuthNZ",
    "AuthNZAdapter",
    # Models & Mixins
    "Base",
    "AuthNZUserMixin",
    "User",
    "PasswordResetToken",
    "Workspace",
    "WorkspaceMember",
    "Task",
    "TeamMember",
    "AuditLog",
    "TrustedDevice",
    "Notification",
    # Services
    "Authenticator",
    "abstractAuthenticator",
    "PasswordHasher",
    "abstractPasswordHasher",
    "TokenService",
    "abstractTokenService",
    "MFAProvider",
    "abstractMFAProvider",
    "DeviceTrustService",
    "SessionStore",
    "abstractSessionStore",
    "PermissionEvaluator",
    "AuditLogger",
    "UserRepository",
    "abstractUserRepository",
    "WorkspaceRepository",
    "OAuthManager",
    "EmailService",
    "WebAuthnService",
    "MetricsCollector",
    "metrics_collector",
    "OPAClient",
    "DeclarativePolicyEngine",
    "DistributedPolicyManager",
    # Database & Settings
    "get_engine",
    "get_session_factory",
    "get_db_session",
    "settings",
    "AuthNZSettings",
    # Routers
    "api_router",
    "create_authnz_router",
    "auth_router",
    "mfa_router",
    "webauthn_router",
    "device_trust_router",
    "workspace_router",
    "team_router",
    "oauth_router",
    "audit_router",
    "notification_router",
    "websocket_router",
    "task_router",
    "health_router",
    "policy_router",
    # Guards
    "CurrentUser",
    "CurrentWorkspace",
    "require_auth",
    "require_role",
    "require_permission",
    "get_current_workspace",
    # Exceptions
    "AuthNZException",
    "InvalidCredentialsException",
    "AccountLockedException",
    "MFARequiredException",
    "TokenRevokedException",
    "TokenExpiredException",
    "InvalidTokenException",
    "PermissionDeniedException",
    "ResourceNotFoundException",
    "WorkspaceNotFoundException",
    "ConflictException",
    "RateLimitExceededException",
    "WebAuthnVerificationException",
    "WebAuthnCloneDetectedException",
    "register_exception_handlers",
]
