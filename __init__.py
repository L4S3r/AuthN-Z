"""
Auth N&Z - Enterprise Identity, Authentication & Authorization Engine
=====================================================================
A production-grade, NIST-compliant, async IAM security engine for Python and FastAPI.

Core Capabilities:
- Robust Password Hashing (Bcrypt, timing side-channel mitigation)
- JWT Token Issuance & Family Rotation (anti-replay/theft defense)
- RFC 6238 TOTP Multi-Factor Authentication & Single-Use Recovery Codes
- Scoped Device Trust Tokens (User-Agent binding & instant revocation)
- Distributed Sessions (Redis-backed with in-memory single-worker fallback)
- Multi-Tenant RBAC & ABAC Policy Engine (Role hierarchy & dynamic evaluation)
- Structured Asynchronous Security Event Audit Logging
- Social Login Gateway (Google OIDC, GitHub OAuth with PKCE)
- Declarative 1-line FastAPI Dependency Guards (require_auth, require_permission, require_role)
"""

# Version
__version__ = "1.0.4"

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

# Core Facades and Services
from authenticator import Authenticator
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

# Database and Settings
from database import get_engine, get_session_factory, get_db_session
from config import settings, AuthNZSettings

# FastAPI Router & Gateway
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

# Declarative Dependency Guards
from guards import (
    CurrentUser,
    CurrentWorkspace,
    require_auth,
    require_role,
    require_permission,
    get_current_workspace,
)

# Standard Exceptions & RFC 7807 Boundaries
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
    register_exception_handlers,
)

__all__ = [
    # Version
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
    # Core Services
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
    "WebAuthnService",
    "MetricsCollector",
    "metrics_collector",
    "OPAClient",
    "DeclarativePolicyEngine",
    "DistributedPolicyManager",
    # Database & Configuration
    "get_engine",
    "get_session_factory",
    "get_db_session",
    "settings",
    "AuthNZSettings",
    # API & Gateways
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
    # Dependency Guards
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
    "register_exception_handlers",
]
