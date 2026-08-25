"""
Auth N&Z - Package Module (auth_nz/__init__.py)
-----------------------------------------------
Exports the full public IAM SDK.
"""

__version__ = "1.0.0"

from guards import (
    CurrentUser,
    CurrentWorkspace,
    require_auth,
    require_role,
    require_permission,
    get_current_workspace,
)
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
from config import settings, AuthNZSettings
from database import get_engine, get_session_factory, get_db_session
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
from api.router import api_router

__all__ = [
    "__version__",
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
    "get_engine",
    "get_session_factory",
    "get_db_session",
    "settings",
    "AuthNZSettings",
    "api_router",
    "CurrentUser",
    "CurrentWorkspace",
    "require_auth",
    "require_role",
    "require_permission",
    "get_current_workspace",
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
