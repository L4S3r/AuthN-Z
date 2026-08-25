"""
Auth N&Z - Package Module (auth_nz/__init__.py)
-----------------------------------------------
Exports the full public IAM SDK.
"""

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
    register_exception_handlers,
)
from config import settings, AuthNZSettings
from authenticator import Authenticator
from password_hasher import PasswordHasher
from token_service import TokenService
from mfa_provider import MFAProvider
from device_trust_service import DeviceTrustService
from session_store import SessionStore
from permission_evaluator import PermissionEvaluator
from audit_logger import AuditLogger
from user_repository import UserRepository
from workspace_repository import WorkspaceRepository
from oauth_provider import OAuthManager
from email_service import EmailService
from webauthn_service import WebAuthnService
from metrics import MetricsCollector, metrics_collector
from api.router import api_router

__all__ = [
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
    "register_exception_handlers",
]
