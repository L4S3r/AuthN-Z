"""
Auth N&Z - FastAPI Application Server (server.py)
-------------------------------------------------
Provides HTTP REST endpoints for the complete authentication,
authorization, multi-factor verification, and audit telemetry system.

Run locally or on a server with:
    uvicorn server:app --host 0.0.0.0 --port 8000 --reload
"""

import hashlib
import json
from typing import Any, Dict, List, Optional
import uuid
import secrets

from fastapi import Depends, FastAPI, HTTPException, Header, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr, Field

from password_hasher import concretePasswordHasher
from user_repository import concreteUserRepository
from token_service import concreteTokenService
from session_store import concreteSessionStore
from mfa_provider import concreteMFAProvider
from authenticator import Authenticator
from permission_evaluator import PermissionEvaluator
from audit_logger import AuditLogger
from device_trust_service import DeviceTrustService


# =============================================================================
# Environment & Documentation Gating Configuration
# =============================================================================
import os

ENVIRONMENT = os.getenv("ENVIRONMENT", "development").lower()
ENABLE_DOCS = os.getenv(
    "ENABLE_DOCS",
    "true" if ENVIRONMENT != "production" else "false"
).lower() == "true"

docs_url = "/docs" if ENABLE_DOCS else None
redoc_url = "/redoc" if ENABLE_DOCS else None
openapi_url = "/openapi.json" if ENABLE_DOCS else None

# =============================================================================
# Application Initialization
# =============================================================================
app = FastAPI(
    title="Auth N&Z - Identity and Access Management System",
    description=(
        "Auth N&Z (Authentication & Authorization Engine)\n\n"
        "A modular, extensible security system providing:\n"
        "- Authentication (AuthN): Salted Bcrypt Hashing, Stateful Redis Sessions, and Stateless JWT Tokens.\n"
        "- Multi-Factor Authentication (MFA): RFC 6238 TOTP and Emergency Single-Use Recovery Codes.\n"
        "- Authorization (AuthZ): Hierarchical RBAC and Attribute-Based Access Control (ABAC) Policy Engine.\n"
        "- Telemetry: Structured Security Audit Trail and Query Interface."
    ),
    version="1.0.0",
    docs_url=docs_url,
    redoc_url=redoc_url,
    openapi_url=openapi_url,
    servers=[
        {
            "url": "https://auth-api.l4s3r.site",
            "description": "Production Gateway (Public HTTPS)",
        },
        {
            "url": "http://localhost:8000",
            "description": "Local Development Server",
        },
    ],
    swagger_ui_parameters={
        "persistAuthorization": True,
        "displayRequestDuration": True,
    },
)

# Explicit CORS Whitelist
ALLOWED_ORIGINS = [
    "https://auth-api.l4s3r.site",
    "https://tasks.l4s3r.site",
    "https://l4s3r.site",
    "https://www.l4s3r.site",
    "http://localhost:3000",
    "http://localhost:5173",
    "http://localhost:8000",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:8000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_origin_regex=r"^https://([a-zA-Z0-9_-]+\.)*(l4s3r\.site|vercel\.app)$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


from oauth_provider import OAuthManager, generate_pkce_pair, generate_oauth_state
from task_repository import TaskRepository
from workspace_repository import WorkspaceRepository
from email_service import EmailService

# Core Component Singletons
hasher = concretePasswordHasher()
repo = concreteUserRepository(db_file="DATABASE.db")
ws_repo = WorkspaceRepository(db_file="DATABASE.db")
sess_store = concreteSessionStore()
token_svc = concreteTokenService(redis_client=sess_store.r)
mfa_prov = concreteMFAProvider()
audit_log = AuditLogger(db_file="DATABASE.db")
oauth_mgr = OAuthManager(redis_client=sess_store.r)
task_repo = TaskRepository(db_file="DATABASE.db")
email_svc = EmailService()
device_trust_svc = DeviceTrustService(db_file="DATABASE.db")

auth = Authenticator(
    user_repo=repo,
    hasher=hasher,
    token_service=token_svc,
    session_store=sess_store,
    mfa_provider=mfa_prov,
)

perm_eval = PermissionEvaluator(user_repo=repo, workspace_repo=ws_repo)

security = HTTPBearer(auto_error=False)


# =============================================================================
# Request / Response Schemas
# =============================================================================
class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: str = Field(..., min_length=5, max_length=100)
    password: str = Field(..., min_length=8)


class AdminCreateUserRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: str = Field(..., min_length=5, max_length=100)
    password: str = Field(..., min_length=8)
    roles: List[str] = ["viewer"]
    department: Optional[str] = "General"
    clearance: Optional[int] = 1


class TaskCreateRequest(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = ""
    status: Optional[str] = "todo"
    priority: Optional[str] = "medium"
    workspace_id: Optional[str] = "ws_default"
    assignee_email: Optional[str] = None
    assignee_name: Optional[str] = None
    assignees: Optional[List[Dict[str, Any]]] = None
    tags: Optional[List[str]] = []
    due_date: Optional[str] = None


class TaskUpdateRequest(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    priority: Optional[str] = None
    workspace_id: Optional[str] = None
    assignee_email: Optional[str] = None
    assignee_name: Optional[str] = None
    assignees: Optional[List[Dict[str, Any]]] = None
    tags: Optional[List[str]] = None
    due_date: Optional[str] = None



class WorkspaceCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    slug: Optional[str] = None
    description: Optional[str] = ""


class WorkspaceUpdateRequest(BaseModel):
    name: Optional[str] = None
    slug: Optional[str] = None
    description: Optional[str] = None


class WorkspaceInviteRequest(BaseModel):
    email: str = Field(..., min_length=5, max_length=100)
    name: Optional[str] = None
    role: Optional[str] = "viewer"
    department: Optional[str] = "General"


class WorkspaceRoleUpdateRequest(BaseModel):
    role: str = Field(..., pattern="^(admin|editor|viewer)$")


class WorkspaceAcceptInviteRequest(BaseModel):
    token: str = Field(..., min_length=10)
    password: str = Field(..., min_length=8)
    name: Optional[str] = None


class WorkspaceSwitchRequest(BaseModel):
    workspace_id: str = Field(..., min_length=3)


class TeamInviteRequest(BaseModel):
    email: str = Field(..., min_length=5, max_length=100)
    name: Optional[str] = None
    role: Optional[str] = "viewer"
    department: Optional[str] = "General"
    provision_password: Optional[str] = None


class TeamAcceptInviteRequest(BaseModel):
    token: str = Field(..., min_length=10)
    password: str = Field(..., min_length=8)
    name: Optional[str] = None




class LoginRequest(BaseModel):
    identifier: str
    password: str
    trusted_device_token: Optional[str] = None


class OAuthExchangeRequest(BaseModel):
    code: str
    code_verifier: Optional[str] = None
    redirect_uri: Optional[str] = None


class MFAVerifySetupRequest(BaseModel):
    code: str = Field(..., min_length=6, max_length=12)




class RefreshRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    session_id: Optional[str] = None
    logout_all_devices: Optional[bool] = False


class MFACompleteRequest(BaseModel):
    user_id: str
    challenge_id: str
    code: str
    remember_device: Optional[bool] = False



# =============================================================================
# Rate Limiting Utilities (Redis-Backed Sliding Window)
# =============================================================================
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
# Security Dependency: Current Authenticated User Context
# =============================================================================
async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> Dict[str, Any]:
    """Extract and validate Bearer token from the Authorization header."""
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization Bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    res = auth.authenticate_token(credentials.credentials)
    if res["status"] != "SUCCESS":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired token: {res.get('reason')}",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return res


# =============================================================================
# Endpoints
# =============================================================================

@app.get("/", tags=["Health"])
async def root():
    return {
        "status": "ONLINE",
        "system": "Auth N&Z",
        "message": "Authentication and Authorization Gateway is operating normally.",
    }


@app.post("/auth/register", tags=["Authentication"], status_code=status.HTTP_201_CREATED)
async def register(req: RegisterRequest, request: Request):
    """Public registration: always assigns default unprivileged 'viewer' role and clearance 1."""
    try:
        hashed_password = hasher.hash(req.password)
        new_user = repo.create_user({
            "username": req.username,
            "email": req.email,
            "hashed_password": hashed_password,
            "roles": ["viewer"],  # Hardened: client cannot supply elevated roles
            "metadata": {
                "department": "General",
                "clearance": 1,
            },
        })
        client_ip = request.client.host if request.client else "unknown"
        audit_log.record_security_event(
            event_name="USER_REGISTERED",
            severity="INFO",
            details={
                "user_id": new_user["id"],
                "username": new_user["username"],
                "ip_address": client_ip,
            },
        )
        return {"status": "SUCCESS", "user": new_user}
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@app.post("/admin/users", tags=["Administration"], status_code=status.HTTP_201_CREATED)
async def admin_create_user(
    req: AdminCreateUserRequest,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Admin-only endpoint: Provision new accounts with custom roles and security clearance."""
    if not perm_eval.has_role(current_user["user_id"], "admin"):
        audit_log.record_access_denial(
            subject_id=current_user["user_id"],
            action="create_user",
            resource="admin/users",
            reason="ADMIN_ROLE_REQUIRED",
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Admin privileges required to provision custom roles.",
        )

    try:
        hashed_password = hasher.hash(req.password)
        new_user = repo.create_user({
            "username": req.username,
            "email": req.email,
            "hashed_password": hashed_password,
            "roles": req.roles,
            "metadata": {
                "department": req.department,
                "clearance": req.clearance,
            },
        })
        client_ip = request.client.host if request.client else "unknown"
        audit_log.record_security_event(
            event_name="ADMIN_USER_PROVISIONED",
            severity="INFO",
            details={
                "created_by": current_user["user_id"],
                "new_user_id": new_user["id"],
                "roles": req.roles,
                "ip_address": client_ip,
            },
        )
        return {"status": "SUCCESS", "user": new_user}
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@app.post("/auth/login", tags=["Authentication"])
async def login(req: LoginRequest, request: Request, response: Response):
    """Primary credential authentication with rate limiting, constant-time execution, and trusted device MFA bypass."""
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "")
    clean_ident = req.identifier.strip().lower()

    # Rate limiting: max 15 requests per minute per IP, max 5 per minute per identifier
    if not check_rate_limit(f"login_ip:{client_ip}", max_requests=15, window_seconds=60) or \
       not check_rate_limit(f"login_user:{clean_ident}", max_requests=5, window_seconds=60):
        audit_log.record_security_event(
            event_name="LOGIN_RATE_LIMITED",
            severity="WARNING",
            details={"identifier": req.identifier, "ip_address": client_ip},
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Please wait 60 seconds before trying again.",
        )

    res = auth.authenticate_credentials(req.identifier, req.password)

    if res["status"] == "SUCCESS":
        audit_log.record_auth_success(res["user_id"], "password", ip_address=client_ip)
        return res
    elif res["status"] == "MFA_REQUIRED":
        # Check if client presented a valid, unexpired trusted-device token
        user_id = res["user_id"]
        cand_token = req.trusted_device_token or request.cookies.get("trusted_device") or request.headers.get("X-Trusted-Device-Token")
        if cand_token:
            trusted_dev = device_trust_svc.verify_trusted_device(
                user_id=user_id,
                raw_token=cand_token,
                user_agent=user_agent,
                ip_address=client_ip,
            )
            if trusted_dev:
                # Valid trusted device: skip second factor
                user = repo.get_by_id(user_id)
                roles = user.get("roles", []) if user else []
                if isinstance(roles, str):
                    try:
                        roles = json.loads(roles)
                    except Exception:
                        roles = []

                access_token = token_svc.create_access_token(user_id, claims={"roles": roles})
                refresh_token = token_svc.create_refresh_token(user_id, claims={"roles": roles})
                session_id = sess_store.create_session(user_id, session_data={"roles": roles})

                audit_log.record_security_event(
                    event_name="MFA_SKIPPED_TRUSTED_DEVICE",
                    severity="INFO",
                    details={
                        "user_id": user_id,
                        "device_id": trusted_dev["id"],
                        "device_label": trusted_dev["device_label"],
                        "ip_address": client_ip,
                    },
                )
                audit_log.record_auth_success(user_id, "password+trusted_device", ip_address=client_ip)

                response.set_cookie(
                    "trusted_device",
                    cand_token.strip(),
                    max_age=30 * 86400,
                    httponly=True,
                    samesite="lax",
                )

                return {
                    "status": "SUCCESS",
                    "mfa_skipped": True,
                    "trusted_device": trusted_dev,
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "session_id": session_id,
                    "user_id": user_id,
                    "roles": roles,
                }

        # Otherwise require TOTP challenge
        return res
    else:
        audit_log.record_auth_failure(
            identifier=req.identifier,
            reason=res.get("reason", "INVALID_CREDENTIALS"),
            ip_address=client_ip,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials provided.",
        )


@app.post("/auth/refresh", tags=["Authentication"])
async def refresh_tokens(req: RefreshRequest, request: Request):
    """Exchange a valid refresh token for a new access token and rotated refresh token."""
    client_ip = request.client.host if request.client else "unknown"
    try:
        payload = token_svc.decode_and_verify(req.refresh_token)
    except ValueError as e:
        audit_log.record_auth_failure(
            identifier="refresh_token",
            reason=f"INVALID_REFRESH_TOKEN: {str(e)}",
            ip_address=client_ip,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid refresh token: {str(e)}",
        )

    if payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Provided token is not a refresh token.",
        )

    user_id = payload.get("sub")
    user = repo.get_by_id(user_id)
    if not user or not user.get("is_active", 1):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is inactive or no longer exists.",
        )

    # Invalidate the old refresh token (Token Rotation)
    old_jti = payload.get("jti")
    if old_jti:
        token_svc.revoke_token(old_jti, expires_at=int(payload.get("exp", 0)))

    roles = user.get("roles", [])
    if isinstance(roles, str):
        try:
            roles = json.loads(roles)
        except Exception:
            roles = []

    new_access_token = token_svc.create_access_token(user_id, claims={"roles": roles})
    new_refresh_token = token_svc.create_refresh_token(user_id, claims={"roles": roles})

    audit_log.record_security_event(
        event_name="TOKEN_REFRESHED",
        severity="INFO",
        details={"user_id": user_id, "ip_address": client_ip},
    )

    return {
        "status": "SUCCESS",
        "access_token": new_access_token,
        "refresh_token": new_refresh_token,
        "user_id": user_id,
    }


@app.post("/auth/logout", tags=["Authentication"])
async def logout(
    req: LogoutRequest = LogoutRequest(),
    request: Request = None,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Invalidate caller's JWT access token and active session (single-device or all devices)."""
    user_id = current_user["user_id"]
    claims = current_user.get("claims", {})
    client_ip = request.client.host if request and request.client else "unknown"

    # Revoke access token JTI in Redis blocklist
    jti = claims.get("jti")
    if jti:
        token_svc.revoke_token(jti, expires_at=int(claims.get("exp", 0)))

    # Invalidate session in Redis
    sessions_deleted = 0
    if req.logout_all_devices:
        sessions_deleted = sess_store.delete_all_user_sessions(user_id)
    elif req.session_id:
        sess_store.delete_session(req.session_id)
        sessions_deleted = 1

    audit_log.record_security_event(
        event_name="USER_LOGGED_OUT",
        severity="INFO",
        details={
            "user_id": user_id,
            "jti_revoked": jti,
            "logout_all_devices": req.logout_all_devices,
            "sessions_deleted": sessions_deleted,
            "ip_address": client_ip,
        },
    )

    return {
        "status": "SUCCESS",
        "message": "Successfully logged out.",
        "jti_revoked": jti,
        "logout_all_devices": req.logout_all_devices,
        "sessions_deleted": sessions_deleted,
    }




@app.post("/auth/mfa/setup", tags=["MFA Enrollment"])
async def setup_mfa(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Generate TOTP secret, provisioning URI, and backup recovery codes for the active user."""
    user_id = current_user["user_id"]
    secret = mfa_prov.generate_secret(user_id)
    backup_codes = mfa_prov.generate_backup_codes(count=8, code_length=10)
    hashed_backups = [hashlib.sha256(c.encode("utf-8")).hexdigest() for c in backup_codes]

    user = repo.get_by_id(user_id)
    metadata = user.get("metadata", {})
    if isinstance(metadata, str):
        metadata = json.loads(metadata)

    # Store as pending secret until verified by 6-digit TOTP input
    metadata["pending_mfa_secret"] = secret
    metadata["pending_backup_codes"] = hashed_backups
    repo.update_user(user_id, {"metadata": metadata})

    uri = mfa_prov.get_provisioning_uri(user_id, secret, user["email"])
    return {
        "status": "SUCCESS",
        "secret": secret,
        "provisioning_uri": uri,
        "backup_codes": backup_codes,
    }


@app.post("/auth/mfa/verify-setup", tags=["MFA Enrollment"])
async def verify_mfa_setup(
    req: MFAVerifySetupRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Verify the 6-digit TOTP code from authenticator app to finalize and activate 2FA."""
    user_id = current_user["user_id"]
    user = repo.get_by_id(user_id)
    metadata = user.get("metadata", {})
    if isinstance(metadata, str):
        metadata = json.loads(metadata)

    pending_secret = metadata.get("pending_mfa_secret") or metadata.get("mfa_secret")
    if not pending_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No pending MFA enrollment found. Please restart MFA setup.",
        )

    is_valid = mfa_prov.verify_totp_code(pending_secret, req.code.strip())
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid 6-digit verification code. Please check your authenticator clock and try again.",
        )

    # Commit active MFA enrollment
    metadata["mfa_enabled"] = True
    metadata["mfa_secret"] = pending_secret
    if "pending_backup_codes" in metadata:
        metadata["backup_codes"] = metadata.pop("pending_backup_codes")
    metadata.pop("pending_mfa_secret", None)
    repo.update_user(user_id, {"metadata": metadata})

    audit_log.record_security_event(
        event_name="MFA_ACTIVATED",
        severity="INFO",
        details={"user_id": user_id},
    )

    return {
        "status": "SUCCESS",
        "message": "Two-factor authentication has been successfully verified and activated.",
    }


@app.post("/auth/mfa/disable", tags=["MFA Enrollment"])
async def disable_mfa(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Disable two-factor authentication for the authenticated user."""
    user_id = current_user["user_id"]
    user = repo.get_by_id(user_id)
    metadata = user.get("metadata", {})
    if isinstance(metadata, str):
        metadata = json.loads(metadata)

    metadata["mfa_enabled"] = False
    metadata.pop("mfa_secret", None)
    metadata.pop("backup_codes", None)
    metadata.pop("pending_mfa_secret", None)
    metadata.pop("pending_backup_codes", None)
    repo.update_user(user_id, {"metadata": metadata})

    # Revoke all trusted devices when MFA is disabled
    device_trust_svc.revoke_all_trusted_devices(user_id)

    audit_log.record_security_event(
        event_name="MFA_DISABLED",
        severity="WARNING",
        details={"user_id": user_id},
    )
    return {"status": "SUCCESS", "message": "Two-factor authentication has been disabled."}




@app.post("/auth/mfa/complete", tags=["MFA Verification"])
async def complete_mfa(req: MFACompleteRequest, request: Request, response: Response):
    """Validate a TOTP code or emergency backup code to finalize an MFA challenge with optional device trust."""
    res = auth.complete_mfa_challenge(req.user_id, req.challenge_id, req.code)
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "")

    if res["status"] == "SUCCESS":
        audit_log.record_auth_success(req.user_id, "mfa_challenge", ip_address=client_ip)

        if req.remember_device:
            dev_rec, raw_dev_token = device_trust_svc.create_trusted_device(
                user_id=req.user_id,
                user_agent=user_agent,
                ip_address=client_ip,
                days_valid=30,
            )
            response.set_cookie(
                "trusted_device",
                raw_dev_token,
                max_age=30 * 86400,
                httponly=True,
                samesite="lax",
            )
            res["trusted_device_token"] = raw_dev_token
            res["trusted_device"] = dev_rec

            audit_log.record_security_event(
                event_name="DEVICE_TRUSTED",
                severity="INFO",
                details={
                    "user_id": req.user_id,
                    "device_id": dev_rec["id"],
                    "device_label": dev_rec["device_label"],
                    "ip_address": client_ip,
                },
            )

        return res
    else:
        audit_log.record_auth_failure(
            identifier=req.user_id,
            reason=res.get("reason", "INVALID_MFA_CODE"),
            ip_address=client_ip,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=res.get("reason", "MFA verification failed."),
        )


@app.get("/auth/trusted-devices", tags=["Device Trust"])
async def list_my_trusted_devices(
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """List all active trusted devices for the authenticated user."""
    user_id = current_user["user_id"]
    current_token = request.cookies.get("trusted_device") or request.headers.get("X-Trusted-Device-Token")
    devices = device_trust_svc.list_trusted_devices(user_id, current_token=current_token)
    return {
        "status": "SUCCESS",
        "devices": devices,
        "count": len(devices),
    }


@app.delete("/auth/trusted-devices/{device_id}", tags=["Device Trust"])
async def revoke_my_trusted_device(
    device_id: str,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Revoke trust for a specific device."""
    user_id = current_user["user_id"]
    client_ip = request.client.host if request.client else "unknown"
    revoked = device_trust_svc.revoke_trusted_device(user_id, device_id)
    if not revoked:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Trusted device not found.")

    audit_log.record_security_event(
        event_name="DEVICE_TRUST_REVOKED",
        severity="INFO",
        details={"user_id": user_id, "device_id": device_id, "ip_address": client_ip},
    )
    return {"status": "SUCCESS", "message": "Device trust revoked successfully."}


@app.delete("/auth/trusted-devices", tags=["Device Trust"])
async def revoke_all_my_trusted_devices(
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Revoke all trusted devices for the authenticated user."""
    user_id = current_user["user_id"]
    client_ip = request.client.host if request.client else "unknown"
    count = device_trust_svc.revoke_all_trusted_devices(user_id)

    audit_log.record_security_event(
        event_name="ALL_DEVICES_TRUST_REVOKED",
        severity="INFO",
        details={"user_id": user_id, "devices_revoked": count, "ip_address": client_ip},
    )
    return {"status": "SUCCESS", "message": f"Successfully revoked {count} trusted device(s)."}


@app.get("/auth/me", tags=["User Context"])
async def get_my_profile(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Retrieve identity context of the authenticated user."""
    user = repo.get_by_id(current_user["user_id"])
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    meta = user.get("metadata", {})
    if isinstance(meta, str):
        try:
            meta = json.loads(meta)
        except Exception:
            meta = {}
    safe_meta = dict(meta) if isinstance(meta, dict) else {}
    safe_meta.pop("mfa_secret", None)
    safe_meta.pop("backup_codes", None)

    roles = user.get("roles", [])
    if isinstance(roles, str):
        try:
            roles = json.loads(roles)
        except Exception:
            roles = []

    safe_user = {
        "id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "roles": roles,
        "metadata": safe_meta,
        "created_at": user.get("created_at"),
    }
    return {"status": "SUCCESS", "user": safe_user, "claims": current_user.get("claims", {})}



@app.get("/documents/{doc_id}", tags=["Protected Resources"])
async def get_protected_document(
    doc_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Protected resource evaluation demonstrating RBAC, ownership, and policy rules."""
    user_id = current_user["user_id"]
    doc_attributes = {
        "owner_id": "u_bob",
        "is_public": False,
        "department": "Finance",
        "required_clearance": 2,
    }

    has_access = perm_eval.is_resource_accessible(
        subject_id=user_id,
        action="read",
        resource_type="documents",
        resource_id=doc_id,
        resource_attributes=doc_attributes,
    )

    if not has_access:
        audit_log.record_access_denial(
            subject_id=user_id,
            action="read",
            resource=f"documents/{doc_id}",
            reason="FORBIDDEN_BY_POLICY",
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden: You do not possess the required permissions or ownership.",
        )

    return {
        "status": "SUCCESS",
        "document_id": doc_id,
        "content": "Confidential financial intelligence report.",
    }


@app.get("/audit/logs", tags=["Audit and Compliance"])
async def get_audit_trail(
    limit: int = 50,
    offset: int = 0,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Query security audit telemetry records. Requires 'admin' role."""
    if not perm_eval.has_role(current_user["user_id"], "admin"):
        audit_log.record_access_denial(
            subject_id=current_user["user_id"],
            action="read",
            resource="audit_logs",
            reason="ADMIN_ROLE_REQUIRED",
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Admin role required to query audit logs.",
        )

    logs = audit_log.query_events({}, limit=limit, offset=offset)
    return {"status": "SUCCESS", "count": len(logs), "logs": logs}


# =============================================================================
# OAuth2 / OpenID Connect (OIDC) Social Login Endpoints
# =============================================================================
def resolve_or_create_oauth_user(profile: Dict[str, Any], client_ip: str) -> Dict[str, Any]:
    """Link an external OAuth profile to an existing account or auto-provision a new user."""
    email = profile.get("email")
    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OAuth identity provider did not provide a valid email address.",
        )

    provider = profile.get("provider", "oauth")
    provider_uid = profile.get("provider_user_id")

    user = repo.get_by_identifier(email)
    if user:
        if not user.get("is_active", 1):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Account associated with this email is inactive.",
            )

        metadata = user.get("metadata", {})
        if isinstance(metadata, str):
            try:
                metadata = json.loads(metadata)
            except Exception:
                metadata = {}

        oauth_map = metadata.setdefault("oauth_providers", {})
        oauth_map[provider] = provider_uid
        if profile.get("picture"):
            metadata["avatar_url"] = profile["picture"]
        repo.update_user(user["id"], {"metadata": metadata})
    else:
        base_username = email.split("@")[0].lower()
        clean_username = "".join(c for c in base_username if c.isalnum() or c in ("_", "-"))
        if len(clean_username) < 3:
            clean_username = f"user_{secrets.token_hex(4)}"

        if repo.get_by_identifier(clean_username):
            clean_username = f"{clean_username}_{secrets.token_hex(3)}"

        dummy_password = secrets.token_urlsafe(32)
        hashed_pw = hasher.hash(dummy_password)

        user = repo.create_user({
            "username": clean_username,
            "email": email,
            "hashed_password": hashed_pw,
            "roles": ["viewer"],
            "metadata": {
                "department": "General",
                "clearance": 1,
                "oauth_providers": {provider: provider_uid},
                "avatar_url": profile.get("picture"),
                "name": profile.get("name"),
            },
        })

        audit_log.record_security_event(
            event_name="USER_OAUTH_PROVISIONED",
            severity="INFO",
            details={
                "user_id": user["id"],
                "email": email,
                "provider": provider,
                "ip_address": client_ip,
            },
        )

    # Check if user has MFA active
    user_meta = user.get("metadata", {})
    if isinstance(user_meta, str):
        try:
            user_meta = json.loads(user_meta)
        except Exception:
            user_meta = {}

    if user_meta.get("mfa_enabled") and user_meta.get("mfa_secret"):
        challenge = auth.initiate_mfa_challenge(user["id"], challenge_type="totp")
        return {
            "status": "MFA_REQUIRED",
            "user_id": user["id"],
            "challenge_id": challenge["challenge_id"],
        }

    roles = user.get("roles", [])
    if isinstance(roles, str):
        try:
            roles = json.loads(roles)
        except Exception:
            roles = []

    access_token = token_svc.create_access_token(user["id"], claims={"roles": roles})
    refresh_token = token_svc.create_refresh_token(user["id"], claims={"roles": roles})
    session_id = sess_store.create_session(user["id"], session_data={"roles": roles})


    safe_metadata = dict(user_meta) if isinstance(user_meta, dict) else {}
    safe_metadata.pop("mfa_secret", None)
    safe_metadata.pop("backup_codes", None)


    audit_log.record_auth_success(user["id"], f"oauth_{provider}", ip_address=client_ip)

    return {
        "status": "SUCCESS",
        "user_id": user["id"],
        "access_token": access_token,
        "refresh_token": refresh_token,
        "session_id": session_id,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "roles": roles,
            "metadata": safe_metadata,
        },
    }



@app.get("/auth/oauth/providers", tags=["OAuth2 / Social Login"])
async def list_oauth_providers():
    """List configured and available OAuth identity providers."""
    return {
        "status": "SUCCESS",
        "available_providers": list(oauth_mgr.providers.keys()),
    }


@app.get("/auth/oauth/{provider}/login", tags=["OAuth2 / Social Login"])
async def oauth_login(
    provider: str,
    request: Request,
    redirect_uri: Optional[str] = None,
    target_app_url: Optional[str] = None,
):
    """Initiate PKCE-protected OAuth authorization flow for web or mobile clients."""
    prov_instance = oauth_mgr.get_provider(provider)
    if not prov_instance:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"OAuth provider '{provider}' is not configured on this server.",
        )

    default_redirect = f"{str(request.base_url).rstrip('/')}/auth/oauth/{provider}/callback"
    final_redirect = redirect_uri or default_redirect

    code_verifier, code_challenge = generate_pkce_pair()
    state = generate_oauth_state()

    oauth_mgr.save_state(
        state=state,
        data={
            "provider": provider,
            "code_verifier": code_verifier,
            "redirect_uri": final_redirect,
            "target_app_url": target_app_url,
        },
        ttl_seconds=600,
    )

    auth_url = prov_instance.get_authorization_url(
        redirect_uri=final_redirect,
        state=state,
        code_challenge=code_challenge,
    )

    return {
        "status": "SUCCESS",
        "provider": provider,
        "authorization_url": auth_url,
        "state": state,
        "code_verifier": code_verifier,
    }


@app.get("/auth/oauth/{provider}/callback", tags=["OAuth2 / Social Login"])
async def oauth_callback(
    provider: str,
    code: str,
    state: str,
    request: Request,
):
    """Handle OAuth authorization code redirect and return issued tokens."""
    state_data = oauth_mgr.consume_state(state)
    if not state_data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired OAuth state parameter.",
        )

    prov_instance = oauth_mgr.get_provider(provider)
    if not prov_instance:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"OAuth provider '{provider}' is not configured.",
        )

    client_ip = request.client.host if request.client else "unknown"
    try:
        profile = await prov_instance.exchange_code(
            code=code,
            redirect_uri=state_data.get("redirect_uri"),
            code_verifier=state_data.get("code_verifier"),
        )
    except Exception as exc:
        audit_log.record_auth_failure(
            identifier=f"oauth_{provider}",
            reason=str(exc),
            ip_address=client_ip,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"OAuth code exchange failed: {str(exc)}",
        )

    return resolve_or_create_oauth_user(profile, client_ip=client_ip)


@app.post("/auth/oauth/{provider}/exchange", tags=["OAuth2 / Social Login"])
async def oauth_exchange_code(
    provider: str,
    req: OAuthExchangeRequest,
    request: Request,
):
    """Direct authorization code exchange for native mobile applications and SPAs."""
    prov_instance = oauth_mgr.get_provider(provider)
    if not prov_instance:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"OAuth provider '{provider}' is not configured.",
        )

    client_ip = request.client.host if request.client else "unknown"
    default_redirect = f"{str(request.base_url).rstrip('/')}/auth/oauth/{provider}/callback"
    redirect_uri = req.redirect_uri or default_redirect

    try:
        profile = await prov_instance.exchange_code(
            code=req.code,
            redirect_uri=redirect_uri,
            code_verifier=req.code_verifier,
        )
    except Exception as exc:
        audit_log.record_auth_failure(
            identifier=f"oauth_{provider}",
            reason=str(exc),
            ip_address=client_ip,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"OAuth exchange failed: {str(exc)}",
        )

    return resolve_or_create_oauth_user(profile, client_ip=client_ip)


# =============================================================================
# Task Management REST Endpoints
# =============================================================================
@app.get("/tasks", tags=["Task Tracker"])
async def get_tasks(
    workspace_id: Optional[str] = None,
    status: Optional[str] = None,
    priority: Optional[str] = None,
    assignee_email: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Retrieve workspace sprint tasks with optional filtering."""
    tasks = task_repo.list_tasks(
        workspace_id=workspace_id,
        status=status,
        priority=priority,
        assignee_email=assignee_email,
    )
    return {"status": "SUCCESS", "count": len(tasks), "tasks": tasks}


@app.post("/tasks", tags=["Task Tracker"])
async def create_task(
    req: TaskCreateRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Create and assign a new team task card, dispatching email notification to all assignees. Requires Editor, Admin, or Superadmin role."""
    ws_id = req.workspace_id or "ws_default"

    # Enforce RBAC: only editors, admins, and superadmins can create tasks
    if not perm_eval.has_role(current_user["user_id"], "editor", scope=ws_id):
        audit_log.record_access_denial(
            subject_id=current_user["user_id"],
            action="create",
            resource=f"workspaces/{ws_id}/tasks",
            reason="EDITOR_OR_ADMIN_ROLE_REQUIRED",
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Editor, Admin, or Superadmin role required to create tasks.",
        )

    user = repo.get_by_id(current_user["user_id"])
    creator_email = user["email"] if user else current_user["user_id"]
    assigned_by_name = user["username"] if user else "Workspace Admin"

    assignees_list = req.assignees or []
    if not assignees_list and req.assignee_email:
        assignees_list = [{
            "email": req.assignee_email.strip().lower(),
            "name": req.assignee_name or req.assignee_email.split("@")[0],
        }]

    primary_email = req.assignee_email or (assignees_list[0]["email"] if assignees_list else creator_email)
    primary_name = req.assignee_name or (assignees_list[0]["name"] if assignees_list else (user["username"] if user else "Member"))

    new_task = task_repo.create_task({
        "workspace_id": ws_id,
        "title": req.title.strip(),
        "description": (req.description or "").strip(),
        "status": req.status or "todo",
        "priority": req.priority or "medium",
        "assignee_email": primary_email,
        "assignee_name": primary_name,
        "assignees": assignees_list,
        "created_by": creator_email,
        "tags": req.tags or [],
        "due_date": req.due_date,
    })

    # Dispatch assignment email notification to all assignees
    targets = assignees_list if assignees_list else ([{"email": primary_email, "name": primary_name}] if primary_email else [])
    for target in targets:
        target_email = target.get("email", "").strip().lower()
        target_name = target.get("name") or target_email.split("@")[0]
        if target_email and "@" in target_email:
            email_svc.send_task_assignment_email(
                recipient_email=target_email,
                recipient_name=target_name,
                task_title=new_task["title"],
                task_description=new_task.get("description"),
                priority=new_task.get("priority", "medium"),
                due_date=new_task.get("due_date"),
                assigned_by=assigned_by_name,
                task_id=new_task["id"],
            )

    return {"status": "SUCCESS", "task": new_task}


@app.patch("/tasks/{task_id}", tags=["Task Tracker"])
async def update_task(
    task_id: str,
    req: TaskUpdateRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Update task card status (Kanban movement), priority, deadline, or assignees. Requires Editor, Admin, or Superadmin role."""
    existing = task_repo.get_task(task_id)
    if not existing:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Task not found.",
        )

    ws_id = existing.get("workspace_id") or "ws_default"

    # Enforce RBAC: only editors, admins, and superadmins can modify tasks
    if not perm_eval.has_role(current_user["user_id"], "editor", scope=ws_id):
        audit_log.record_access_denial(
            subject_id=current_user["user_id"],
            action="update",
            resource=f"tasks/{task_id}",
            reason="EDITOR_OR_ADMIN_ROLE_REQUIRED",
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Editor, Admin, or Superadmin role required to modify tasks.",
        )

    updates = {k: v for k, v in req.model_dump().items() if v is not None}
    updated = task_repo.update_task(task_id, updates)

    # If assignees were updated, notify any newly added assignees
    user = repo.get_by_id(current_user["user_id"])
    assigned_by_name = user["username"] if user else "Workspace Admin"

    existing_assignees = set()
    for a in existing.get("assignees", []):
        if isinstance(a, dict) and a.get("email"):
            existing_assignees.add(a["email"].strip().lower())
    if existing.get("assignee_email"):
        existing_assignees.add(existing["assignee_email"].strip().lower())

    new_targets = []
    if req.assignees is not None:
        for a in req.assignees:
            email = a.get("email", "").strip().lower()
            if email and email not in existing_assignees:
                new_targets.append(a)
    elif req.assignee_email and req.assignee_email.strip().lower() not in existing_assignees:
        new_targets.append({
            "email": req.assignee_email.strip().lower(),
            "name": req.assignee_name or req.assignee_email.split("@")[0],
        })

    for target in new_targets:
        target_email = target.get("email", "").strip().lower()
        target_name = target.get("name") or target_email.split("@")[0]
        if target_email and "@" in target_email:
            email_svc.send_task_assignment_email(
                recipient_email=target_email,
                recipient_name=target_name,
                task_title=updated.get("title", existing["title"]),
                task_description=updated.get("description", existing.get("description")),
                priority=updated.get("priority", existing.get("priority", "medium")),
                due_date=updated.get("due_date", existing.get("due_date")),
                assigned_by=assigned_by_name,
                task_id=task_id,
            )

    return {"status": "SUCCESS", "task": updated}




@app.delete("/tasks/{task_id}", tags=["Task Tracker"])
async def delete_task(
    task_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Delete a task card from the workspace. Requires task creator (with editor role), workspace admin, or superadmin role."""
    existing_task = task_repo.get_task(task_id)
    if not existing_task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Task not found.",
        )

    user = repo.get_by_id(current_user["user_id"])
    caller_email = user["email"].strip().lower() if user and user.get("email") else ""
    task_creator = (existing_task.get("created_by") or "").strip().lower()
    ws_id = existing_task.get("workspace_id") or "ws_default"

    is_creator = bool(caller_email and caller_email == task_creator)
    is_editor = perm_eval.has_role(current_user["user_id"], "editor", scope=ws_id)
    is_admin = perm_eval.has_role(current_user["user_id"], "admin", scope=ws_id)
    is_superadmin = perm_eval.has_role(current_user["user_id"], "superadmin")

    if not (is_superadmin or is_admin or (is_creator and is_editor)):
        audit_log.record_access_denial(
            subject_id=current_user["user_id"],
            action="delete",
            resource=f"tasks/{task_id}",
            reason="CREATOR_EDITOR_OR_ADMIN_ROLE_REQUIRED",
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Workspace admin, superadmin, or task creator (with editor role) required to delete this task.",
        )

    deleted = task_repo.delete_task(task_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Task not found.",
        )
    return {"status": "SUCCESS", "deleted_task_id": task_id}



# =============================================================================
# Team Management & Invitation REST Endpoints
# =============================================================================
@app.get("/team/members", tags=["Team Management"])
async def list_team_members(
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """List all workspace members and pending email invitations."""
    members = task_repo.list_team_members()
    return {"status": "SUCCESS", "count": len(members), "members": members}


@app.post("/team/invite", tags=["Team Management"])
async def invite_team_member(
    req: TeamInviteRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Invite a new colleague to the team workspace with email notification. Requires 'admin' role."""
    if not perm_eval.has_role(current_user["user_id"], "admin"):
        audit_log.record_access_denial(
            subject_id=current_user["user_id"],
            action="invite",
            resource="team_members",
            reason="ADMIN_ROLE_REQUIRED",
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Admin role required to invite team members.",
        )

    admin_user = repo.get_by_id(current_user["user_id"])
    invited_by_name = admin_user["username"] if admin_user else "Admin"

    invitation = task_repo.invite_member(
        email=req.email,
        name=req.name or req.email.split("@")[0],
        role=req.role or "viewer",
        department=req.department or "General",
        invited_by=invited_by_name,
    )


    # Dispatch branded invitation email
    email_res = email_svc.send_invitation_email(
        recipient_email=invitation["email"],
        recipient_name=invitation["name"],
        role=invitation["role"],
        department=invitation["department"],
        invited_by=invited_by_name,
        invite_token=invitation["invite_token"],
    )

    audit_log.record_security_event(
        event_name="TEAM_MEMBER_INVITED",
        severity="INFO",
        details={
            "invited_email": req.email,
            "role": req.role,
            "department": req.department,
            "invited_by": invited_by_name,
            "invite_token": invitation["invite_token"],
            "email_dispatched": email_res.get("delivered", False),
        },
    )

    return {
        "status": "SUCCESS",
        "message": f"Invitation notification dispatched to {req.email}.",
        "invite_url": email_res.get("invite_url"),
        "member": invitation,
    }


@app.get("/team/invite/verify", tags=["Team Management"])
async def verify_team_invitation(token: str):
    """Verify an invitation token for a new user landing on the accept-invite page."""
    invite = task_repo.get_invitation_by_token(token)
    if not invite:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invitation token not found or already consumed.",
        )

    if invite.get("is_expired"):
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="This invitation link has expired. Please request a new invitation.",
        )

    return {
        "status": "SUCCESS",
        "email": invite["email"],
        "name": invite["name"],
        "role": invite["role"],
        "department": invite["department"],
        "invited_by": invite.get("invited_by", "Workspace Admin"),
        "expires_at": invite.get("expires_at"),
    }


@app.post("/team/invite/accept", tags=["Team Management"])
async def accept_team_invitation(
    req: TeamAcceptInviteRequest,
    request: Request,
):
    """Accept an invitation, register credentials, activate workspace clearance, and log in."""
    invite = task_repo.get_invitation_by_token(req.token)
    if not invite:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invitation token not found or already consumed.",
        )

    if invite.get("is_expired"):
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="This invitation link has expired. Please request a new invitation.",
        )

    email = invite["email"].strip().lower()
    client_ip = request.client.host if request.client else "unknown"
    clearance_levels = {"admin": 3, "editor": 2, "viewer": 1}
    clearance = clearance_levels.get(invite["role"], 1)

    existing_user = repo.get_by_identifier(email)
    hashed_pw = hasher.hash(req.password)

    if existing_user:
        # Update existing user role & credentials
        user_id = existing_user["id"]
        roles = existing_user.get("roles", [])
        if isinstance(roles, str):
            try:
                roles = json.loads(roles)
            except Exception:
                roles = []
        if invite["role"] not in roles:
            roles.append(invite["role"])

        metadata = existing_user.get("metadata", {})
        if isinstance(metadata, str):
            try:
                metadata = json.loads(metadata)
            except Exception:
                metadata = {}
        metadata["department"] = invite["department"]
        metadata["clearance"] = max(metadata.get("clearance", 1), clearance)
        if req.name:
            metadata["name"] = req.name.strip()

        repo.update_user(user_id, {
            "hashed_password": hashed_pw,
            "roles": roles,
            "metadata": metadata,
            "is_active": 1,
        })
        user = repo.get_by_id(user_id)
    else:
        # Provision new user account
        base_username = email.split("@")[0].lower()
        clean_username = "".join(c for c in base_username if c.isalnum() or c in ("_", "-"))
        if len(clean_username) < 3 or repo.get_by_identifier(clean_username):
            clean_username = f"{clean_username}_{secrets.token_hex(3)}"

        user = repo.create_user({
            "username": clean_username,
            "email": email,
            "hashed_password": hashed_pw,
            "roles": [invite["role"]],
            "metadata": {
                "department": invite["department"],
                "clearance": clearance,
                "name": req.name.strip() if req.name else invite["name"],
            },
        })
        user_id = user["id"]
        roles = [invite["role"]]

    # Mark invitation as accepted in SQLite
    task_repo.accept_invitation(req.token)

    # Generate JWT tokens and active session
    access_token = token_svc.create_access_token(user_id, claims={"roles": roles})
    refresh_token = token_svc.create_refresh_token(user_id, claims={"roles": roles})
    session_id = sess_store.create_session(user_id, session_data={"roles": roles})

    safe_meta = user.get("metadata", {})
    if isinstance(safe_meta, str):
        try:
            safe_meta = json.loads(safe_meta)
        except Exception:
            safe_meta = {}
    safe_meta.pop("mfa_secret", None)
    safe_meta.pop("backup_codes", None)

    audit_log.record_security_event(
        event_name="TEAM_INVITE_ACCEPTED",
        severity="INFO",
        details={
            "user_id": user_id,
            "email": email,
            "role": invite["role"],
            "department": invite["department"],
            "ip_address": client_ip,
        },
    )

    return {
        "status": "SUCCESS",
        "message": "Invitation accepted. Welcome to the workspace!",
        "user_id": user_id,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "session_id": session_id,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "roles": roles,
            "metadata": safe_meta,
        },
    }


@app.delete("/team/members/{member_email}", tags=["Team Management"])
async def remove_team_member(
    member_email: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Remove a member, delete their registered user account, and revoke sessions. Requires admin role."""
    caller_id = current_user["user_id"]
    if not perm_eval.has_role(caller_id, "admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin role required to remove team members.",
        )

    clean_email = member_email.strip().lower()

    # 1. Check if user is in users table
    user = repo.get_by_identifier(clean_email)
    if user:
        if user["id"] == caller_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot remove your own administrator account.",
            )
        # Invalidate sessions & delete user
        sess_store.delete_all_user_sessions(user["id"])
        repo.delete_user(user["id"])

    # 2. Also remove from team_members table
    task_repo.remove_member(clean_email)

    audit_log.record_security_event(
        event_name="TEAM_MEMBER_REMOVED",
        severity="WARNING",
        details={
            "removed_email": clean_email,
            "removed_by": caller_id,
        },
    )

    return {
        "status": "SUCCESS",
        "message": f"Member {clean_email} has been removed.",
        "removed_email": clean_email,
    }


# =============================================================================
# Workspaces & Multi-Tenancy REST Endpoints
# =============================================================================

@app.post("/workspaces", tags=["Workspaces"])
async def create_workspace(
    req: WorkspaceCreateRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Create a new team workspace. The creator is automatically assigned as the Workspace Admin."""
    user = repo.get_by_id(current_user["user_id"])
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    try:
        new_ws = ws_repo.create_workspace(
            name=req.name,
            created_by=current_user["user_id"],
            slug=req.slug,
            description=req.description,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    audit_log.record_security_event(
        event_name="WORKSPACE_CREATED",
        severity="INFO",
        details={
            "workspace_id": new_ws["id"],
            "workspace_name": new_ws["name"],
            "slug": new_ws["slug"],
            "created_by": current_user["user_id"],
        },
    )
    return {"status": "SUCCESS", "workspace": new_ws}


@app.get("/workspaces", tags=["Workspaces"])
async def list_user_workspaces(
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """List all workspaces the authenticated user belongs to (or all workspaces if Superadmin)."""
    user = repo.get_by_id(current_user["user_id"])
    user_email = user["email"] if user else None

    is_superadmin = perm_eval.has_role(current_user["user_id"], "superadmin")
    if is_superadmin:
        workspaces = ws_repo.list_all_workspaces()
    else:
        workspaces = ws_repo.list_workspaces_for_user(
            user_id=current_user["user_id"],
            email=user_email,
        )

    return {"status": "SUCCESS", "count": len(workspaces), "workspaces": workspaces}


@app.get("/workspaces/{workspace_id}", tags=["Workspaces"])
async def get_workspace_details(
    workspace_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Retrieve workspace profile, metadata, and member metrics."""
    is_authorized = perm_eval.has_role(current_user["user_id"], "viewer", scope=workspace_id) or perm_eval.has_role(current_user["user_id"], "superadmin")
    if not is_authorized:
        audit_log.record_access_denial(
            subject_id=current_user["user_id"],
            action="view",
            resource=f"workspaces/{workspace_id}",
            reason="WORKSPACE_MEMBERSHIP_REQUIRED",
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: You are not a member of this workspace.",
        )

    ws = ws_repo.get_workspace(workspace_id)
    if not ws:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Workspace not found.")

    metrics = ws_repo.count_members(workspace_id)
    return {"status": "SUCCESS", "workspace": ws, "metrics": metrics}


@app.patch("/workspaces/{workspace_id}", tags=["Workspaces"])
async def update_workspace(
    workspace_id: str,
    req: WorkspaceUpdateRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Update workspace name, slug, or description. Requires Workspace Admin or Superadmin role."""
    is_admin = perm_eval.has_role(current_user["user_id"], "admin", scope=workspace_id)
    if not is_admin:
        audit_log.record_access_denial(
            subject_id=current_user["user_id"],
            action="update",
            resource=f"workspaces/{workspace_id}",
            reason="ADMIN_ROLE_REQUIRED",
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Workspace Admin or Superadmin role required.",
        )

    updates = {k: v for k, v in req.model_dump().items() if v is not None}
    try:
        updated = ws_repo.update_workspace(workspace_id, updates)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    if not updated:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Workspace not found.")

    audit_log.record_security_event(
        event_name="WORKSPACE_UPDATED",
        severity="INFO",
        details={"workspace_id": workspace_id, "updates": updates, "updated_by": current_user["user_id"]},
    )
    return {"status": "SUCCESS", "workspace": updated}


@app.delete("/workspaces/{workspace_id}", tags=["Workspaces"])
async def delete_workspace(
    workspace_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Delete a workspace and cascade delete all its tasks and member associations. Requires Workspace Admin or Superadmin."""
    is_admin = perm_eval.has_role(current_user["user_id"], "admin", scope=workspace_id)
    if not is_admin:
        audit_log.record_access_denial(
            subject_id=current_user["user_id"],
            action="delete",
            resource=f"workspaces/{workspace_id}",
            reason="ADMIN_ROLE_REQUIRED",
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Workspace Admin or Superadmin role required.",
        )

    try:
        deleted = ws_repo.delete_workspace(workspace_id)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Workspace not found.")

    audit_log.record_security_event(
        event_name="WORKSPACE_DELETED",
        severity="WARNING",
        details={"workspace_id": workspace_id, "deleted_by": current_user["user_id"]},
    )
    return {"status": "SUCCESS", "deleted_workspace_id": workspace_id}


# =============================================================================
# Workspace Member & Invitation REST Endpoints
# =============================================================================

@app.get("/workspaces/{workspace_id}/members", tags=["Workspaces"])
async def list_workspace_members(
    workspace_id: str,
    status_filter: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """List all members and pending invitations for a specific workspace."""
    is_authorized = perm_eval.has_role(current_user["user_id"], "viewer", scope=workspace_id) or perm_eval.has_role(current_user["user_id"], "superadmin")
    if not is_authorized:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: You are not a member of this workspace.",
        )

    members = ws_repo.list_members(workspace_id=workspace_id, status=status_filter)
    return {"status": "SUCCESS", "count": len(members), "members": members}


@app.post("/workspaces/{workspace_id}/invite", tags=["Workspaces"])
async def invite_workspace_member(
    workspace_id: str,
    req: WorkspaceInviteRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Invite a new colleague to a specific workspace with a defined role. Requires Workspace Admin or Superadmin."""
    is_admin = perm_eval.has_role(current_user["user_id"], "admin", scope=workspace_id)
    if not is_admin:
        audit_log.record_access_denial(
            subject_id=current_user["user_id"],
            action="invite",
            resource=f"workspaces/{workspace_id}/members",
            reason="ADMIN_ROLE_REQUIRED",
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Admin role required to invite workspace members.",
        )

    admin_user = repo.get_by_id(current_user["user_id"])
    invited_by_name = admin_user["username"] if admin_user else "Workspace Admin"

    try:
        invitation = ws_repo.invite_member(
            workspace_id=workspace_id,
            email=req.email,
            name=req.name,
            role=req.role or "viewer",
            department=req.department or "General",
            invited_by=invited_by_name,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    # Dispatch branded invitation email
    email_res = email_svc.send_invitation_email(
        recipient_email=invitation["email"],
        recipient_name=invitation["name"],
        role=invitation["role"],
        department=invitation["department"],
        invited_by=invited_by_name,
        invite_token=invitation["invite_token"],
        workspace_name=invitation.get("workspace_name", "TaskTracker Workspace"),
    )

    audit_log.record_security_event(
        event_name="WORKSPACE_MEMBER_INVITED",
        severity="INFO",
        details={
            "workspace_id": workspace_id,
            "invited_email": req.email,
            "role": req.role,
            "department": req.department,
            "invited_by": invited_by_name,
            "invite_token": invitation["invite_token"],
            "email_dispatched": email_res.get("delivered", False),
        },
    )

    return {
        "status": "SUCCESS",
        "message": f"Invitation notification dispatched to {req.email} for {invitation.get('workspace_name')}.",
        "invite_url": email_res.get("invite_url"),
        "member": invitation,
    }


@app.patch("/workspaces/{workspace_id}/members/{user_id_or_email:path}/role", tags=["Workspaces"])
async def update_workspace_member_role(
    workspace_id: str,
    user_id_or_email: str,
    req: WorkspaceRoleUpdateRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Change a colleague's clearance role within a specific workspace. Requires Workspace Admin or Superadmin."""
    is_admin = perm_eval.has_role(current_user["user_id"], "admin", scope=workspace_id)
    if not is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Admin role required to update member roles.",
        )

    updated = ws_repo.update_member_role(workspace_id, user_id_or_email, req.role)
    if not updated:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Member not found in this workspace.")

    audit_log.record_security_event(
        event_name="WORKSPACE_MEMBER_ROLE_UPDATED",
        severity="INFO",
        details={
            "workspace_id": workspace_id,
            "member": user_id_or_email,
            "new_role": req.role,
            "updated_by": current_user["user_id"],
        },
    )
    return {"status": "SUCCESS", "message": f"Role updated to '{req.role}' for {user_id_or_email}."}


@app.delete("/workspaces/{workspace_id}/members/{user_id_or_email:path}", tags=["Workspaces"])
async def remove_workspace_member(
    workspace_id: str,
    user_id_or_email: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Remove a colleague from a specific workspace or cancel their invitation. Requires Workspace Admin or Superadmin."""
    is_admin = perm_eval.has_role(current_user["user_id"], "admin", scope=workspace_id)
    if not is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Admin role required to remove members.",
        )

    # Check for self-removal
    curr_user = repo.get_by_id(current_user["user_id"])
    curr_email = curr_user["email"].lower() if curr_user else ""
    from urllib.parse import unquote
    clean_target = unquote(user_id_or_email).strip().lower()

    if clean_target in (current_user["user_id"].lower(), curr_email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot remove your own administrator membership from the workspace.",
        )

    removed = ws_repo.remove_member(workspace_id, user_id_or_email)
    if not removed:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Member not found in this workspace.")

    audit_log.record_security_event(
        event_name="WORKSPACE_MEMBER_REMOVED",
        severity="WARNING",
        details={
            "workspace_id": workspace_id,
            "removed_member": user_id_or_email,
            "removed_by": current_user["user_id"],
        },
    )
    return {"status": "SUCCESS", "message": f"Member {user_id_or_email} removed from workspace."}


@app.get("/workspaces/invite/verify", tags=["Workspaces"])
async def verify_workspace_invitation(token: str):
    """Verify an invitation token when a user lands on the accept-invite onboarding page."""
    invite = ws_repo.get_invitation_by_token(token)
    if not invite:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invitation token not found or already consumed.",
        )

    if invite.get("is_expired"):
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="This invitation link has expired. Please request a new invitation.",
        )

    return {
        "status": "SUCCESS",
        "email": invite["email"],
        "name": invite["name"],
        "role": invite["role"],
        "department": invite["department"],
        "workspace_id": invite["workspace_id"],
        "workspace_name": invite.get("workspace_name", "TaskTracker Workspace"),
        "invited_by": invite.get("invited_by", "Workspace Admin"),
        "expires_at": invite.get("expires_at"),
    }


@app.post("/workspaces/invite/accept", tags=["Workspaces"])
async def accept_workspace_invitation(
    req: WorkspaceAcceptInviteRequest,
    request: Request,
):
    """Accept a workspace invitation, register credentials, activate workspace membership, and log in."""
    invite = ws_repo.get_invitation_by_token(req.token)
    if not invite:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invitation token not found or already consumed.",
        )

    if invite.get("is_expired"):
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="This invitation link has expired. Please request a new invitation.",
        )

    email = invite["email"].strip().lower()
    workspace_id = invite["workspace_id"]
    client_ip = request.client.host if request.client else "unknown"
    clearance_levels = {"admin": 3, "editor": 2, "viewer": 1}
    clearance = clearance_levels.get(invite["role"], 1)

    existing_user = repo.get_by_identifier(email)
    hashed_pw = hasher.hash(req.password)

    if existing_user:
        user_id = existing_user["id"]
        roles = existing_user.get("roles", [])
        if isinstance(roles, str):
            try:
                roles = json.loads(roles)
            except Exception:
                roles = []
        if invite["role"] not in roles:
            roles.append(invite["role"])

        metadata = existing_user.get("metadata", {})
        if isinstance(metadata, str):
            try:
                metadata = json.loads(metadata)
            except Exception:
                metadata = {}
        metadata["department"] = invite["department"]
        metadata["clearance"] = max(metadata.get("clearance", 1), clearance)
        if req.name:
            metadata["name"] = req.name.strip()

        repo.update_user(user_id, {
            "hashed_password": hashed_pw,
            "roles": roles,
            "metadata": metadata,
            "is_active": 1,
        })
        user = repo.get_by_id(user_id)
    else:
        base_username = email.split("@")[0].lower()
        clean_username = "".join(c for c in base_username if c.isalnum() or c in ("_", "-"))
        if len(clean_username) < 3 or repo.get_by_identifier(clean_username):
            clean_username = f"{clean_username}_{secrets.token_hex(3)}"

        user = repo.create_user({
            "username": clean_username,
            "email": email,
            "hashed_password": hashed_pw,
            "roles": [invite["role"]],
            "metadata": {
                "department": invite["department"],
                "clearance": clearance,
                "name": req.name.strip() if req.name else invite["name"],
            },
        })
        user_id = user["id"]
        roles = [invite["role"]]

    # Mark invitation as accepted in SQLite workspace_members
    accepted = ws_repo.accept_invitation(req.token, user_id=user_id)
    if not accepted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invitation token not found or already consumed.",
        )

    # Generate JWT tokens and active session
    access_token = token_svc.create_access_token(user_id, claims={"roles": roles, "workspace_id": workspace_id})
    refresh_token = token_svc.create_refresh_token(user_id, claims={"roles": roles, "workspace_id": workspace_id})
    session_id = sess_store.create_session(user_id, session_data={"roles": roles, "workspace_id": workspace_id})

    safe_meta = user.get("metadata", {})
    if isinstance(safe_meta, str):
        try:
            safe_meta = json.loads(safe_meta)
        except Exception:
            safe_meta = {}
    safe_meta.pop("mfa_secret", None)
    safe_meta.pop("backup_codes", None)

    audit_log.record_security_event(
        event_name="WORKSPACE_INVITE_ACCEPTED",
        severity="INFO",
        details={
            "user_id": user_id,
            "email": email,
            "workspace_id": workspace_id,
            "role": invite["role"],
            "department": invite["department"],
            "ip_address": client_ip,
        },
    )

    return {
        "status": "SUCCESS",
        "message": f"Invitation accepted. Welcome to {invite.get('workspace_name', 'the workspace')}!",
        "user_id": user_id,
        "workspace_id": workspace_id,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "session_id": session_id,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "roles": roles,
            "metadata": safe_meta,
        },
    }


@app.post("/auth/workspaces/switch", tags=["Workspaces", "Authentication"])
async def switch_active_workspace(
    req: WorkspaceSwitchRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Switch the authenticated user's active tenant workspace context, returning refreshed scoped JWT tokens."""
    target_ws_id = req.workspace_id.strip()
    user_id = current_user["user_id"]
    user = repo.get_by_id(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    is_superadmin = perm_eval.has_role(user_id, "superadmin")
    ws = ws_repo.get_workspace(target_ws_id)
    if not ws:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target workspace not found.")

    member = ws_repo.get_member(target_ws_id, user_id=user_id, email=user.get("email"))
    if not member and not is_superadmin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: You are not an active member of this workspace.",
        )

    # Scoped roles in this workspace
    workspace_role = member["role"] if member else ("superadmin" if is_superadmin else "viewer")
    roles = [workspace_role]
    if is_superadmin and "superadmin" not in roles:
        roles.append("superadmin")

    # Issue refreshed JWT tokens scoped to target workspace
    access_token = token_svc.create_access_token(user_id, claims={"roles": roles, "workspace_id": target_ws_id})
    refresh_token = token_svc.create_refresh_token(user_id, claims={"roles": roles, "workspace_id": target_ws_id})
    session_id = sess_store.create_session(user_id, session_data={"roles": roles, "workspace_id": target_ws_id})

    audit_log.record_security_event(
        event_name="WORKSPACE_SWITCHED",
        severity="INFO",
        details={
            "user_id": user_id,
            "workspace_id": target_ws_id,
            "workspace_name": ws["name"],
            "role": workspace_role,
        },
        workspace_id=target_ws_id,
    )

    return {
        "status": "SUCCESS",
        "message": f"Active workspace switched to '{ws['name']}'.",
        "active_workspace": {
            "id": ws["id"],
            "name": ws["name"],
            "slug": ws["slug"],
            "role": workspace_role,
        },
        "access_token": access_token,
        "refresh_token": refresh_token,
        "session_id": session_id,
    }


@app.get("/workspaces/{workspace_id}/audit-logs", tags=["Workspaces", "Security & Auditing"])
async def get_workspace_audit_logs(
    workspace_id: str,
    limit: int = 50,
    offset: int = 0,
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Retrieve security audit telemetry for a specific workspace. Requires Workspace Admin or Superadmin."""
    is_admin = perm_eval.has_role(current_user["user_id"], "admin", scope=workspace_id)
    if not is_admin:
        audit_log.record_access_denial(
            subject_id=current_user["user_id"],
            action="view_audit_logs",
            resource=f"workspaces/{workspace_id}/audit-logs",
            reason="ADMIN_ROLE_REQUIRED",
            workspace_id=workspace_id,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Workspace Admin or Superadmin role required to view audit logs.",
        )

    filters = {"workspace_id": workspace_id}
    if event_type:
        filters["event_type"] = event_type
    if severity:
        filters["severity"] = severity.upper()

    logs = audit_log.query_events(filters, limit=min(limit, 200), offset=offset)
    return {
        "status": "SUCCESS",
        "workspace_id": workspace_id,
        "count": len(logs),
        "audit_logs": logs,
    }




