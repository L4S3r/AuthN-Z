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

from fastapi import Depends, FastAPI, HTTPException, Header, Request, status
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

# Core Component Singletons
hasher = concretePasswordHasher()
repo = concreteUserRepository(db_file="DATABASE.db")
sess_store = concreteSessionStore()
token_svc = concreteTokenService(redis_client=sess_store.r)
mfa_prov = concreteMFAProvider()
audit_log = AuditLogger(db_file="DATABASE.db")
oauth_mgr = OAuthManager(redis_client=sess_store.r)
task_repo = TaskRepository(db_file="DATABASE.db")

auth = Authenticator(
    user_repo=repo,
    hasher=hasher,
    token_service=token_svc,
    session_store=sess_store,
    mfa_provider=mfa_prov,
)

perm_eval = PermissionEvaluator(user_repo=repo)

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
    assignee_email: Optional[str] = None
    assignee_name: Optional[str] = None
    tags: Optional[List[str]] = []
    due_date: Optional[str] = None


class TaskUpdateRequest(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    priority: Optional[str] = None
    assignee_email: Optional[str] = None
    assignee_name: Optional[str] = None
    tags: Optional[List[str]] = None
    due_date: Optional[str] = None


class TeamInviteRequest(BaseModel):
    email: str = Field(..., min_length=5, max_length=100)
    name: Optional[str] = None
    role: Optional[str] = "viewer"
    department: Optional[str] = "General"
    provision_password: Optional[str] = None



class LoginRequest(BaseModel):
    identifier: str
    password: str


class OAuthExchangeRequest(BaseModel):
    code: str
    code_verifier: Optional[str] = None
    redirect_uri: Optional[str] = None



class RefreshRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    session_id: Optional[str] = None
    logout_all_devices: Optional[bool] = False


class MFACompleteRequest(BaseModel):
    user_id: str
    challenge_id: str
    code: str



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
async def login(req: LoginRequest, request: Request):
    """Primary credential authentication with rate limiting and constant-time execution."""
    client_ip = request.client.host if request.client else "unknown"
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

    metadata["mfa_enabled"] = True
    metadata["mfa_secret"] = secret
    metadata["backup_codes"] = hashed_backups
    repo.update_user(user_id, {"metadata": metadata})

    uri = mfa_prov.get_provisioning_uri(user_id, secret, user["email"])
    return {
        "status": "SUCCESS",
        "secret": secret,
        "provisioning_uri": uri,
        "backup_codes": backup_codes,
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
    repo.update_user(user_id, {"metadata": metadata})

    audit_log.record_security_event(
        event_name="MFA_DISABLED",
        severity="WARNING",
        details={"user_id": user_id},
    )
    return {"status": "SUCCESS", "message": "Two-factor authentication has been disabled."}



@app.post("/auth/mfa/complete", tags=["MFA Verification"])
async def complete_mfa(req: MFACompleteRequest, request: Request):
    """Validate a TOTP code or emergency backup code to finalize an MFA challenge."""
    res = auth.complete_mfa_challenge(req.user_id, req.challenge_id, req.code)
    client_ip = request.client.host if request.client else "unknown"

    if res["status"] == "SUCCESS":
        audit_log.record_auth_success(req.user_id, "mfa_challenge", ip_address=client_ip)
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


@app.get("/auth/me", tags=["User Context"])
async def get_my_profile(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Retrieve identity context of the authenticated user."""
    user = repo.get_by_id(current_user["user_id"])
    return {"status": "SUCCESS", "user": user, "claims": current_user.get("claims", {})}


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

    roles = user.get("roles", [])
    if isinstance(roles, str):
        try:
            roles = json.loads(roles)
        except Exception:
            roles = []

    access_token = token_svc.create_access_token(user["id"], claims={"roles": roles})
    refresh_token = token_svc.create_refresh_token(user["id"], claims={"roles": roles})
    session_id = sess_store.create_session(user["id"], session_data={"roles": roles})

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
    status: Optional[str] = None,
    priority: Optional[str] = None,
    assignee_email: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Retrieve workspace sprint tasks with optional filtering."""
    tasks = task_repo.list_tasks(
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
    """Create and assign a new team task card."""
    user = repo.get_by_id(current_user["user_id"])
    creator_email = user["email"] if user else current_user["user_id"]

    new_task = task_repo.create_task({
        "title": req.title,
        "description": req.description or "",
        "status": req.status or "todo",
        "priority": req.priority or "medium",
        "assignee_email": req.assignee_email or creator_email,
        "assignee_name": req.assignee_name or (user["username"] if user else "Member"),
        "created_by": creator_email,
        "tags": req.tags or [],
        "due_date": req.due_date,
    })

    return {"status": "SUCCESS", "task": new_task}


@app.patch("/tasks/{task_id}", tags=["Task Tracker"])
async def update_task(
    task_id: str,
    req: TaskUpdateRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Update task card status (Kanban movement), priority, or assignee."""
    existing = task_repo.get_task(task_id)
    if not existing:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Task not found.",
        )

    updates = {k: v for k, v in req.model_dump().items() if v is not None}
    updated = task_repo.update_task(task_id, updates)
    return {"status": "SUCCESS", "task": updated}


@app.delete("/tasks/{task_id}", tags=["Task Tracker"])
async def delete_task(
    task_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Delete a task card from the workspace."""
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
    """Invite a new colleague to the team workspace with email notification."""
    admin_user = repo.get_by_id(current_user["user_id"])
    invited_by_name = admin_user["username"] if admin_user else "Admin"

    # Auto-provision backend user account if temporary password was provided
    if req.provision_password and len(req.provision_password) >= 8:
        existing = repo.get_by_identifier(req.email)
        if not existing:
            clearance_levels = {"admin": 3, "editor": 2, "viewer": 1}
            hashed_pw = hasher.hash(req.provision_password)
            repo.create_user({
                "username": req.email.split("@")[0].lower(),
                "email": req.email.strip().lower(),
                "hashed_password": hashed_pw,
                "roles": [req.role or "viewer"],
                "metadata": {
                    "department": req.department or "General",
                    "clearance": clearance_levels.get(req.role or "viewer", 1),
                    "name": req.name or req.email.split("@")[0],
                },
            })

    invitation = task_repo.invite_member(
        email=req.email,
        name=req.name or req.email.split("@")[0],
        role=req.role or "viewer",
        department=req.department or "General",
        invited_by=invited_by_name,
    )

    audit_log.record_security_event(
        event_name="TEAM_MEMBER_INVITED",
        severity="INFO",
        details={
            "invited_email": req.email,
            "role": req.role,
            "department": req.department,
            "invited_by": invited_by_name,
        },
    )

    return {
        "status": "SUCCESS",
        "message": f"Invitation email notification dispatched to {req.email}.",
        "member": invitation,
    }


@app.delete("/team/members/{member_email}", tags=["Team Management"])
async def remove_team_member(
    member_email: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Remove a member or cancel an invitation. Requires admin role."""
    if not perm_eval.has_role(current_user["user_id"], "admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin role required to remove team members.",
        )

    removed = task_repo.remove_member(member_email)
    return {"status": "SUCCESS", "removed_email": member_email}


