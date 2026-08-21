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
    docs_url="/docs",
    redoc_url="/redoc",
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Core Component Singletons
hasher = concretePasswordHasher()
repo = concreteUserRepository(db_file="DATABASE.db")
token_svc = concreteTokenService()
sess_store = concreteSessionStore()
mfa_prov = concreteMFAProvider()
audit_log = AuditLogger(db_file="DATABASE.db")

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
    email: EmailStr
    password: str = Field(..., min_length=8)
    roles: List[str] = ["viewer"]
    department: Optional[str] = "General"
    clearance: Optional[int] = 1


class LoginRequest(BaseModel):
    identifier: str
    password: str


class MFACompleteRequest(BaseModel):
    user_id: str
    challenge_id: str
    code: str


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
    """Register a new user account with hashed credentials."""
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


@app.post("/auth/login", tags=["Authentication"])
async def login(req: LoginRequest, request: Request):
    """Primary credential authentication. Returns JWT/Session or an MFA challenge."""
    res = auth.authenticate_credentials(req.identifier, req.password)
    client_ip = request.client.host if request.client else "unknown"

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
