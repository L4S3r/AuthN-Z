"""
Auth N&Z - Idiomatic FastAPI Security Dependency Guards (guards.py)
------------------------------------------------------------------
Provides clean, declarative, 1-line security guards for consuming FastAPI applications:
- require_auth()
- require_role("admin")
- require_permission("tasks:write")
- CurrentUser & CurrentWorkspace dependency injection models
"""

from typing import Any, Callable, Dict, List, Optional
import json
import logging
from fastapi import Depends, HTTPException, Header, Path, Query, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from config import settings
from exceptions import (
    InvalidTokenException,
    PermissionDeniedException,
    TokenExpiredException,
    TokenRevokedException,
    WorkspaceNotFoundException,
)
from api.dependencies import (
    auth,
    perm_eval,
    user_repo,
    ws_repo,
    token_svc,
    security,
)

logger = logging.getLogger("auth_nz.guards")


# =============================================================================
# Typed Identity Context Models
# =============================================================================
class CurrentUser(BaseModel):
    """Authenticated user context injected into route handlers."""
    id: str = Field(..., description="Unique User UUID string")
    username: str = Field(..., description="User unique login handle")
    email: str = Field(..., description="User primary email address")
    roles: List[str] = Field(default_factory=list, description="Global assigned RBAC roles")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Custom metadata, department, clearance")
    workspace_id: Optional[str] = Field(default=None, description="Active tenant workspace scope")
    claims: Dict[str, Any] = Field(default_factory=dict, description="Decoded JWT claims")

    @property
    def clearance(self) -> int:
        return int(self.metadata.get("clearance", 1))

    @property
    def department(self) -> str:
        return str(self.metadata.get("department", "General"))


class CurrentWorkspace(BaseModel):
    """Active workspace tenant context injected into route handlers."""
    id: str = Field(..., description="Unique Workspace UUID or slug")
    name: str = Field(..., description="Workspace organization display name")
    slug: str = Field(..., description="Workspace URL slug")
    role: str = Field(default="viewer", description="Caller's scoped membership role within this workspace")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Workspace metadata")


# =============================================================================
# Declarative Dependency Guard Factories
# =============================================================================

def require_auth(auto_error: bool = True) -> Callable:
    """
    FastAPI dependency guard ensuring request is authenticated via Bearer token or HttpOnly cookie.
    
    Usage:
        @router.get("/profile")
        async def get_profile(user: CurrentUser = Depends(require_auth())):
            return {"id": user.id, "email": user.email}
    """
    async def _auth_guard(
        request: Request,
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    ) -> Optional[CurrentUser]:
        token: Optional[str] = None

        if credentials and credentials.credentials:
            token = credentials.credentials.strip()
        if not token:
            auth_hdr = request.headers.get("authorization")
            if auth_hdr and auth_hdr.lower().startswith("bearer "):
                token = auth_hdr[7:].strip()

        if not token:
            cookie_token = request.cookies.get("access_token")
            if cookie_token:
                token = str(cookie_token).strip().strip('"').strip("'")

        if not token:
            if not auto_error:
                return None
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication credentials required (access_token cookie or Bearer token).",
                headers={"WWW-Authenticate": "Bearer"},
            )

        res = await auth.authenticate_token(token)
        if res["status"] != "SUCCESS":
            if not auto_error:
                return None
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid or expired token: {res.get('reason')}",
                headers={"WWW-Authenticate": "Bearer"},
            )

        user_id = res["user_id"]
        claims = res.get("claims", {})
        user_record = await user_repo.get_by_id(user_id)
        if not user_record or not user_record.get("is_active", 1):
            if not auto_error:
                return None
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User account is inactive or not found.",
            )

        meta = user_record.get("metadata", {})
        if isinstance(meta, str):
            try:
                meta = json.loads(meta)
            except Exception:
                meta = {}
        safe_meta = dict(meta) if isinstance(meta, dict) else {}
        safe_meta.pop("mfa_secret", None)
        safe_meta.pop("backup_codes", None)

        roles = user_record.get("roles", [])
        if isinstance(roles, str):
            try:
                roles = json.loads(roles)
            except Exception:
                roles = []

        return CurrentUser(
            id=str(user_record["id"]),
            username=user_record["username"],
            email=user_record["email"],
            roles=roles,
            metadata=safe_meta,
            workspace_id=claims.get("workspace_id"),
            claims=claims,
        )

    return _auth_guard


def require_role(
    required_role: str,
    scope: Optional[str] = None,
    scope_param: str = "workspace_id",
) -> Callable:
    """
    FastAPI dependency guard requiring caller to have a specific role or higher in role hierarchy.
    
    Hierarchy: superadmin > admin > developer > editor > viewer
    
    Usage:
        @router.delete("/projects/{project_id}")
        async def delete_project(user: CurrentUser = Depends(require_role("admin"))):
            ...
    """
    async def _role_guard(
        request: Request,
        current_user: CurrentUser = Depends(require_auth()),
    ) -> CurrentUser:
        effective_scope = scope
        if not effective_scope:
            # Check path params, query params, headers, or token claim
            effective_scope = (
                request.path_params.get(scope_param)
                or request.query_params.get(scope_param)
                or request.headers.get("x-workspace-id")
                or current_user.workspace_id
            )

        has_role = await perm_eval.has_role(
            subject_id=current_user.id,
            required_role=required_role,
            scope=effective_scope,
        )

        if not has_role:
            raise PermissionDeniedException(
                detail=f"Access denied: '{required_role}' role or higher required.",
                required_role=required_role,
            )

        return current_user

    return _role_guard


def require_permission(
    permission: str,
    resource_type: Optional[str] = None,
    scope_param: str = "workspace_id",
) -> Callable:
    """
    FastAPI dependency guard enforcing fine-grained RBAC permissions or ABAC policy rules.
    
    Usage:
        @router.post("/billing/invoices")
        async def create_invoice(user: CurrentUser = Depends(require_permission("billing:create"))):
            ...
    """
    async def _permission_guard(
        request: Request,
        current_user: CurrentUser = Depends(require_auth()),
    ) -> CurrentUser:
        effective_scope = (
            request.path_params.get(scope_param)
            or request.query_params.get(scope_param)
            or request.headers.get("x-workspace-id")
            or current_user.workspace_id
        )

        context: Dict[str, Any] = {
            "workspace_id": effective_scope,
            "roles": current_user.roles,
            "clearance": current_user.clearance,
            "department": current_user.department,
        }

        has_perm = await perm_eval.has_permission(
            subject_id=current_user.id,
            required_permission=permission,
            context=context,
        )

        if not has_perm:
            raise PermissionDeniedException(
                detail=f"Access denied: '{permission}' permission required.",
                required_permission=permission,
            )

        return current_user

    return _permission_guard


def get_current_workspace(scope_param: str = "workspace_id") -> Callable:
    """
    FastAPI dependency resolving caller's active workspace and verified member role.
    
    Usage:
        @router.get("/workspaces/{workspace_id}/settings")
        async def get_settings(workspace: CurrentWorkspace = Depends(get_current_workspace())):
            return {"workspace": workspace.name, "role": workspace.role}
    """
    async def _workspace_guard(
        request: Request,
        current_user: CurrentUser = Depends(require_auth()),
    ) -> CurrentWorkspace:
        target_ws = (
            request.path_params.get(scope_param)
            or request.query_params.get(scope_param)
            or request.headers.get("x-workspace-id")
            or current_user.workspace_id
        )

        if not target_ws:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Missing workspace identifier in path parameter '{scope_param}', query, or header.",
            )

        resolved_id = await ws_repo._resolve_ws_id(str(target_ws)) or str(target_ws)
        ws = await ws_repo.get_workspace(resolved_id)
        if not ws:
            raise WorkspaceNotFoundException(workspace_id=target_ws)

        is_superadmin = await perm_eval.has_role(current_user.id, "superadmin")
        member = await ws_repo.get_member(resolved_id, user_id=current_user.id, email=current_user.email)

        if (not member or member.get("status") != "active") and not is_superadmin:
            raise PermissionDeniedException(
                detail="Access denied: You are not an active member of this workspace.",
                required_role="viewer",
            )

        caller_role = member["role"] if member else ("superadmin" if is_superadmin else "viewer")

        return CurrentWorkspace(
            id=str(ws["id"]),
            name=ws["name"],
            slug=ws["slug"],
            role=caller_role,
            metadata=ws.get("metadata") or {},
        )

    return _workspace_guard
