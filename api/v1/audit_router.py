"""
Auth N&Z - Security Audit & Protected Resources Router (api/v1/audit_router.py)
--------------------------------------------------------------------------------
Provides endpoints for compliance log queries, multi-tenant audit telemetry,
and ABAC protected resource access demonstration.
"""

from typing import Any, Dict, Optional
import logging
from fastapi import APIRouter, Depends, HTTPException, Query, status

from api.dependencies import (
    perm_eval,
    audit_log,
    ws_repo,
    get_current_user,
)

logger = logging.getLogger("auth_nz.audit_router")

router = APIRouter(tags=["Audit and Compliance"])


@router.get("/documents/{doc_id}", tags=["Protected Resources"])
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

    has_access = await perm_eval.is_resource_accessible(
        subject_id=user_id,
        action="read",
        resource_type="documents",
        resource_id=doc_id,
        resource_attributes=doc_attributes,
    )

    if not has_access:
        await audit_log.record_access_denial(
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


@router.get("/audit/logs")
async def get_audit_trail(
    limit: int = 50,
    offset: int = 0,
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    workspace_id: Optional[str] = None,
    subject_id: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Query security audit telemetry records. Requires 'admin' or 'superadmin' role (scoped or global)."""
    user_id = current_user["user_id"]
    is_superadmin = await perm_eval.has_role(user_id, "superadmin")
    is_global_admin = await perm_eval.has_role(user_id, "admin")

    filters = {}
    if workspace_id:
        ws_id = await ws_repo._resolve_ws_id(workspace_id) or workspace_id
        is_ws_admin = await perm_eval.has_role(user_id, "admin", scope=ws_id)
        if not (is_superadmin or is_global_admin or is_ws_admin):
            await audit_log.record_access_denial(
                subject_id=user_id,
                action="read",
                resource=f"workspaces/{ws_id}/audit-logs",
                reason="ADMIN_ROLE_REQUIRED",
                workspace_id=ws_id,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: Admin role required for this workspace's audit telemetry.",
            )
        filters["workspace_id"] = ws_id
    else:
        if not (is_superadmin or is_global_admin):
            await audit_log.record_access_denial(
                subject_id=user_id,
                action="read",
                resource="audit_logs",
                reason="ADMIN_ROLE_REQUIRED",
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: Global Admin or Superadmin role required to query global audit logs.",
            )

    if event_type:
        filters["event_type"] = event_type
    if severity:
        filters["severity"] = severity.upper()
    if subject_id:
        if not (is_superadmin or is_global_admin) and subject_id != user_id and not workspace_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: Cannot query other users' audit events without global admin privileges.",
            )
        filters["subject_id"] = subject_id

    logs = await audit_log.query_events(filters, limit=min(limit, 200), offset=offset)
    return {
        "status": "SUCCESS",
        "count": len(logs),
        "logs": logs,
        "audit_logs": logs,
    }


@router.get("/workspaces/{workspace_id}/audit-logs", tags=["Workspaces", "Security & Auditing"])
async def get_workspace_audit_logs(
    workspace_id: str,
    limit: int = 50,
    offset: int = 0,
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    include_global: bool = True,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Retrieve security audit telemetry for a specific workspace. Requires Workspace Admin or Superadmin."""
    ws_id = await ws_repo._resolve_ws_id(workspace_id)
    is_admin = await perm_eval.has_role(current_user["user_id"], "admin", scope=ws_id)
    if not is_admin:
        await audit_log.record_access_denial(
            subject_id=current_user["user_id"],
            action="view_audit_logs",
            resource=f"workspaces/{ws_id}/audit-logs",
            reason="ADMIN_ROLE_REQUIRED",
            workspace_id=ws_id,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Workspace Admin or Superadmin role required to view audit logs.",
        )

    filters = {"workspace_id": ws_id}
    if event_type:
        filters["event_type"] = event_type
    if severity:
        filters["severity"] = severity.upper()

    logs = await audit_log.query_events(
        filters,
        limit=min(limit, 200),
        offset=offset,
        include_global=include_global,
    )
    return {
        "status": "SUCCESS",
        "workspace_id": ws_id,
        "count": len(logs),
        "audit_logs": logs,
        "logs": logs,
    }
