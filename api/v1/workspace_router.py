"""
Auth N&Z - Multi-Tenant Workspace Router (api/v1/workspace_router.py)
---------------------------------------------------------------------
Provides endpoints for workspace provisioning, directory listings, metadata management,
member invitations, clearance role assignment, invitation onboarding, and tenant switching.
"""

from typing import Any, Dict, List, Optional
import json
import logging
import secrets
from urllib.parse import unquote
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from api.dependencies import (
    hasher,
    user_repo,
    ws_repo,
    perm_eval,
    audit_log,
    email_svc,
    token_svc,
    sess_store,
    get_current_user,
    set_auth_cookies,
)
from api.schemas import (
    WorkspaceCreateRequest,
    WorkspaceUpdateRequest,
    WorkspaceInviteRequest,
    WorkspaceRoleUpdateRequest,
    WorkspaceAcceptInviteRequest,
    WorkspaceSwitchRequest,
)

logger = logging.getLogger("auth_nz.workspace_router")

router = APIRouter(tags=["Workspaces"])


@router.post("/workspaces", status_code=status.HTTP_201_CREATED)
async def create_workspace(
    req: WorkspaceCreateRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Create a new team workspace. The creator is automatically assigned as the Workspace Admin."""
    user = await user_repo.get_by_id(current_user["user_id"])
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    try:
        new_ws = await ws_repo.create_workspace(
            name=req.name,
            created_by=current_user["user_id"],
            slug=req.slug,
            description=req.description,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    await audit_log.record_security_event(
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


@router.get("/workspaces")
async def list_user_workspaces(
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """List all workspaces the authenticated user belongs to (or all workspaces if Superadmin)."""
    user = await user_repo.get_by_id(current_user["user_id"])
    user_email = user["email"] if user else None

    is_superadmin = await perm_eval.has_role(current_user["user_id"], "superadmin")
    if is_superadmin:
        workspaces = await ws_repo.list_all_workspaces()
        for w in workspaces:
            if not w.get("member_role"):
                w["member_role"] = "superadmin"
                w["role"] = "superadmin"
                w["member_status"] = "active"
    else:
        workspaces = await ws_repo.list_workspaces_for_user(
            user_id=current_user["user_id"],
            email=user_email,
        )

    return {"status": "SUCCESS", "count": len(workspaces), "workspaces": workspaces}


@router.get("/workspaces/{workspace_id}")
async def get_workspace_details(
    workspace_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Retrieve workspace profile, metadata, and member metrics."""
    ws_id = await ws_repo._resolve_ws_id(workspace_id) or workspace_id
    is_authorized = await perm_eval.has_role(current_user["user_id"], "viewer", scope=ws_id)
    if not is_authorized:
        await audit_log.record_access_denial(
            subject_id=current_user["user_id"],
            action="view",
            resource=f"workspaces/{ws_id}",
            reason="WORKSPACE_MEMBERSHIP_REQUIRED",
            workspace_id=ws_id,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: You are not a member of this workspace.",
        )

    ws = await ws_repo.get_workspace(ws_id)
    if not ws:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Workspace not found.")

    metrics = await ws_repo.count_members(ws_id)
    return {"status": "SUCCESS", "workspace": ws, "metrics": metrics}


@router.patch("/workspaces/{workspace_id}")
async def update_workspace(
    workspace_id: str,
    req: WorkspaceUpdateRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Update workspace name, slug, or description. Requires Workspace Admin or Superadmin role."""
    ws_id = await ws_repo._resolve_ws_id(workspace_id) or workspace_id
    is_admin = await perm_eval.has_role(current_user["user_id"], "admin", scope=ws_id)
    if not is_admin:
        await audit_log.record_access_denial(
            subject_id=current_user["user_id"],
            action="update",
            resource=f"workspaces/{ws_id}",
            reason="ADMIN_ROLE_REQUIRED",
            workspace_id=ws_id,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Workspace Admin or Superadmin role required.",
        )

    updates = {k: v for k, v in req.model_dump().items() if v is not None}
    try:
        updated = await ws_repo.update_workspace(ws_id, updates)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    if not updated:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Workspace not found.")

    await audit_log.record_security_event(
        event_name="WORKSPACE_UPDATED",
        severity="INFO",
        details={"workspace_id": ws_id, "updates": updates, "updated_by": current_user["user_id"]},
        workspace_id=ws_id,
    )
    return {"status": "SUCCESS", "workspace": updated}


@router.delete("/workspaces/{workspace_id}")
async def delete_workspace(
    workspace_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Delete a workspace and cascade delete all its tasks and member associations. Requires Workspace Admin or Superadmin."""
    ws_id = await ws_repo._resolve_ws_id(workspace_id) or workspace_id
    is_admin = await perm_eval.has_role(current_user["user_id"], "admin", scope=ws_id)
    if not is_admin:
        await audit_log.record_access_denial(
            subject_id=current_user["user_id"],
            action="delete",
            resource=f"workspaces/{ws_id}",
            reason="ADMIN_ROLE_REQUIRED",
            workspace_id=ws_id,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Workspace Admin or Superadmin role required.",
        )

    try:
        deleted = await ws_repo.delete_workspace(ws_id)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Workspace not found.")

    await audit_log.record_security_event(
        event_name="WORKSPACE_DELETED",
        severity="WARNING",
        details={"workspace_id": ws_id, "deleted_by": current_user["user_id"]},
        workspace_id=ws_id,
    )
    return {"status": "SUCCESS", "deleted_workspace_id": ws_id}


@router.get("/workspaces/{workspace_id}/members")
async def list_workspace_members(
    workspace_id: str,
    status_filter: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """List all members and pending invitations for a specific workspace."""
    ws_id = await ws_repo._resolve_ws_id(workspace_id) or workspace_id
    is_authorized = await perm_eval.has_role(current_user["user_id"], "viewer", scope=ws_id)
    if not is_authorized:
        await audit_log.record_access_denial(
            subject_id=current_user["user_id"],
            action="list_members",
            resource=f"workspaces/{ws_id}/members",
            reason="WORKSPACE_MEMBERSHIP_REQUIRED",
            workspace_id=ws_id,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: You are not a member of this workspace.",
        )

    members = await ws_repo.list_members(workspace_id=ws_id, status=status_filter)
    return {"status": "SUCCESS", "count": len(members), "members": members}


@router.post("/workspaces/{workspace_id}/invite")
async def invite_workspace_member(
    workspace_id: str,
    req: WorkspaceInviteRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Invite a new colleague to a specific workspace with a defined role. Requires Workspace Admin or Superadmin."""
    ws_id = await ws_repo._resolve_ws_id(workspace_id) or workspace_id
    is_admin = await perm_eval.has_role(current_user["user_id"], "admin", scope=ws_id)
    if not is_admin:
        await audit_log.record_access_denial(
            subject_id=current_user["user_id"],
            action="invite",
            resource=f"workspaces/{ws_id}/members",
            reason="ADMIN_ROLE_REQUIRED",
            workspace_id=ws_id,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Admin role required to invite workspace members.",
        )

    admin_user = await user_repo.get_by_id(current_user["user_id"])
    invited_by_name = admin_user["username"] if admin_user else "Workspace Admin"

    try:
        invitation = await ws_repo.invite_member(
            workspace_id=ws_id,
            email=req.email,
            name=req.name,
            role=req.role or "viewer",
            department=req.department or "General",
            invited_by=invited_by_name,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    email_res = email_svc.send_invitation_email(
        recipient_email=invitation["email"],
        recipient_name=invitation["name"],
        role=invitation["role"],
        department=invitation["department"],
        invited_by=invited_by_name,
        invite_token=invitation["invite_token"],
        workspace_name=invitation.get("workspace_name", "TaskTracker Workspace"),
    )

    await audit_log.record_security_event(
        event_name="WORKSPACE_MEMBER_INVITED",
        severity="INFO",
        details={
            "workspace_id": ws_id,
            "invited_email": req.email,
            "role": req.role,
            "department": req.department,
            "invited_by": invited_by_name,
            "invite_token": invitation["invite_token"],
            "email_dispatched": email_res.get("delivered", False),
        },
        workspace_id=ws_id,
    )

    return {
        "status": "SUCCESS",
        "message": f"Invitation notification dispatched to {req.email} for {invitation.get('workspace_name')}.",
        "invite_url": email_res.get("invite_url"),
        "member": invitation,
        "invitation": invitation,
    }


@router.patch("/workspaces/{workspace_id}/members/{user_id_or_email:path}/role")
async def update_workspace_member_role(
    workspace_id: str,
    user_id_or_email: str,
    req: WorkspaceRoleUpdateRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Change a colleague's clearance role within a specific workspace. Requires Workspace Admin or Superadmin."""
    ws_id = await ws_repo._resolve_ws_id(workspace_id) or workspace_id
    is_admin = await perm_eval.has_role(current_user["user_id"], "admin", scope=ws_id)
    if not is_admin:
        await audit_log.record_access_denial(
            subject_id=current_user["user_id"],
            action="update_member_role",
            resource=f"workspaces/{ws_id}/members/{user_id_or_email}/role",
            reason="ADMIN_ROLE_REQUIRED",
            workspace_id=ws_id,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Admin role required to update member roles.",
        )

    updated = await ws_repo.update_member_role(ws_id, user_id_or_email, req.role)
    if not updated:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Member not found in this workspace.")

    await audit_log.record_security_event(
        event_name="WORKSPACE_MEMBER_ROLE_UPDATED",
        severity="INFO",
        details={
            "workspace_id": ws_id,
            "member": user_id_or_email,
            "new_role": req.role,
            "updated_by": current_user["user_id"],
        },
        workspace_id=ws_id,
    )
    return {"status": "SUCCESS", "message": f"Role updated to '{req.role}' for {user_id_or_email}."}


@router.delete("/workspaces/{workspace_id}/members/{user_id_or_email:path}")
async def remove_workspace_member(
    workspace_id: str,
    user_id_or_email: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Remove a colleague from a specific workspace or cancel their invitation. Requires Workspace Admin or Superadmin."""
    ws_id = await ws_repo._resolve_ws_id(workspace_id) or workspace_id
    is_admin = await perm_eval.has_role(current_user["user_id"], "admin", scope=ws_id)
    if not is_admin:
        await audit_log.record_access_denial(
            subject_id=current_user["user_id"],
            action="remove_member",
            resource=f"workspaces/{ws_id}/members/{user_id_or_email}",
            reason="ADMIN_ROLE_REQUIRED",
            workspace_id=ws_id,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Admin role required to remove members.",
        )

    curr_user = await user_repo.get_by_id(current_user["user_id"])
    curr_email = curr_user["email"].lower() if curr_user else ""
    clean_target = unquote(user_id_or_email).strip().lower()

    if clean_target in (current_user["user_id"].lower(), curr_email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot remove your own administrator membership from the workspace.",
        )

    removed = await ws_repo.remove_member(ws_id, user_id_or_email)
    if not removed:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Member not found in this workspace.")

    await audit_log.record_security_event(
        event_name="WORKSPACE_MEMBER_REMOVED",
        severity="WARNING",
        details={
            "workspace_id": ws_id,
            "removed_member": user_id_or_email,
            "removed_by": current_user["user_id"],
        },
        workspace_id=ws_id,
    )
    return {"status": "SUCCESS", "message": f"Member {user_id_or_email} removed from workspace."}


@router.get("/workspaces/invite/verify")
async def verify_workspace_invitation(token: str):
    """Verify an invitation token when a user lands on the accept-invite onboarding page."""
    invite = await ws_repo.get_invitation_by_token(token)
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


@router.post("/workspaces/invite/accept")
async def accept_workspace_invitation(
    req: WorkspaceAcceptInviteRequest,
    request: Request,
    response: Response,
):
    """Accept a workspace invitation, register credentials, activate workspace membership, and log in."""
    invite = await ws_repo.get_invitation_by_token(req.token)
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

    existing_user = await user_repo.get_by_identifier(email)
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
        existing_name = metadata.get("name")
        if not existing_name and req.name and req.name.strip():
            metadata["name"] = req.name.strip()

        await user_repo.update_user(user_id, {
            "hashed_password": hashed_pw,
            "roles": roles,
            "metadata": metadata,
            "is_active": 1,
        })
        user = await user_repo.get_by_id(user_id)
    else:
        base_username = email.split("@")[0].lower()
        clean_username = "".join(c for c in base_username if c.isalnum() or c in ("_", "-"))
        if len(clean_username) < 3 or await user_repo.get_by_identifier(clean_username):
            clean_username = f"{clean_username}_{secrets.token_hex(3)}"

        user = await user_repo.create_user({
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

    user_meta = user.get("metadata", {})
    if isinstance(user_meta, str):
        try:
            user_meta = json.loads(user_meta)
        except Exception:
            user_meta = {}

    sync_name = req.name.strip() if req.name else (user_meta.get("name") or invite.get("name") or user.get("username"))

    accepted = await ws_repo.accept_invitation(req.token, user_id=user_id, name=sync_name)
    if not accepted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invitation token not found or already consumed.",
        )

    access_token = token_svc.create_access_token(user_id, claims={"roles": roles, "workspace_id": workspace_id})
    refresh_token = token_svc.create_refresh_token(user_id, claims={"roles": roles, "workspace_id": workspace_id})
    session_id = sess_store.create_session(user_id, session_data={"roles": roles, "workspace_id": workspace_id})

    set_auth_cookies(response, request, access_token, refresh_token)

    safe_meta = user.get("metadata", {})
    if isinstance(safe_meta, str):
        try:
            safe_meta = json.loads(safe_meta)
        except Exception:
            safe_meta = {}
    safe_meta.pop("mfa_secret", None)
    safe_meta.pop("backup_codes", None)

    await audit_log.record_security_event(
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


@router.post("/auth/workspaces/switch")
async def switch_active_workspace(
    req: WorkspaceSwitchRequest,
    request: Request,
    response: Response,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Switch the authenticated user's active tenant workspace context, returning refreshed scoped JWT tokens."""
    target_ws_id = req.workspace_id.strip()
    resolved_id = await ws_repo._resolve_ws_id(target_ws_id) or target_ws_id
    user_id = current_user["user_id"]
    user = await user_repo.get_by_id(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    is_superadmin = await perm_eval.has_role(user_id, "superadmin")
    ws = await ws_repo.get_workspace(resolved_id)
    if not ws:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target workspace not found.")

    member = await ws_repo.get_member(resolved_id, user_id=user_id, email=user.get("email"))
    if (not member or member.get("status") != "active") and not is_superadmin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: You are not an active member of this workspace.",
        )

    workspace_role = member["role"] if member else ("superadmin" if is_superadmin else "viewer")
    roles = [workspace_role]
    if is_superadmin and "superadmin" not in roles:
        roles.append("superadmin")

    access_token = token_svc.create_access_token(user_id, claims={"roles": roles, "workspace_id": resolved_id})
    refresh_token = token_svc.create_refresh_token(user_id, claims={"roles": roles, "workspace_id": resolved_id})
    session_id = sess_store.create_session(user_id, session_data={"roles": roles, "workspace_id": resolved_id})

    set_auth_cookies(response, request, access_token, refresh_token)

    await audit_log.record_security_event(
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
