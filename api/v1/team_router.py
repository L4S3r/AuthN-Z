"""
Auth N&Z - Legacy Team Router (api/v1/team_router.py)
-----------------------------------------------------
Endpoints for team member listings, single-workspace member invites,
invitation verification/acceptance, and member de-provisioning.
"""

from typing import Any, Dict, Optional
import json
import logging
import secrets
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from api.dependencies import (
    hasher,
    user_repo,
    task_repo,
    perm_eval,
    audit_log,
    email_svc,
    token_svc,
    sess_store,
    get_current_user,
    set_auth_cookies,
)
from api.schemas import TeamInviteRequest, TeamAcceptInviteRequest

logger = logging.getLogger("auth_nz.team_router")

router = APIRouter(tags=["Team Management"])


@router.get("/team/members")
async def list_team_members(
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """List all workspace members and pending email invitations. Requires active viewer clearance."""
    user_id = current_user["user_id"]
    if not await perm_eval.has_role(user_id, "viewer"):
        await audit_log.record_access_denial(
            subject_id=user_id,
            action="view",
            resource="team_members",
            reason="VIEWER_ROLE_REQUIRED",
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Active viewer or member role required.",
        )

    members = await task_repo.list_team_members()
    return {"status": "SUCCESS", "count": len(members), "members": members}


@router.post("/team/invite")
async def invite_team_member(
    req: TeamInviteRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Invite a new colleague to the team workspace with email notification. Requires 'admin' role."""
    if not await perm_eval.has_role(current_user["user_id"], "admin"):
        await audit_log.record_access_denial(
            subject_id=current_user["user_id"],
            action="invite",
            resource="team_members",
            reason="ADMIN_ROLE_REQUIRED",
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Admin role required to invite team members.",
        )

    admin_user = await user_repo.get_by_id(current_user["user_id"])
    invited_by_name = admin_user["username"] if admin_user else "Admin"

    invitation = await task_repo.invite_member(
        email=req.email,
        name=req.name or req.email.split("@")[0],
        role=req.role or "viewer",
        department=req.department or "General",
        invited_by=invited_by_name,
    )

    email_res = email_svc.send_invitation_email(
        recipient_email=invitation["email"],
        recipient_name=invitation["name"],
        role=invitation["role"],
        department=invitation["department"],
        invited_by=invited_by_name,
        invite_token=invitation["invite_token"],
    )

    await audit_log.record_security_event(
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


@router.get("/team/invite/verify")
async def verify_team_invitation(token: str):
    """Verify an invitation token for a new user landing on the accept-invite page."""
    invite = await task_repo.get_invitation_by_token(token)
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


@router.post("/team/invite/accept")
async def accept_team_invitation(
    req: TeamAcceptInviteRequest,
    request: Request,
    response: Response,
):
    """Accept an invitation, register credentials, activate workspace clearance, and log in."""
    invite = await task_repo.get_invitation_by_token(req.token)
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
        if req.name:
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

    await task_repo.accept_invitation(req.token)

    access_token = token_svc.create_access_token(user_id, claims={"roles": roles})
    refresh_token = token_svc.create_refresh_token(user_id, claims={"roles": roles})
    session_id = sess_store.create_session(user_id, session_data={"roles": roles})

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


@router.delete("/team/members/{member_email}")
async def remove_team_member(
    member_email: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Remove a member, delete their registered user account, and revoke sessions. Requires admin role."""
    caller_id = current_user["user_id"]
    if not await perm_eval.has_role(caller_id, "admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin role required to remove team members.",
        )

    clean_email = member_email.strip().lower()

    user = await user_repo.get_by_identifier(clean_email)
    if user:
        if user["id"] == caller_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot remove your own administrator account.",
            )
        sess_store.delete_all_user_sessions(user["id"])
        await user_repo.delete_user(user["id"])

    await task_repo.remove_member(clean_email)

    await audit_log.record_security_event(
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
