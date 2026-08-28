"""
Auth N&Z - Task Management Router (api/v1/task_router.py)
---------------------------------------------------------
Endpoints for task sprint board creation, query filtering, state transition updates,
and deletion with multi-assignee email notifications and real-time WebSocket broadcast.
"""

from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
import logging
import uuid
from fastapi import APIRouter, Depends, HTTPException, Query, status

from api.dependencies import (
    user_repo,
    ws_repo,
    task_repo,
    perm_eval,
    audit_log,
    email_svc,
    get_current_user,
)
from api.schemas import TaskCreateRequest, TaskUpdateRequest
from api.v1.websocket_router import ws_manager, create_and_push_notification

logger = logging.getLogger("auth_nz.task_router")

router = APIRouter(tags=["Task Tracker"])


@router.get("/tasks")
async def get_tasks(
    workspace_id: Optional[str] = None,
    status: Optional[str] = None,
    priority: Optional[str] = None,
    assignee_email: Optional[str] = None,
    limit: Optional[int] = Query(None, ge=1, le=200, description="Max records to return per page"),
    offset: int = Query(0, ge=0, description="Offset index for pagination"),
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Retrieve workspace sprint tasks with strict tenant workspace membership verification and DB pagination."""
    user_id = current_user["user_id"]
    is_superadmin = await perm_eval.has_role(user_id, "superadmin")

    if workspace_id:
        ws_id = await ws_repo._resolve_ws_id(workspace_id) or workspace_id
        is_authorized = await perm_eval.has_role(user_id, "viewer", scope=ws_id)
        if not is_authorized:
            await audit_log.record_access_denial(
                subject_id=user_id,
                action="view_tasks",
                resource=f"workspaces/{ws_id}/tasks",
                reason="WORKSPACE_MEMBERSHIP_REQUIRED",
                workspace_id=ws_id,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: You are not an active member of this workspace.",
            )
        repo_res = await task_repo.list_tasks(
            workspace_id=ws_id,
            status=status,
            priority=priority,
            assignee_email=assignee_email,
            limit=limit,
            offset=offset,
        )
        tasks = repo_res["tasks"]
        total_count = repo_res["total"]
    else:
        if is_superadmin:
            repo_res = await task_repo.list_tasks(
                workspace_id=None,
                status=status,
                priority=priority,
                assignee_email=assignee_email,
                limit=limit,
                offset=offset,
            )
            tasks = repo_res["tasks"]
            total_count = repo_res["total"]
        else:
            user = await user_repo.get_by_id(user_id)
            user_workspaces = await ws_repo.list_workspaces_for_user(
                user_id=user_id,
                email=user.get("email") if user else None,
            )
            allowed_ws_ids = {
                str(w["id"]) for w in user_workspaces
                if w.get("member_status") == "active" or w.get("role") or w.get("member_role")
            }
            if not allowed_ws_ids:
                return {
                    "status": "SUCCESS",
                    "count": 0,
                    "total": 0,
                    "limit": limit if limit is not None else 0,
                    "offset": offset,
                    "tasks": [],
                }

            ws_uuids = [uuid.UUID(wid) for wid in sorted(allowed_ws_ids)]
            repo_res = await task_repo.list_tasks(
                workspace_ids=ws_uuids,
                status=status,
                priority=priority,
                assignee_email=assignee_email,
                limit=limit,
                offset=offset,
            )
            tasks = repo_res["tasks"]
            total_count = repo_res["total"]

    return {
        "status": "SUCCESS",
        "count": len(tasks),
        "total": total_count,
        "limit": limit if limit is not None else total_count,
        "offset": offset,
        "tasks": tasks,
    }


@router.get("/tasks/{task_id}")
async def get_single_task(
    task_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Retrieve a single task by ID. Strictly verifies active membership in the task's workspace."""
    task = await task_repo.get_task(task_id)
    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Task not found.",
        )

    ws_id = task.get("workspace_id") or "ws_default"
    user_id = current_user["user_id"]

    is_authorized = await perm_eval.has_role(user_id, "viewer", scope=ws_id)
    if not is_authorized:
        await audit_log.record_access_denial(
            subject_id=user_id,
            action="view_task",
            resource=f"tasks/{task_id}",
            reason="WORKSPACE_MEMBERSHIP_REQUIRED",
            workspace_id=ws_id,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: You are not an active member of this workspace.",
        )

    return {"status": "SUCCESS", "task": task}


@router.post("/tasks")
async def create_task(
    req: TaskCreateRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Create and assign a new team task card, dispatching email notification to all assignees. Requires Editor, Admin, or Superadmin role."""
    ws_id = req.workspace_id or "ws_default"

    if not await perm_eval.has_role(current_user["user_id"], "editor", scope=ws_id):
        await audit_log.record_access_denial(
            subject_id=current_user["user_id"],
            action="create",
            resource=f"workspaces/{ws_id}/tasks",
            reason="EDITOR_OR_ADMIN_ROLE_REQUIRED",
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Editor, Admin, or Superadmin role required to create tasks.",
        )

    user = await user_repo.get_by_id(current_user["user_id"])
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

    new_task = await task_repo.create_task({
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
            assigned_user = await user_repo.get_by_identifier(target_email)
            if assigned_user:
                await create_and_push_notification(
                    user_id=assigned_user["id"],
                    notif_type="TASK_ASSIGNED",
                    title="Task Assigned",
                    message=f"You were assigned to '{new_task['title']}' by {assigned_by_name}.",
                    link=f"/?task={new_task['id']}&workspace={ws_id}",
                    workspace_id=ws_id,
                    task_id=new_task["id"],
                )

    await ws_manager.broadcast_to_workspace(
        ws_id,
        {
            "event": "task.created",
            "workspace_id": ws_id,
            "task": new_task,
            "actor": {
                "id": user["id"] if user else current_user["user_id"],
                "username": user["username"] if user else "Member",
                "email": creator_email,
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    )

    return {"status": "SUCCESS", "task": new_task}


@router.patch("/tasks/{task_id}")
async def update_task(
    task_id: str,
    req: TaskUpdateRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Update task card status (Kanban movement), priority, deadline, or assignees. Requires Editor, Admin, or Superadmin role."""
    existing = await task_repo.get_task(task_id)
    if not existing:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Task not found.",
        )

    ws_id = existing.get("workspace_id") or "ws_default"

    if not await perm_eval.has_role(current_user["user_id"], "editor", scope=ws_id):
        await audit_log.record_access_denial(
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
    updated = await task_repo.update_task(task_id, updates)

    user = await user_repo.get_by_id(current_user["user_id"])
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
            assigned_user = await user_repo.get_by_identifier(target_email)
            if assigned_user:
                await create_and_push_notification(
                    user_id=assigned_user["id"],
                    notif_type="TASK_ASSIGNED",
                    title="Task Assigned",
                    message=f"You were assigned to '{updated.get('title', existing['title'])}' by {assigned_by_name}.",
                    link=f"/?task={task_id}&workspace={ws_id}",
                    workspace_id=ws_id,
                    task_id=task_id,
                )

    await ws_manager.broadcast_to_workspace(
        ws_id,
        {
            "event": "task.updated",
            "workspace_id": ws_id,
            "task": updated,
            "actor": {
                "id": user["id"] if user else current_user["user_id"],
                "username": user["username"] if user else "Member",
                "email": user["email"] if user else "",
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    )

    return {"status": "SUCCESS", "task": updated}


@router.delete("/tasks/{task_id}")
async def delete_task(
    task_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Delete a task card from the workspace. Requires task creator (with editor role), workspace admin, or superadmin role."""
    existing_task = await task_repo.get_task(task_id)
    if not existing_task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Task not found.",
        )

    user = await user_repo.get_by_id(current_user["user_id"])
    caller_email = user["email"].strip().lower() if user and user.get("email") else ""
    task_creator = (existing_task.get("created_by") or "").strip().lower()
    ws_id = existing_task.get("workspace_id") or "ws_default"

    is_creator = bool(caller_email and caller_email == task_creator)
    is_editor = await perm_eval.has_role(current_user["user_id"], "editor", scope=ws_id)
    is_admin = await perm_eval.has_role(current_user["user_id"], "admin", scope=ws_id)
    is_superadmin = await perm_eval.has_role(current_user["user_id"], "superadmin")

    if not (is_superadmin or is_admin or (is_creator and is_editor)):
        await audit_log.record_access_denial(
            subject_id=current_user["user_id"],
            action="delete",
            resource=f"tasks/{task_id}",
            reason="CREATOR_EDITOR_OR_ADMIN_ROLE_REQUIRED",
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Workspace admin, superadmin, or task creator (with editor role) required to delete this task.",
        )

    deleted = await task_repo.delete_task(task_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Task not found.",
        )

    await ws_manager.broadcast_to_workspace(
        ws_id,
        {
            "event": "task.deleted",
            "workspace_id": ws_id,
            "task_id": task_id,
            "actor": {
                "id": user["id"] if user else current_user["user_id"],
                "username": user["username"] if user else "Member",
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    )

    return {"status": "SUCCESS", "deleted_task_id": task_id}
