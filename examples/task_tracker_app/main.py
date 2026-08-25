"""
Task Tracker App - Reference Consumer Showcase (examples/task_tracker_app/main.py)
---------------------------------------------------------------------------------
Demonstrates how an external consuming Python/FastAPI service imports and consumes
the core 'auth-nz' IAM engine and guards its own domain routes with 1-line dependencies.

Run locally:
    uvicorn examples.task_tracker_app.main:app --port 8080 --reload
"""

from typing import Any, Dict, List, Optional
import uuid
from fastapi import Depends, FastAPI, HTTPException, status
from pydantic import BaseModel, Field

# 1. Import from Auth N&Z Package
from auth_nz import (
    api_router as authnz_router,
    register_exception_handlers,
    require_auth,
    require_role,
    require_permission,
    get_current_workspace,
    CurrentUser,
    CurrentWorkspace,
)

# 2. Initialize Consumer Application
app = FastAPI(
    title="Task Tracker (Secured by Auth N&Z)",
    description="Example enterprise sprint tracker consuming Auth N&Z for authentication and multi-tenant authorization.",
    version="1.0.0",
)

# 3. Register RFC 7807 Error Boundaries
register_exception_handlers(app)

# 4. Mount Auth N&Z Endpoints (/auth/*, /workspaces/*, /audit/*, /notifications/*)
app.include_router(authnz_router)


# =============================================================================
# Consumer Domain Schemas & In-Memory Database
# =============================================================================
class TaskCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = ""
    priority: str = "medium"
    workspace_id: str = "ws_default"


class TaskResponse(BaseModel):
    id: str
    title: str
    description: str
    priority: str
    workspace_id: str
    created_by: str


# In-memory storage for demo app
DB_TASKS: Dict[str, Dict[str, Any]] = {}


# =============================================================================
# Consumer Domain Routes Protected with Auth N&Z Guards
# =============================================================================

@app.get("/app/profile", tags=["User Profile"])
async def get_my_profile(
    user: CurrentUser = Depends(require_auth()),
):
    """
    1. Require Authenticated User:
    Injects the verified user context and claims without manual token parsing.
    """
    return {
        "status": "SUCCESS",
        "user_id": user.id,
        "username": user.username,
        "email": user.email,
        "roles": user.roles,
        "clearance": user.clearance,
        "department": user.department,
    }


@app.post("/app/tasks", response_model=TaskResponse, tags=["Tasks"])
async def create_sprint_task(
    task_in: TaskCreate,
    user: CurrentUser = Depends(require_permission("tasks:create")),
    workspace: CurrentWorkspace = Depends(get_current_workspace()),
):
    """
    2. Require Fine-Grained Permission & Workspace Verification:
    Enforces 'tasks:create' permission and validates membership in the target workspace.
    """
    task_id = str(uuid.uuid4())
    record = {
        "id": task_id,
        "title": task_in.title,
        "description": task_in.description or "",
        "priority": task_in.priority,
        "workspace_id": workspace.id,
        "created_by": user.email,
    }
    DB_TASKS[task_id] = record
    return record


@app.delete("/app/tasks/{task_id}", tags=["Tasks"])
async def delete_sprint_task(
    task_id: str,
    user: CurrentUser = Depends(require_role("admin")),
):
    """
    3. Require Role Hierarchy:
    Guarantees only 'admin' or 'superadmin' users can delete sprint tasks.
    """
    if task_id not in DB_TASKS:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Task not found.")

    deleted = DB_TASKS.pop(task_id)
    return {"status": "SUCCESS", "message": f"Task '{deleted['title']}' deleted by {user.username}."}
