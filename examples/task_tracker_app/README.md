# Task Tracker App (Example Auth N&Z Consumer Showcase)

This standalone example demonstrates how an external Python/FastAPI microservice or web backend integrates the **Auth N&Z** core package to protect its own endpoints with clean, 1-line declarative dependency guards.

---

## 🚀 Quickstart

### 1. Install Auth N&Z
```bash
pip install -e ../..
```

### 2. Run Example Service
```bash
uvicorn examples.task_tracker_app.main:app --port 8080 --reload
```

---

## 🛡️ Integration Patterns

### 1. Require Authenticated User
```python
from fastapi import Depends
from auth_nz import require_auth, CurrentUser

@app.get("/app/profile")
async def get_profile(user: CurrentUser = Depends(require_auth())):
    return {"user_id": user.id, "email": user.email}
```

### 2. Require Fine-Grained Scoped Permission
```python
from auth_nz import require_permission, CurrentUser

@app.post("/app/tasks")
async def create_task(user: CurrentUser = Depends(require_permission("tasks:create"))):
    ...
```

### 3. Require Role Hierarchy
```python
from auth_nz import require_role, CurrentUser

@app.delete("/app/tasks/{task_id}")
async def delete_task(user: CurrentUser = Depends(require_role("admin"))):
    ...
```
