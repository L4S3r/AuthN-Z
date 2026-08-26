---
name: auth-nz-core
description: >-
  Comprehensive guide, architectural reference, and integration runbook for the published l4s3r-authnz
  (Authentication & Authorization) engine and adapter framework. Use when scaffolding, integrating, or extending
  production-grade authentication, BYOU custom models, multi-tenant RBAC/ABAC authorization, MFA/TOTP, WebAuthn passkeys,
  JWT token families, device trust binding, password hashing, OAuth2/OIDC, and session management into Python/FastAPI/SQLAlchemy projects.
---

# Auth N&Z Core Engine & Framework Guide (`l4s3r-authnz`)

This skill provides an architectural blueprint and runbook for **Auth N&Z** (`l4s3r-authnz`), a modular, production-grade, NIST-compliant Identity and Access Management (IAM) framework and authorization adapter for Python and FastAPI.

- **PyPI Package**: `l4s3r-authnz`
- **Installation**: `pip install l4s3r-authnz`
- **Repository**: [https://github.com/L4S3r/AuthN-Z](https://github.com/L4S3r/AuthN-Z)
- **Primary CLI**: `authnz`

---

## 1. Architectural Overview & Component Map

The core framework is built with **Python 3.10+**, **FastAPI**, **SQLAlchemy 2.0 (`asyncpg`)**, and **Redis** (with in-memory fallback).

```
                      ┌────────────────────────────────────────┐
                      │            Host Application            │
                      │  - Custom User Model (BYOU Mixin)      │
                      │  - Custom FastAPI App / Routers        │
                      └──────────────────┬─────────────────────┘
                                         │
                                         ▼
                      ┌────────────────────────────────────────┐
                      │         Auth N&Z Adapter Layer         │
                      │     (adapter.py / configure_authnz)    │
                      └──────────────────┬─────────────────────┘
                                         │
       ┌──────────────────┬──────────────┼───────────────┬──────────────────┐
       ▼                  ▼              ▼               ▼                  ▼
┌──────────────┐   ┌──────────────┐┌──────────────┐┌──────────────┐  ┌──────────────┐
│PasswordHasher│   │ TokenService ││ MFAProvider  ││ DeviceTrust  │  │ SessionStore │
│(Argon2/Bcrypt│   │ (JWT Family) ││  (RFC 6238)  ││ (UA Binding) │  │(Redis/Memory)│
└──────────────┘   └──────────────┘└──────────────┘└──────────────┘  └──────────────┘
       │                  │              │               │                  │
       └──────────────────┴──────────────┼───────────────┴──────────────────┘
                                         ▼
                      ┌────────────────────────────────────────┐
                      │    Repositories & Policy Evaluator     │
                      │  UserRepository | WorkspaceRepository  │
                      │         PermissionEvaluator            │
                      └──────────────────┬─────────────────────┘
                                         ▼
                      ┌────────────────────────────────────────┐
                      │       PostgreSQL Async / Models        │
                      │   (models.py, database.py, alembic)    │
                      └────────────────────────────────────────┘
```

### Core Module Map

| Submodule / File | Responsibility | Key Exports / API |
| :--- | :--- | :--- |
| `auth_nz.models` (`models.py`) | Relational SQLAlchemy ORM models & Mixins | `AuthNZUserMixin`, `Base`, `User`, `Workspace`, `WorkspaceMember`, `Task`, `AuditLog`, `TrustedDevice`, `Notification` |
| `auth_nz.routers` (`api/router.py`) | Selective Router Factory & Domain Sub-Routers | `create_authnz_router()`, `api_router`, `auth_router`, `mfa_router`, `webauthn_router`, `workspace_router`, `task_router` |
| `auth_nz.adapter` (`adapter.py`) | Programmatic configuration and adapter wrapper | `configure_authnz()`, `AuthNZ`, `AuthNZAdapter` |
| `auth_nz.guards` (`guards.py`) | 1-line declarative FastAPI security dependency guards | `require_auth()`, `require_role()`, `require_permission()`, `get_current_workspace()`, `CurrentUser`, `CurrentWorkspace` |
| `auth_nz.database` (`database.py`) | Async SQLAlchemy engine and session lifecycle | `get_engine()`, `get_session_factory()`, `get_db_session()` |
| `auth_nz.exceptions` (`exceptions.py`) | RFC 7807 problem details error boundaries | `register_exception_handlers()`, `AuthNZException`, `InvalidCredentialsException` |
| `cli.py` (`authnz`) | Scriptable administration CLI control plane | `authnz users`, `authnz workspaces`, `authnz policies`, `authnz audit`, `authnz health` |

---

## 2. Integration Recipes

### Recipe 1: Fast Package Install & 1-Line Route Guards (Resource Server Mode)

When securing downstream microservices with zero database overhead:

```python
from fastapi import FastAPI, Depends
from auth_nz import (
    require_auth,
    require_role,
    require_permission,
    CurrentUser,
    register_exception_handlers,
)

app = FastAPI(title="Resource Microservice")
register_exception_handlers(app)

@app.get("/api/me")
async def get_my_profile(user: CurrentUser = Depends(require_auth())):
    return {"id": user.id, "email": user.email, "roles": user.roles}

@app.post("/api/billing/charge")
async def process_billing(user: CurrentUser = Depends(require_permission("billing:charge"))):
    return {"status": "success", "charged_by": user.email}

@app.delete("/api/admin/purge")
async def admin_purge(user: CurrentUser = Depends(require_role("admin"))):
    return {"status": "purged"}
```

---

### Recipe 2: Bring-Your-Own-User (BYOU) Model & Selective Routers

When embedding authentication directly into a host application with custom database tables:

```python
from fastapi import FastAPI
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from auth_nz.models import AuthNZUserMixin
from auth_nz.routers import create_authnz_router
from auth_nz.adapter import configure_authnz

# 1. Define host app's User table inheriting AuthNZUserMixin
class Base(DeclarativeBase):
    pass

class User(Base, AuthNZUserMixin):
    __tablename__ = "users"
    company_name: Mapped[str]
    stripe_customer_id: Mapped[str | None] = mapped_column(nullable=True)

# 2. Configure Auth N&Z with the host model & settings
configure_authnz(
    user_model=User,
    jwt_secret_key="my_super_secret_high_entropy_jwt_signing_key",
)

# 3. Selectively mount desired endpoints
app = FastAPI(title="SaaS Core")

app.include_router(
    create_authnz_router(
        enable_auth=True,        # /auth/login, /auth/register, /auth/me, /auth/refresh
        enable_mfa=True,         # /auth/mfa/setup, /auth/mfa/verify
        enable_webauthn=True,    # /auth/webauthn (FIDO2 Passkeys)
        enable_workspaces=False, # Disable multi-tenancy
        enable_tasks=False,      # Disable demo task tracker
    ),
    prefix="/api/v1",
)
```

---

### Recipe 3: Running as a Turnkey Standalone IAM Microservice

When deploying Auth N&Z as a dedicated centralized auth server (e.g. on a mini-server or cloud container):

```bash
# 1. Start via bare-metal Python (consumes ~50 MB RAM, recommended for mini-servers)
uvicorn server:app --host 0.0.0.0 --port 8000 --reload

# 2. Or start complete local container stack (API + PostgreSQL + Redis + OPA)
docker compose up -d
```

Swagger API documentation is immediately available at `http://localhost:8000/docs`.

---

### Recipe 4: CLI Administration (`authnz`)

```bash
# Manage Users
authnz users list
authnz users create --username alice --email alice@example.com --password SecretPassword123! --role admin
authnz users reset-password --email alice@example.com --password NewSecretPassword123!

# Manage Multi-Tenant Workspaces
authnz workspaces list
authnz workspaces create --name "Acme Corp" --slug "acme"

# Inspect & Reload Policies
authnz policies inspect
authnz policies reload
authnz policies simulate --email alice@example.com --action read --resource-type documents

# Tail Security Audit Logs
authnz audit tail --limit 25 --severity CRITICAL

# Diagnostics
authnz health check
authnz metrics dump
```

---

## 3. Testing Strategy

Run the automated offline test suite:
```bash
pytest
```
*43 passed unit and integration tests across cryptography, guards, router factory, policies, OPA, and telemetry.*
