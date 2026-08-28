---
name: auth-nz-core
description: >-
  Comprehensive guide, architectural reference, and integration runbook for the published l4s3r-authnz
  (Authentication & Authorization) engine, multi-tier caching layer, and adapter framework. Use when scaffolding,
  integrating, or extending production-grade authentication, BYOU custom models, multi-tenant RBAC/ABAC authorization,
  MFA/TOTP, WebAuthn passkeys, JWT token families, device trust binding, password hashing, OAuth2/OIDC, L1/L2 profile
  caching, HTTP 304 ETag negotiation, and session management into Python/FastAPI/SQLAlchemy projects.
---

# Auth N&Z Core Engine & Framework Guide (`l4s3r-authnz`)

This skill provides an architectural blueprint and runbook for **Auth N&Z** (`l4s3r-authnz`), a modular, production-grade, NIST-compliant Identity and Access Management (IAM) framework and authorization adapter for Python and FastAPI.

- **PyPI Package**: `l4s3r-authnz` (v1.1.0)
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
                      │   (adapter.py / AuthNZ / configure)    │
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
                      │    Repositories, Cache & Evaluators    │
                      │  UserRepository | UserProfileCache     │
                      │  WorkspaceRepository | PermissionEval   │
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
| `auth_nz.models` (`models.py`) | Core BYOU declarative identity models & Mixin | `Base`, `AuthNZUserMixin`, `PasswordResetToken`, `TrustedDevice` |
| `default_user.py` | Turnkey default User model (when no custom BYOU model is supplied) | `User` (subclasses `Base`, `AuthNZUserMixin`) |
| `workspace_models.py` | Turnkey workspace & task domain models | `Workspace`, `WorkspaceMember`, `Task`, `TeamMember`, `AuditLog`, `Notification` |
| `user_repository.py` | User persistence and multi-tier caching engine | `UserRepository`, `UserProfileCache`, `abstractUserRepository` |
| `auth_nz.routers` (`api/router.py`) | Selective Router Factory & Domain Sub-Routers | `create_authnz_router()`, `api_router`, `auth_router`, `mfa_router`, `webauthn_router`, `workspace_router`, `task_router` |
| `auth_nz.adapter` (`adapter.py`) | Programmatic configuration and object-oriented adapter wrapper | `configure_authnz()`, `AuthNZ`, `AuthNZAdapter` |
| `auth_nz.guards` (`guards.py`) | 1-line declarative FastAPI security dependency guards | `require_auth()`, `require_role()`, `require_permission()`, `get_current_workspace()`, `CurrentUser`, `CurrentWorkspace` |
| `api.dependencies` (`dependencies.py`) | Shared singletons, security schemes, and HTTP 304 ETag helpers | `generate_etag()`, `handle_conditional_response()`, `get_current_user` |
| `auth_nz.database` (`database.py`) | Async SQLAlchemy engine and session lifecycle | `get_engine()`, `get_session_factory()`, `get_db_session()` |
| `auth_nz.exceptions` (`exceptions.py`) | RFC 7807 problem details error boundaries | `register_exception_handlers()`, `AuthNZException`, `InvalidCredentialsException` |
| `cli.py` (`authnz`) | Scriptable administration CLI control plane | `authnz users`, `authnz workspaces`, `authnz policies`, `authnz audit`, `authnz health` |
| `db_manager.py` | PostgreSQL database inspection, querying, and maintenance | `stats`, `audit`, `workspaces`, `members`, `users`, `tasks`, `purge-audit` |
| `seed_admin.py` | Out-of-band root administrator provisioning | `seed_admin.py --username admin --email admin@example.com --password ...` |

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
from fastapi import FastAPI, Depends
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from auth_nz.models import Base, AuthNZUserMixin
from auth_nz.adapter import AuthNZ
from auth_nz.guards import CurrentUser, require_auth

# 1. Define host app's User table inheriting AuthNZUserMixin on shared Base
class User(Base, AuthNZUserMixin):
    __tablename__ = "users"
    company_name: Mapped[str]
    stripe_customer_id: Mapped[str | None] = mapped_column(nullable=True)

# 2. Create Async Database Session Factory
engine = create_async_engine("postgresql+asyncpg://user:pass@localhost:5432/my_app")
session_factory = async_sessionmaker(engine)

# 3. Initialize AuthNZ Adapter with your custom model & session factory
authnz = AuthNZ(
    user_model=User,
    session_factory=session_factory,
    jwt_secret_key="my_super_secret_high_entropy_jwt_signing_key",
)

# 4. Selectively mount desired endpoints
app = FastAPI(title="SaaS Core")

app.include_router(
    authnz.create_router(
        enable_auth=True,        # /auth/login, /auth/register, /auth/me, /auth/refresh
        enable_mfa=True,         # /auth/mfa/setup, /auth/mfa/verify
        enable_webauthn=True,    # /auth/webauthn (FIDO2 Passkeys)
        enable_device_trust=True,# /auth/trusted-devices
        enable_workspaces=False, # Disable multi-tenancy
        enable_tasks=False,      # Disable turnkey task tracker
    ),
    prefix="/api/v1",
)

# 5. Protect endpoints
@app.get("/api/v1/profile")
async def get_profile(user: CurrentUser = Depends(require_auth())):
    return {"id": user.id, "email": user.email, "company": user.metadata.get("company_name")}
```

---

### Recipe 3: Multi-Tier Profile Caching & HTTP 304 Fast-Path

Auth N&Z automatically caches identity metadata in L1 memory (<1ms) and L2 Redis (60s TTL), with conditional HTTP ETag evaluation:

```python
from fastapi import APIRouter, Request, Response, Depends
from api.dependencies import get_current_user, handle_conditional_response, user_repo

router = APIRouter()

@router.get("/user/settings")
async def get_settings(
    request: Request,
    response: Response,
    current_user: dict = Depends(get_current_user),
):
    user = await user_repo.get_by_id(current_user["user_id"])
    payload = {"status": "SUCCESS", "settings": user.get("metadata", {})}
    # Emits ETag & Cache-Control, returns 304 Not Modified if client cache is fresh
    return handle_conditional_response(request, response, payload)
```

---

### Recipe 4: Client-Side TanStack Query & Reactive WebSocket Push

Frontend client applications should use conservative caching and WebSocket event listeners to eliminate polling:

```typescript
import { QueryClient } from '@tanstack/react-query';

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 5 * 60 * 1000,    // 5 minutes
      gcTime: 10 * 60 * 1000,       // 10 minutes
      refetchOnWindowFocus: false,  // Prevents tab-switch request storms
      refetchOnMount: false,
      refetchOnReconnect: true,
    },
  },
});

// Event-driven mutation invalidations
export const onPasskeyMutated = () => {
  queryClient.invalidateQueries({ queryKey: ['webauthn', 'credentials'] });
};

export const onProfileMutated = () => {
  queryClient.invalidateQueries({ queryKey: ['auth', 'me'] });
};
```

---

### Recipe 5: CLI Administration (`authnz`)

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
*62 passed unit and integration tests across cryptography, guards, router factory, policies, OPA, observability, L1/L2 query caching, ETags, and BYOU isolation.*
