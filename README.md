# Auth N&Z - Enterprise Identity, Authentication & Authorization Engine

[![PyPI Version](https://img.shields.io/pypi/v/l4s3r-authnz.svg)](https://pypi.org/project/l4s3r-authnz/)
[![PyPI Downloads](https://img.shields.io/pypi/dm/l4s3r-authnz.svg)](https://pypi.org/project/l4s3r-authnz/)
[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-green.svg)](https://fastapi.tiangolo.com/)
[![License](https://img.shields.io/badge/license-MIT-purple.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-44%20passed%20%28100%25%29-brightgreen.svg)]()

> "I don't care if the user exists; I care if they are authorized to perform this specific action."

**Auth N&Z** is a modular, production-grade, NIST-compliant Identity and Access Management (IAM) framework and multi-tenant authorization engine built with Python, FastAPI, and asynchronous SQLAlchemy 2.0 (`asyncpg`).

---

## Key Capabilities

### 1. Authentication (AuthN)
- **Dual-Engine Password Hashing:** Argon2id (OWASP recommended) & Bcrypt with transparent zero-downtime hash migration.
- **Stateless JWT Token Families:** Automatic refresh token rotation with instant cascade revocation on token theft/replay attacks.
- **Stateful Redis Distributed Sessions:** Sub-millisecond session validation and single-click remote multi-device revocation.
- **FIDO2 / WebAuthn Level 3 Passkeys:** Platform biometrics (Apple Touch ID/Face ID, Windows Hello, Android Biometrics) & hardware keys (YubiKey).
- **RFC 6238 TOTP Multi-Factor Authentication:** Authenticator app integration with single-use Base58 recovery backup codes.
- **Device Trust Binding:** Cryptographic device fingerprinting with User-Agent binding for remembered MFA devices.
- **Social OAuth2 / OIDC:** Google OpenID Connect and GitHub OAuth with PKCE verification and JIT user provisioning.

![W3C FIDO2 and WebAuthn Passkey Ceremony Flowchart](assets/webauthn_passkey_ceremony_flowchart.jpg)

---

### 2. Authorization (AuthZ), OPA & Multi-Tenancy
- **Hierarchical RBAC:** `superadmin` > `admin` > `developer` > `editor` > `viewer`.
- **Open Policy Agent (OPA) & Declarative Rego Engine:** Externalized policy storage with hybrid fallback and circuit breaker.
- **Fine-Grained ABAC Policy Engine:** Context-aware resource evaluation based on ownership, security clearance, department, and custom rules.
- **Distributed Redis Decision Caching:** High-speed L1/L2 permission caching with real-time Pub/Sub cache invalidation.
- **Multi-Tenant Workspaces:** Isolated organizational tenant boundaries, scoped role clearance, and idempotent invitation lifecycles.
- **Declarative FastAPI Guards:** 1-line dependency injection (`require_auth()`, `require_role("admin")`, `require_permission("tasks:write")`).

![Distributed Policy Storage and OPA Architecture](assets/opa_policy_engine_architecture.jpg)

---

### 3. Production Observability & Telemetry
- **Prometheus Metrics (`GET /metrics`):** Telemetry for authentication rates, token verification outcomes, active sessions, and request latency histograms.
- **Deep Health Probes (`GET /health/live`, `GET /health/ready`, `GET /health`):** Asynchronous connectivity probes against PostgreSQL and Redis.
- **Tamper-Evident Audit Logging:** Structured security event telemetry with severity levels (`INFO`, `WARNING`, `CRITICAL`).
- **Interactive Administration CLI (`cli.py` / `authnz`):** Complete CLI for user management, workspace administration, and audit inspection.

![Observability & Telemetry Architecture](assets/observability_telemetry_architecture.jpg)

---

## System Architecture

![Full-Stack System Architecture](assets/system_architecture_diagram.jpg)

```
Auth N&Z/
├── adapter.py                # Unified configuration & adapter layer (configure_authnz, AuthNZ)
├── models.py                 # SQLAlchemy 2.0 models & AuthNZUserMixin (BYOU pattern)
├── config.py                 # Typed configuration via pydantic-settings
├── exceptions.py             # RFC 7807 Problem Details error boundaries
├── guards.py                 # Declarative FastAPI dependency guards
├── metrics.py                # Prometheus metrics collection engine
├── server.py                 # Lean FastAPI gateway entrypoint (88 lines)
├── cli.py                    # Interactive administration CLI (authnz)
├── policy_engine.py          # Declarative local engine & distributed caching
├── opa_client.py             # Open Policy Agent async client with circuit breaker
├── webauthn_service.py       # FIDO2 / WebAuthn passkey ceremony service
├── policies/
│   ├── rules.json            # Declarative RBAC and ABAC rule definitions
│   └── authnz.rego           # Open Policy Agent Rego policy suite
├── api/
│   ├── dependencies.py       # Shared singletons and dependency injection
│   ├── schemas.py            # Pydantic v2 schemas
│   ├── router.py             # Router factory (create_authnz_router) & aggregated gateway
│   └── v1/
│       ├── auth_router.py         # /auth (login, register, refresh, me, logout)
│       ├── mfa_router.py          # /auth/mfa (setup, verify, disable, complete)
│       ├── webauthn_router.py     # /auth/webauthn (passkeys & security keys)
│       ├── device_trust_router.py # /auth/trusted-devices (CRUD & revocation)
│       ├── workspace_router.py    # /workspaces (tenants, members, roles, switch)
│       ├── team_router.py         # /team (legacy invitations & management)
│       ├── oauth_router.py        # /auth/oauth (Google OIDC & GitHub OAuth)
│       ├── audit_router.py        # /audit/logs & protected documents
│       ├── notification_router.py # /notifications (in-app notification feed)
│       ├── websocket_router.py    # /ws/workspaces/{id} real-time connection manager
│       ├── health_router.py       # /health/live, /health/ready, /metrics
│       ├── policy_router.py       # /admin/policies (inspect, reload, simulate)
│       └── task_router.py         # /tasks (sprint deliverable board)
└── examples/
    └── task_tracker_app/     # Consumer showcase microservice
```

---

## JWT Token Security & Session Lifecycle

![Token Security Lifecycle Flowchart](assets/token_security_lifecycle_flowchart.jpg)

1. **Initial Authentication:** User logs in via password, MFA, passkey, or OAuth 2.0 PKCE, receiving a short-lived access token and a long-lived refresh token.
2. **Token Family Lineage:** Each refresh cycle rotates both tokens. Presenting an already-consumed token immediately triggers a **Theft Cascade Revocation** of all sessions.
3. **Proactive Client Heartbeat:** Client inspects JWT `exp` timestamp and silently calls `POST /auth/refresh` before expiration.
4. **Stateful Redis Invalidation:** Remote single-click logout instantly purges the user's sessions across all connected devices.

---

## Multi-Tenant Workspace & Task Lifecycle

![Team Task Workflow Diagram](assets/team_task_workflow_diagram.jpg)

1. **Workspace Provisioning:** Users create workspaces or are invited by administrators.
2. **Contextual Workspace Switching:** `POST /auth/workspaces/switch` issues scoped JWT access tokens with workspace permissions.
3. **Invitation Dispatch:** Workspace Admin invites members via email with single-use cryptographic tokens.
4. **Task Deliverable Creation:** Tasks are created with JSONB tags, deadlines, priority levels, and multiple assignees.
5. **Real-Time Push & Email:** In-app WebSocket events and transactional SMTP emails are automatically dispatched.

---

## Quickstart

### 1. Installation

Install via PyPI:
```bash
pip install l4s3r-authnz
```

Or install from source in editable mode:
```bash
git clone https://github.com/L4S3r/AuthN-Z.git
cd AuthN-Z
pip install -e .
```

---

### 2. Local Environment Configuration

Copy the template configuration and customize your secrets:
```bash
cp .env.example .env
```

Key variables in `.env`:
```dotenv
ENVIRONMENT=development
JWT_SECRET_KEY=your_super_secret_high_entropy_key_32_bytes_long
DATABASE_URL=postgresql+asyncpg://authnz_app:password123@localhost:5432/authnz
REDIS_HOST=localhost
REDIS_PORT=6379
REQUIRE_REDIS=false
PASSWORD_HASH_ALGORITHM=argon2id
OPA_ENABLED=false
```

---

### 3. Running the Standalone Gateway

#### Option A: Bare-Metal Python / Uvicorn (Fastest for Local Dev & Low-RAM Mini-Servers)
```bash
# Start FastAPI gateway
uvicorn server:app --host 0.0.0.0 --port 8000 --reload
```
Interactive Swagger docs: **http://localhost:8000/docs**

---

#### Option B: Self-Contained Docker Compose Stack
Launch the complete stack (FastAPI Gateway + PostgreSQL 16 + Redis 7 + Open Policy Agent):

```bash
# 1. Start all containers in detached mode
docker compose up -d

# 2. Bootstrap initial root administrator account
docker compose exec auth-api python seed_admin.py

# 3. Verify container health and table statistics
docker compose exec auth-api python db_manager.py stats

# 4. View real-time application logs
docker compose logs -f auth-api

# 5. Tear down containers and volumes
docker compose down -v
```

---

## Framework & Adapter Integration Patterns

Auth N&Z is designed to integrate into external FastAPI applications at 3 architectural levels:

### Pattern A: Modular Adapter & Custom User Model (BYOU)

Retain your application's own `User` table identity with custom columns and selectively mount only the routes you need:

```python
from fastapi import FastAPI
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

# 1. Import Core Identity Base, Mixin, and Adapter
from auth_nz.models import Base, AuthNZUserMixin
from auth_nz.adapter import AuthNZ
from auth_nz.guards import CurrentUser, require_auth, require_role, require_permission

# 2. Define custom User model inheriting AuthNZUserMixin on shared Base
class User(Base, AuthNZUserMixin):
    __tablename__ = "users"
    company_name: Mapped[str]
    stripe_customer_id: Mapped[str | None] = mapped_column(nullable=True)

# 3. Create Async Database Session Factory
engine = create_async_engine("postgresql+asyncpg://user:pass@localhost:5432/my_app")
session_factory = async_sessionmaker(engine)

# 4. Initialize AuthNZ Adapter with your custom model & session factory
authnz = AuthNZ(
    user_model=User,
    session_factory=session_factory,
    jwt_secret_key="custom_secret_key_here",
)

# 5. Mount ONLY the desired routes (e.g. Auth + MFA + WebAuthn, exclude turnkey tasks)
app = FastAPI(title="My SaaS Application")

app.include_router(
    authnz.create_router(
        enable_auth=True,
        enable_mfa=True,
        enable_webauthn=True,
        enable_device_trust=True,
        enable_workspaces=False,  # Exclude standalone workspace domain if not needed
        enable_tasks=False,       # Exclude standalone task tracker
    ),
    prefix="/api/v1",
)

# 6. Protect host endpoints with 1-line declarative guards
@app.get("/api/v1/profile")
async def get_profile(user: CurrentUser = Depends(require_auth())):
    return {"id": user.id, "email": user.email, "roles": user.roles}
```

---

### Pattern B: Lightweight Resource Server Guards (Zero-DB Mode)

In downstream microservices (e.g. Billing, Inventory), validate incoming JWT tokens and enforce RBAC/ABAC permissions with zero database overhead:

```python
from fastapi import FastAPI, Depends
from auth_nz.guards import require_auth, require_role, require_permission, CurrentUser
from auth_nz.exceptions import register_exception_handlers

app = FastAPI(title="Billing Microservice")
register_exception_handlers(app)

@app.get("/invoices")
async def get_invoices(user: CurrentUser = Depends(require_permission("invoices:read"))):
    return {"status": "ok", "user": user.email}

@app.delete("/invoices/{invoice_id}")
async def delete_invoice(user: CurrentUser = Depends(require_role("admin"))):
    return {"status": "deleted"}
```

---

### Pattern C: Turnkey Standalone IAM Microservice

Run the standalone server out of the box with the complete suite (Auth, Passkeys, Multi-Tenant Workspaces, Task Tracker, Telemetry, and Admin CLI):

```python
from fastapi import FastAPI
from auth_nz import api_router, register_exception_handlers

app = FastAPI(title="Turnkey Auth Gateway")
register_exception_handlers(app)
app.include_router(api_router)
```

---

## 💻 Administration & Control Plane Utilities

Auth N&Z includes comprehensive CLI tools for operator administration:

### 1. Interactive Control Plane (`cli.py` / `authnz`)

```bash
# User Management
authnz users list
authnz users create --username alice --email alice@example.com --password SecretPassword123! --role admin
authnz users reset-password --email alice@example.com --password NewSecretPassword123!
authnz users delete --email alice@example.com

# Workspace Administration
authnz workspaces list
authnz workspaces create --name "Acme Corp" --slug "acme"

# Declarative Policies & OPA
authnz policies inspect
authnz policies reload
authnz policies simulate --email alice@example.com --action read --resource-type documents

# Security Audit Inspection
authnz audit tail --limit 25 --severity CRITICAL

# Diagnostics & Observability
authnz health check
authnz metrics dump
```

### 2. Database Inspection & Maintenance (`db_manager.py`)

```bash
python db_manager.py stats                    # Record counts across all tables
python db_manager.py audit -n 50 -s CRITICAL   # Filter security audit logs
python db_manager.py workspaces               # List workspaces with member counts
python db_manager.py users -r admin           # Filter registered users by role
python db_manager.py devices                  # Inspect enrolled trusted devices
python db_manager.py purge-audit --yes        # Safely purge telemetry logs
```

### 3. Bootstrap & Promotion Utilities

```bash
# Bootstrap root administrator without exposing HTTP endpoints
python seed_admin.py

# Promote existing user account to Superadmin
python promote_admin.py -i admin@example.com --super --clearance 5
```

---

## 🧪 Running the Test Suite

Execute the comprehensive offline test suite:
```bash
pytest
```
*Result: 44 passed, 1 skipped (live PostgreSQL integration guard), 100% success.*

---

## 📄 License
MIT License. Auth N&Z is built for enterprise-grade security, compliance, and developer velocity.
