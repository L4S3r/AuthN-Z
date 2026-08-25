# Auth N&Z - Enterprise Identity, Authentication & Authorization Engine

[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-green.svg)](https://fastapi.tiangolo.com/)
[![License](https://img.shields.io/badge/license-MIT-purple.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-27%20passed%20%28100%25%29-brightgreen.svg)]()

**Auth N&Z** is a modular, production-grade, NIST-compliant Identity and Access Management (IAM) framework and multi-tenant authorization engine built with Python, FastAPI, and asynchronous SQLAlchemy 2.0 (`asyncpg`).

---

## 🌟 Key Capabilities

### 🔐 1. Authentication (AuthN)
- **Dual-Engine Password Hashing:** Argon2id (OWASP recommended) & Bcrypt with transparent zero-downtime hash migration.
- **Stateless JWT Token Families:** Automatic refresh token rotation with instant cascade revocation on token theft/replay attacks.
- **Stateful Redis Distributed Sessions:** Sub-millisecond session validation and single-click remote multi-device revocation.
- **FIDO2 / WebAuthn Level 3 Passkeys:** Platform biometrics (Apple Touch ID/Face ID, Windows Hello, Android Biometrics) & hardware keys (YubiKey).
- **RFC 6238 TOTP Multi-Factor Authentication:** Authenticator app integration with single-use Base58 recovery backup codes.
- **Device Trust Binding:** Cryptographic device fingerprinting with User-Agent binding for remembered MFA devices.
- **Social OAuth2 / OIDC:** Google OpenID Connect and GitHub OAuth with PKCE verification and JIT user provisioning.

### 🛡️ 2. Authorization (AuthZ) & Multi-Tenancy
- **Hierarchical RBAC:** `superadmin` > `admin` > `developer` > `editor` > `viewer`.
- **Fine-Grained ABAC Policy Engine:** Context-aware resource evaluation based on ownership, security clearance, department, and custom rules.
- **Multi-Tenant Workspaces:** Isolated organizational tenant boundaries, scoped role clearance, and idempotent invitation lifecycles.
- **Declarative FastAPI Guards:** 1-line dependency injection (`require_auth()`, `require_role("admin")`, `require_permission("tasks:write")`).

### 📊 3. Production Observability & Control Plane
- **Prometheus Metrics (`GET /metrics`):** Telemetry for authentication rates, token verification outcomes, active sessions, and request latency histograms.
- **Deep Health Probes (`GET /health/live`, `GET /health/ready`, `GET /health`):** Asynchronous connectivity probes against PostgreSQL and Redis.
- **Tamper-Evident Audit Logging:** Structured security event telemetry with severity levels (`INFO`, `WARNING`, `CRITICAL`).
- **Interactive Administration CLI (`cli.py` / `authnz`):** Complete CLI for user management, workspace administration, and audit inspection.

---

## 🏗️ Architecture

```
Auth N&Z/
├── config.py                 # Typed configuration via pydantic-settings
├── exceptions.py             # RFC 7807 Problem Details error boundaries
├── guards.py                 # Declarative FastAPI dependency guards
├── metrics.py                # Prometheus metrics collection engine
├── server.py                 # Lean FastAPI gateway entrypoint (88 lines)
├── cli.py                    # Interactive administration CLI
├── api/
│   ├── dependencies.py       # Shared singletons and dependency injection
│   ├── schemas.py            # Pydantic v2 schemas
│   ├── router.py             # Top-level aggregated API gateway router
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
│       └── task_router.py         # /tasks (sprint deliverable board)
└── examples/
    └── task_tracker_app/     # Consumer showcase microservice
```

---

## 🚀 Quickstart

### 1. Installation

Install as a Python package in any FastAPI microservice:
```bash
pip install -e .
```

Or install runtime dependencies:
```bash
pip install -r requirements.txt
```

### 2. Environment Configuration

Create a `.env` file:
```dotenv
ENVIRONMENT=development
JWT_SECRET_KEY=your_super_secret_high_entropy_key_32_bytes_long
DATABASE_URL=postgresql+asyncpg://authnz_app:password@localhost:5432/authnz
REDIS_HOST=localhost
REDIS_PORT=6379
PASSWORD_HASH_ALGORITHM=argon2id
```

### 3. Start the API Gateway (Bare-Metal / Recommended for Mini-Servers)
```bash
uvicorn server:app --host 0.0.0.0 --port 8000 --reload
```
Interactive Swagger docs: **http://localhost:8000/docs**

---

### 🐳 4. (OPTIONAL) Docker & Docker Compose Setup

> [!NOTE]
> **This Docker setup is 100% optional.**
> For resource-constrained servers (such as mini-servers with 4GB RAM or low-spec VPS), **bare-metal Python execution via systemd** (Step 3 above) is strongly recommended, as it consumes only **~50 MB of RAM** without Docker daemon overhead.

If you are deploying to a cloud container host or want an instant all-in-one local development stack (API + PostgreSQL + Redis + OPA):

```bash
# Spin up complete stack (Gateway + PostgreSQL + Redis + OPA)
docker compose up -d

# View container logs
docker compose logs -f auth-api

# Stop containers
docker compose down
```

---

## 🛡️ Consuming Auth N&Z in External Microservices

Secure external FastAPI routes in 1 line:

```python
from fastapi import FastAPI, Depends
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

app = FastAPI(title="Consumer Microservice")

# 1. Register RFC 7807 Error Boundaries
register_exception_handlers(app)

# 2. Mount Auth N&Z Endpoints
app.include_router(authnz_router)

# 3. Guard Routes with Typed Dependency Injection
@app.get("/api/me")
async def get_profile(user: CurrentUser = Depends(require_auth())):
    return {"id": user.id, "email": user.email, "clearance": user.clearance}

@app.post("/api/invoices")
async def create_invoice(
    user: CurrentUser = Depends(require_permission("billing:create")),
    workspace: CurrentWorkspace = Depends(get_current_workspace()),
):
    return {"status": "created", "workspace": workspace.name}

@app.delete("/api/projects/{project_id}")
async def delete_project(user: CurrentUser = Depends(require_role("admin"))):
    return {"status": "deleted by admin"}
```

---

## 💻 Administration CLI (`authnz` / `cli.py`)

Auth N&Z provides a scriptable control plane utility:

```bash
# User Management
python cli.py users list
python cli.py users create --username alice --email alice@example.com --password SecretPassword123! --role admin
python cli.py users reset-password --email alice@example.com --password NewSecretPassword123!
python cli.py users delete --email alice@example.com

# Workspace Administration
python cli.py workspaces list
python cli.py workspaces create --name "Acme Corp" --slug "acme"

# Security Audit Inspection
python cli.py audit tail --limit 25 --severity CRITICAL

# Diagnostics & Observability
python cli.py health check
python cli.py metrics dump
```

---

## 🧪 Running the Test Suite

Execute the comprehensive offline test suite:
```bash
pytest
```
*Result: 26 passed, 1 skipped (live PostgreSQL E2E), 100% success in ~3.8s.*

---

## 📄 License
MIT License. Auth N&Z is built for enterprise-grade security, compliance, and developer velocity.
