---
name: auth-nz-core
description: >-
  Comprehensive guide, architectural reference, and integration runbook for the core Auth N&Z
  (Authentication & Authorization) engine. Use when scaffolding, integrating, or extending
  production-grade authentication, multi-tenant RBAC/ABAC authorization, MFA/TOTP, JWT token families,
  device trust binding, password hashing, OAuth2/OIDC, and session management into Python/FastAPI/SQLAlchemy projects.
---

# Auth N&Z Core Engine: Integration & Reusability Guide

This skill provides a reusable architectural blueprint and runbook for the core **Auth N&Z** authentication, authorization, and identity management engine (excluding application-specific API route implementations like `server.py`).

- **Upstream Repository**: [https://github.com/L4S3r/AuthN-Z](https://github.com/L4S3r/AuthN-Z)
- **Clone URL**: `https://github.com/L4S3r/AuthN-Z.git`
- **Core Engine Modules**: `authenticator.py`, `models.py`, `permission_evaluator.py`, `token_service.py`, `mfa_provider.py`, `device_trust_service.py`, `session_store.py`, `user_repository.py`, `workspace_repository.py`, `database.py`, `password_hasher.py`, `email_service.py`, `oauth_provider.py`, `audit_logger.py`.

Use this guide to integrate production-ready, NIST-compliant identity security into any Python project.

---

## 1. Architectural Overview & Component Map

The core engine is built using **Python 3.10+**, **asyncio**, **SQLAlchemy 2.0 (asyncpg)**, and **Redis** (with graceful in-memory single-worker fallback).

```
                      ┌────────────────────────────────────────┐
                      │            Authenticator               │ (Unified Facade)
                      │          (authenticator.py)            │
                      └──────────────────┬─────────────────────┘
                                         │
       ┌──────────────────┬──────────────┼───────────────┬──────────────────┐
       ▼                  ▼              ▼               ▼                  ▼
┌──────────────┐   ┌──────────────┐┌──────────────┐┌──────────────┐  ┌──────────────┐
│PasswordHasher│   │ TokenService ││ MFAProvider  ││ DeviceTrust  │  │ SessionStore │
│ (bcrypt:12)  │   │  (JWT/Black) ││  (RFC 6238)  ││ (UA Binding) │  │(Redis/Memory)│
└──────────────┘   └──────────────┘└──────────────┘└──────────────┘  └──────────────┘
       │                  │              │               │                  │
       └──────────────────┴──────────────┼───────────────┴──────────────────┘
                                         ▼
                      ┌────────────────────────────────────────┐
                      │    Repositories & Policy Evaluator     │
                      │  UserRepository | WorkspaceRepository   │
                      │         PermissionEvaluator            │
                      └──────────────────┬─────────────────────┘
                                         ▼
                      ┌────────────────────────────────────────┐
                      │       PostgreSQL Async / Models        │
                      │   (models.py, database.py, alembic)    │
                      └────────────────────────────────────────┘
```

### Core File Inventory (Non-Server Components)

| File | Primary Responsibility | Key Classes / Functions |
| :--- | :--- | :--- |
| `models.py` | Declarative SQLAlchemy ORM models with async UUID primary keys | `User`, `TrustedDevice`, `Workspace`, `WorkspaceMember`, `WorkspaceInvitation`, `PasswordResetToken`, `AuditLog`, `Notification` |
| `database.py` | Async database engine pooling & session lifecycle factory | `get_engine()`, `get_session_factory()`, `get_db_session()` |
| `password_hasher.py` | Constant-time password hashing & verification via Bcrypt | `PasswordHasher` (`hash`, `verify`, `needs_rehash`) |
| `token_service.py` | JWT token issuance, verification, token family rotation, blacklist | `TokenService` (`create_access_token`, `create_refresh_token`, `revoke_token`) |
| `mfa_provider.py` | RFC 6238 TOTP generation/verification & single-use backup codes | `MFAProvider` (`generate_secret`, `verify_totp`, `verify_and_consume_backup_code`) |
| `device_trust_service.py` | Scoped high-entropy device trust tokens with exact User-Agent binding | `DeviceTrustService` (`create_trusted_device`, `verify_trusted_device`, `revoke_trusted_device`) |
| `session_store.py` | Redis-backed distributed sessions with TTL and in-memory fallback | `SessionStore` (`create_session`, `get_session`, `delete_session`, `revoke_all_for_user`) |
| `permission_evaluator.py` | Hybrid RBAC / ABAC policy engine with role hierarchy & wildcards | `PermissionEvaluator` (`has_permission`, `has_role`, `evaluate_policy`, `get_effective_permissions`) |
| `user_repository.py` | Data access layer for user accounts, credentials, and lockout state | `UserRepository` (`get_by_id`, `get_by_email`, `record_failed_attempt`, `reset_failed_attempts`) |
| `workspace_repository.py`| Multi-tenant organization boundaries, memberships, and invitations | `WorkspaceRepository` (`create_workspace`, `add_member`, `create_invitation`, `accept_invitation`) |
| `oauth_provider.py` | Social login integration (Google OIDC, GitHub OAuth) | `GoogleOAuthProvider`, `GitHubOAuthProvider` (`get_authorization_url`, `exchange_code`) |
| `email_service.py` | Transactional email delivery with HTML templates (SMTP / Resend) | `EmailService` (`send_verification_email`, `send_password_reset_email`, `send_invitation_email`) |
| `audit_logger.py` | Asynchronous structured security event logger | `AuditLogger` (`record_security_event`) |
| `authenticator.py` | Unified authentication orchestration facade | `Authenticator` (`authenticate_credentials`, `authenticate_token`, `authenticate_session`, `initiate_mfa_challenge`, `complete_mfa_challenge`) |
| `db_manager.py` | Database schema initialization and index creation CLI | `init_db()`, `drop_db()` |
| `promote_admin.py` | CLI tool to grant superadmin privileges to users | `promote_user()` |
| `seed_admin.py` | CLI bootstrapper for initial administrative user | `seed_default_admin()` |

---

## 2. Core Security Specifications

### 2.1 Password Hashing (`password_hasher.py`)
- **Algorithm**: Bcrypt with configurable salt work factor (default: `12`).
- **Timing Defense**: Verifies against `DUMMY_BCRYPT_HASH` when a user identifier is not found to eliminate user enumeration side-channels.
- **Rehash Detection**: Supports transparent password rehashing if algorithm parameters change.

### 2.2 Token Management (`token_service.py`)
- **Access Tokens**: Short-lived (default: 15 minutes) JWTs containing `sub`, `roles`, `workspace_id`, `type="access"`.
- **Refresh Tokens**: Long-lived (default: 7 days) JWTs with family tracking (`family_id`, `parent_jti`).
- **Revocation / Blacklist**: Revoked `jti` identifiers stored in Redis with TTL matching token expiration.

### 2.3 Multi-Factor Authentication (`mfa_provider.py`)
- **Protocol**: Time-based One-Time Password (RFC 6238 TOTP).
- **Provisioning**: Generates `otpauth://totp/...` URIs compatible with Google Authenticator, Authy, 1Password.
- **Backup Codes**: Generates 8-character high-entropy alphanumeric recovery codes, stored as one-way SHA-256 hashes. Codes are consumed atomically on first use.

### 2.4 Device Trust Binding (`device_trust_service.py`)
- **Token Storage**: High-entropy 32-byte URL-safe tokens stored exclusively as SHA-256 digests (`token_hash`).
- **User-Agent Binding**: Strictly enforces exact string equality between the presented `User-Agent` header and `device.user_agent` recorded at enrollment.
- **Fail-Closed**: Any missing or empty User-Agent (or mismatch) returns `None` and triggers MFA fallback without updating `last_used_at`.
- **Tradeoff**: Browser auto-updates change the User-Agent string over time; this deliberately bounces the user back to MFA to maintain zero-trust integrity.

### 2.5 Access Control & Policy Engine (`permission_evaluator.py`)
- **Role Hierarchy**:
  $$\text{superadmin} \succ \text{admin} \succ \text{developer} \succ \text{editor} \succ \text{viewer}$$
- **Scoping**: Evaluates global roles (`User.roles`) or tenant-scoped roles (`WorkspaceMember.role`).
- **Wildcards**: Supports glob permissions (e.g., `tasks:*`, `*:read`).
- **ABAC Policies**: Dynamically evaluates object ownership, security clearance levels, and department boundaries.

---

## 3. Database Schema Reference (`models.py`)

All models inherit from `Base = declarative_base()` and use UUID primary keys:

```python
# Core Relationships
User 1:N TrustedDevice (CASCADE delete)
User 1:N PasswordResetToken (CASCADE delete)
User 1:N WorkspaceMember (CASCADE delete)
Workspace 1:N WorkspaceMember (CASCADE delete)
Workspace 1:N WorkspaceInvitation (CASCADE delete)
```

### Key Tables
1. `users`: Identity credentials, `roles` (JSONB/JSON), `mfa_enabled`, `mfa_secret`, `failed_login_attempts`, `locked_until`.
2. `trusted_devices`: `user_id`, `token_hash` (unique SHA-256), `user_agent`, `device_label`, `ip_address`, `expires_at`, `last_used_at`.
3. `workspaces`: Tenant organization boundaries with unique `slug`.
4. `workspace_members`: Composite mapping `(workspace_id, user_id)` with assigned `role` and `status`.
5. `audit_logs`: Immutable security log capturing `event_type`, `user_id`, `severity`, `ip_address`, `details`.

---

## 4. How to Drop Auth N&Z into a New Project

### Step 0: Clone or Copy Core Modules from Repository

Clone the upstream repository [https://github.com/L4S3r/AuthN-Z](https://github.com/L4S3r/AuthN-Z):
```bash
# Clone the repository
git clone https://github.com/L4S3r/AuthN-Z.git

# Copy core engine files into your new project's auth directory (excluding server.py)
mkdir -p ./my_project/auth
cp AuthN-Z/{authenticator,database,device_trust_service,email_service,mfa_provider,models,oauth_provider,password_hasher,permission_evaluator,session_store,token_service,user_repository,workspace_repository,audit_logger}.py ./my_project/auth/
```

### Step 1: Install Required Dependencies

Add the following to your new project's `requirements.txt`:

```text
bcrypt>=4.0.0
pyjwt[crypto]>=2.8.0
cryptography>=41.0.0
pyotp>=2.9.0
python-dotenv>=1.0.0
SQLAlchemy>=2.0.0
asyncpg>=0.29.0
alembic>=1.13.0
redis>=5.0.0
pydantic>=2.0.0
pydantic-settings>=2.0.0
email-validator>=2.0.0
httpx>=0.25.0
```

### Step 2: Configure Environment Variables (`.env`)

```ini
ENVIRONMENT=development
DATABASE_URL=postgresql+asyncpg://app_user:app_password@127.0.0.1:5432/app_db
JWT_SECRET_KEY=your-32-byte-hex-secret-key-here
REDIS_HOST=127.0.0.1
REDIS_PORT=6379

# Email Delivery (Optional)
SMTP_HOST=smtp.resend.com
SMTP_PORT=587
SMTP_USER=resend
SMTP_PASSWORD=your_smtp_password
SMTP_FROM=App Auth <no-reply@yourdomain.com>
```

### Step 3: Run Database Migrations

Initialize Alembic or run the schema creation tool:
```bash
alembic upgrade head
# Or use the built-in db_manager:
python -c "import asyncio; from db_manager import init_db; asyncio.run(init_db())"
```

---

## 5. Standard Integration Recipes

### Recipe A: Initializing the Authenticator and Evaluator

```python
from database import get_session_factory
from user_repository import UserRepository
from workspace_repository import WorkspaceRepository
from password_hasher import PasswordHasher
from token_service import TokenService
from session_store import SessionStore
from mfa_provider import MFAProvider
from device_trust_service import DeviceTrustService
from permission_evaluator import PermissionEvaluator
from authenticator import Authenticator

# Initialize components
session_factory = get_session_factory()
user_repo = UserRepository(session_factory=session_factory)
ws_repo = WorkspaceRepository(session_factory=session_factory)
hasher = PasswordHasher(work_factor=12)
token_service = TokenService(secret_key="your_jwt_secret")
session_store = SessionStore()
mfa_provider = MFAProvider()
device_trust = DeviceTrustService(session_factory=session_factory)

# Core Facades
evaluator = PermissionEvaluator(user_repo=user_repo, workspace_repo=ws_repo)
authenticator = Authenticator(
    user_repo=user_repo,
    hasher=hasher,
    token_service=token_service,
    session_store=session_store,
    mfa_provider=mfa_provider,
    device_trust_service=device_trust,
)
```

---

### Recipe B: User Registration and Password Hashing

```python
async def register_user(username: str, email: str, raw_password: str):
    # 1. Check existing user
    if await user_repo.get_by_email(email):
        raise ValueError("Email already registered.")
    
    # 2. Hash password securely
    password_hash = hasher.hash(raw_password)

    # 3. Create user record
    user = await user_repo.create_user(
        username=username,
        email=email,
        password_hash=password_hash,
        roles=["viewer"],
    )
    return user
```

---

### Recipe C: Login with MFA & Device Trust Verification

```python
async def login_flow(email: str, password: str, trusted_device_cookie: str | None, user_agent: str, ip: str):
    # Authenticate credentials and check trusted device bypass
    result = await authenticator.authenticate_credentials(
        identifier=email,
        plain_password=password,
        trusted_device_token=trusted_device_cookie,
        user_agent=user_agent,
        ip_address=ip,
    )

    if result["status"] == "MFA_REQUIRED":
        # Return challenge ID to client for TOTP prompt
        return {
            "mfa_required": True,
            "user_id": result["user_id"],
            "challenge_id": result["challenge_id"],
        }

    # Successful login: issue JWT tokens
    user_id = result["user"]["id"]
    access_token = token_service.create_access_token(user_id, claims={"roles": result["user"]["roles"]})
    refresh_token = token_service.create_refresh_token(user_id)
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
    }
```

---

### Recipe D: Completing MFA & Issuing a Trusted Device Token

```python
async def complete_mfa_flow(user_id: str, challenge_id: str, totp_code: str, remember_device: bool, user_agent: str, ip: str):
    result = await authenticator.complete_mfa_challenge(
        user_id=user_id,
        challenge_id=challenge_id,
        response_code=totp_code,
        remember_device=remember_device,
        user_agent=user_agent,
        ip_address=ip,
    )

    response = {
        "access_token": result["access_token"],
        "refresh_token": result["refresh_token"],
    }

    # If remember_device was requested and verified, set HttpOnly cookie
    if result.get("trusted_device_token"):
        response["trusted_device_cookie"] = result["trusted_device_token"]
        response["cookie_max_age"] = 30 * 86400  # 30 days

    return response
```

---

### Recipe E: Protecting Routes with RBAC & ABAC

```python
async def enforce_task_edit(user_id: str, workspace_id: str, task: dict):
    # 1. RBAC Check: Does user have editor role in the workspace?
    has_role = await evaluator.has_role(user_id, "editor", scope=workspace_id)
    if not has_role:
        raise PermissionError("User lacks required editor role in workspace.")

    # 2. Permission Check: Can user update tasks?
    can_update = await evaluator.has_permission(user_id, "tasks:update", context={"workspace_id": workspace_id})
    if not can_update:
        raise PermissionError("User lacks 'tasks:update' permission.")

    # 3. ABAC Check: Evaluate resource ownership and security clearance
    user = await user_repo.get_by_id(user_id)
    is_allowed = await evaluator.evaluate_policy(
        subject_attributes={"id": user_id, "role": user["roles"][0]},
        action="update",
        resource_attributes={"owner_id": task["created_by"], "workspace_id": workspace_id},
    )
    if not is_allowed:
        raise PermissionError("Policy evaluation rejected resource modification.")
```

---

## 6. Testing Strategy

When implementing or testing this core engine in other projects:
- **Unit Tests**: Mock `session_factory` and repositories to test logic in isolation (see `tests/test_cryptography.py` and `tests/test_authorization.py`).
- **Integration Tests**: Spin up an ephemeral PostgreSQL test database and apply Alembic migrations before running pytest with `--asyncio-mode=auto`.
