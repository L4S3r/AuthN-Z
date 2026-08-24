# Auth N&Z - Enterprise Authentication, Authorization & Team Task Gateway

Auth N&Z is a modular, high-security Python Identity and Access Management (IAM) framework and multi-tenant collaboration engine built on FastAPI, asynchronous SQLAlchemy 2.0, and PostgreSQL (`asyncpg`).

---

## 1. System Architecture

![Full-Stack System Architecture](assets/system_architecture_diagram.jpg)

The framework adheres to strict Separation of Concerns across computational, security, and persistence layers:

1. **Password Hasher (`password_hasher.py`)**
   - Salted Bcrypt hashing with cost factor 12.
   - Algorithmic migration detection (`needs_rehash`).
   - Constant-time verification (`bcrypt.checkpw`) against timing side-channel attacks.

2. **User Repository (`user_repository.py`)**
   - Async PostgreSQL storage engine with connection pooling via `asyncpg` and SQLAlchemy 2.0.
   - Case-insensitive identifier lookups, soft deactivation (`is_active = 0`), and hard deletion.
   - Native PostgreSQL `JSONB` for extensible roles, security clearance, and OAuth provider metadata.

3. **Workspace & Multi-Tenancy Repository (`workspace_repository.py`)**
   - Isolated multi-tenant workspace provisioning with human-readable slugs.
   - Scoped workspace membership with role hierarchy (`superadmin`, `admin`, `developer`, `editor`, `viewer`).
   - Idempotent invitation workflows with `ON CONFLICT DO UPDATE` handling.

4. **Task & Team Repository (`task_repository.py`)**
   - High-concurrency PostgreSQL storage for sprint tasks, tags, and multi-assignee lists.
   - Multi-assignee support (`assignees` JSONB array) with real-time WebSocket event dispatch.
   - Cryptographic single-use invitation tokens with 7-day TTL expiration.

5. **Token Service (`token_service.py`)**
   - Stateless cryptographic JWT generation and verification (`HS256`).
   - Registered claims enforcement: `sub`, `iat`, `exp`, `jti`, and `type` (`access` vs. `refresh`).
   - Proactive token refresh rotation and Redis-backed revocation blocklists.

6. **Session Store (`session_store.py`)**
   - Stateful in-memory session management backed by Redis hashes (with in-memory fallback).
   - Sliding TTL expiration with secondary user index (`user_sessions:{user_id}`) for instant multi-device revocation.

7. **Multi-Factor Authentication Provider (`mfa_provider.py`)**
   - RFC 6238 Time-based One-Time Password (TOTP) standard.
   - 160-bit Base32 secret generation with `otpauth://totp/` provisioning URIs.
   - Single-use Base58 emergency backup codes stored as SHA-256 digests.

8. **Device Trust Service (`device_trust_service.py`)**
   - Cryptographic device fingerprinting with SHA-256 token hashing.
   - User-Agent matching and browser parsing to safely bypass second-factor challenges on enrolled devices.
   - Automatic 30-day TTL expiration and remote device revocation.

9. **Security Audit Logger (`audit_logger.py`)**
   - Structured, tamper-evident security telemetry stored in PostgreSQL `audit_logs`.
   - Comprehensive indexing on `timestamp`, `event_type`, `severity`, `subject_id`, and `workspace_id`.
   - Automatic sanitization to ensure no plaintext passwords or secrets are ever recorded.

10. **Database Management CLI (`db_manager.py`)**
    - Direct command-line inspection and maintenance tool (`stats`, `users`, `workspaces`, `members`, `tasks`, `audit`, `purge-all`, `reset-db`).

11. **HTTP Gateway Server (`server.py`)**
    - Production FastAPI REST service running under Uvicorn/systemd with real-time WebSockets.
    - Interactive OpenAPI documentation at `/docs`.

---

## 2. Multi-Tenancy & Task Workflow

![Team Task Workflow Diagram](assets/team_task_workflow_diagram.jpg)

### Workflow Steps:
1. **Workspace Provisioning:** Users create workspaces or are invited by administrators.
2. **Contextual Workspace Switching:** `POST /auth/workspaces/switch` issues scoped JWT access tokens with workspace permissions.
3. **Invitation Dispatch:** Workspace Admin invites members via email with single-use cryptographic tokens.
4. **Task Deliverable Creation:** Tasks are created with JSONB tags, deadlines, priority levels, and multiple assignees.
5. **Real-Time Push & Email:** In-app WebSocket events and transactional SMTP emails are automatically dispatched.
6. **Scoped RBAC Clearance:** Only members with `editor`, `admin`, or `superadmin` roles within the active workspace can mutate sprint tasks.

---

## 3. JWT Token Security & Session Lifecycle

![Token Security Lifecycle Flowchart](assets/token_security_lifecycle_flowchart.jpg)

### Security Lifecycle:
1. **Initial Authentication:** User logs in via password, MFA, or OAuth 2.0 PKCE, receiving a short-lived access token and a long-lived refresh token.
2. **Proactive Client Heartbeat:** Client inspects JWT `exp` timestamp and silently calls `POST /auth/refresh` before expiration.
3. **Reactive 401 Interception:** If any request returns `401 Unauthorized`, silent token rotation is attempted before failing.
4. **Automatic Clean Logout:** If refresh token is revoked or expired, the client immediately redirects to `/login?expired=true`.

---

## 4. Getting Started

### Prerequisites
- Python 3.10+
- PostgreSQL 14+ (Local or Remote)
- (Optional) Redis server for distributed session management
- (Optional) SMTP Server credentials for transactional email delivery

### Installation

```bash
git clone <repository-url>
cd "Auth N&Z"
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Environment Configuration

Copy the sample environment file and configure your PostgreSQL database credentials:

```bash
cp .env.example .env
```

Configure your `.env`:
```ini
DATABASE_URL=postgresql+asyncpg://authnz_app:YourSecurePassword@localhost:5432/authnz
JWT_SECRET_KEY=your_super_secret_jwt_key_here
```

### Running Database Migrations

Apply database schema migrations via Alembic:

```bash
alembic upgrade head
```

### Seeding Root Administrator

Provision your initial root administrator account directly via CLI:

```bash
python3 seed_admin.py
```

### Running the Server

```bash
uvicorn server:app --host 0.0.0.0 --port 8000 --reload
```

Interactive API documentation will be available at: `http://localhost:8000/docs`

---

## 5. Database Management CLI

[`db_manager.py`](file:///C:/Users/Lenovo/Documents/Auth%20N&Z/db_manager.py) provides administrative and telemetry inspection utilities:

```bash
# View table record counts
python3 db_manager.py stats

# List all registered users
python3 db_manager.py users

# List all workspaces and member counts
python3 db_manager.py workspaces

# View recent security audit logs
python3 db_manager.py audit --limit 25

# Purge all tables (Fresh Reset)
python3 db_manager.py purge-all --yes

# Reset database and bootstrap root administrator
python3 db_manager.py reset-db --yes
```

---

## 6. Continuous Integration & Testing

The repository includes a comprehensive `pytest` automated testing suite executed on GitHub Actions across Python 3.10, 3.11, 3.12, 3.13, and 3.14 with live PostgreSQL service containers:

```bash
# Run test suite locally
pytest -v
```

---

## 7. API Reference Summary

### Authentication & MFA
- `POST /auth/register` - Public account registration (Viewer role).
- `POST /auth/login` - Primary credential authentication with trusted-device bypass.
- `POST /auth/refresh` - Rotate refresh token for a new token pair.
- `POST /auth/logout` - Invalidate current session or all active sessions.
- `POST /auth/mfa/setup` - Generate TOTP QR secret and emergency backup codes.
- `POST /auth/mfa/verify-setup` - Confirm TOTP enrollment.
- `POST /auth/mfa/complete` - Finalize TOTP challenge with device trust enrollment.
- `GET /auth/me` - Retrieve current user profile and role claims.

### Workspaces & Multi-Tenancy
- `GET /workspaces` - List workspaces for current user.
- `POST /workspaces` - Create new team workspace.
- `GET /workspaces/{id}` - Retrieve workspace details and metrics.
- `POST /auth/workspaces/switch` - Switch active tenant context and receive scoped tokens.
- `GET /workspaces/{id}/audit-logs` - Query workspace-specific audit telemetry.

### Task Management
- `GET /tasks` - List tasks with optional status, priority, and assignee filters.
- `POST /tasks` - Create sprint task and broadcast notifications.
- `PATCH /tasks/{id}` - Update status, priority, deadline, or assignees.
- `DELETE /tasks/{id}` - Delete task deliverable from workspace.

### Audit & Security Telemetry
- `GET /audit/logs` - Query security telemetry audit trail (Admin only).
- `GET /auth/trusted-devices` - List enrolled trusted devices for current user.
- `DELETE /auth/trusted-devices/{device_id}` - Revoke specific trusted device.
