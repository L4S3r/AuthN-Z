# Auth N&Z - Enterprise Authentication, Authorization & Team Task Gateway

Auth N&Z is a modular, high-security Python Identity and Access Management (IAM) framework and team collaboration engine designed for distributed architectures, microservices, and standalone mini-servers.

---

## 1. System Architecture

![Full-Stack System Architecture](assets/system_architecture_diagram.jpg)

The framework adheres to strict Separation of Concerns across computational and persistence layers:

1. **Password Hasher (`password_hasher.py`)**
   - Salted Bcrypt hashing with cost factor 12.
   - Algorithmic migration detection (`needs_rehash`).
   - Constant-time verification (`bcrypt.checkpw`) against timing side-channel attacks.

2. **User Repository (`user_repository.py`)**
   - SQLite WAL storage engine (`DATABASE.db`).
   - Case-insensitive identifier lookups, soft deactivation (`is_active = 0`), and hard deletion.
   - JSON-encoded extensible roles and OAuth provider metadata.

3. **Task & Team Repository (`task_repository.py`)**
   - High-concurrency SQLite storage for tasks, sprints, member rosters, and invitations.
   - Multi-assignee support (`assignees` JSON array) with backward compatibility.
   - Cryptographic single-use invitation tokens with 7-day TTL expiration.

4. **Token Service (`token_service.py`)**
   - Stateless cryptographic JWT generation and verification (`HS256`).
   - Registered claims enforcement: `sub`, `iat`, `exp`, `jti`, and `type` (`access` vs. `refresh`).
   - Proactive token refresh rotation and revocation blocklists.

5. **Session Store (`session_store.py`)**
   - Stateful in-memory session management backed by Redis hashes.
   - Sliding TTL expiration with secondary user index (`user_sessions:{user_id}`) for instant multi-device revocation.

6. **Multi-Factor Authentication Provider (`mfa_provider.py`)**
   - RFC 6238 Time-based One-Time Password (TOTP) standard.
   - 160-bit Base32 secret generation with `otpauth://totp/` provisioning URIs.
   - Single-use Base58 emergency backup codes stored as SHA-256 digests.

7. **Email Service (`email_service.py`)**
   - SMTP SSL/TLS client with dynamic `.env` configuration reloading.
   - Branded HTML templates for team invitations and task assignments.
   - RFC 5322 deliverability headers (`Message-ID`, `Return-Path`, `Auto-Submitted: auto-generated`).

8. **Database Manager CLI (`db_manager.py`)**
   - Direct command-line inspection and maintenance tool (`stats`, `users`, `tasks`, `audit`, `purge-tasks`, `reset-db`).

9. **HTTP Gateway Server (`server.py`)**
   - Production FastAPI REST service running under Uvicorn/systemd at `https://auth-api.l4s3r.site`.
   - Interactive OpenAPI documentation at `/docs`.

---

## 2. Team Onboarding & Task Assignment Workflow

![Team Task Workflow Diagram](assets/team_task_workflow_diagram.jpg)

### Workflow Steps:
1. **Invitation Dispatch:** Workspace Admin enters the colleague's email address and role.
2. **Secure Token Generation:** A cryptographically random single-use token (7-day expiration) is generated and dispatched via SMTP email.
3. **Colleague Onboarding:** The invitee opens `/invite/accept?token=...`, chooses a secure password, and activates their account.
4. **Task Deliverable Creation:** Tasks are created with titles, descriptions, priority badges, deadlines, and multiple assigned colleagues.
5. **Broadcast Notifications:** Automated email notifications are immediately dispatched to all assigned members.
6. **Kanban Collaboration:** Team members inspect task specifications, view assigner details, update workflow stages, and track deadlines.

---

## 3. JWT Token Security & Session Lifecycle

![Token Security Lifecycle Flowchart](assets/token_security_lifecycle_flowchart.jpg)

### Security Lifecycle:
1. **Initial Authentication:** User logs in via password, MFA, or OAuth 2.0 PKCE, receiving a short-lived access token and a long-lived refresh token.
2. **Proactive Client Heartbeat:** Every 45 seconds (and upon tab focus), the client inspects the JWT `exp` timestamp. If within 60 seconds of expiration, it silently calls `POST /auth/refresh`.
3. **Reactive 401 Interception:** If any request returns `401 Unauthorized`, an `auth:unauthorized` event triggers silent token rotation.
4. **Automatic Clean Logout:** If the refresh token is revoked or expired, the client clears all storage and immediately redirects to `/login?expired=true`.

---

## 4. Getting Started

### Prerequisites
- Python 3.10+
- (Optional) Redis server for stateful session persistence
- (Optional) SMTP Server credentials for email dispatch

### Installation

```bash
cd "C:\Users\Lenovo\Documents\Auth N&Z"
pip install -r requirements.txt
```

### Running the Server Locally

```bash
uvicorn server:app --host 0.0.0.0 --port 8000 --reload
```

### Database Management CLI

```bash
# View table record counts and journal mode
python db_manager.py stats

# Inspect registered users
python db_manager.py users

# List all tasks
python db_manager.py tasks

# View recent security audit logs
python db_manager.py audit --limit 20
```

---

## 5. API Reference

### Authentication Endpoints
- `POST /auth/register` - Public account registration.
- `POST /auth/login` - Primary credential authentication with rate limiting.
- `POST /auth/refresh` - Rotate refresh token for a new token pair.
- `POST /auth/logout` - Invalidate current session or all active sessions.
- `POST /auth/mfa/setup` - Generate TOTP QR secret and emergency backup codes.
- `POST /auth/mfa/complete` - Finalize TOTP or backup code verification.
- `GET /auth/me` - Retrieve current profile and role claims.

### Social Login & OAuth2 (PKCE)
- `GET /auth/oauth/providers` - Discover available OAuth providers.
- `GET /auth/oauth/{provider}/login` - Initiate PKCE authorization flow.
- `GET /auth/oauth/{provider}/callback` - Process authorization code and issue tokens.

### Team Management & Invitations
- `GET /team/members` - List all workspace members and pending invites.
- `POST /team/invite` - Send email invitation with secure token.
- `GET /team/invite/verify?token=...` - Verify invitation token validity.
- `POST /team/invite/accept` - Complete onboarding and activate account.
- `DELETE /team/members/{email}` - Remove member and terminate all active sessions.

### Task Management
- `GET /tasks` - List tasks with optional status, priority, and assignee filters.
- `POST /tasks` - Create task deliverable and notify all assigned members.
- `PATCH /tasks/{id}` - Update status, priority, deadline, or assignees.
- `DELETE /tasks/{id}` - Delete task deliverable from workspace.

### Audit & Administration
- `GET /audit/logs` - Query security telemetry audit trail (Admin only).
