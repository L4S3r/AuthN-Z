# Auth N&Z - Future Development and Roadmap

This document outlines strategic enhancements, production hardening steps, and advanced feature expansions for the Auth N&Z system.

---

## 1. OAuth2 and OpenID Connect (OIDC) Social Login Integration (COMPLETED)

### Objective
Allow users to authenticate using external identity providers (Google, GitHub, Microsoft, Apple).

### Status
Implemented and active via `oauth_provider.py` and `server.py`:
- `GoogleOAuth2Provider` and `GitHubOAuth2Provider` with PKCE (RFC 7636) and single-use state verification.
- Automatic account provisioning and email-based identity linking in `user_repository.py`.
- Endpoints:
  - `GET /auth/oauth/providers` - Discover enabled providers.
  - `GET /auth/oauth/{provider}/login` - Web/Browser redirect initiation with PKCE.
  - `GET /auth/oauth/{provider}/callback` - Web OAuth redirect callback handler.
  - `POST /auth/oauth/{provider}/exchange` - Direct authorization code exchange for mobile apps (Flutter, React Native, Swift, Kotlin).

---

## 2. Multi-Tenancy and Scoped Permissions (COMPLETED)

### Objective
Support SaaS multi-tenant environments with isolated organization boundaries, custom team workspaces, and scoped role clearances.

### Status
Implemented and active via `workspace_repository.py`, `permission_evaluator.py`, `audit_logger.py`, and `server.py`:
- `WorkspaceRepository` providing multi-workspace provisioning, cryptographic invite tokens, member role management, and idempotent invitations (`ON CONFLICT DO UPDATE`).
- Scoped RBAC in `PermissionEvaluator` (`superadmin` > `admin` > `developer` > `editor` > `viewer`) evaluated per workspace scope.
- REST endpoints for Workspace CRUD, member onboarding, and contextual workspace switching (`POST /auth/workspaces/switch`).
- Workspace-scoped audit logging telemetry in `AuditLogger` (`GET /workspaces/{id}/audit-logs`).
- Task gateway authorization enforcing that only Editors, Admins, and Superadmins can create, edit, or delete sprint tasks.

---

## 3. Production Database and Scalability Migration (COMPLETED)

### Objective
Transition storage engines from local SQLite to distributed, production-grade databases with non-blocking async execution.

### Status
Implemented and active across all repositories:
- Asynchronous SQLAlchemy 2.0 and `asyncpg` connection pooling in `database.py`.
- 9 declarative relational models in `models.py` with native `UUID`, `JSONB`, and `TIMESTAMPTZ` types.
- Zero-downtime Alembic database schema migrations (`alembic/versions/0001_initial_schema.py`).
- 5 async repository implementations: `user_repository.py`, `workspace_repository.py`, `task_repository.py`, `audit_logger.py`, and `device_trust_service.py`.
- Full CLI administrative toolkit in `db_manager.py`, `seed_admin.py`, and `promote_admin.py`.

---

## 4. WebAuthn and FIDO2 Passkey Support (COMPLETED)

### Objective
Enable biometric, hardware-key (YubiKey), and passwordless authentication standards.

### Status
Implemented and cryptographically verified via `fido2` (`python-fido2`), `webauthn_service.py`, and `api/v1/webauthn_router.py`:
- W3C WebAuthn Level 3 / FIDO2 `Fido2Server` ceremony orchestration.
- Full `attestationObject` CBOR parsing, origin/challenge verification, and COSE public key persistence.
- Cryptographic ECDSA assertion signature verification (`authenticate_complete`).
- Strictly-monotonic sign counter tracking with automatic clone/regression detection raising `CRITICAL` security audit events (`WEBAUTHN_CLONE_DETECTED`).
- Support for platform authenticators (Apple Touch ID / Face ID, Windows Hello, Android Biometrics) and roaming hardware security keys (YubiKey).

---

## 5. Distributed Policy Storage and Open Policy Agent (OPA) Integration (COMPLETED)

### Objective
Externalize fine-grained authorization rules into declarative policy definitions.

### Status
Implemented and active via `policy_engine.py`, `opa_client.py`, `policies/rules.json`, `policies/authnz.rego`, and `api/v1/policy_router.py`:
- Decoupled RBAC and ABAC rules into declarative JSON (`policies/rules.json`) and Open Policy Agent Rego (`policies/authnz.rego`).
- Zero-downtime dynamic policy hot-reload API (`POST /admin/policies/reload`) and interactive policy simulation (`POST /admin/policies/simulate`).
- Distributed Redis L2 decision caching with automatic cache eviction.
- CLI policy administration (`python cli.py policies inspect`, `python cli.py policies reload`, `python cli.py policies simulate`).

---

## 6. Security Telemetry, Anomaly Detection, and Rate Limiting (PARTIALLY COMPLETED)

### Objective
Detect credential stuffing, distributed brute-force attacks, and compromised credentials.

### Status & Implemented Controls
Implemented and active via `api/dependencies.py`, `authenticator.py`, and `audit_logger.py`:
- Distributed sliding-window rate limiting on login, password-reset, and email endpoints with automatic in-memory sliding-window fallback when Redis is unreachable.
- Automated progressive account lockout with exponential backoff after repeated failed authentication attempts (Redis-backed with in-memory fallback).
- Structured audit event recording with contextual metadata (IP address, user agent, event severity).

### Next Roadmap Items
1. Add IP geolocation and device fingerprinting to `AuditLogger` for impossible travel detection.
2. Provide webhook integrations for real-time alerts on `CRITICAL` severity events (Slack, PagerDuty, Email).
