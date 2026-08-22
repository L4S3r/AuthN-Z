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

## 2. WebAuthn and FIDO2 Passkey Support

### Objective
Enable biometric, hardware-key (YubiKey), and passwordless authentication standards.

### Implementation Plan
1. Add `py_webauthn` dependency.
2. Implement Passkey registration challenge generation and credential attestation verification.
3. Store public key credentials and counter values in `user_repository.py`.
4. Integrate with `Authenticator` as a first-class primary or second factor.

---

## 3. Distributed Policy Storage and Open Policy Agent (OPA) Integration

### Objective
Externalize fine-grained authorization rules into declarative policy definitions.

### Implementation Plan
1. Decouple hardcoded RBAC/ABAC matrices into external JSON/YAML configuration or OPA Rego policies.
2. Support dynamic policy updates without application restarts.
3. Introduce caching layer (Redis) for resolved effective permission sets with pub/sub cache invalidation.

---

## 4. Production Database and Scalability Migration

### Objective
Transition storage engines from local SQLite to distributed, production-grade databases.

### Implementation Plan
1. Implement `PostgresUserRepository` and `PostgresAuditLogger` using connection pooling (`asyncpg` / `SQLAlchemy`).
2. Add automated database migration tooling (`alembic`).
3. Migrate `AuditLogger` to a dedicated time-series or append-only log engine (Elasticsearch, OpenSearch, or ClickHouse) for high-throughput environments.

---

## 5. Security Telemetry, Anomaly Detection, and Rate Limiting

### Objective
Detect credential stuffing, distributed brute-force attacks, and compromised credentials.

### Implementation Plan
1. Integrate sliding-window rate limiting using Redis token bucket algorithms (e.g. max 5 failed logins per minute per IP).
2. Implement automated account lockout with exponential backoff after repeated failed attempts.
3. Add IP geolocation and device fingerprinting to `AuditLogger` for impossible travel detection.
4. Provide webhook integrations for real-time alerts on `CRITICAL` severity events (Slack, PagerDuty, Email).

---

## 6. Multi-Tenancy and Scoped Permissions (COMPLETED)

### Objective
Support SaaS multi-tenant environments with isolated organization boundaries, custom team workspaces, and scoped role clearances.

### Status
Implemented and active via `workspace_repository.py`, `permission_evaluator.py`, `audit_logger.py`, and `server.py`:
- `WorkspaceRepository` providing multi-workspace provisioning, cryptographic invite tokens, member role management, and migration.
- Scoped RBAC in `PermissionEvaluator` (`superadmin` > `admin` > `editor` > `viewer`) evaluated per workspace scope.
- REST endpoints for Workspace CRUD, member onboarding, and contextual workspace switching (`POST /auth/workspaces/switch`).
- Workspace-scoped audit logging telemetry in `AuditLogger` (`GET /workspaces/{id}/audit-logs`).
- Task gateway authorization enforcing that only Editors, Admins, and Superadmins can create, edit, or delete sprint tasks.
