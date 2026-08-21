# Auth N&Z - Future Development and Roadmap

This document outlines strategic enhancements, production hardening steps, and advanced feature expansions for the Auth N&Z system.

---

## 1. OAuth2 and OpenID Connect (OIDC) Social Login Integration

### Objective
Allow users to authenticate using external identity providers (Google, GitHub, Microsoft, Apple).

### Implementation Plan
1. Create `OAuth2Provider` abstract interface.
2. Implement Authorization Code Grant flow with PKCE (Proof Key for Code Exchange).
3. Add user linking in `UserRepository` to map external provider IDs (e.g. `google_sub_123`) to internal account IDs.
4. Expose `/auth/oauth/{provider}/login` and `/auth/oauth/{provider}/callback` endpoints.

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

## 6. Multi-Tenancy and Scoped Permissions

### Objective
Support SaaS multi-tenant environments with isolated organization boundaries.

### Implementation Plan
1. Add `tenant_id` column to `users`, `audit_logs`, and session state.
2. Introduce scoped role assignments in `PermissionEvaluator` (e.g. user is `admin` in `org_1`, but `viewer` in `org_2`).
3. Enforce tenant isolation middleware to prevent cross-tenant data leakage.
