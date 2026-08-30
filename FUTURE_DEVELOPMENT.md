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

---

## 7. Client-Side Query Caching & Server-Side Metadata TTL Caching (COMPLETED)

### Objective
Drastically reduce PostgreSQL query load and network roundtrips on resource-constrained mini-servers / VPS instances by eliminating short-polling loops and caching read-heavy identity metadata.

### Status
Implemented and verified across backend multi-tier caching, HTTP conditional 304 handling, WebSocket reactive push, and frontend TanStack Query caching:
- **Server-Side L1/L2 Profile Caching**: `UserProfileCache` in `user_repository.py` providing in-memory L1 fast-path lookup (<1ms) and distributed Redis L2 cache keys (`authnz:cache:user:{id}`) with automatic TTL expiry and invalidation on profile updates, role assignments, account suspension, password reset, and passkey enrollment.
- **HTTP Conditional Caching & ETags**: `generate_etag` and `handle_conditional_response` in `api/dependencies.py` returning `ETag` and `Cache-Control: private, max-age=60, stale-while-revalidate=300` headers on `GET /auth/me`, `GET /auth/webauthn/credentials`, and `GET /auth/trusted-devices`, with instant `304 Not Modified` fast-path execution.
- **Multi-Worker Pub/Sub Invalidation**: Distributed Redis Pub/Sub channel (`authnz:cache:*`) in `api/v1/websocket_router.py` synchronizing local in-memory L1 cache evictions across multi-worker Uvicorn clusters with loopback suppression.
- **Zero-Polling Real-Time Notifications**: WebSocket push events (`notification.received`, `notification.read`, `notification.read_all`) in `api/v1/notification_router.py` and `api/v1/websocket_router.py`, eliminating background HTTP short-polling.
- **Client-Side Query Configuration**: TanStack Query client with `staleTime: 5m`, `gcTime: 10m`, `refetchOnWindowFocus: false`, `refetchOnMount: false`, `refetchOnReconnect: true`, and event-driven mutation invalidation.

---

## 8. Bare-Metal Mini-Server & VPS Production Hardening (No Docker)

### Objective
Provide operational hardening, resource safety guards, automated maintenance, and reliability patterns tailored specifically for the decoupled production architecture:
* **Frontend UI (`tasks.l4s3r.site`):** Hosted on **Vercel** (Global Edge CDN & Serverless SSR).
* **Backend IAM & Database Engine:** Hosted on the **Bare-Metal Linux Mini-Server** (1–2 vCPU, 3–4 GB RAM) running native **systemd**, **native PostgreSQL 16**, **native Redis 7**, and **native Python/Uvicorn** with **Caddy / Nginx**.

---

### 8.1 Decoupled Resource Footprint on Mini-Server
Because the frontend UI is offloaded to Vercel, the mini-server does not run any Node.js or SSR processes. 100% of the 3–4 GB RAM is dedicated to backend services:
* **Operating System & Kernel:** ~150 MB
* **PostgreSQL 16 (Tuned):** ~120–180 MB
* **Redis 7 (In-Memory + TTL Cache):** ~30–60 MB
* **Uvicorn (2 Workers):** ~120–160 MB
* **Caddy Reverse Proxy:** ~25 MB
* **Total Idle Memory Footprint:** **< 600 MB RAM** (Leaving 2.5+ GB headroom for burst traffic and PostgreSQL shared buffers).

---

### 8.2 Native Linux Log Rotation & Journald Trimming
* **The Problem:** Unbounded Uvicorn application logs and `systemd-journald` can fill the disk (`ENOSPC`), causing database transaction halts.
* **The Solution:**
  1. Cap systemd journal logs to 300MB in `/etc/systemd/journald.conf`:
     ```ini
     [Journal]
     SystemMaxUse=300M
     SystemMaxFileSize=30M
     ```
  2. Configure native logrotate in `/etc/logrotate.d/authnz`:
     ```text
     /var/log/authnz/*.log {
         daily
         missingok
         rotate 7
         compress
         delaycompress
         notifempty
         create 0640 authnz authnz
     }
     ```
  3. Schedule automated weekly audit log pruning via user crontab:
     ```bash
     0 3 * * 0 /opt/auth-nz/.venv/bin/python /opt/auth-nz/db_manager.py purge-audit --days 90
     ```

---

### 8.3 Systemd Memory Capping (Cgroups v2) & Swapfile Safety Net
* **The Problem:** Sudden traffic spikes or heavy queries can trigger the Linux kernel OOM killer against PostgreSQL or Redis.
* **The Solution:**
  1. **Configure a 2–4 GB Swapfile with Low Swappiness:**
     ```bash
     sudo fallocate -l 4G /swapfile
     sudo chmod 600 /swapfile
     sudo mkswap /swapfile
     sudo swapon /swapfile
     echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
     # Set swappiness to 10 (prefer RAM, swap only under severe pressure)
     sudo sysctl vm.swappiness=10
     echo 'vm.swappiness=10' | sudo tee -a /etc/sysctl.conf
     ```
  2. **Redis Memory Overcommit Settings:**
     ```bash
     sudo sysctl vm.overcommit_memory=1
     echo 'vm.overcommit_memory=1' | sudo tee -a /etc/sysctl.conf
     ```
  3. **Enforce Hard Memory Ceilings via Systemd (`MemoryMax` / `MemoryHigh`):**
     Add cgroup memory limits directly to the backend service unit so Uvicorn never starves PostgreSQL or Redis.

---

### 8.4 Native Systemd Service Unit File (`/etc/systemd/system/authnz-api.service`)
```ini
[Unit]
Description=Auth N&Z FastAPI Backend Gateway
After=network.target postgresql.service redis.service
Wants=postgresql.service redis.service

[Service]
Type=simple
User=authnz
Group=authnz
WorkingDirectory=/opt/auth-nz
EnvironmentFile=/opt/auth-nz/.env
ExecStart=/opt/auth-nz/.venv/bin/uvicorn server:app --host 127.0.0.1 --port 8000 --workers 2
Restart=always
RestartSec=3s
LimitNOFILE=65535

# Systemd Resource Control (No Docker needed!)
MemoryHigh=384M
MemoryMax=512M
CPUQuota=150%

[Install]
WantedBy=multi-user.target
```

---

### 8.5 Database Connection Pool Tuning (Native PostgreSQL)
Configure SQLAlchemy async engine in `database.py` with conservative, bounded connection pools:
```python
engine = create_async_engine(
    settings.get_database_url(),
    pool_size=10,            # Max persistent connections (saves ~100MB RAM)
    max_overflow=5,          # Max bursting connections
    pool_timeout=30,         # Seconds to wait for connection
    pool_recycle=1800,       # Recycle connections every 30 mins
    pool_pre_ping=True,      # Check connection liveness before checkout
)
```

---

### 8.6 Automated Off-Site Backups via Native Systemd Timers
Schedule a daily encrypted database dump using native `pg_dump` and a lightweight systemd timer with zero intermediate disk waste:

#### Backup Script (`/opt/auth-nz/scripts/backup_db.sh`)
```bash
#!/usr/bin/env bash
set -eo pipefail
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="authnz_backup_${TIMESTAMP}.sql.gz"

# Stream pg_dump through gzip directly to Cloudflare R2 / AWS S3
pg_dump -U authnz -d authnz_db -Fc | gzip | \
  aws s3 cp - "s3://${BACKUP_S3_BUCKET}/daily/${BACKUP_NAME}" --endpoint-url ${S3_ENDPOINT}
```

#### Systemd Timer (`/etc/systemd/system/authnz-backup.timer`)
```ini
[Unit]
Description=Daily Off-Site Database Backup Timer

[Timer]
OnCalendar=*-*-* 03:30:00
Persistent=true

[Install]
WantedBy=timers.target
```

---

### 8.7 Reverse Proxy Edge Hardening & Vercel CORS (`Caddyfile`)

#### Caddy Configuration on Mini-Server (`/etc/caddy/Caddyfile`)
```caddyfile
api.l4s3r.site {
    encode gzip zstd
    
    # Reverse proxy to local Uvicorn for REST API and WebSockets
    reverse_proxy localhost:8000 {
        header_up X-Real-IP {remote_host}
        header_up X-Forwarded-Proto {scheme}
    }
}
```

#### Cross-Origin Cookie & CORS Settings (`config.py` / `.env`)
When Vercel (`tasks.l4s3r.site`) communicates with the mini-server API (`api.l4s3r.site`), cookies are shared seamlessly across subdomains:
```ini
# Shared root domain for seamless authentication cookies
COOKIE_DOMAIN=.l4s3r.site
COOKIE_SAMESITE=lax
COOKIE_SECURE=true
CORS_ORIGINS=["https://tasks.l4s3r.site"]
```
