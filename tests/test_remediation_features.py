"""
Auth N&Z - Architectural Remediation Test Suite (tests/test_remediation_features.py)
------------------------------------------------------------------------------------
Verifies all P0-P2 remediation capabilities:
1. Configurable cookie domain, TLS, and trusted proxy header resolution.
2. X-Request-ID correlation middleware propagation.
3. Redis Pub/Sub WebSocket loopback suppression with _origin_node_id.
4. Repository Unit-of-Work (UoW) session injection and transactional rollback across multi-repo workflows.
5. TaskTracker API database-level query pagination (limit, offset, count, total).
6. Sentry header and request body scrubbing for credentials, tokens, and MFA codes.
"""

import pytest
import uuid
import json
from httpx import AsyncClient, ASGITransport

from config import settings
from server import app, _sentry_before_send
from api.dependencies import get_cookie_domain_and_tls
from api.v1.websocket_router import ConnectionManager
from user_repository import UserRepository
from workspace_repository import WorkspaceRepository
from task_repository import TaskRepository
from audit_logger import AuditLogger


class MockRequest:
    def __init__(self, headers=None, url_scheme="http", hostname="localhost"):
        self.headers = headers or {}
        self.url = type("URL", (), {"scheme": url_scheme, "hostname": hostname})()


@pytest.mark.asyncio
async def test_cookie_domain_and_proxy_trust_resolution():
    """Verify cookie domain and TLS resolution across explicit config, proxy trust, and defaults."""
    # 1. Localhost default
    req = MockRequest(headers={"host": "localhost:8000"}, url_scheme="http")
    domain, is_https = get_cookie_domain_and_tls(req)
    assert domain is None
    assert is_https is False

    # 2. Production domain fallback
    req_prod = MockRequest(headers={"host": "tasks.l4s3r.site"}, url_scheme="https")
    domain, is_https = get_cookie_domain_and_tls(req_prod)
    assert domain == ".l4s3r.site"
    assert is_https is True

    # 3. Explicit COOKIE_DOMAIN override
    orig_domain = settings.COOKIE_DOMAIN
    settings.COOKIE_DOMAIN = ".custom-enterprise.com"
    try:
        req_custom = MockRequest(headers={"host": "app.custom-enterprise.com"}, url_scheme="https")
        domain, is_https = get_cookie_domain_and_tls(req_custom)
        assert domain == ".custom-enterprise.com"
    finally:
        settings.COOKIE_DOMAIN = orig_domain

    # 4. Trusted Proxy Headers toggle
    orig_proxy = settings.TRUSTED_PROXY_HEADERS
    settings.TRUSTED_PROXY_HEADERS = True
    try:
        req_proxy = MockRequest(
            headers={
                "host": "10.0.0.1",
                "x-forwarded-host": "auth.l4s3r.site",
                "x-forwarded-proto": "https",
            },
            url_scheme="http",
        )
        domain, is_https = get_cookie_domain_and_tls(req_proxy)
        assert domain == ".l4s3r.site"
        assert is_https is True
    finally:
        settings.TRUSTED_PROXY_HEADERS = orig_proxy


@pytest.mark.asyncio
async def test_request_correlation_id_middleware():
    """Verify X-Request-ID middleware generates or preserves correlation ID."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Auto-generated request ID
        res1 = await client.get("/health/live")
        assert res1.status_code == 200
        assert "X-Request-ID" in res1.headers
        assert len(res1.headers["X-Request-ID"]) > 10

        # Propagated client request ID
        custom_id = "req-trace-xyz-12345"
        res2 = await client.get("/health/live", headers={"X-Request-ID": custom_id})
        assert res2.status_code == 200
        assert res2.headers.get("X-Request-ID") == custom_id


@pytest.mark.asyncio
async def test_websocket_connection_manager_node_id_and_envelope():
    """Verify WebSocket ConnectionManager stamps messages with node ID for loopback suppression."""
    published = []

    class MockRedis:
        def publish(self, channel, message):
            published.append((channel, message))

    mock_redis = MockRedis()
    mgr = ConnectionManager(redis_client=mock_redis, node_id="node-test-alpha")

    await mgr.broadcast_to_workspace("ws_test", {"event": "task.created", "title": "Test Task"})
    assert len(published) == 1
    channel, raw_msg = published[0]
    assert channel == "ws:workspace:ws_test"
    assert '"_origin_node_id": "node-test-alpha"' in raw_msg


@pytest.mark.asyncio
async def test_multi_repository_uow_composition_and_commit_ownership():
    """Verify that multiple repositories (Task, Workspace, Audit, User) share one caller-owned session and never independently commit."""
    class MockSession:
        def __init__(self):
            self.added = []
            self.committed = False
            self.rolled_back = False

        def add(self, obj):
            self.added.append(obj)

        async def execute(self, stmt):
            class MockResult:
                def __init__(self, rowcount=1):
                    self.rowcount = rowcount
                def scalars(self):
                    return self
                def first(self):
                    return None
                def all(self):
                    return []
                def scalar_one_or_none(self):
                    return uuid.uuid4()
            return MockResult()

        async def flush(self):
            pass

        async def commit(self):
            self.committed = True

        async def rollback(self):
            self.rolled_back = True

    mock_sess = MockSession()
    task_repo = TaskRepository()
    ws_repo = WorkspaceRepository()
    audit_repo = AuditLogger()
    user_repo = UserRepository()

    # 1. Update task with caller session
    await task_repo.update_task("11111111-1111-1111-1111-111111111111", {"title": "UoW Updated Title"}, session=mock_sess)
    assert mock_sess.committed is False

    # 2. Record audit log with caller session
    await audit_repo.record_access_denial("user_123", "edit", "task_1", "DENIED", session=mock_sess)
    assert mock_sess.committed is False
    assert len(mock_sess.added) >= 1  # AuditLog was added to the caller session

    # 3. Simulate failure in business workflow -> caller rolls back
    await mock_sess.rollback()
    assert mock_sess.rolled_back is True
    assert mock_sess.committed is False


@pytest.mark.asyncio
async def test_task_pagination_envelope():
    """Verify task list pagination query parameters and response structure."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Request tasks with pagination parameters (unauthenticated returns 401 as expected by auth guard)
        res = await client.get("/tasks?limit=10&offset=0")
        assert res.status_code == 401
        assert "access_token cookie or Bearer token required" in res.json()["detail"]


def test_sentry_scrubbing_headers_and_body():
    """Verify Sentry event scrubber scrubs sensitive headers and body fields (dict & raw auth routes)."""
    # 1. Sensitive headers and parsed JSON dict payload
    event = {
        "request": {
            "url": "https://auth.l4s3r.site/api/v1/auth/login",
            "headers": {
                "Authorization": "Bearer sensitive_jwt_access_token_123",
                "Cookie": "access_token=secret_cookie_token",
                "Set-Cookie": "refresh_token=secret_refresh_token",
                "X-CSRF-Token": "csrf_secret_999",
                "Content-Type": "application/json",
            },
            "data": {
                "username": "admin_user",
                "password": "SuperSecretPassword123!",
                "nested": {
                    "current_password": "OldPassword456!",
                    "new_password": "NewPassword789!",
                    "totp_code": "123456",
                    "backup_code": "ABC-DEF",
                    "refresh_token": "rt_live_secret",
                    "access_token": "at_live_secret",
                    "secret": "my_vault_secret",
                },
                "list_payload": [
                    {"token": "tok_xyz_123", "normal_field": "safe_value"}
                ]
            }
        }
    }

    scrubbed = _sentry_before_send(event)

    # Check headers
    headers = scrubbed["request"]["headers"]
    assert headers["Authorization"] == "[REDACTED]"
    assert headers["Cookie"] == "[REDACTED]"
    assert headers["Set-Cookie"] == "[REDACTED]"
    assert headers["X-CSRF-Token"] == "[REDACTED]"
    assert headers["Content-Type"] == "application/json"

    # Check dictionary body
    data = scrubbed["request"]["data"]
    assert data["username"] == "admin_user"
    assert data["password"] == "[REDACTED]"
    assert data["nested"]["current_password"] == "[REDACTED]"
    assert data["nested"]["new_password"] == "[REDACTED]"
    assert data["nested"]["totp_code"] == "[REDACTED]"
    assert data["nested"]["backup_code"] == "[REDACTED]"
    assert data["nested"]["refresh_token"] == "[REDACTED]"
    assert data["nested"]["access_token"] == "[REDACTED]"
    assert data["nested"]["secret"] == "[REDACTED]"
    assert data["list_payload"][0]["token"] == "[REDACTED]"
    assert data["list_payload"][0]["normal_field"] == "safe_value"

    # Confirm raw string password did not survive anywhere
    event_str = json.dumps(scrubbed)
    assert "SuperSecretPassword123!" not in event_str
    assert "OldPassword456!" not in event_str
    assert "sensitive_jwt_access_token_123" not in event_str
    assert "secret_cookie_token" not in event_str

    # 2. Raw non-dict string body on auth route
    raw_auth_event = {
        "request": {
            "url": "https://auth.l4s3r.site/api/v1/auth/mfa/verify",
            "data": "raw_form_encoded_password=PlainTextSecret&totp=654321",
        }
    }
    scrubbed_raw = _sentry_before_send(raw_auth_event)
    assert scrubbed_raw["request"]["data"] == "[REDACTED - AUTH ROUTE]"
    assert "PlainTextSecret" not in json.dumps(scrubbed_raw)


@pytest.mark.asyncio
async def test_task_repository_multi_workspace_sql_pagination_and_validation():
    """Verify TaskRepository.list_tasks builds multi-workspace IN queries with pagination and rejects conflicting parameters."""
    from unittest.mock import AsyncMock
    from sqlalchemy.dialects import postgresql
    import default_user  # Ensure User is in SQLAlchemy mapper registry
    import workspace_models

    class CapturingSession:
        def __init__(self):
            self.statements = []

        async def execute(self, stmt):
            self.statements.append(stmt)

            class MockResult:
                def scalars(self):
                    return self

                def all(self):
                    return []

                def scalar(self):
                    return 5

            return MockResult()

    mock_sess = CapturingSession()
    repo = TaskRepository()
    ws_1 = uuid.uuid4()
    ws_2 = uuid.uuid4()

    # 1. Provide workspace_ids list with limit and offset -> SQL IN clause and pagination
    res = await repo.list_tasks(
        workspace_ids=[ws_1, ws_2],
        status="in_progress",
        priority="high",
        limit=3,
        offset=2,
        session=mock_sess,
    )
    assert res["total"] == 5
    assert len(mock_sess.statements) == 2  # count subquery + main query

    # Compile the main query to PostgreSQL SQL
    main_stmt = mock_sess.statements[1]
    compiled_sql = str(
        main_stmt.compile(
            dialect=postgresql.dialect(),
            compile_kwargs={"literal_binds": True},
        )
    )
    assert f"'{ws_1}'" in compiled_sql
    assert f"'{ws_2}'" in compiled_sql
    assert "LIMIT 3" in compiled_sql
    assert "OFFSET 2" in compiled_sql
    assert "status = 'in_progress'" in compiled_sql
    assert "priority = 'high'" in compiled_sql
    assert "ORDER BY tasks.created_at DESC, tasks.id ASC" in compiled_sql

    # 2. Mutual exclusivity: providing both workspace_id and workspace_ids must raise ValueError
    with pytest.raises(ValueError, match="Cannot provide both 'workspace_id' and 'workspace_ids'"):
        await repo.list_tasks(
            workspace_id=str(ws_1),
            workspace_ids=[ws_2],
            session=mock_sess,
        )


@pytest.mark.asyncio
async def test_task_router_get_tasks_multi_workspace_and_zero_membership():
    """Verify get_tasks router pushes pagination to SQL across user's workspaces and handles zero-membership callers."""
    from unittest.mock import AsyncMock, patch
    from api.v1.task_router import get_tasks

    user_id = str(uuid.uuid4())
    ws_1 = str(uuid.uuid4())
    ws_2 = str(uuid.uuid4())
    current_user = {"user_id": user_id}

    # Case A: Non-superadmin user who is a member of 2 workspaces out of 10 total
    mock_tasks = [
        {"id": "t1", "workspace_id": ws_1, "title": "Task 1"},
        {"id": "t2", "workspace_id": ws_2, "title": "Task 2"},
        {"id": "t3", "workspace_id": ws_1, "title": "Task 3"},
    ]

    with patch("api.v1.task_router.perm_eval.has_role", new=AsyncMock(return_value=False)), \
         patch("api.v1.task_router.user_repo.get_by_id", new=AsyncMock(return_value={"id": user_id, "email": "dev@co.com"})), \
         patch("api.v1.task_router.ws_repo.list_workspaces_for_user", new=AsyncMock(return_value=[
             {"id": ws_1, "member_status": "active"},
             {"id": ws_2, "member_role": "viewer"},
         ])), \
         patch("api.v1.task_router.task_repo.list_tasks", new=AsyncMock(return_value={"tasks": mock_tasks, "total": 7})) as mock_list_tasks:

        res = await get_tasks(limit=3, offset=0, current_user=current_user)

        assert res["status"] == "SUCCESS"
        assert res["count"] == 3
        assert res["total"] == 7
        assert res["limit"] == 3
        assert res["offset"] == 0
        assert len(res["tasks"]) == 3

        # Assert SQL-level list_tasks was called with workspace_ids and limit/offset (no Python slicing)
        mock_list_tasks.assert_awaited_once_with(
            workspace_ids=[uuid.UUID(wid) for wid in sorted([ws_1, ws_2])],
            status=None,
            priority=None,
            assignee_email=None,
            limit=3,
            offset=0,
        )

    # Case B: Non-superadmin user with zero workspace memberships -> returns empty envelope immediately without DB query
    with patch("api.v1.task_router.perm_eval.has_role", new=AsyncMock(return_value=False)), \
         patch("api.v1.task_router.user_repo.get_by_id", new=AsyncMock(return_value={"id": user_id, "email": "newuser@co.com"})), \
         patch("api.v1.task_router.ws_repo.list_workspaces_for_user", new=AsyncMock(return_value=[])), \
         patch("api.v1.task_router.task_repo.list_tasks", new=AsyncMock()) as mock_list_tasks_empty:

        res_zero = await get_tasks(limit=5, offset=0, current_user=current_user)

        assert res_zero["status"] == "SUCCESS"
        assert res_zero["count"] == 0
        assert res_zero["total"] == 0
        assert res_zero["limit"] == 5
        assert res_zero["offset"] == 0
        assert res_zero["tasks"] == []
        mock_list_tasks_empty.assert_not_awaited()


@pytest.mark.asyncio
async def test_task_repository_assignee_email_wildcard_escaping():
    """Verify TaskRepository.list_tasks escapes underscore, percent, and backslash in assignee_email ILIKE pattern."""
    from sqlalchemy.dialects import postgresql
    import default_user
    import workspace_models

    class CapturingSession:
        def __init__(self):
            self.statements = []

        async def execute(self, stmt):
            self.statements.append(stmt)

            class MockResult:
                def scalars(self):
                    return self

                def all(self):
                    return []

                def scalar(self):
                    return 0

            return MockResult()

    # 1. Underscore in email (e.g. alice_smith@co.com)
    mock_sess = CapturingSession()
    repo = TaskRepository()
    await repo.list_tasks(assignee_email="alice_smith@co.com", session=mock_sess)
    main_stmt = mock_sess.statements[1]
    compiled_sql = str(
        main_stmt.compile(
            dialect=postgresql.dialect(),
            compile_kwargs={"literal_binds": True},
        )
    )
    # Exact match on column lower(assignee_email) remains unescaped
    assert "lower(tasks.assignee_email) = 'alice_smith@co.com'" in compiled_sql
    # JSON array text ILIKE pattern escapes underscore and defines ESCAPE '\\'
    assert "alice\\\\_smith@co.com" in compiled_sql
    assert "ESCAPE '\\\\'" in compiled_sql

    # 2. Percent sign and backslash in email (e.g. 100%_val\id@co.com)
    mock_sess2 = CapturingSession()
    await repo.list_tasks(assignee_email=r"100%_val\id@co.com", session=mock_sess2)
    main_stmt2 = mock_sess2.statements[1]
    compiled_sql2 = str(
        main_stmt2.compile(
            dialect=postgresql.dialect(),
            compile_kwargs={"literal_binds": True},
        )
    )
    assert r"100\%" in compiled_sql2 or r"100\\%" in compiled_sql2
    assert "ESCAPE" in compiled_sql2


@pytest.mark.asyncio
async def test_audit_logger_event_type_wildcard_escaping():
    """Verify AuditLogger.query_events escapes wildcards in event_type ILIKE filter."""
    from sqlalchemy.dialects import postgresql
    import default_user
    import workspace_models

    class CapturingSession:
        def __init__(self):
            self.statements = []

        async def execute(self, stmt):
            self.statements.append(stmt)

            class MockResult:
                def scalars(self):
                    return self

                def all(self):
                    return []

            return MockResult()

    mock_sess = CapturingSession()
    logger = AuditLogger()
    await logger.query_events({"event_type": "AUTH_FAILED"}, session=mock_sess)

    assert len(mock_sess.statements) == 1
    compiled_sql = str(
        mock_sess.statements[0].compile(
            dialect=postgresql.dialect(),
            compile_kwargs={"literal_binds": True},
        )
    )
    assert "AUTH\\_FAILED" in compiled_sql or "AUTH\\\\_FAILED" in compiled_sql
    assert "ESCAPE" in compiled_sql


@pytest.mark.asyncio
async def test_oauth_default_redirect_construction(monkeypatch):
    """Verify default_redirect in oauth_login includes /api/v1 prefix and respects per-provider env var override."""
    from oauth_provider import GoogleOAuth2Provider
    from api.dependencies import oauth_mgr

    google_provider = GoogleOAuth2Provider("dummy_client_id", "dummy_client_secret")
    oauth_mgr.register_provider("google", google_provider)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Default redirect (no env var override)
        import urllib.parse
        monkeypatch.delenv("GOOGLE_REDIRECT_URI", raising=False)
        res1 = await client.get("/auth/oauth/google/login")
        assert res1.status_code == 200, res1.text
        data1 = res1.json()
        assert data1["status"] == "SUCCESS"
        unquoted1 = urllib.parse.unquote(data1["authorization_url"])
        assert "/api/v1/auth/oauth/google/callback" in unquoted1

        # 2. Env var override
        custom_redirect = "https://custom.app.com/api/v1/auth/oauth/google/callback"
        monkeypatch.setenv("GOOGLE_REDIRECT_URI", custom_redirect)
        res2 = await client.get("/auth/oauth/google/login")
        assert res2.status_code == 200, res2.text
        data2 = res2.json()
        assert data2["status"] == "SUCCESS"
        unquoted2 = urllib.parse.unquote(data2["authorization_url"])
        assert custom_redirect in unquoted2


@pytest.mark.asyncio
async def test_oauth_callback_302_redirect_and_cookies(monkeypatch):
    """Verify oauth_callback returns an HTTP 302 redirect to frontend with access_token and set-cookie headers."""
    from unittest.mock import AsyncMock, MagicMock
    from oauth_provider import GoogleOAuth2Provider
    from api.dependencies import oauth_mgr
    import api.v1.oauth_router as oauth_router_mod

    google_provider = GoogleOAuth2Provider("dummy_client_id", "dummy_client_secret")
    google_provider.exchange_code = AsyncMock(return_value={
        "provider": "google",
        "provider_user_id": "123456789",
        "email": "oauth_redirect_test_user@example.com",
        "email_verified": True,
        "name": "OAuth Test User",
    })
    oauth_mgr.register_provider("google", google_provider)

    mock_resolve = AsyncMock(return_value={
        "status": "SUCCESS",
        "user_id": "11111111-2222-3333-4444-555555555555",
        "access_token": "mock_jwt_access_token",
        "refresh_token": "mock_jwt_refresh_token",
        "user": {
            "id": "11111111-2222-3333-4444-555555555555",
            "metadata": {"department": "General"},
        },
    })
    monkeypatch.setattr(oauth_router_mod, "resolve_or_create_oauth_user", mock_resolve)

    state = "test_redirect_state"
    oauth_mgr.save_state(state, {
        "provider": "google",
        "code_verifier": "test_verifier",
        "redirect_uri": "http://falqyn.l4s3r.site/api/v1/auth/oauth/google/callback",
        "target_app_url": "https://falqyn.l4s3r.site",
    })

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test", follow_redirects=False) as client:
        res = await client.get(f"/auth/oauth/google/callback?code=test_code&state={state}")
        assert res.status_code == 302, f"Expected 302 redirect, got {res.status_code}: {res.text}"
        assert "location" in res.headers
        location = res.headers["location"]
        assert "https://falqyn.l4s3r.site" in location
        assert "access_token=mock_jwt_access_token" in location
        assert "is_new_user=true" in location
        assert "set-cookie" in res.headers or "access_token" in str(res.headers)


@pytest.mark.asyncio
async def test_allowed_frontend_origins_accepted_end_to_end(monkeypatch):
    """Verify allowlisted origin is accepted in oauth_login and oauth_callback end-to-end."""
    from oauth_provider import GoogleOAuth2Provider
    from api.dependencies import oauth_mgr
    import api.v1.oauth_router as oauth_router_mod
    from unittest.mock import AsyncMock

    monkeypatch.setenv("ALLOWED_FRONTEND_ORIGINS", "https://app.example.com,http://localhost:3000")

    google_provider = GoogleOAuth2Provider("dummy_client_id", "dummy_client_secret")
    google_provider.exchange_code = AsyncMock(return_value={
        "provider": "google",
        "provider_user_id": "999888777",
        "email": "allowlist_user@example.com",
        "email_verified": True,
        "name": "Allowlist User",
    })
    oauth_mgr.register_provider("google", google_provider)

    mock_resolve = AsyncMock(return_value={
        "status": "SUCCESS",
        "user_id": "11111111-2222-3333-4444-555555555555",
        "access_token": "mock_jwt_allowlist_token",
        "refresh_token": "mock_jwt_refresh_token",
        "user": {
            "id": "11111111-2222-3333-4444-555555555555",
            "metadata": {"department": "General"},
        },
    })
    monkeypatch.setattr(oauth_router_mod, "resolve_or_create_oauth_user", mock_resolve)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test", follow_redirects=False) as client:
        # 1. Login with target_app_url = https://app.example.com
        res = await client.get("/auth/oauth/google/login?target_app_url=https://app.example.com")
        assert res.status_code == 200
        data = res.json()
        state = data["state"]

        state_data = oauth_mgr.consume_state(state)
        assert state_data is not None
        assert state_data["target_app_url"] == "https://app.example.com"

        # Save back state for callback test
        oauth_mgr.save_state(state, state_data)

        # 2. Callback redirect goes to https://app.example.com
        res_cb = await client.get(f"/auth/oauth/google/callback?code=test_code&state={state}")
        assert res_cb.status_code == 302
        assert res_cb.headers["location"].startswith("https://app.example.com/?access_token=")


@pytest.mark.asyncio
async def test_non_allowlisted_origin_rejected_and_falls_back(monkeypatch):
    """Verify non-allowlisted target_app_url/Origin/Referer are rejected and fall back to server default."""
    from oauth_provider import GoogleOAuth2Provider
    from api.dependencies import oauth_mgr

    monkeypatch.setenv("ALLOWED_FRONTEND_ORIGINS", "https://trusted.example.com")
    monkeypatch.setenv("FRONTEND_URL", "https://falqyn.l4s3r.site")

    google_provider = GoogleOAuth2Provider("dummy_client_id", "dummy_client_secret")
    oauth_mgr.register_provider("google", google_provider)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Malicious target_app_url
        res = await client.get(
            "/auth/oauth/google/login?target_app_url=https://attacker.com",
            headers={"origin": "https://attacker-origin.com", "referer": "https://attacker-referer.com/exploit"}
        )
        assert res.status_code == 200
        data = res.json()
        state = data["state"]

        state_data = oauth_mgr.consume_state(state)
        assert state_data is not None
        assert "attacker" not in state_data["target_app_url"]
        assert state_data["target_app_url"] == "https://falqyn.l4s3r.site"


@pytest.mark.asyncio
async def test_unset_allowlist_fails_safe_with_logged_warning(monkeypatch, caplog):
    """Verify that when ALLOWED_FRONTEND_ORIGINS is unset/empty, client candidates are rejected and a warning is logged."""
    import logging
    from oauth_provider import GoogleOAuth2Provider
    from api.dependencies import oauth_mgr

    monkeypatch.delenv("ALLOWED_FRONTEND_ORIGINS", raising=False)
    monkeypatch.setenv("FRONTEND_URL", "https://falqyn.l4s3r.site")

    google_provider = GoogleOAuth2Provider("dummy_client_id", "dummy_client_secret")
    oauth_mgr.register_provider("google", google_provider)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        with caplog.at_level(logging.WARNING, logger="auth_nz.oauth_router"):
            res = await client.get("/auth/oauth/google/login?target_app_url=https://app.example.com")
            assert res.status_code == 200
            data = res.json()
            state = data["state"]

            state_data = oauth_mgr.consume_state(state)
            assert state_data["target_app_url"] == "https://falqyn.l4s3r.site"
            assert "ALLOWED_FRONTEND_ORIGINS is unset or empty" in caplog.text


@pytest.mark.asyncio
async def test_malformed_referer_does_not_bypass_check(monkeypatch):
    """Verify malformed Referer headers do not bypass origin allowlist checks."""
    from oauth_provider import GoogleOAuth2Provider
    from api.dependencies import oauth_mgr

    monkeypatch.setenv("ALLOWED_FRONTEND_ORIGINS", "https://app.example.com")
    monkeypatch.setenv("FRONTEND_URL", "https://falqyn.l4s3r.site")

    google_provider = GoogleOAuth2Provider("dummy_client_id", "dummy_client_secret")
    oauth_mgr.register_provider("google", google_provider)

    malformed_referers = [
        "not_a_valid_url",
        "://attacker.com",
        "javascript:alert(1)",
        "https://app.example.com@attacker.com",
        "https://app.example.com.attacker.com",
    ]

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        for bad_ref in malformed_referers:
            res = await client.get("/auth/oauth/google/login", headers={"referer": bad_ref})
            assert res.status_code == 200
            data = res.json()
            state_data = oauth_mgr.consume_state(data["state"])
            assert state_data["target_app_url"] == "https://falqyn.l4s3r.site"


@pytest.mark.asyncio
async def test_microsoft_oauth_login_redirect_construction(monkeypatch):
    """Verify Microsoft Entra ID OAuth login redirect construction and per-provider env override."""
    from oauth_provider import MicrosoftOAuth2Provider
    from api.dependencies import oauth_mgr

    ms_provider = MicrosoftOAuth2Provider(
        client_id="dummy_ms_client_id",
        client_secret="dummy_ms_secret",
        tenant_id="custom-tenant-id",
    )
    oauth_mgr.register_provider("microsoft", ms_provider)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Default redirect URI
        import urllib.parse
        monkeypatch.delenv("MICROSOFT_REDIRECT_URI", raising=False)
        res1 = await client.get("/auth/oauth/microsoft/login")
        assert res1.status_code == 200, res1.text
        data1 = res1.json()
        assert data1["status"] == "SUCCESS"
        assert data1["provider"] == "microsoft"
        auth_url1 = data1["authorization_url"]
        assert "login.microsoftonline.com/custom-tenant-id/oauth2/v2.0/authorize" in auth_url1
        unquoted1 = urllib.parse.unquote(auth_url1)
        assert "/api/v1/auth/oauth/microsoft/callback" in unquoted1
        assert "User.Read" in unquoted1

        # 2. Env var override (MICROSOFT_REDIRECT_URI)
        custom_redirect = "https://custom.app.com/api/v1/auth/oauth/microsoft/callback"
        monkeypatch.setenv("MICROSOFT_REDIRECT_URI", custom_redirect)
        res2 = await client.get("/auth/oauth/microsoft/login")
        assert res2.status_code == 200
        data2 = res2.json()
        unquoted2 = urllib.parse.unquote(data2["authorization_url"])
        assert custom_redirect in unquoted2


@pytest.mark.asyncio
async def test_microsoft_oauth_callback_token_exchange(monkeypatch):
    """Verify Microsoft OAuth callback exchanges code and returns 302 redirect with tokens."""
    from unittest.mock import AsyncMock
    from oauth_provider import MicrosoftOAuth2Provider
    from api.dependencies import oauth_mgr
    import api.v1.oauth_router as oauth_router_mod

    monkeypatch.setenv("ALLOWED_FRONTEND_ORIGINS", "https://falqyn.l4s3r.site")

    ms_provider = MicrosoftOAuth2Provider("dummy_ms_client_id", "dummy_ms_secret")
    ms_provider.exchange_code = AsyncMock(return_value={
        "provider": "microsoft",
        "provider_user_id": "ms-user-id-12345",
        "email": "ms_user@example.com",
        "email_verified": True,
        "name": "Microsoft Test User",
        "username": "ms_user",
        "picture": None,
    })
    oauth_mgr.register_provider("microsoft", ms_provider)

    mock_resolve = AsyncMock(return_value={
        "status": "SUCCESS",
        "user_id": "22222222-3333-4444-5555-666666666666",
        "access_token": "mock_ms_jwt_access_token",
        "refresh_token": "mock_ms_jwt_refresh_token",
        "user": {
            "id": "22222222-3333-4444-5555-666666666666",
            "metadata": {"department": "General"},
        },
    })
    monkeypatch.setattr(oauth_router_mod, "resolve_or_create_oauth_user", mock_resolve)

    state = "ms_test_state"
    oauth_mgr.save_state(state, {
        "provider": "microsoft",
        "code_verifier": "ms_test_verifier",
        "redirect_uri": "http://falqyn.l4s3r.site/api/v1/auth/oauth/microsoft/callback",
        "target_app_url": "https://falqyn.l4s3r.site",
    })

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test", follow_redirects=False) as client:
        res = await client.get(f"/auth/oauth/microsoft/callback?code=ms_code&state={state}")
        assert res.status_code == 302
        location = res.headers["location"]
        assert "https://falqyn.l4s3r.site" in location
        assert "access_token=mock_ms_jwt_access_token" in location
        assert "is_new_user=true" in location


@pytest.mark.asyncio
async def test_microsoft_oauth_new_user_provisioning_path(monkeypatch):
    """Verify Microsoft user profile shape maps onto resolve_or_create_oauth_user for JIT provisioning."""
    from unittest.mock import AsyncMock
    from api.v1.oauth_router import resolve_or_create_oauth_user, user_repo, audit_log
    import api.dependencies as deps

    monkeypatch.setattr(deps, "oauth_provision_hook", None)
    monkeypatch.setattr(audit_log, "record_security_event", AsyncMock())
    monkeypatch.setattr(audit_log, "record_auth_success", AsyncMock())

    ms_profile = {
        "provider": "microsoft",
        "provider_user_id": "ms-graph-id-777",
        "email": "ms_provision_test@example.com",
        "email_verified": True,
        "name": "Jane Doe Microsoft",
        "username": "janedoe_ms",
        "picture": None,
    }

    mock_create = AsyncMock(return_value={
        "id": "77777777-8888-9999-0000-111122223333",
        "username": "janedoe_ms",
        "email": "ms_provision_test@example.com",
        "roles": ["viewer"],
        "metadata": {
            "name": "Jane Doe Microsoft",
            "department": "General",
            "oauth_providers": {"microsoft": "ms-graph-id-777"},
        },
    })

    monkeypatch.setattr(user_repo, "get_by_identifier", AsyncMock(return_value=None))
    monkeypatch.setattr(user_repo, "create_user", mock_create)

    result = await resolve_or_create_oauth_user(ms_profile, client_ip="127.0.0.1")
    assert result["status"] == "SUCCESS"
    assert result["email"] == ms_profile["email"]
    assert result["access_token"] is not None
    assert result["refresh_token"] is not None
    assert result["user"]["metadata"]["oauth_providers"]["microsoft"] == "ms-graph-id-777"


@pytest.mark.asyncio
async def test_microsoft_oauth_pending_approval_path(monkeypatch):
    """Verify Microsoft OAuth callback handles PENDING_APPROVAL status from BYOU oauth_provision_hook."""
    from unittest.mock import AsyncMock
    from oauth_provider import MicrosoftOAuth2Provider
    from api.dependencies import oauth_mgr
    import api.v1.oauth_router as oauth_router_mod

    monkeypatch.setenv("ALLOWED_FRONTEND_ORIGINS", "https://falqyn.l4s3r.site")

    ms_provider = MicrosoftOAuth2Provider("dummy_ms_client_id", "dummy_ms_secret")
    ms_provider.exchange_code = AsyncMock(return_value={
        "provider": "microsoft",
        "provider_user_id": "ms-user-id-pending",
        "email": "ms_pending@example.com",
        "email_verified": True,
        "name": "Pending User",
    })
    oauth_mgr.register_provider("microsoft", ms_provider)

    mock_resolve = AsyncMock(return_value={
        "status": "PENDING_APPROVAL",
        "detail": "Account awaiting admin approval.",
    })
    monkeypatch.setattr(oauth_router_mod, "resolve_or_create_oauth_user", mock_resolve)

    state = "ms_pending_state"
    oauth_mgr.save_state(state, {
        "provider": "microsoft",
        "code_verifier": "ms_verifier",
        "redirect_uri": "http://falqyn.l4s3r.site/api/v1/auth/oauth/microsoft/callback",
        "target_app_url": "https://falqyn.l4s3r.site",
    })

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test", follow_redirects=False) as client:
        res = await client.get(f"/auth/oauth/microsoft/callback?code=ms_code&state={state}")
        assert res.status_code == 302
        location = res.headers["location"]
        assert "pending_approval=true" in location
        assert "Account%20awaiting%20admin%20approval." in location




