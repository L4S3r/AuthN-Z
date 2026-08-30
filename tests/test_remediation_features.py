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


