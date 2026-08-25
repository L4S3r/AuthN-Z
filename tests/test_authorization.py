"""
Authorization & Policy Engine Unit Tests (tests/test_authorization.py)
"""

import pytest
from permission_evaluator import PermissionEvaluator


class MockUserRepo:
    def __init__(self, users_dict):
        self.users = users_dict

    async def get_by_id(self, user_id):
        return self.users.get(str(user_id))


class MockWorkspaceRepo:
    def __init__(self, members_dict):
        self.members = members_dict

    async def get_member(self, workspace_id, user_id=None, email=None):
        return self.members.get((str(workspace_id), str(user_id)))


@pytest.mark.asyncio
async def test_role_hierarchy_expansion():
    evaluator = PermissionEvaluator()
    expanded = evaluator._expand_roles(["admin"])
    assert "admin" in expanded
    assert "developer" in expanded
    assert "editor" in expanded
    assert "viewer" in expanded

    super_expanded = evaluator._expand_roles(["superadmin"])
    assert "superadmin" in super_expanded
    assert "admin" in super_expanded
    assert "developer" in super_expanded
    assert "editor" in super_expanded
    assert "viewer" in super_expanded


@pytest.mark.asyncio
async def test_has_role_with_global_and_scoped_contexts():
    users = {
        "user_super": {"id": "user_super", "roles": ["superadmin"], "is_active": 1},
        "user_viewer": {"id": "user_viewer", "roles": ["viewer"], "is_active": 1},
        "user_member": {"id": "user_member", "roles": ["viewer"], "is_active": 1},
    }
    members = {
        ("ws_100", "user_member"): {"role": "editor", "status": "active"},
    }

    mock_user_repo = MockUserRepo(users)
    mock_ws_repo = MockWorkspaceRepo(members)
    evaluator = PermissionEvaluator(user_repo=mock_user_repo, workspace_repo=mock_ws_repo)

    # Superadmin has all roles everywhere
    assert await evaluator.has_role("user_super", "admin") is True
    assert await evaluator.has_role("user_super", "admin", scope="ws_100") is True

    # Global viewer does not have admin
    assert await evaluator.has_role("user_viewer", "admin") is False
    assert await evaluator.has_role("user_viewer", "viewer") is True

    # Scoped role check
    assert await evaluator.has_role("user_member", "editor", scope="ws_100") is True
    assert await evaluator.has_role("user_member", "viewer", scope="ws_100") is True
    assert await evaluator.has_role("user_member", "admin", scope="ws_100") is False


@pytest.mark.asyncio
async def test_permission_wildcards_and_effective_permissions():
    users = {
        "user_dev": {"id": "user_dev", "roles": ["developer"], "is_active": 1},
        "user_admin": {"id": "user_admin", "roles": ["admin"], "is_active": 1},
    }
    mock_user_repo = MockUserRepo(users)
    mock_ws_repo = MockWorkspaceRepo({})
    evaluator = PermissionEvaluator(user_repo=mock_user_repo, workspace_repo=mock_ws_repo)

    assert await evaluator.has_permission("user_admin", "any:arbitrary:permission") is True
    assert await evaluator.has_permission("user_dev", "code:read") is True
    assert await evaluator.has_permission("user_dev", "code:write") is True
    assert await evaluator.has_permission("user_dev", "billing:manage") is False


@pytest.mark.asyncio
async def test_abac_policy_evaluation():
    evaluator = PermissionEvaluator()

    # 1. Superadmin override
    sub_admin = {"id": "sub_1", "role": "superadmin", "clearance": 1}
    res_secret = {"owner_id": "other_user", "required_clearance": 5}
    assert await evaluator.evaluate_policy(sub_admin, "read", res_secret) is True

    # 2. Ownership match
    sub_owner = {"id": "sub_2", "role": "viewer", "clearance": 1}
    res_owned = {"owner_id": "sub_2", "required_clearance": 5}
    assert await evaluator.evaluate_policy(sub_owner, "update", res_owned) is True

    # 3. Department and clearance match
    sub_eng = {"id": "sub_3", "department": "Engineering", "clearance": 3}
    res_eng = {"owner_id": "other", "department": "Engineering", "required_clearance": 2}
    assert await evaluator.evaluate_policy(sub_eng, "read", res_eng) is True

    # 4. Clearance failure
    res_high = {"owner_id": "other", "department": "Engineering", "required_clearance": 4}
    assert await evaluator.evaluate_policy(sub_eng, "read", res_high) is False


@pytest.mark.asyncio
async def test_verify_trusted_device_user_agent_exact_match_and_mismatch():
    """
    Test verify_trusted_device User-Agent enforcement:
    (a) Matching user_agent succeeds and updates last_used_at / commit.
    (b) Mismatched user_agent returns None and aborts update.
    (c) Missing/empty user_agent fails closed.
    """
    import uuid
    from datetime import datetime, timedelta, timezone
    from unittest.mock import AsyncMock, MagicMock
    from device_trust_service import DeviceTrustService
    from models import TrustedDevice

    test_user_id = uuid.uuid4()
    raw_token = "valid_high_entropy_token_secret_12345"
    token_hash = DeviceTrustService._hash_token(raw_token)
    enrolled_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
    mismatched_ua = "curl/8.4.0"

    device_id = uuid.uuid4()
    now_utc = datetime.now(timezone.utc)

    # 1. Matching User-Agent -> Returns device record and commits update
    mock_device = TrustedDevice(
        id=device_id,
        user_id=test_user_id,
        token_hash=token_hash,
        device_label="Google Chrome on Windows",
        user_agent=enrolled_ua,
        ip_address="192.168.1.100",
        created_at=now_utc,
        expires_at=now_utc + timedelta(days=30),
        last_used_at=now_utc,
    )

    session = AsyncMock()
    exec_result = MagicMock()
    exec_result.scalars.return_value.first.return_value = mock_device
    session.execute.return_value = exec_result

    session_ctx = AsyncMock()
    session_ctx.__aenter__.return_value = session
    session_ctx.__aexit__.return_value = None
    session_factory = MagicMock(return_value=session_ctx)

    service = DeviceTrustService(session_factory=session_factory)

    result = await service.verify_trusted_device(
        user_id=str(test_user_id),
        raw_token=raw_token,
        user_agent=enrolled_ua,
        ip_address="192.168.1.100",
    )
    assert result is not None
    assert result["id"] == str(device_id)
    assert result["user_id"] == str(test_user_id)
    assert session.commit.called is True

    # 2. Mismatched User-Agent (e.g. cookie replay with curl) -> Returns None, no update commit
    session.reset_mock()
    exec_result = MagicMock()
    exec_result.scalars.return_value.first.return_value = mock_device
    session.execute.return_value = exec_result

    mismatch_result = await service.verify_trusted_device(
        user_id=str(test_user_id),
        raw_token=raw_token,
        user_agent=mismatched_ua,
        ip_address="192.168.1.100",
    )
    assert mismatch_result is None
    assert session.commit.called is False

    # 3. Missing/None incoming User-Agent -> Fail closed (returns None)
    session.reset_mock()
    exec_result = MagicMock()
    exec_result.scalars.return_value.first.return_value = mock_device
    session.execute.return_value = exec_result

    none_ua_result = await service.verify_trusted_device(
        user_id=str(test_user_id),
        raw_token=raw_token,
        user_agent=None,
    )
    assert none_ua_result is None
    assert session.commit.called is False

    # 4. Missing/Empty stored User-Agent (legacy device) -> Fail closed (returns None)
    legacy_device = TrustedDevice(
        id=device_id,
        user_id=test_user_id,
        token_hash=token_hash,
        device_label="Legacy Device",
        user_agent="",
        ip_address="192.168.1.100",
        created_at=now_utc,
        expires_at=now_utc + timedelta(days=30),
        last_used_at=now_utc,
    )
    session.reset_mock()
    exec_result = MagicMock()
    exec_result.scalars.return_value.first.return_value = legacy_device
    session.execute.return_value = exec_result

    legacy_result = await service.verify_trusted_device(
        user_id=str(test_user_id),
        raw_token=raw_token,
        user_agent=enrolled_ua,
    )
    assert legacy_result is None
    assert session.commit.called is False

