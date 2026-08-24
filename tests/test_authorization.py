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
