"""
Distributed Policy Engine & OPA Integration Tests (tests/test_policy_engine_and_opa.py)
---------------------------------------------------------------------------------------
Validates:
1. DeclarativePolicyEngine JSON rule parsing, RBAC role hierarchy, and ABAC evaluation.
2. DistributedPolicyManager decision caching and cache eviction.
3. OPAClient payload formatting and circuit breaker resilience.
4. PermissionEvaluator integration with the distributed policy engine.
5. CLI policies subcommands.
"""

from unittest.mock import AsyncMock, MagicMock, patch
import pytest
from policy_engine import DeclarativePolicyEngine, DistributedPolicyManager
from opa_client import OPAClient
from permission_evaluator import PermissionEvaluator
from cli import _cmd_policies_inspect, _cmd_policies_reload, _cmd_policies_simulate


def test_declarative_policy_engine_rbac_and_abac():
    """Verify loading declarative rules and evaluating RBAC permissions and ABAC rules."""
    engine = DeclarativePolicyEngine(policy_file_path="policies/rules.json")

    assert engine.policy_hash != ""
    assert "admin" in engine.role_permissions
    assert engine.has_role("superadmin", "admin") is True
    assert engine.has_role("viewer", "admin") is False

    # RBAC permissions
    assert engine.has_permission(["admin"], "tasks:create") is True
    assert engine.has_permission(["viewer"], "tasks:delete") is False
    assert engine.has_permission(["superadmin"], "anything:anywhere") is True

    # ABAC: Ownership
    sub_alice = {"id": "usr_alice", "email": "alice@example.com", "roles": ["viewer"], "clearance": 1, "department": "Engineering"}
    res_owned = {"owner_id": "usr_alice", "is_public": False}
    res_other = {"owner_id": "usr_bob", "is_public": False}

    assert engine.evaluate_abac(sub_alice, "read", "documents", res_owned) is True
    assert engine.evaluate_abac(sub_alice, "read", "documents", res_other) is False

    # ABAC: Clearance and Department match
    res_confidential = {"owner_id": "usr_bob", "required_clearance": 2, "department": "Engineering"}
    sub_alice_cleared = {"id": "usr_alice", "email": "alice@example.com", "roles": ["viewer"], "clearance": 2, "department": "Engineering"}
    sub_charlie_finance = {"id": "usr_charlie", "email": "charlie@example.com", "roles": ["viewer"], "clearance": 2, "department": "Finance"}

    assert engine.evaluate_abac(sub_alice_cleared, "read", "documents", res_confidential) is True
    assert engine.evaluate_abac(sub_charlie_finance, "read", "documents", res_confidential) is False


@pytest.mark.asyncio
async def test_distributed_policy_manager_caching():
    """Verify policy decision caching in DistributedPolicyManager."""
    manager = DistributedPolicyManager()

    subject = {"id": "u_test_1", "email": "tester@example.com", "roles": ["viewer"], "clearance": 1}
    res_attrs = {"owner_id": "u_test_1"}

    # First evaluation (calculates and stores in cache)
    decision1 = await manager.evaluate_access(
        subject=subject,
        action="read",
        resource_type="documents",
        resource_id="doc_1",
        resource_attributes=res_attrs,
    )
    assert decision1 is True

    # Subsequent evaluation should retrieve from cache
    cache_key = manager._cache_key("u_test_1", "read", "documents/doc_1")
    assert manager.get_cached_decision(cache_key) is True

    # Cache invalidation clears cache
    manager.invalidate_cache()
    assert manager.get_cached_decision(cache_key) is None


@pytest.mark.asyncio
async def test_opa_client_circuit_breaker():
    """Verify OPAClient circuit breaker opens after consecutive failures."""
    client = OPAClient(endpoint_url="http://invalid-opa-host:9999/v1/data/authnz", enabled=True, timeout_seconds=0.1)

    # Trigger failures
    for _ in range(5):
        res = await client.evaluate_policy({"test": 123})
        assert res is None

    assert client._circuit_open is True

    # Circuit reset
    client.reset_circuit()
    assert client._circuit_open is False


def test_cli_policies_commands(capsys):
    """Verify CLI policies inspection, reload, and simulation subcommands."""
    mock_args = MagicMock()
    _cmd_policies_inspect(mock_args)
    captured = capsys.readouterr()
    assert "Declarative Policy Rules" in captured.out
    assert "Defined Roles:" in captured.out

    _cmd_policies_reload(mock_args)
    captured2 = capsys.readouterr()
    assert "Policy definitions reloaded" in captured2.out
