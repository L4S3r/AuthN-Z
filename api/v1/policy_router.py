"""
Auth N&Z - Policy Engine & OPA Administration Router (api/v1/policy_router.py)
-------------------------------------------------------------------------------
Endpoints for managing declarative authorization rules, hot-reloading policies without
downtime, and running interactive "what-if" policy simulation evaluations.
"""

from typing import Any, Dict, Optional
import logging
from fastapi import APIRouter, Depends, HTTPException, status

from api.dependencies import (
    perm_eval,
    user_repo,
    get_current_user,
)
from api.schemas import PolicySimulateRequest
from config import settings

logger = logging.getLogger("auth_nz.policy_router")

router = APIRouter(prefix="/admin/policies", tags=["Policy Engine & OPA"])


@router.get("")
async def inspect_policies(
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Inspect active declarative policies, loaded rule hash, and OPA daemon connectivity status."""
    is_admin = await perm_eval.has_role(current_user["user_id"], "admin")
    if not is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Admin or Superadmin role required to inspect policies.",
        )

    engine = perm_eval.policy_manager.engine
    opa = perm_eval.policy_manager.opa

    return {
        "status": "SUCCESS",
        "policy_file": engine.policy_file_path,
        "policy_hash": engine.policy_hash,
        "role_hierarchy": engine.role_hierarchy,
        "defined_roles": list(engine.role_permissions.keys()),
        "abac_rules_count": len(engine.abac_rules),
        "abac_rules": engine.abac_rules,
        "opa_integration": {
            "enabled": opa.enabled,
            "endpoint_url": opa.endpoint_url,
            "circuit_breaker_open": opa._circuit_open,
            "consecutive_failures": opa._consecutive_failures,
        },
    }


@router.post("/reload")
async def reload_policies(
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Hot-reload declarative policies from disk and invalidate all distributed caches with zero downtime."""
    is_admin = await perm_eval.has_role(current_user["user_id"], "admin")
    if not is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Admin or Superadmin role required to reload policies.",
        )

    success = perm_eval.policy_manager.engine.load_policies()
    perm_eval.policy_manager.invalidate_cache()
    perm_eval.policy_manager.opa.reset_circuit()

    engine = perm_eval.policy_manager.engine
    return {
        "status": "SUCCESS" if success else "FALLBACK_LOADED",
        "message": "Policy definitions reloaded and distributed caches evicted.",
        "policy_hash": engine.policy_hash,
        "abac_rules_count": len(engine.abac_rules),
    }


@router.post("/simulate")
async def simulate_policy_decision(
    req: PolicySimulateRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Interactive policy decision simulation testing access for arbitrary subject and resource attributes."""
    is_admin = await perm_eval.has_role(current_user["user_id"], "admin")
    if not is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Admin or Superadmin role required to simulate policies.",
        )

    # 1. Resolve subject
    subject = req.subject
    if not subject and req.subject_id:
        user = await user_repo.get_by_id(req.subject_id)
        if user:
            meta = user.get("metadata", {})
            if isinstance(meta, str):
                import json
                try:
                    meta = json.loads(meta)
                except Exception:
                    meta = {}
            roles = user.get("roles", [])
            if isinstance(roles, str):
                import json
                try:
                    roles = json.loads(roles)
                except Exception:
                    roles = []
            subject = {
                "id": str(user["id"]),
                "username": user["username"],
                "email": user["email"],
                "roles": roles,
                "clearance": int(meta.get("clearance", 1)),
                "department": meta.get("department", "General"),
                "is_superadmin": "superadmin" in roles,
            }

    if not subject:
        subject = {
            "id": req.subject_id or "simulated_user",
            "username": "simulated_user",
            "email": "simulated@example.com",
            "roles": ["viewer"],
            "clearance": 1,
            "department": "General",
            "is_superadmin": False,
        }

    # Evaluate decision
    decision = await perm_eval.policy_manager.evaluate_access(
        subject=subject,
        action=req.action,
        resource_type=req.resource_type,
        resource_id=req.resource_id,
        resource_attributes=req.resource_attributes,
        context=req.context,
    )

    return {
        "status": "SUCCESS",
        "allowed": decision,
        "evaluation_input": {
            "subject": subject,
            "action": req.action,
            "resource": {
                "type": req.resource_type,
                "id": req.resource_id,
                **req.resource_attributes,
            },
            "context": req.context,
        },
    }
