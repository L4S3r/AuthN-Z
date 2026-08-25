"""
Auth N&Z - Permission Evaluator & Scoped Authorization Engine (PostgreSQL Async)
--------------------------------------------------------------------------------
Evaluates whether an authenticated subject possesses authority to execute actions on
resources within global and workspace-scoped contexts (supporting RBAC, ABAC, Multi-Tenancy,
and OPA / Declarative Rego policies) using async repositories and distributed caching.
"""

from abc import ABC, abstractmethod
import inspect
import json
import logging
from typing import Any, Dict, List, Optional, Set

from user_repository import UserRepository
from workspace_repository import WorkspaceRepository
from policy_engine import DistributedPolicyManager, DeclarativePolicyEngine
from opa_client import OPAClient

logger = logging.getLogger("auth_nz.permission_evaluator")


async def _maybe_await(val: Any) -> Any:
    """Helper to await a coroutine if async, or return value directly if sync."""
    if inspect.isawaitable(val):
        return await val
    return val


class abstractPermissionEvaluator(ABC):
    """Abstract interface defining access control and authorization policy evaluation mechanisms."""

    @abstractmethod
    async def has_permission(
        self,
        subject_id: str,
        required_permission: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Check if a subject possesses a specific permission within an optional workspace context."""
        pass

    @abstractmethod
    async def has_role(
        self,
        subject_id: str,
        required_role: str,
        scope: Optional[str] = None,
    ) -> bool:
        """Check if a subject is assigned a specific role globally or within a workspace scope."""
        pass

    @abstractmethod
    async def is_resource_accessible(
        self,
        subject_id: str,
        action: str,
        resource_type: str,
        resource_id: str,
        resource_attributes: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Evaluate fine-grained, resource-level access control with ownership and role checks."""
        pass

    @abstractmethod
    async def get_effective_permissions(
        self,
        subject_id: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        """Compile and return all distinct permissions granted via direct, inherited, and scoped roles."""
        pass

    @abstractmethod
    async def evaluate_policy(
        self,
        subject_attributes: Dict[str, Any],
        action: str,
        resource_attributes: Dict[str, Any],
        environment_attributes: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Execute an Attribute-Based Access Control (ABAC) evaluation."""
        pass


class PermissionEvaluator(abstractPermissionEvaluator):
    def __init__(
        self,
        user_repo: Optional[UserRepository] = None,
        workspace_repo: Optional[WorkspaceRepository] = None,
        policy_manager: Optional[DistributedPolicyManager] = None,
        redis_client: Optional[Any] = None,
        role_permissions: Optional[Dict[str, List[str]]] = None,
        role_hierarchy: Optional[Dict[str, List[str]]] = None,
    ):
        self.user_repo = user_repo or UserRepository()
        self.workspace_repo = workspace_repo or WorkspaceRepository()
        self.policy_manager = policy_manager or DistributedPolicyManager(
            redis_client=redis_client,
            opa_client=OPAClient(),
            policy_engine=DeclarativePolicyEngine(),
        )

        # Fallback mappings if manually passed
        self.custom_role_permissions = role_permissions
        self.custom_role_hierarchy = role_hierarchy

    def _normalize_role(self, role: str) -> str:
        """Normalize role aliases (e.g. 'super-admin' / 'super_admin' -> 'superadmin')."""
        clean = (role or "").strip().lower()
        if clean in ("super-admin", "super_admin", "superadmin", "root", "rootadmin"):
            return "superadmin"
        return clean

    def _expand_roles(self, direct_roles: List[str]) -> Set[str]:
        """Traverse role hierarchy to resolve all inherited roles."""
        hierarchy = self.custom_role_hierarchy or {
            "superadmin": ["admin", "developer", "editor", "viewer"],
            "admin": ["developer", "editor", "viewer"],
            "developer": ["editor", "viewer"],
            "editor": ["viewer"],
            "viewer": [],
        }

        normalized = [self._normalize_role(r) for r in direct_roles if r]
        all_roles = set(normalized)
        queue = list(normalized)
        while queue:
            current_role = queue.pop(0)
            inherited = hierarchy.get(current_role, [])
            for inh in inherited:
                norm_inh = self._normalize_role(inh)
                if norm_inh not in all_roles:
                    all_roles.add(norm_inh)
                    queue.append(norm_inh)
        return all_roles

    async def get_effective_permissions(
        self,
        subject_id: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        """Compile and return all distinct permissions granted via direct, inherited, and scoped roles."""
        user = await _maybe_await(self.user_repo.get_by_id(subject_id))
        if not user or not user.get("is_active", 1):
            return []

        global_roles = user.get("roles", [])
        if isinstance(global_roles, str):
            try:
                global_roles = json.loads(global_roles)
            except Exception:
                global_roles = []

        all_roles = list(global_roles)

        # Check workspace-scoped role if context has workspace_id
        if context and context.get("workspace_id"):
            ws_id = context["workspace_id"]
            member = await _maybe_await(self.workspace_repo.get_member(ws_id, user_id=subject_id, email=user.get("email")))
            if member and member.get("status") == "active":
                all_roles.append(member.get("role", "viewer"))

        expanded_roles = self._expand_roles(all_roles)

        # Superadmin / Admin blanket wildcard check
        if "superadmin" in expanded_roles or "admin" in expanded_roles:
            return ["*"]

        permissions: Set[str] = set()
        role_map = self.custom_role_permissions or self.policy_manager.engine.role_permissions
        for role in expanded_roles:
            role_perms = role_map.get(role, set())
            if isinstance(role_perms, list):
                role_perms = set(role_perms)
            if "*" in role_perms:
                return ["*"]
            permissions.update(role_perms)

        return sorted(list(permissions))

    async def has_role(
        self,
        subject_id: str,
        required_role: str,
        scope: Optional[str] = None,
    ) -> bool:
        """Check if a subject possesses a specific role or higher (scoped or global)."""
        user = await _maybe_await(self.user_repo.get_by_id(subject_id))
        if not user or not user.get("is_active", 1):
            return False

        global_roles = user.get("roles", [])
        if isinstance(global_roles, str):
            try:
                global_roles = json.loads(global_roles)
            except Exception:
                global_roles = []

        # Superadmin bypass
        if any(self._normalize_role(r) == "superadmin" for r in global_roles):
            return True

        target_role = self._normalize_role(required_role)

        if scope:
            if hasattr(self.workspace_repo, "_resolve_ws_id"):
                resolved_id = await _maybe_await(self.workspace_repo._resolve_ws_id(scope)) or scope
            else:
                resolved_id = scope
            member = await _maybe_await(self.workspace_repo.get_member(resolved_id, user_id=subject_id, email=user.get("email")))
            if member and member.get("status") == "active":
                member_role = self._normalize_role(member.get("role", "viewer"))
                expanded = self._expand_roles([member_role])
                if target_role in expanded:
                    return True

        # Global role check
        expanded_global = self._expand_roles(global_roles)
        return target_role in expanded_global

    async def has_permission(
        self,
        subject_id: str,
        required_permission: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Check if a subject possesses a specific permission (supporting wildcards and OPA)."""
        granted = await self.get_effective_permissions(subject_id, context)

        if "*" in granted or required_permission in granted:
            return True

        for perm in granted:
            if perm.endswith(":*"):
                domain_prefix = perm[:-1]
                if required_permission.startswith(domain_prefix):
                    return True

        return False

    async def is_resource_accessible(
        self,
        subject_id: str,
        action: str,
        resource_type: str,
        resource_id: str,
        resource_attributes: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Evaluate fine-grained, resource-level access control via distributed policy engine."""
        user = await _maybe_await(self.user_repo.get_by_id(subject_id))
        if not user or not user.get("is_active", 1):
            return False

        user_roles = user.get("roles", [])
        if isinstance(user_roles, str):
            try:
                user_roles = json.loads(user_roles)
            except Exception:
                user_roles = []

        meta = user.get("metadata", {})
        if isinstance(meta, str):
            try:
                meta = json.loads(meta)
            except Exception:
                meta = {}

        subject_payload = {
            "id": str(user["id"]),
            "username": user["username"],
            "email": user["email"],
            "roles": user_roles,
            "clearance": int(meta.get("clearance", 1)),
            "department": meta.get("department", "General"),
            "is_superadmin": "superadmin" in [self._normalize_role(r) for r in user_roles],
        }

        # Check access via Distributed Policy Manager (Cache -> OPA -> Declarative ABAC)
        return await self.policy_manager.evaluate_access(
            subject=subject_payload,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            resource_attributes=resource_attributes,
            context=context,
        )

    async def evaluate_policy(
        self,
        subject_attributes: Dict[str, Any],
        action: str,
        resource_attributes: Dict[str, Any],
        environment_attributes: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Execute an Attribute-Based Access Control (ABAC) evaluation."""
        return self.policy_manager.engine.evaluate_abac(
            subject=subject_attributes,
            action=action,
            resource_type=resource_attributes.get("type", "documents"),
            resource_attributes=resource_attributes,
            context=environment_attributes,
        )


concretePermissionEvaluator = PermissionEvaluator