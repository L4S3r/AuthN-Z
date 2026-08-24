"""
Auth N&Z - Permission Evaluator & Scoped Authorization Engine (PostgreSQL Async)
--------------------------------------------------------------------------------
Evaluates whether an authenticated subject possesses authority to execute actions on
resources within global and workspace-scoped contexts (supporting RBAC, ABAC, and Multi-Tenancy)
using async repositories.
"""

from abc import ABC, abstractmethod
import inspect
import json
import logging
from typing import Any, Dict, List, Optional, Set

from user_repository import UserRepository
from workspace_repository import WorkspaceRepository

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
        role_permissions: Optional[Dict[str, List[str]]] = None,
        role_hierarchy: Optional[Dict[str, List[str]]] = None,
    ):
        self.user_repo = user_repo or UserRepository()
        self.workspace_repo = workspace_repo or WorkspaceRepository()

        self.role_permissions = role_permissions or {
            "viewer": [
                "tasks:read",
                "documents:read",
                "reports:read",
                "workspaces:read",
                "team:read",
            ],
            "editor": [
                "tasks:read",
                "tasks:create",
                "tasks:write",
                "tasks:update",
                "documents:read",
                "documents:write",
                "documents:create",
                "reports:read",
                "workspaces:read",
                "team:read",
            ],
            "developer": [
                "code:read",
                "code:write",
                "code:commit",
                "tasks:read",
                "tasks:create",
                "tasks:write",
                "tasks:update",
                "documents:read",
                "documents:write",
                "documents:create",
                "reports:read",
                "workspaces:read",
                "team:read",
            ],
            "admin": ["*"],
            "superadmin": ["*"],
            "super-admin": ["*"],
            "super_admin": ["*"],
        }

        self.role_hierarchy = role_hierarchy or {
            "superadmin": ["admin", "developer", "editor", "viewer"],
            "super-admin": ["superadmin", "admin", "developer", "editor", "viewer"],
            "super_admin": ["superadmin", "admin", "developer", "editor", "viewer"],
            "admin": ["developer", "editor", "viewer"],
            "developer": ["editor", "viewer"],
            "editor": ["viewer"],
            "viewer": [],
        }

    def _normalize_role(self, role: str) -> str:
        """Normalize role aliases (e.g. 'super-admin' / 'super_admin' -> 'superadmin')."""
        clean = (role or "").strip().lower()
        if clean in ("super-admin", "super_admin", "superadmin", "root", "rootadmin"):
            return "superadmin"
        return clean

    def _expand_roles(self, direct_roles: List[str]) -> Set[str]:
        """Traverse role_hierarchy to resolve all inherited roles."""
        normalized = [self._normalize_role(r) for r in direct_roles if r]
        all_roles = set(normalized)
        queue = list(normalized)
        while queue:
            current_role = queue.pop(0)
            inherited = self.role_hierarchy.get(current_role, [])
            for r in inherited:
                norm_r = self._normalize_role(r)
                if norm_r not in all_roles:
                    all_roles.add(norm_r)
                    queue.append(norm_r)
        return all_roles

    async def _get_global_roles(self, subject_id: str) -> List[str]:
        """Retrieve global roles directly assigned on the user account."""
        user = await _maybe_await(self.user_repo.get_by_id(subject_id))
        if not user or not user.get("is_active", 1):
            return []
        raw_roles = user.get("roles", [])
        if isinstance(raw_roles, str):
            try:
                return json.loads(raw_roles)
            except Exception:
                return []
        return raw_roles if isinstance(raw_roles, list) else []

    async def has_role(
        self,
        subject_id: str,
        required_role: str,
        scope: Optional[str] = None,
    ) -> bool:
        """
        Check if a subject is assigned a specific role.
        - Supports global superadmin bypass.
        - Supports workspace scoping: if scope is a workspace_id, checks workspace_members table.
        - Evaluates role hierarchy (superadmin > admin > developer > editor > viewer).
        """
        norm_required = self._normalize_role(required_role)
        global_roles = await self._get_global_roles(subject_id)
        effective_global = self._expand_roles(global_roles)

        # 1. Global superadmin has all roles everywhere
        if "superadmin" in effective_global:
            return True

        # 2. If scope is provided (workspace_id), check workspace membership
        if scope:
            ws_id = scope.strip()
            member = await _maybe_await(
                self.workspace_repo.get_member(ws_id, user_id=subject_id)
            )
            if member and member.get("status") == "active":
                member_role = member.get("role", "viewer")
                effective_scoped = self._expand_roles([member_role])
                if norm_required in effective_scoped:
                    return True

            # Also check if user is a global admin
            if "admin" in effective_global and norm_required in self._expand_roles(["admin"]):
                return True

            return False

        # 3. If no scope, evaluate against global roles
        return norm_required in effective_global

    async def get_effective_permissions(
        self,
        subject_id: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        """Compile all distinct permissions granted via direct, inherited, and scoped roles."""
        global_roles = await self._get_global_roles(subject_id)
        effective_roles = set(self._expand_roles(global_roles))

        # Check for workspace context
        if context and context.get("workspace_id"):
            ws_id = str(context["workspace_id"]).strip()
            member = await _maybe_await(
                self.workspace_repo.get_member(ws_id, user_id=subject_id)
            )
            if member and member.get("status") == "active":
                scoped_role = member.get("role", "viewer")
                effective_roles.update(self._expand_roles([scoped_role]))

        permissions: Set[str] = set()
        for role in effective_roles:
            perms_for_role = self.role_permissions.get(role, [])
            permissions.update(perms_for_role)

        return list(permissions)

    async def has_permission(
        self,
        subject_id: str,
        required_permission: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Check if a subject possesses a specific permission (supporting wildcards)."""
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
        """Evaluate fine-grained, resource-level access control."""
        user = await _maybe_await(self.user_repo.get_by_id(subject_id))
        if not user or not user.get("is_active", 1):
            return False

        attrs = resource_attributes or {}
        clean_action = action.strip().lower()
        clean_type = resource_type.strip().lower()
        scope = context.get("workspace_id") if context else attrs.get("workspace_id")

        # Admin or Superadmin role bypass
        is_admin = await self.has_role(subject_id, "admin", scope=scope)
        is_super = await self.has_role(subject_id, "superadmin")
        if is_admin or is_super:
            return True

        # Specific permission check
        perm_key = f"{clean_type}:{clean_action}"
        if await self.has_permission(subject_id, perm_key, context):
            return True

        # Resource creator / owner check
        if attrs.get("created_by") == user.get("email") or attrs.get("owner_id") == str(subject_id):
            return True

        # Public access check
        if attrs.get("is_public") and clean_action in ("read", "view", "download"):
            return True

        # Default deny
        return False

    async def evaluate_policy(
        self,
        subject_attributes: Dict[str, Any],
        action: str,
        resource_attributes: Dict[str, Any],
        environment_attributes: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Execute an Attribute-Based Access Control (ABAC) evaluation."""
        roles = subject_attributes.get("roles", [])
        if isinstance(roles, str):
            try:
                roles = json.loads(roles)
            except Exception:
                roles = []

        is_super = "superadmin" in roles or subject_attributes.get("role") == "superadmin"

        # 1. Environmental constraints (e.g., mandatory MFA verification)
        if environment_attributes and environment_attributes.get("mfa_required") and not is_super:
            if not environment_attributes.get("mfa_verified", False):
                return False

        # 2. Superadmin / Admin override
        if is_super or "admin" in roles or subject_attributes.get("role") == "admin":
            return True

        # 3. Ownership rule
        sub_id = subject_attributes.get("id")
        owner_id = resource_attributes.get("owner_id")
        if sub_id and owner_id and str(sub_id) == str(owner_id):
            return True

        # 4. Department match with security clearance check
        sub_dept = subject_attributes.get("department")
        res_dept = resource_attributes.get("department")
        if sub_dept and res_dept and sub_dept.lower() == res_dept.lower():
            user_clearance = subject_attributes.get("clearance", 1)
            required_clearance = resource_attributes.get("required_clearance", 1)
            if user_clearance >= required_clearance:
                return True

        # Default deny
        return False


concretePermissionEvaluator = PermissionEvaluator