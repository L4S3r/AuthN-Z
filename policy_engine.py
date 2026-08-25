"""
Auth N&Z - Distributed Policy Engine & Caching Manager (policy_engine.py)
-------------------------------------------------------------------------
Loads and evaluates declarative authorization policies (JSON/YAML rules), manages
hybrid OPA fallback, and maintains distributed Redis L2 decision caches with Pub/Sub invalidation.
"""

from typing import Any, Dict, List, Optional, Set
import asyncio
from datetime import datetime, timezone
import hashlib
import json
import logging
import os
import time

from config import settings
from opa_client import OPAClient

logger = logging.getLogger("auth_nz.policy_engine")


class DeclarativePolicyEngine:
    """Local declarative RBAC and ABAC rule engine."""

    def __init__(self, policy_file_path: Optional[str] = None):
        self.policy_file_path = policy_file_path or settings.POLICY_FILE_PATH
        self.role_hierarchy: Dict[str, int] = {
            "superadmin": 5,
            "admin": 4,
            "developer": 3,
            "editor": 2,
            "viewer": 1,
        }
        self.role_permissions: Dict[str, Set[str]] = {}
        self.abac_rules: List[Dict[str, Any]] = []
        self.policy_hash: str = ""
        self.load_policies()

    def load_policies(self) -> bool:
        """Load policy definitions from disk."""
        if not os.path.exists(self.policy_file_path):
            logger.warning("Policy file '%s' not found. Using built-in defaults.", self.policy_file_path)
            self._load_fallback_defaults()
            return False

        try:
            with open(self.policy_file_path, "r", encoding="utf-8") as f:
                content = f.read()
                data = json.loads(content)

            self.role_hierarchy = data.get("role_hierarchy", self.role_hierarchy)
            roles_data = data.get("roles", {})
            self.role_permissions = {}
            for role_name, role_info in roles_data.items():
                self.role_permissions[role_name.lower()] = set(role_info.get("permissions", []))

            self.abac_rules = data.get("abac_rules", [])
            self.policy_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]
            logger.info("Loaded declarative policy rules from %s (Hash: %s)", self.policy_file_path, self.policy_hash)
            return True
        except Exception as exc:
            logger.error("Failed to parse policy file %s: %s. Using fallback defaults.", self.policy_file_path, exc)
            self._load_fallback_defaults()
            return False

    def _load_fallback_defaults(self) -> None:
        self.role_permissions = {
            "superadmin": {"*"},
            "admin": {
                "workspaces:read", "workspaces:update", "workspaces:delete", "workspaces:invite",
                "workspaces:manage_members", "workspaces:audit_logs", "tasks:create", "tasks:read",
                "tasks:update", "tasks:delete", "team:invite", "team:manage", "documents:read",
                "documents:write", "documents:delete"
            },
            "developer": {
                "code:read", "code:write", "code:commit", "workspaces:read", "tasks:create",
                "tasks:read", "tasks:update", "documents:read", "documents:write", "reports:read", "team:read"
            },
            "editor": {"workspaces:read", "tasks:create", "tasks:read", "tasks:update", "documents:read", "documents:write"},
            "viewer": {"workspaces:read", "tasks:read", "documents:read"},
        }
        self.policy_hash = "built-in-defaults"

    def has_role(self, caller_role: str, required_role: str) -> bool:
        """Evaluate role hierarchy comparison."""
        c_level = self.role_hierarchy.get(caller_role.lower(), 0)
        r_level = self.role_hierarchy.get(required_role.lower(), 0)
        return c_level >= r_level

    def has_permission(self, caller_roles: List[str], required_permission: str) -> bool:
        """Evaluate if any of the caller roles possesses the required permission or wildcard."""
        req_perm = required_permission.lower()
        for role in caller_roles:
            r_perms = self.role_permissions.get(role.lower(), set())
            if "*" in r_perms or req_perm in r_perms:
                return True
            # Wildcard domain check (e.g. tasks:* matches tasks:read)
            if ":" in req_perm:
                domain = req_perm.split(":", 1)[0]
                if f"{domain}:*" in r_perms:
                    return True
        return False

    def evaluate_abac(
        self,
        subject: Dict[str, Any],
        action: str,
        resource_type: str,
        resource_attributes: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Evaluate declarative ABAC condition rules."""
        # 1. Superadmin / Admin bypass
        role = subject.get("role")
        roles = list(subject.get("roles", []))
        if role and role not in roles:
            roles.append(role)

        normalized_roles = [r.lower() for r in roles]
        if "superadmin" in normalized_roles or "admin" in normalized_roles or subject.get("is_superadmin"):
            return True

        sub_id = str(subject.get("id") or subject.get("user_id") or "")
        sub_email = str(subject.get("email") or "").lower()
        sub_clearance = int(subject.get("clearance") or subject.get("metadata", {}).get("clearance", 1))
        sub_department = str(subject.get("department") or subject.get("metadata", {}).get("department", "General"))

        res_owner = str(resource_attributes.get("owner_id") or "")
        res_created_by = str(resource_attributes.get("created_by") or "").lower()
        res_public = bool(resource_attributes.get("is_public", False))
        res_clearance = resource_attributes.get("required_clearance")
        res_dept = resource_attributes.get("department")

        # Ownership Rule
        if res_owner and res_owner == sub_id:
            return True

        # Public Resource Rule
        if res_public and action in ("read", "view"):
            return True

        # Clearance & Department Rule
        if res_clearance is not None or res_dept is not None:
            if res_dept is not None and res_dept.lower() == sub_department.lower():
                req_clear = int(res_clearance) if res_clearance is not None else 1
                if sub_clearance >= req_clear:
                    return True

        # Task Creator Rule
        if resource_type == "tasks":
            if res_created_by and res_created_by == sub_email:
                if any(self.has_role(r, "editor") for r in roles):
                    return True

        return False


class DistributedPolicyManager:
    """Orchestrates declarative policy evaluation, OPA sidecar queries, and Redis caching."""

    def __init__(
        self,
        redis_client: Optional[Any] = None,
        opa_client: Optional[OPAClient] = None,
        policy_engine: Optional[DeclarativePolicyEngine] = None,
    ):
        self.r = redis_client
        self.opa = opa_client or OPAClient()
        self.engine = policy_engine or DeclarativePolicyEngine()
        self._in_memory_cache: Dict[str, Tuple[bool, float]] = {}
        self.cache_ttl = settings.POLICY_CACHE_TTL_SECONDS

    def _cache_key(self, subject_id: str, action: str, resource: str, scope: Optional[str] = None) -> str:
        raw = f"{subject_id}:{scope or 'global'}:{action}:{resource}"
        h = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
        return f"authnz:perm_cache:{h}"

    def get_cached_decision(self, cache_key: str) -> Optional[bool]:
        """Check Redis and local memory for cached policy decision."""
        # 1. Check Redis
        if self.r is not None:
            try:
                val = self.r.get(cache_key)
                if val is not None:
                    return val == "1"
            except Exception:
                pass

        # 2. Check in-memory
        if cache_key in self._in_memory_cache:
            decision, exp = self._in_memory_cache[cache_key]
            if time.time() < exp:
                return decision
            else:
                self._in_memory_cache.pop(cache_key, None)

        return None

    def cache_decision(self, cache_key: str, decision: bool) -> None:
        """Store policy decision in Redis and local memory with TTL."""
        val_str = "1" if decision else "0"
        if self.r is not None:
            try:
                self.r.set(cache_key, val_str, ex=self.cache_ttl)
            except Exception:
                pass
        self._in_memory_cache[cache_key] = (decision, time.time() + self.cache_ttl)

    def invalidate_cache(self, user_id: Optional[str] = None) -> None:
        """Evict cached decisions from Redis and local memory."""
        self._in_memory_cache.clear()
        if self.r is not None:
            try:
                if user_id:
                    # Invalidate specific user cache
                    keys = self.r.keys("authnz:perm_cache:*")
                    if keys:
                        self.r.delete(*keys)
                else:
                    keys = self.r.keys("authnz:perm_cache:*")
                    if keys:
                        self.r.delete(*keys)
            except Exception as exc:
                logger.warning("Failed to invalidate Redis policy cache: %s", exc)

    async def evaluate_access(
        self,
        subject: Dict[str, Any],
        action: str,
        resource_type: str,
        resource_id: str,
        resource_attributes: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Evaluate access permission using cached decisions, OPA query, or local declarative engine.
        """
        sub_id = str(subject.get("id") or subject.get("user_id") or "")
        scope = (context or {}).get("workspace_id")
        cache_key = self._cache_key(sub_id, action, f"{resource_type}/{resource_id}", scope)

        # 1. Check Cache
        cached = self.get_cached_decision(cache_key)
        if cached is not None:
            return cached

        # 2. Try Open Policy Agent (OPA) if configured
        if self.opa.enabled:
            opa_payload = {
                "user": subject,
                "action": action,
                "resource": {
                    "type": resource_type,
                    "id": resource_id,
                    **(resource_attributes or {}),
                },
                "context": context or {},
            }
            opa_decision = await self.opa.evaluate_policy(opa_payload)
            if opa_decision is not None:
                self.cache_decision(cache_key, opa_decision)
                return opa_decision

        # 3. Fallback to Local Declarative Policy Engine
        # First check RBAC permission mapping
        user_roles = subject.get("roles", [])
        has_rbac = self.engine.has_permission(user_roles, f"{resource_type}:{action}")
        if has_rbac:
            self.cache_decision(cache_key, True)
            return True

        # Next check ABAC rules
        has_abac = self.engine.evaluate_abac(
            subject=subject,
            action=action,
            resource_type=resource_type,
            resource_attributes=resource_attributes or {},
            context=context,
        )

        self.cache_decision(cache_key, has_abac)
        return has_abac
