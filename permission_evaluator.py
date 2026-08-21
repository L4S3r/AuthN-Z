"""
Component Role: Permission Evaluator (Authorization Engine)
-----------------------------------------------------------
This component evaluates whether an authenticated subject (user, service account, or API key) has the 
authority to execute a specific action on a given resource within a defined context (supporting RBAC,
ABAC, or PBAC models).

System Relationship:
After the Authenticator establishes *who* the user is, application endpoints, controllers, and services
invoke the PermissionEvaluator to determine *what* the subject is allowed to do. It consults policy rules,
assigned roles, resource ownership attributes, and environmental conditions (such as IP range or time),
returning authorization decisions that are subsequently recorded by the AuditLogger.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Set
import json
from user_repository import UserRepository

class abstractPermissionEvaluator(ABC):
    """Abstract interface defining access control and authorization policy evaluation mechanisms."""

    @abstractmethod
    def has_permission(
        self,
        subject_id: str,
        required_permission: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Check if a subject possesses a specific permission (e.g., 'documents:read', 'users:delete').

        Args:
            subject_id: The unique identifier of the user or subject requesting access.
            required_permission: The permission string or key being tested.
            context: Optional contextual parameters (e.g., tenant ID, organization ID, request timestamp).

        Returns:
            True if the subject has the required permission, False otherwise.

        Edge Cases to Consider:
            - Wildcard permissions (e.g., 'documents:*' satisfying 'documents:read').
            - Inherited permissions through hierarchical groups or nested roles.
            - Explicit deny rules overriding allow rules.
        """
        ...

    @abstractmethod
    def has_role(
        self,
        subject_id: str,
        required_role: str,
        scope: Optional[str] = None,
    ) -> bool:
        """
        Check if a subject is assigned a specific role (e.g., 'admin', 'editor', 'viewer').

        Args:
            subject_id: The unique identifier of the user or subject.
            required_role: The role name to verify.
            scope: Optional scoping boundary (e.g., 'org_123' or 'project_abc').

        Returns:
            True if the subject holds the role in the given scope, False otherwise.

        Edge Cases to Consider:
            - Role hierarchies (e.g., 'admin' implicitly inheriting 'editor' and 'viewer' rights).
            - Scoped vs. global role assignments.
            - Expired or time-bounded role assignments.
        """
        ...

    @abstractmethod
    def is_resource_accessible(
        self,
        subject_id: str,
        action: str,
        resource_type: str,
        resource_id: str,
        resource_attributes: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Evaluate fine-grained, resource-level access control (e.g., verifying if subject owns the resource).

        Args:
            subject_id: The identifier of the requesting user.
            action: The operation intended on the resource (e.g., 'edit', 'delete', 'download').
            resource_type: The domain model or category of resource (e.g., 'invoice', 'report').
            resource_id: The unique identifier of the target resource instance.
            resource_attributes: Optional attributes of the resource (e.g., {'owner_id': '...', 'is_public': True}).

        Returns:
            True if the action on the specific resource is permitted, False otherwise.

        Edge Cases to Consider:
            - Missing resource attributes requiring on-demand database fetches vs. caller-provided attributes.
            - Public vs. private resource accessibility.
            - Ownership-based bypasses (e.g., resource owner having full access regardless of general roles).
        """
        ...

    @abstractmethod
    def get_effective_permissions(
        self,
        subject_id: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        """
        Compile and return the complete, flattened list of distinct permissions granted to the subject.

        Args:
            subject_id: The identifier of the user or subject.
            context: Optional contextual parameters (e.g., current tenant or organization).

        Returns:
            A deduplicated list of permission strings currently granted to the subject.

        Edge Cases to Consider:
            - Performance overhead when resolving large role hierarchies.
            - Caching of computed effective permissions and cache invalidation on role changes.
            - Resolution of contradictory deny and allow rules.
        """
        ...

    @abstractmethod
    def evaluate_policy(
        self,
        subject_attributes: Dict[str, Any],
        action: str,
        resource_attributes: Dict[str, Any],
        environment_attributes: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Execute an Attribute-Based Access Control (ABAC) evaluation combining subject, action, resource, and environment.

        Args:
            subject_attributes: Attributes of the requester (e.g., {'id': '123', 'department': 'Finance', 'clearance': 3}).
            action: The requested action verb (e.g., 'approve_expense').
            resource_attributes: Attributes of the target (e.g., {'department': 'Finance', 'amount': 5000}).
            environment_attributes: Environmental variables (e.g., {'ip_address': '10.0.0.1', 'time': '14:00', 'mfa_verified': True}).

        Returns:
            True if the ABAC policy evaluates to permit, False if deny (default-deny principle).

        Edge Cases to Consider:
            - Strict default-deny posture on missing attributes or rule evaluation errors.
            - Order of policy evaluation and conflict resolution strategies (e.g., Deny-Overrides vs. Allow-Overrides).
        """
        ...
class PermissionEvaluator(abstractPermissionEvaluator):
    def __init__(
        self,
        user_repo:Optional[concreteUserRepository]=None,
        role_permissions:Optional[Dict[str,List[str]]]=None,
        role_hierarchy:Optional[Dict[str,List[str]]]=None
        ):
        self.user_repo=user_repo or concreteUserRepository()

        self.role_permissions=role_permissions or {
            "viewer":["documents:read","reports:read"],
            "editor":["documents:read","documents:write","documents:create","reports:read"],
            "admin":["*"]
        }
        self.role_hierarchy = role_hierarchy or {
            "admin": ["editor", "viewer"],
            "editor": ["viewer"],
            "viewer": [],
        }

    def _expand_roles(self,direct_roles:List[str])-> Set[str]:
        """Traverse role_hierarchy to resolve all inherited roles."""
        all_roles=set(direct_roles)
        queue=list(direct_roles)
        while queue:
            current_role=queue.pop(0)
            inherited_role=self.role_hierarchy.get(current_role,[])
            for r in inherited_role:
                if r not in all_roles:
                    all_roles.add(r)
                    queue.append(r)
        return all_roles
    
    def get_effective_permissions(
        self,
        subject_id:str,
        context:Optional[Dict[str,Any]]=None,
    )->List[str]:
        """Compile and return all distinct permissions granted via direct and inherited roles."""
        user=self.user_repo.get_by_id(subject_id)
        if not user or not user.get("is_active",1):
            return []
        raw_roles=user.get("roles",[])
        if isinstance(raw_roles,str):
            try:
                raw_roles=json.loads(raw_roles)
            except Exception:
                raw_roles=[]
        effective_roles=self._expand_roles(raw_roles)
        permissions:Set[str]=set()
        for role in effective_roles:
            perms_for_role=self.role_permissions.get(role,[])
            permissions.update(perms_for_role)
        return list(permissions)
    
    def has_permission(
        self,
        subject_id: str,
        required_permission: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Check if a subject possesses a specific permission (e.g., 'documents:read', 'users:delete')."""
        granted_permissions=self.get_effective_permissions(subject_id,context)

        if "*" in granted_permissions or required_permission in granted_permissions:
            return True
        for perm in granted_permissions:
            if perm.endswith(":*"):
                domain_prefix=perm[:-1]
                if required_permission.startswith(domain_prefix):
                    return True
        return False

    def has_role(
        self,
        subject_id: str,
        required_role: str,
        scope: Optional[str] = None,
    ) -> bool:
        """Check if a subject is assigned a specific role (e.g., 'admin', 'editor', 'viewer')."""
        user=self.user_repo.get_by_id(subject_id)
        if not user or not user.get("is_active",1):
            return False
        raw_roles=user.get("roles",[])
        if isinstance(raw_roles,str):
            try:
                raw_roles=json.loads(raw_roles)
            except Exception:
                raw_roles=[]
        effective_roles=self._expand_roles(raw_roles)
        return required_role in effective_roles
    
    def is_resource_accessible(
        self,
        subject_id: str,
        action: str,
        resource_type: str,
        resource_id: str,
        resource_attributes: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Evaluate fine-grained, resource-level access control (e.g., verifying if subject owns the resource)."""
        user=self.user_repo.get_by_id(subject_id)
        if not user or not user.get("is_active",1):
            return False

        #fallback if caller didn't provide resource_attributes
        attrs=resource_attributes or {}
        clean_action=action.strip().lower()
        clean_type=resource_type.strip().lower()
        #admin/role bypass
        if self.has_permission(subject_id,f"{clean_type}:{clean_action}") or self.has_role(subject_id,"admin"):
            return True
        #ownership check
        if attrs.get("owner_id")==str(subject_id):
            return True
        #public access
        if attrs.get("is_public") and clean_action in ("read","view","download"):
            return True
        #deny by default
        return False
    def evaluate_policy(
        self,
        subject_attributes: Dict[str, Any],
        action: str,
        resource_attributes: Dict[str, Any],
        environment_attributes: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Execute an Attribute-Based Access Control (ABAC) evaluation combining subject, action, resource, and environment."""
        #admin override
        if subject_attributes.get("role") == "admin" or "admin" in subject_attributes.get("roles",[]):
            return True
        #department match
        sub_dept=subject_attributes.get("department")
        res_dept=resource_attributes.get("department")
        if sub_dept and res_dept and sub_dept.lower() == res_dept.lower():
            user_clearance=subject_attributes.get("clearance",1)
            required_clearance=resource_attributes.get("required_clearance",1)
            if user_clearance>=required_clearance:
                return True
        #security clearance
        if subject_attributes.get("clearance",0) >= resource_attributes.get("required_clearance",1):
            return True
        #environmental constraints
        if environment_attributes and environment_attributes.get("mfa_required"):
            if not environment_attributes.get("mfa_verified",False):
                return False
        #ownership rule
        sub_id=subject_attributes.get("id")
        owner_id=resource_attributes.get("owner_id")
        if sub_id and owner_id and str(sub_id)==str(owner_id):
            return True
        #deny by default
        return False