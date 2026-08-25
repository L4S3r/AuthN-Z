package authnz

import rego.v1

# Default deny
default allow := false

# Role hierarchy numeric mapping
role_levels := {
    "superadmin": 5,
    "admin": 4,
    "developer": 3,
    "editor": 2,
    "viewer": 1,
}

# 1. Global Superadmin Bypass
allow if {
    input.user.roles[_] == "superadmin"
}

allow if {
    input.user.is_superadmin == true
}

# 2. Workspace Scoped Role Evaluation
allow if {
    required_role := input.required_role
    caller_role := input.user.workspace_role
    role_levels[caller_role] >= role_levels[required_role]
}

# 3. Fine-Grained Permission Evaluation
allow if {
    permission := input.permission
    caller_permissions := input.user.permissions
    caller_permissions[_] == permission
}

allow if {
    caller_permissions := input.user.permissions
    caller_permissions[_] == "*"
}

# 4. ABAC Rule: Document Ownership
allow if {
    input.action == "read"
    input.resource.type == "documents"
    input.resource.owner_id == input.user.id
}

# 5. ABAC Rule: Clearance Level and Department Matching
allow if {
    input.action == "read"
    input.resource.type == "documents"
    input.user.clearance >= input.resource.required_clearance
    input.user.department == input.resource.department
}

# 6. ABAC Rule: Public Resources
allow if {
    input.action == "read"
    input.resource.is_public == true
}

# 7. ABAC Rule: Task Creator Deletion
allow if {
    input.action == "delete"
    input.resource.type == "tasks"
    input.resource.created_by == input.user.email
    role_levels[input.user.workspace_role] >= 2
}
