"""
Auth N&Z - Guards Submodule (auth_nz.guards)
--------------------------------------------
Re-exports FastAPI declarative security guards and context models.
"""

from guards import (
    CurrentUser,
    CurrentWorkspace,
    require_auth,
    require_role,
    require_permission,
    get_current_workspace,
)

__all__ = [
    "CurrentUser",
    "CurrentWorkspace",
    "require_auth",
    "require_role",
    "require_permission",
    "get_current_workspace",
]
