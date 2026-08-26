"""
Auth N&Z - Routers Submodule (auth_nz.routers)
----------------------------------------------
Re-exports the router factory and individual domain sub-routers.
"""

from api.router import (
    api_router,
    create_authnz_router,
    auth_router,
    mfa_router,
    webauthn_router,
    device_trust_router,
    workspace_router,
    team_router,
    oauth_router,
    audit_router,
    notification_router,
    websocket_router,
    task_router,
    health_router,
    policy_router,
)

__all__ = [
    "api_router",
    "create_authnz_router",
    "auth_router",
    "mfa_router",
    "webauthn_router",
    "device_trust_router",
    "workspace_router",
    "team_router",
    "oauth_router",
    "audit_router",
    "notification_router",
    "websocket_router",
    "task_router",
    "health_router",
    "policy_router",
]
