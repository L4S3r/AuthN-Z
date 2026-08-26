"""
Auth N&Z - Top-Level API Router & Factory (api/router.py)
---------------------------------------------------------
Aggregates versioned domain sub-routers into a centralized API gateway router
and provides the create_authnz_router factory for selective endpoint mounting.
"""

from typing import List, Optional
from fastapi import APIRouter

from api.v1.auth_router import router as auth_router
from api.v1.mfa_router import router as mfa_router
from api.v1.device_trust_router import router as device_trust_router
from api.v1.workspace_router import router as workspace_router
from api.v1.team_router import router as team_router
from api.v1.oauth_router import router as oauth_router
from api.v1.audit_router import router as audit_router
from api.v1.notification_router import router as notification_router
from api.v1.websocket_router import router as websocket_router
from api.v1.task_router import router as task_router
from api.v1.webauthn_router import router as webauthn_router
from api.v1.health_router import router as health_router
from api.v1.policy_router import router as policy_router


def create_authnz_router(
    *,
    enable_auth: bool = True,
    enable_mfa: bool = True,
    enable_webauthn: bool = True,
    enable_device_trust: bool = True,
    enable_workspaces: bool = True,
    enable_team: bool = True,
    enable_oauth: bool = True,
    enable_audit: bool = True,
    enable_notifications: bool = True,
    enable_websockets: bool = True,
    enable_health: bool = True,
    enable_policies: bool = True,
    enable_tasks: bool = True,
    prefix: str = "",
    tags: Optional[List[str]] = None,
) -> APIRouter:
    """
    Factory function to construct a modular Auth N&Z APIRouter with selective feature toggles.
    Allows host projects to mount only the specific IAM endpoints they require.
    """
    router = APIRouter(prefix=prefix, tags=tags or [])

    if enable_auth:
        router.include_router(auth_router)
    if enable_mfa:
        router.include_router(mfa_router)
    if enable_webauthn:
        router.include_router(webauthn_router)
    if enable_device_trust:
        router.include_router(device_trust_router)
    if enable_workspaces:
        router.include_router(workspace_router)
    if enable_team:
        router.include_router(team_router)
    if enable_oauth:
        router.include_router(oauth_router)
    if enable_audit:
        router.include_router(audit_router)
    if enable_notifications:
        router.include_router(notification_router)
    if enable_websockets:
        router.include_router(websocket_router)
    if enable_tasks:
        router.include_router(task_router)
    if enable_health:
        router.include_router(health_router)
    if enable_policies:
        router.include_router(policy_router)

    return router


# Default pre-aggregated API router (all features enabled)
api_router = create_authnz_router()

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
