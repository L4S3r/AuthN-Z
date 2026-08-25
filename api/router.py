"""
Auth N&Z - Top-Level API Router (api/router.py)
----------------------------------------------
Aggregates versioned domain sub-routers (e.g. v1) into a centralized API gateway router.
"""

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

api_router = APIRouter()

#mount all domain routers into top-level API router
api_router.include_router(auth_router)
api_router.include_router(mfa_router)
api_router.include_router(device_trust_router)
api_router.include_router(workspace_router)
api_router.include_router(team_router)
api_router.include_router(oauth_router)
api_router.include_router(audit_router)
api_router.include_router(notification_router)
api_router.include_router(websocket_router)
api_router.include_router(task_router)
api_router.include_router(webauthn_router)
api_router.include_router(health_router)
api_router.include_router(policy_router)
