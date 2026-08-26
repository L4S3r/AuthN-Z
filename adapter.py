"""
Auth N&Z - Adapter & Framework Configuration Layer (adapter.py)
---------------------------------------------------------------
Provides the programmatic configuration interface and unified AuthNZ adapter
for integrating Auth N&Z into host FastAPI applications, supporting custom
User models (BYOU), custom database session providers, and selective routing.
"""

from typing import Any, Callable, Dict, List, Optional, Type
import logging
from fastapi import APIRouter
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from config import settings
from password_hasher import abstractPasswordHasher
from user_repository import UserRepository, abstractUserRepository
from workspace_repository import WorkspaceRepository
from api.router import (
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
import api.dependencies as deps

logger = logging.getLogger("auth_nz.adapter")


def configure_authnz(
    *,
    user_model: Optional[Type[Any]] = None,
    session_factory: Optional[async_sessionmaker[AsyncSession]] = None,
    jwt_secret_key: Optional[str] = None,
    password_hasher: Optional[abstractPasswordHasher] = None,
    user_repository: Optional[abstractUserRepository] = None,
    workspace_repository: Optional[Any] = None,
    redis_client: Optional[Any] = None,
    password_hash_algorithm: Optional[str] = None,
    access_token_expire_minutes: Optional[int] = None,
    refresh_token_expire_days: Optional[int] = None,
) -> None:
    """
    Global configuration helper for Auth N&Z.
    Configures shared dependencies, models, and cryptographic parameters across the entire framework.
    """
    if jwt_secret_key:
        settings.JWT_SECRET_KEY = jwt_secret_key
        deps.token_svc.secret_key = jwt_secret_key

    if password_hash_algorithm:
        settings.PASSWORD_HASH_ALGORITHM = password_hash_algorithm

    if access_token_expire_minutes is not None:
        settings.ACCESS_TOKEN_EXPIRE_MINUTES = access_token_expire_minutes
        deps.token_svc.access_token_expire_minutes = access_token_expire_minutes

    if refresh_token_expire_days is not None:
        settings.REFRESH_TOKEN_EXPIRE_DAYS = refresh_token_expire_days
        deps.token_svc.refresh_token_expire_days = refresh_token_expire_days

    if password_hasher is not None:
        deps.hasher = password_hasher
        deps.auth.hasher = password_hasher

    if redis_client is not None:
        if hasattr(deps.sess_store, "r"):
            deps.sess_store.r = redis_client
        if hasattr(deps.token_svc, "r"):
            deps.token_svc.r = redis_client
        if hasattr(deps.oauth_mgr, "r"):
            deps.oauth_mgr.r = redis_client
        if hasattr(deps.webauthn_svc, "r"):
            deps.webauthn_svc.r = redis_client

    if session_factory is not None:
        deps.user_repo.session_factory = session_factory
        deps.ws_repo.session_factory = session_factory
        deps.task_repo.session_factory = session_factory

    if user_model is not None:
        deps.user_repo.user_model = user_model

    if user_repository is not None:
        deps.user_repo = user_repository
        deps.auth.user_repo = user_repository
        deps.perm_eval.user_repo = user_repository

    if workspace_repository is not None:
        deps.ws_repo = workspace_repository
        deps.perm_eval.workspace_repo = workspace_repository

    logger.info("Auth N&Z configured successfully for host application.")


class AuthNZ:
    """
    Unified Object-Oriented Framework Adapter for Auth N&Z.
    Encapsulates configuration, user models, and router generation for host applications.
    """

    def __init__(
        self,
        *,
        user_model: Optional[Type[Any]] = None,
        session_factory: Optional[async_sessionmaker[AsyncSession]] = None,
        jwt_secret_key: Optional[str] = None,
        redis_client: Optional[Any] = None,
        password_hash_algorithm: Optional[str] = None,
        user_repository: Optional[abstractUserRepository] = None,
    ):
        configure_authnz(
            user_model=user_model,
            session_factory=session_factory,
            jwt_secret_key=jwt_secret_key,
            redis_client=redis_client,
            password_hash_algorithm=password_hash_algorithm,
            user_repository=user_repository,
        )
        self.user_model = user_model
        self.session_factory = session_factory

    def create_router(
        self,
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
        """Construct a modular APIRouter with custom feature toggles."""
        return create_authnz_router(
            enable_auth=enable_auth,
            enable_mfa=enable_mfa,
            enable_webauthn=enable_webauthn,
            enable_device_trust=enable_device_trust,
            enable_workspaces=enable_workspaces,
            enable_team=enable_team,
            enable_oauth=enable_oauth,
            enable_audit=enable_audit,
            enable_notifications=enable_notifications,
            enable_websockets=enable_websockets,
            enable_health=enable_health,
            enable_policies=enable_policies,
            enable_tasks=enable_tasks,
            prefix=prefix,
            tags=tags,
        )

    # Sub-router accessors
    @property
    def auth_router(self) -> APIRouter:
        return auth_router

    @property
    def mfa_router(self) -> APIRouter:
        return mfa_router

    @property
    def webauthn_router(self) -> APIRouter:
        return webauthn_router

    @property
    def device_trust_router(self) -> APIRouter:
        return device_trust_router

    @property
    def workspace_router(self) -> APIRouter:
        return workspace_router

    @property
    def team_router(self) -> APIRouter:
        return team_router

    @property
    def oauth_router(self) -> APIRouter:
        return oauth_router

    @property
    def audit_router(self) -> APIRouter:
        return audit_router

    @property
    def notification_router(self) -> APIRouter:
        return notification_router

    @property
    def websocket_router(self) -> APIRouter:
        return websocket_router

    @property
    def task_router(self) -> APIRouter:
        return task_router

    @property
    def health_router(self) -> APIRouter:
        return health_router

    @property
    def policy_router(self) -> APIRouter:
        return policy_router


AuthNZAdapter = AuthNZ

__all__ = [
    "configure_authnz",
    "AuthNZ",
    "AuthNZAdapter",
]
