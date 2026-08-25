"""
Auth N&Z - FastAPI Application Server (server.py)
-------------------------------------------------
Main gateway entrypoint mounting modular domain routers, CORS middleware,
RFC 7807 exception handlers, and service singletons.

Run locally with:
    uvicorn server:app --host 0.0.0.0 --port 8000 --reload
"""

from contextlib import asynccontextmanager
from typing import Any, Dict
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from config import settings
from database import get_engine
from models import Base
from exceptions import register_exception_handlers
from api.router import api_router
from api.dependencies import (
    hasher,
    user_repo as repo,
    ws_repo,
    sess_store,
    token_svc,
    mfa_prov,
    audit_log,
    device_trust_svc,
    oauth_mgr,
    task_repo,
    email_svc,
    auth,
    perm_eval,
    get_current_user,
    set_auth_cookies,
    clear_auth_cookies,
    set_trusted_device_cookie,
    clear_trusted_device_cookie,
    check_rate_limit,
)
from api.v1.websocket_router import ws_manager, create_and_push_notification

# Documentation gating based on environment
docs_url = "/docs" if settings.docs_enabled else None
redoc_url = "/redoc" if settings.docs_enabled else None
openapi_url = "/openapi.json" if settings.docs_enabled else None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan context manager handling async startup and table verification."""
    try:
        engine = get_engine()
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    except Exception:
        pass
    yield


# FastAPI Application Factory
app = FastAPI(
    lifespan=lifespan,
    title="Auth N&Z - Identity and Access Management System",
    description=(
        "Auth N&Z (Authentication & Authorization Engine)\n\n"
        "A modular, extensible security system providing:\n"
        "- Authentication (AuthN): Salted Bcrypt Hashing, Stateful Redis Sessions, and Stateless JWT Tokens.\n"
        "- Multi-Factor Authentication (MFA): RFC 6238 TOTP and Emergency Single-Use Recovery Codes.\n"
        "- Authorization (AuthZ): Hierarchical RBAC and Attribute-Based Access Control (ABAC) Policy Engine.\n"
        "- Telemetry: Structured Security Audit Trail and Query Interface."
    ),
    version="1.0.0",
    docs_url=docs_url,
    redoc_url=redoc_url,
    openapi_url=openapi_url,
    servers=[
        {
            "url": "https://auth-api.l4s3r.site",
            "description": "Production Gateway (Public HTTPS)",
        },
        {
            "url": "http://localhost:8000",
            "description": "Local Development Server",
        },
    ],
    swagger_ui_parameters={
        "persistAuthorization": True,
        "displayRequestDuration": True,
    },
)

import time
from fastapi import Request, Response
from metrics import metrics_collector

# Explicit CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ALLOWED_ORIGINS,
    allow_origin_regex=r"^https://(([a-zA-Z0-9_-]+\.)*l4s3r\.site|l4s3r-[a-zA-Z0-9_-]+\.vercel\.app)$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def prometheus_metrics_middleware(request: Request, call_next):
    """Automatically record HTTP request count and latency for Prometheus metrics."""
    t0 = time.perf_counter()
    try:
        response = await call_next(request)
        duration = time.perf_counter() - t0
        metrics_collector.record_http_request(
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            duration_seconds=duration,
        )
        return response
    except Exception as exc:
        duration = time.perf_counter() - t0
        metrics_collector.record_http_request(
            method=request.method,
            path=request.url.path,
            status_code=500,
            duration_seconds=duration,
        )
        raise exc


# Register RFC 7807 global exception boundaries
register_exception_handlers(app)

# Mount all modular domain routers
app.include_router(api_router)


@app.get("/", tags=["Health"])
async def root_health_check() -> Dict[str, str]:
    """Root health check probe for load balancers and deployment verification."""
    return {
        "status": "HEALTHY",
        "service": "Auth N&Z Gateway",
        "version": "1.0.0",
        "environment": settings.ENVIRONMENT,
        "message": "Authentication and Authorization Gateway is operating normally.",
    }
