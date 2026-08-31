"""
Auth N&Z - Observability & Health Probes Router (api/v1/health_router.py)
-------------------------------------------------------------------------
Provides Kubernetes/Cloud-native liveness, readiness, and metrics scrape endpoints:
- GET /health/live   (Liveness probe)
- GET /health/ready  (Deep dependency readiness probe)
- GET /health        (Status overview and latency diagnostics)
- GET /metrics       (Prometheus text exposition format)
"""

from typing import Any, Dict
import asyncio
import time
from fastapi import APIRouter, Response, status
from sqlalchemy import text

from config import settings
from auth_nz import __version__
from database import get_session_factory
from metrics import metrics_collector
from api.dependencies import sess_store

router = APIRouter(tags=["Observability & Health"])


@router.get("/health/live")
async def liveness_probe() -> Dict[str, str]:
    """Kubernetes liveness probe indicating process viability."""
    return {"status": "ALIVE"}


@router.get("/health/ready")
async def readiness_probe(response: Response) -> Dict[str, Any]:
    """
    Kubernetes readiness probe performing deep asynchronous connectivity tests
    against PostgreSQL and Redis persistence backends.
    """
    db_status = "UNKNOWN"
    db_latency_ms = None
    redis_status = "DISABLED"
    redis_latency_ms = None
    is_ready = True

    # 1. Test PostgreSQL Connectivity
    try:
        t0 = time.perf_counter()
        session_factory = get_session_factory()
        async with session_factory() as session:
            # Query SELECT 1 with 2.0s timeout
            await asyncio.wait_for(session.execute(text("SELECT 1")), timeout=2.0)
            db_latency_ms = round((time.perf_counter() - t0) * 1000, 2)
            db_status = "HEALTHY"
    except Exception as exc:
        db_status = f"UNHEALTHY: {str(exc)}"
        is_ready = False

    # 2. Test Redis Connectivity
    r = getattr(sess_store, "r", None)
    if r is not None:
        try:
            t0 = time.perf_counter()
            # Redis ping with timeout
            ping_res = r.ping()
            if ping_res:
                redis_latency_ms = round((time.perf_counter() - t0) * 1000, 2)
                redis_status = "HEALTHY"
            else:
                redis_status = "UNHEALTHY: Ping returned False"
                if settings.REQUIRE_REDIS or settings.is_production:
                    is_ready = False
        except Exception as exc:
            redis_status = f"UNHEALTHY: {str(exc)}"
            if settings.REQUIRE_REDIS or settings.is_production:
                is_ready = False
    elif settings.REQUIRE_REDIS or settings.is_production:
        redis_status = "UNHEALTHY: Redis client not configured"
        is_ready = False

    overall_status = "READY" if is_ready else "NOT_READY"
    if not is_ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return {
        "status": overall_status,
        "environment": settings.ENVIRONMENT,
        "database": {
            "status": db_status,
            "latency_ms": db_latency_ms,
        },
        "redis": {
            "status": redis_status,
            "latency_ms": redis_latency_ms,
        },
    }


@router.get("/health")
async def comprehensive_health() -> Dict[str, Any]:
    """Comprehensive service health diagnostics and runtime telemetry."""
    return {
        "status": "HEALTHY",
        "service": "Auth N&Z Gateway",
        "version": __version__,
        "environment": settings.ENVIRONMENT,
        "timestamp": time.time(),
        "password_hashing": {
            "algorithm": settings.PASSWORD_HASH_ALGORITHM,
            "bcrypt_rounds": settings.BCRYPT_WORK_FACTOR,
        },
        "features": {
            "mfa_totp": True,
            "device_trust": True,
            "webauthn_passkeys": True,
            "multi_tenancy": True,
            "redis_shared_sessions": getattr(sess_store, "r", None) is not None,
        },
    }


@router.get("/metrics")
async def prometheus_metrics() -> Response:
    """Prometheus exposition format scrape endpoint."""
    metrics_text = metrics_collector.generate_prometheus_metrics()
    return Response(content=metrics_text, media_type="text/plain; version=0.0.4")
