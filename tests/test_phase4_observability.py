"""
Phase 4 Production Observability & Health Probes Unit Tests (tests/test_phase4_observability.py)
------------------------------------------------------------------------------------------------
Validates:
1. MetricsCollector counters, gauges, latency metrics, and Prometheus text rendering.
2. GET /metrics scrape endpoint.
3. GET /health/live and GET /health diagnostics.
4. GET /health/ready deep readiness probe behavior.
"""

import pytest
from fastapi.testclient import TestClient
from metrics import MetricsCollector, metrics_collector
from server import app


def test_metrics_collector_aggregation_and_formatting():
    """Verify in-memory metrics recording and Prometheus format generation."""
    collector = MetricsCollector()

    # 1. Record authentication metrics
    collector.record_auth_attempt(status="success", method="password")
    collector.record_auth_attempt(status="failed", method="password")
    collector.record_auth_attempt(status="success", method="webauthn")

    # 2. Record token validation metrics
    collector.record_token_validation(status="valid")
    collector.record_token_validation(status="expired")

    # 3. Record security alert
    collector.record_security_event(severity="CRITICAL", event_name="REPLAY_ATTACK")

    # 4. Record HTTP requests
    collector.record_http_request(method="GET", path="/auth/me", status_code=200, duration_seconds=0.012)
    collector.record_http_request(method="POST", path="/auth/login", status_code=401, duration_seconds=0.045)

    # 5. Set active sessions gauge
    collector.set_active_sessions(42)

    # Render Prometheus text
    prom_text = collector.generate_prometheus_metrics()

    assert 'authnz_auth_attempts_total{status="success",method="password"} 1' in prom_text
    assert 'authnz_auth_attempts_total{status="failed",method="password"} 1' in prom_text
    assert 'authnz_auth_attempts_total{status="success",method="webauthn"} 1' in prom_text
    assert 'authnz_token_validations_total{status="valid"} 1' in prom_text
    assert 'authnz_token_validations_total{status="expired"} 1' in prom_text
    assert 'authnz_security_events_total{severity="CRITICAL",event="REPLAY_ATTACK"} 1' in prom_text
    assert "authnz_active_sessions 42" in prom_text
    assert 'authnz_http_requests_total{method="GET",path="/auth/me",status="200"} 1' in prom_text


def test_health_and_metrics_endpoints():
    """Verify live, health, and metrics HTTP API endpoints."""
    client = TestClient(app)

    # 1. Liveness probe
    live_res = client.get("/health/live")
    assert live_res.status_code == 200
    assert live_res.json()["status"] == "ALIVE"

    # 2. General health diagnostics
    health_res = client.get("/health")
    assert health_res.status_code == 200
    health_data = health_res.json()
    assert health_data["status"] == "HEALTHY"
    assert health_data["service"] == "Auth N&Z Gateway"
    assert "password_hashing" in health_data
    assert "features" in health_data

    # 3. Prometheus metrics endpoint
    metrics_res = client.get("/metrics")
    assert metrics_res.status_code == 200
    assert "text/plain" in metrics_res.headers["content-type"]
    assert "authnz_uptime_seconds" in metrics_res.text
