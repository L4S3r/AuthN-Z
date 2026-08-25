"""
Auth N&Z - Prometheus Observability & Metrics Collector (metrics.py)
-------------------------------------------------------------------
Tracks high-resolution security telemetry, authentication success/failure rates,
token validation outcomes, and HTTP request latency in Prometheus exposition format.
"""

from typing import Dict, Tuple
from collections import defaultdict
from datetime import datetime, timezone
import logging
import threading
import time

logger = logging.getLogger("auth_nz.metrics")


class MetricsCollector:
    """Thread-safe Prometheus metrics collector for Auth N&Z."""

    def __init__(self):
        self._lock = threading.Lock()
        # Counters
        self.auth_attempts: Dict[Tuple[str, str], int] = defaultdict(int)  # (status, method) -> count
        self.token_validations: Dict[str, int] = defaultdict(int)         # status -> count
        self.security_events: Dict[Tuple[str, str], int] = defaultdict(int) # (severity, event) -> count
        self.http_requests: Dict[Tuple[str, str, int], int] = defaultdict(int) # (method, endpoint, status_code) -> count
        self.http_latencies: Dict[Tuple[str, str], float] = defaultdict(float) # (method, endpoint) -> total_seconds
        self.http_counts: Dict[Tuple[str, str], int] = defaultdict(int)        # (method, endpoint) -> request_count
        self.active_sessions: int = 0
        self.start_time: float = time.time()

    def record_auth_attempt(self, status: str, method: str = "password") -> None:
        """Record an authentication attempt (e.g. status='success'|'failed'|'locked'|'mfa_required')."""
        with self._lock:
            self.auth_attempts[(status.lower(), method.lower())] += 1

    def record_token_validation(self, status: str) -> None:
        """Record token validation outcome (e.g. status='valid'|'expired'|'revoked'|'invalid')."""
        with self._lock:
            self.token_validations[status.lower()] += 1

    def record_security_event(self, severity: str, event_name: str) -> None:
        """Record security event occurrence."""
        with self._lock:
            self.security_events[(severity.upper(), event_name.upper())] += 1

    def record_http_request(self, method: str, path: str, status_code: int, duration_seconds: float) -> None:
        """Record HTTP request metrics."""
        # Sanitize path to prevent cardinality explosion
        clean_path = path.split("?")[0]
        # Replace UUIDs in path with {id} placeholder
        parts = clean_path.split("/")
        sanitized_parts = []
        for p in parts:
            if len(p) >= 32 and ("-" in p or p.isalnum()):
                sanitized_parts.append("{id}")
            else:
                sanitized_parts.append(p)
        clean_path = "/".join(sanitized_parts) or "/"

        with self._lock:
            self.http_requests[(method.upper(), clean_path, status_code)] += 1
            self.http_latencies[(method.upper(), clean_path)] += duration_seconds
            self.http_counts[(method.upper(), clean_path)] += 1

    def set_active_sessions(self, count: int) -> None:
        """Set current active session count gauge."""
        with self._lock:
            self.active_sessions = max(0, count)

    def generate_prometheus_metrics(self) -> str:
        """Render all metrics in Prometheus text exposition format (version 0.0.4)."""
        lines = []
        now_ts = time.time()
        uptime_seconds = int(now_ts - self.start_time)

        # Process Uptime
        lines.append("# HELP authnz_uptime_seconds Total runtime of the Auth N&Z gateway in seconds.")
        lines.append("# TYPE authnz_uptime_seconds gauge")
        lines.append(f"authnz_uptime_seconds {uptime_seconds}")

        with self._lock:
            # 1. Authentication Attempts
            lines.append("# HELP authnz_auth_attempts_total Total authentication attempts partitioned by status and method.")
            lines.append("# TYPE authnz_auth_attempts_total counter")
            for (status, method), count in self.auth_attempts.items():
                lines.append(f'authnz_auth_attempts_total{{status="{status}",method="{method}"}} {count}')

            # 2. Token Validations
            lines.append("# HELP authnz_token_validations_total Total token verification checks partitioned by outcome.")
            lines.append("# TYPE authnz_token_validations_total counter")
            for status, count in self.token_validations.items():
                lines.append(f'authnz_token_validations_total{{status="{status}"}} {count}')

            # 3. Security Events
            lines.append("# HELP authnz_security_events_total Security audit events and alerts partitioned by severity.")
            lines.append("# TYPE authnz_security_events_total counter")
            for (severity, event), count in self.security_events.items():
                lines.append(f'authnz_security_events_total{{severity="{severity}",event="{event}"}} {count}')

            # 4. Active Sessions Gauge
            lines.append("# HELP authnz_active_sessions Active authenticated user sessions.")
            lines.append("# TYPE authnz_active_sessions gauge")
            lines.append(f"authnz_active_sessions {self.active_sessions}")

            # 5. HTTP Requests Total
            lines.append("# HELP authnz_http_requests_total Total HTTP requests handled partitioned by method, path, and status code.")
            lines.append("# TYPE authnz_http_requests_total counter")
            for (method, path, status_code), count in self.http_requests.items():
                lines.append(f'authnz_http_requests_total{{method="{method}",path="{path}",status="{status_code}"}} {count}')

            # 6. HTTP Request Latency
            lines.append("# HELP authnz_http_request_duration_seconds_total Total duration of HTTP requests in seconds.")
            lines.append("# TYPE authnz_http_request_duration_seconds_total counter")
            for (method, path), total_sec in self.http_latencies.items():
                lines.append(f'authnz_http_request_duration_seconds_total{{method="{method}",path="{path}"}} {total_sec:.6f}')

        return "\n".join(lines) + "\n"


# Global Metrics Collector Singleton
metrics_collector = MetricsCollector()
