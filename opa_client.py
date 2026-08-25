"""
Auth N&Z - Open Policy Agent (OPA) Client (opa_client.py)
--------------------------------------------------------
Provides asynchronous communication with Open Policy Agent (OPA) daemon / sidecars
for evaluating declarative Rego authorization policies with circuit-breaker protection.
"""

from typing import Any, Dict, Optional
import logging
import httpx
from config import settings

logger = logging.getLogger("auth_nz.opa_client")


class OPAClient:
    """Non-blocking HTTP client for Open Policy Agent evaluation queries."""

    def __init__(
        self,
        endpoint_url: Optional[str] = None,
        timeout_seconds: Optional[float] = None,
        enabled: Optional[bool] = None,
    ):
        self.endpoint_url = endpoint_url or settings.OPA_URL
        self.timeout = timeout_seconds or settings.OPA_TIMEOUT_SECONDS
        self.enabled = enabled if enabled is not None else settings.OPA_ENABLED
        self._consecutive_failures = 0
        self._circuit_open = False

    async def evaluate_policy(self, input_data: Dict[str, Any]) -> Optional[bool]:
        """
        Query OPA decision endpoint: POST /v1/data/<package>/<rule>
        Payload format: {"input": { ... }}
        Returns boolean decision or None if OPA is disabled/unreachable.
        """
        if not self.enabled:
            return None

        if self._circuit_open and self._consecutive_failures >= 5:
            # Circuit open: fast fallback without blocking
            return None

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                res = await client.post(
                    self.endpoint_url,
                    json={"input": input_data},
                    headers={"Content-Type": "application/json"},
                )

                if res.status_code == 200:
                    data = res.json()
                    self._consecutive_failures = 0
                    self._circuit_open = False
                    # OPA returns {"result": true/false} or {"result": {"allow": true}}
                    result = data.get("result")
                    if isinstance(result, bool):
                        return result
                    elif isinstance(result, dict):
                        return bool(result.get("allow", False))
                    return bool(result)
                else:
                    logger.warning("OPA query returned non-200 status %d: %s", res.status_code, res.text)
                    self._record_failure()
                    return None

        except Exception as exc:
            logger.warning("Failed to query OPA server at %s: %s", self.endpoint_url, exc)
            self._record_failure()
            return None

    def _record_failure(self) -> None:
        self._consecutive_failures += 1
        if self._consecutive_failures >= 5:
            self._circuit_open = True
            logger.error("OPA circuit breaker opened after 5 consecutive timeouts/failures. Falling back to local engine.")

    def reset_circuit(self) -> None:
        self._consecutive_failures = 0
        self._circuit_open = False
