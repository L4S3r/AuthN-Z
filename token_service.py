"""
Component Role: Token Service
-----------------------------
This component is responsible for creating, signing, parsing, and validating cryptographic tokens 
(such as JWTs, PASETOs, or signed bearer tokens) used for stateless authentication and authorization.

System Relationship:
Upon successful identity verification by the Authenticator, the TokenService issues access and refresh
tokens to the client. API gateways, middleware, or service boundaries then use this service to decode and
validate incoming bearer tokens, extracting claims (subject ID, roles, scopes, issuer) before passing the
context to the PermissionEvaluator for fine-grained authorization checks.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, Set
from datetime import datetime, timedelta, timezone
import jwt
import os
import secrets
import uuid

try:
    import redis
except ImportError:
    redis = None



class abstractTokenService(ABC):
    """Abstract interface defining cryptographic token creation, verification, and revocation mechanisms."""

    @abstractmethod
    def create_access_token(
        self,
        subject_id: str,
        claims: Optional[Dict[str, Any]] = None,
        lifetime_seconds: int = 900,
    ) -> str:
        """
        Mint a signed, short-lived access token containing subject identity and custom claims.

        Args:
            subject_id: Unique identifier of the authenticated user or entity (the 'sub' claim).
            claims: Optional dictionary of additional contextual claims (e.g., roles, permissions, tenant_id).
            lifetime_seconds: Token validity duration in seconds (default is 15 minutes / 900 seconds).

        Returns:
            A cryptographically signed token string.

        Edge Cases to Consider:
            - Preventing claim collisions with standard claims ('sub', 'iat', 'exp', 'iss', 'nbf').
            - Secret key or asymmetric signing key unavailability.
            - Handling negative or excessively large lifetime values.
        """
        ...

    @abstractmethod
    def create_refresh_token(
        self,
        subject_id: str,
        claims: Optional[Dict[str, Any]] = None,
        lifetime_seconds: int = 604800,
        family_id: Optional[str] = None,
    ) -> str:
        """
        Mint a long-lived refresh token associated with a token family for rotation and reuse detection.
        """
        ...

    @abstractmethod
    def revoke_family(self, family_id: str, lifetime_seconds: int = 604800) -> bool:
        """Revoke an entire token family upon token reuse / theft detection."""
        ...

    @abstractmethod
    def is_family_revoked(self, family_id: str) -> bool:
        """Check if a token family has been revoked."""
        ...

    @abstractmethod
    def decode_and_verify(self, token: str) -> Dict[str, Any]:
        """
        Validate token signature, expiration, issuer, and return the decoded payload/claims dictionary.
        """
        ...

    @abstractmethod
    def revoke_token(self, token_identifier: str, expires_at: Optional[int] = None) -> bool:
        """
        Add a token or token identifier (e.g., 'jti' claim) to a revocation blocklist.

        Args:
            token_identifier: The unique token ID ('jti') or full token string to invalidate.
            expires_at: Optional Unix timestamp when the token naturally expires (used for pruning blocklists).

        Returns:
            True if the token was successfully added to the revocation list, False otherwise.

        Edge Cases to Consider:
            - Automatic cleanup/TTL of blacklisted entries after their natural expiration date.
            - Handling revocation when distributed cache/datastore is temporarily unreachable.
        """
        ...

    @abstractmethod
    def is_token_revoked(self, token_identifier: str) -> bool:
        """
        Check if a given token identifier exists within the revocation blocklist.

        Args:
            token_identifier: The unique token ID ('jti') or hash to check.

        Returns:
            True if the token has been explicitly revoked prior to expiration, False otherwise.

        Edge Cases to Consider:
            - Fast lookup latency requirements for high-throughput request validation.
            - Fallback behavior during cache misses or store connectivity disruptions.
        """
        ...

import logging

logger = logging.getLogger("auth_nz.token_service")


class TokenService(abstractTokenService):
    def __init__(
        self,
        secret_key: Optional[str] = None,
        algorithm: str = "HS256",
        redis_client: Optional[Any] = None,
    ):
        self.algorithm = algorithm
        self.secret_key = secret_key or self._get_or_generate_secret_key()
        host_env = os.getenv("REDIS_HOST", "127.0.0.1")
        port_env = int(os.getenv("REDIS_PORT", "6379"))
        password_env = os.getenv("REDIS_PASSWORD", None)
        is_prod = os.getenv("ENVIRONMENT", "development").lower() == "production"
        require_redis = os.getenv("REQUIRE_REDIS", "false").lower() in ("true", "1") or is_prod

        if host_env == "localhost":
            host_env = "127.0.0.1"

        if redis_client is not None:
            self.r = redis_client
        elif redis is not None:
            try:
                self.r = redis.Redis(
                    host=host_env,
                    port=port_env,
                    password=password_env,
                    db=0,
                    decode_responses=True,
                    socket_connect_timeout=0.5,
                    socket_timeout=0.5,
                )
                self.r.ping()
            except Exception as exc:
                if require_redis:
                    raise RuntimeError(
                        f"CRITICAL CONFIGURATION ERROR: Redis is required for shared multi-worker JWT blocklist in production "
                        f"(ENVIRONMENT=production or REQUIRE_REDIS=true), but could not be reached at {host_env}:{port_env} ({exc})."
                    )
                logger.warning(
                    "[ARCHITECTURE NOTICE] Redis connection failed (%s). Falling back to in-memory JWT blocklist. "
                    "Warning: In-memory blocklists are not shared across multi-process workers (uvicorn --workers > 1).",
                    exc,
                )
                self.r = None
        else:
            if require_redis:
                raise RuntimeError(
                    "CRITICAL CONFIGURATION ERROR: The 'redis' Python package is required in production (ENVIRONMENT=production or REQUIRE_REDIS=true), but is not installed."
                )
            self.r = None
            logger.warning(
                "[ARCHITECTURE NOTICE] The 'redis' package is not installed. Falling back to in-memory JWT blocklist. "
                "Install with `python -m pip install redis` to enable shared Redis persistence."
            )
        self._in_memory_blocklist: Set[str] = set()
        self._in_memory_revoked_families: Set[str] = set()


    def _get_or_generate_secret_key(self, key_name: str = "JWT_SECRET_KEY") -> str:
        existing_key = os.environ.get(key_name)
        if existing_key:
            return existing_key
        if os.path.exists(".env"):
            with open(".env", "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith(f"{key_name}="):
                        return line.strip().split("=", 1)[1]
        new_key = secrets.token_urlsafe(32)
        with open(".env", "a", encoding="utf-8") as f:
            f.write(f"{key_name}={new_key}\n")
        print(f"Generated new secret key and saved to .env as '{key_name}'")
        return new_key

    def create_access_token(
        self,
        subject_id: str,
        claims: Optional[Dict[str, Any]] = None,
        lifetime_seconds: int = 900,
    ) -> str:
        """Mint a short-lived signed access token."""
        now = datetime.now(timezone.utc)
        exp = now + timedelta(seconds=lifetime_seconds)
        payload = {
            "sub": str(subject_id),
            "iat": now,
            "exp": exp,
            "jti": str(uuid.uuid4()),
            "type": "access",
        }
        if claims:
            for k, v in claims.items():
                if k not in payload:
                    payload[k] = v
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

    def create_refresh_token(
        self,
        subject_id: str,
        claims: Optional[Dict[str, Any]] = None,
        lifetime_seconds: int = 604800,
        family_id: Optional[str] = None,
    ) -> str:
        """Mint a long-lived refresh token associated with a token family."""
        now = datetime.now(timezone.utc)
        exp = now + timedelta(seconds=lifetime_seconds)
        fid = family_id or str(uuid.uuid4())
        payload = {
            "sub": str(subject_id),
            "iat": now,
            "exp": exp,
            "jti": str(uuid.uuid4()),
            "family_id": fid,
            "type": "refresh",
        }

        if claims:
            for k, v in claims.items():
                if k not in payload:
                    payload[k] = v
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

    def decode_and_verify(self, token: str) -> Dict[str, Any]:
        """Validate token signature, expiration, issuer, family, and return decoded payload/claims dictionary."""
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                options={"require": ["sub", "exp", "iat", "jti"]},
            )
            if self.is_token_revoked(payload["jti"]):
                raise ValueError("Token has been revoked")
            
            fid = payload.get("family_id")
            if fid and self.is_family_revoked(fid):
                raise ValueError("Token family has been revoked due to security violation")

            return payload
        except jwt.ExpiredSignatureError:
            raise ValueError("Token has expired")
        except jwt.InvalidTokenError as e:
            raise ValueError(f"Invalid token: {e}")

    def revoke_token(self, token_identifier: str, expires_at: Optional[int] = None) -> bool:
        """Add a token jti to the Redis revocation blocklist with matching TTL."""
        ttl = 604800  # Default 7 days fallback
        if expires_at is not None:
            now_ts = int(datetime.now(timezone.utc).timestamp())
            ttl = max(1, expires_at - now_ts)

        if self.r is not None:
            try:
                key = f"revoked_token:{token_identifier}"
                self.r.set(key, "1", ex=ttl)
                return True
            except Exception as exc:
                logger.error(
                    "Failed to record token revocation in Redis (%s). Falling back to memory.",
                    exc,
                )

        self._in_memory_blocklist.add(token_identifier)
        return True

    def is_token_revoked(self, token_identifier: str) -> bool:
        """Check if a token jti is in the Redis or fallback revocation blocklist."""
        if self.r is not None:
            try:
                key = f"revoked_token:{token_identifier}"
                return bool(self.r.exists(key))
            except Exception as exc:
                logger.error(
                    "Failed to query token revocation in Redis (%s). Falling back to memory.",
                    exc,
                )
        return token_identifier in self._in_memory_blocklist

    def revoke_family(self, family_id: str, lifetime_seconds: int = 604800) -> bool:
        """Revoke an entire token family upon token reuse / theft detection."""
        if self.r is not None:
            try:
                key = f"revoked_family:{family_id}"
                self.r.set(key, "1", ex=lifetime_seconds)
                return True
            except Exception as exc:
                logger.error(
                    "Failed to record family revocation in Redis (%s). Falling back to memory.",
                    exc,
                )
        self._in_memory_revoked_families.add(family_id)
        return True

    def is_family_revoked(self, family_id: str) -> bool:
        """Check if a token family has been revoked."""
        if self.r is not None:
            try:
                key = f"revoked_family:{family_id}"
                return bool(self.r.exists(key))
            except Exception as exc:
                logger.error(
                    "Failed to query family revocation in Redis (%s). Falling back to memory.",
                    exc,
                )
        return family_id in self._in_memory_revoked_families



concreteTokenService = TokenService


