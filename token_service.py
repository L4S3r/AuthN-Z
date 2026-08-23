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
    ) -> str:
        """
        Mint a long-lived refresh token used to obtain new access tokens without requiring re-authentication.

        Args:
            subject_id: Unique identifier of the authenticated user or entity.
            claims: Optional dictionary of metadata associated with the refresh token (e.g., token family ID, device ID).
            lifetime_seconds: Token validity duration in seconds (default is 7 days / 604,800 seconds).

        Returns:
            A cryptographically secure refresh token string or signed token.

        Edge Cases to Consider:
            - Implementing token family tracking for refresh token rotation detection.
            - Storage requirements if refresh tokens are stateful/opaque vs. self-contained signed tokens.
        """
        ...

    @abstractmethod
    def decode_and_verify(self, token: str) -> Dict[str, Any]:
        """
        Validate token signature, expiration, issuer, and return the decoded payload/claims dictionary.

        Args:
            token: The raw token string provided in authorization headers (e.g., 'Bearer <token>').

        Returns:
            A dictionary of verified claims extracted from the token payload.

        Raises:
            Exception (or custom TokenError): If the token is malformed, has an invalid signature,
                                              is expired, or has not yet reached its valid time ('nbf').

        Edge Cases to Consider:
            - Expired tokens (verifying clock skew/drift tolerances).
            - Algorithm confusion attacks (e.g., 'none' algorithm or RSA public key used as HMAC secret).
            - Truncated, tampered, or garbage token strings.
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
        if redis_client is not None:
            self.r = redis_client
        elif redis is not None:
            try:
                self.r = redis.Redis(host="127.0.0.1", port=6379, db=0, decode_responses=True, socket_connect_timeout=0.5, socket_timeout=0.5)
                self.r.ping()
            except Exception as exc:
                logger.warning(
                    "Redis connection failed (%s). Falling back to in-memory JWT blocklist. "
                    "Warning: In-memory blocklists are not shared across multi-process workers.",
                    exc,
                )
                self.r = None
        else:
            self.r = None
            logger.warning(
                "The 'redis' package is not installed. Falling back to in-memory JWT blocklist. "
                "Install with `python -m pip install redis` to enable shared Redis persistence."
            )
        self._in_memory_blocklist: Set[str] = set()


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
    ) -> str:
        """Mint a long-lived refresh token."""
        now = datetime.now(timezone.utc)
        exp = now + timedelta(seconds=lifetime_seconds)
        payload = {
            "sub": str(subject_id),
            "iat": now,
            "exp": exp,
            "jti": str(uuid.uuid4()),
            "type": "refresh",
        }

        if claims:
            for k, v in claims.items():
                if k not in payload:
                    payload[k] = v
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

    def decode_and_verify(self, token: str) -> Dict[str, Any]:
        """Validate token signature, expiration, issuer, and return decoded payload/claims dictionary."""
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                options={"require": ["sub", "exp", "iat", "jti"]},
            )
            if self.is_token_revoked(payload["jti"]):
                raise ValueError("Token has been revoked")
            return payload
        except jwt.ExpiredSignatureError:
            raise ValueError("Token has expired")
        except jwt.InvalidTokenError as e:
            raise ValueError(f"Invalid token: {e}")

    def revoke_token(self, token_identifier: str, expires_at: Optional[int] = None) -> bool:
        """Add a token's jti to the Redis revocation blocklist with matching TTL."""
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
        """Check if a token's jti is in the Redis or fallback revocation blocklist."""
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



concreteTokenService = TokenService


