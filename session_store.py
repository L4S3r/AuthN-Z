"""
Component Role: Session Store
----------------------------
This component manages stateful user sessions, tracking active logins, session metadata,
and sliding or fixed expiration times in a persistent or in-memory store (e.g., Redis, DB).

System Relationship:
Used as an alternative or complementary mechanism to stateless tokens. When the Authenticator
validates user credentials in a stateful architecture, it creates an active session in the SessionStore.
Incoming HTTP requests provide a session ID (usually via secure cookies), which this component resolves
to the associated user ID and session context. It also enables features like remote logout, single-sign-on
session management, and concurrent session revocation.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, Set
from datetime import datetime, timezone
import secrets
import json
import os
try:
    import redis
except ImportError:
    redis = None


class abstractSessionStore(ABC):
    """Abstract interface defining stateful session creation, retrieval, extension, and invalidation."""

    @abstractmethod
    def create_session(
        self,
        user_id: str,
        session_data: Optional[Dict[str, Any]] = None,
        ttl_seconds: int = 3600,
    ) -> str:
        pass

    @abstractmethod
    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    def update_session_data(
        self, session_id: str, session_data: Dict[str, Any]
    ) -> bool:
        pass

    @abstractmethod
    def refresh_session_ttl(
        self, session_id: str, ttl_seconds: int = 3600
    ) -> bool:
        pass

    @abstractmethod
    def delete_session(self, session_id: str) -> bool:
        pass

    @abstractmethod
    def delete_all_user_sessions(
        self, user_id: str, except_session_id: Optional[str] = None
    ) -> int:
        pass


from config import settings
import logging

logger = logging.getLogger("auth_nz.session_store")


class SessionStore(abstractSessionStore):
    def __init__(self, host=None, port=None, db=None, ttl=1800):
        self.ttl = ttl
        self._in_memory_sessions: Dict[str, Dict[str, Any]] = {}
        self._in_memory_user_index: Dict[str, Set[str]] = {}

        host_env = host or settings.REDIS_HOST
        port_env = port or settings.REDIS_PORT
        db_env = db if db is not None else settings.REDIS_DB
        password_env = settings.REDIS_PASSWORD
        require_redis = (settings.REQUIRE_REDIS or settings.is_production) and not settings.is_testing
        is_testing = settings.is_testing
        if is_testing and not settings.REQUIRE_REDIS:
            self.r = None
        elif redis is not None:
            try:
                self.r = redis.Redis(
                    host=host_env,
                    port=port_env,
                    password=password_env,
                    db=db,
                    decode_responses=True,
                    socket_connect_timeout=0.2,
                    socket_timeout=0.2,
                )
                self.r.ping()
            except Exception as exc:
                if require_redis:
                    raise RuntimeError(
                        f"CRITICAL CONFIGURATION ERROR: Redis is required for shared multi-worker state in production "
                        f"(ENVIRONMENT=production or REQUIRE_REDIS=true), but could not be reached at {host_env}:{port_env} ({exc}). "
                        f"Refusing to start with process-isolated in-memory state."
                    )
                logger.warning(
                    "[ARCHITECTURE NOTICE] Redis session store unreachable at %s:%s (%s). "
                    "Running in SINGLE-WORKER in-memory mode. "
                    "Sessions are not shared across multi-process workers (uvicorn --workers > 1).",
                    host_env,
                    port_env,
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
                "[ARCHITECTURE NOTICE] The 'redis' package is not installed. Running in SINGLE-WORKER in-memory mode. "
                "Install with `python -m pip install redis` to enable shared Redis persistence."
            )

    def create_session(
        self,
        user_id: str,
        session_data: Optional[Dict[str, Any]] = None,
        ttl_seconds: int = 3600,
    ) -> str:
        """Initialize and store a new active session for a user, returning a unique session ID."""
        session_id = secrets.token_urlsafe(32)

        session_payload = {
            "user_id": user_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "data": json.dumps(session_data or {}),
        }

        if self.r is not None:
            try:
                session_key = f"session:{session_id}"
                self.r.hset(session_key, mapping=session_payload)
                self.r.expire(session_key, ttl_seconds)

                user_session_key = f"user_sessions:{user_id}"
                self.r.sadd(user_session_key, session_id)
                self.r.expire(user_session_key, ttl_seconds)
                return session_id
            except Exception as exc:
                logger.error("Redis create_session failed (%s). Falling back to memory.", exc)

        # In-memory fallback
        self._in_memory_sessions[session_id] = session_payload
        self._in_memory_user_index.setdefault(user_id, set()).add(session_id)
        return session_id

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve session state and metadata by session ID if valid."""
        session = None
        if self.r is not None:
            try:
                session_key = f"session:{session_id}"
                session = self.r.hgetall(session_key)
            except Exception as exc:
                logger.error("Redis get_session failed (%s). Checking memory.", exc)

        if not session:
            session = self._in_memory_sessions.get(session_id)

        if not session:
            return None

        parsed = dict(session)
        if "data" in parsed and isinstance(parsed["data"], str):
            try:
                data_dict = json.loads(parsed["data"])
                parsed["data"] = data_dict
                if isinstance(data_dict, dict):
                    for k, v in data_dict.items():
                        if k not in parsed:
                            parsed[k] = v
            except (ValueError, TypeError):
                parsed["data"] = {}
        elif isinstance(parsed.get("data"), dict):
            for k, v in parsed["data"].items():
                if k not in parsed:
                    parsed[k] = v
        return parsed

    def update_session_data(self, session_id: str, session_data: Dict[str, Any]) -> bool:
        """Update custom data stored inside an existing active session."""
        current_session = self.get_session(session_id)
        if not current_session:
            return False

        current_data = current_session.get("data", {})
        current_data.update(session_data)
        serialized = json.dumps(current_data)

        if self.r is not None:
            try:
                self.r.hset(f"session:{session_id}", "data", serialized)
                return True
            except Exception as exc:
                logger.error("Redis update_session_data failed (%s).", exc)

        if session_id in self._in_memory_sessions:
            self._in_memory_sessions[session_id]["data"] = serialized
            return True
        return False

    def refresh_session_ttl(self, session_id: str, ttl_seconds: int = 3600) -> bool:
        """Extend the expiration time of an active session (sliding expiration)."""
        ttl_to_apply = ttl_seconds if ttl_seconds is not None else self.ttl
        if self.r is not None:
            try:
                return bool(self.r.expire(f"session:{session_id}", ttl_to_apply))
            except Exception as exc:
                logger.error("Redis refresh_session_ttl failed (%s).", exc)
        return session_id in self._in_memory_sessions

    def delete_session(self, session_id: str) -> bool:
        """Explicitly terminate and remove a single session."""
        current = self.get_session(session_id)
        user_id = current.get("user_id") if current else None

        if self.r is not None:
            try:
                if user_id:
                    self.r.srem(f"user_sessions:{user_id}", session_id)
                return bool(self.r.delete(f"session:{session_id}"))
            except Exception as exc:
                logger.error("Redis delete_session failed (%s).", exc)

        if user_id and user_id in self._in_memory_user_index:
            self._in_memory_user_index[user_id].discard(session_id)
        return self._in_memory_sessions.pop(session_id, None) is not None

    def delete_all_user_sessions(
        self, user_id: str, except_session_id: Optional[str] = None
    ) -> int:
        """Invalidate all active sessions belonging to a specific user."""
        count = 0
        if self.r is not None:
            try:
                user_index_key = f"user_sessions:{user_id}"
                session_ids = self.r.smembers(user_index_key)
                if session_ids:
                    sessions_to_delete = [
                        sid for sid in session_ids if sid != except_session_id
                    ]
                    if sessions_to_delete:
                        keys_to_delete = [f"session:{sid}" for sid in sessions_to_delete]
                        pipe = self.r.pipeline()
                        pipe.delete(*keys_to_delete)
                        pipe.srem(user_index_key, *sessions_to_delete)
                        if not except_session_id or len(sessions_to_delete) == len(session_ids):
                            pipe.delete(user_index_key)
                        pipe.execute()
                        count = len(sessions_to_delete)
            except Exception as exc:
                logger.error("Redis delete_all_user_sessions failed (%s).", exc)

        # Clear in-memory as well
        if user_id in self._in_memory_user_index:
            sids = list(self._in_memory_user_index[user_id])
            for sid in sids:
                if sid != except_session_id:
                    self._in_memory_sessions.pop(sid, None)
                    self._in_memory_user_index[user_id].discard(sid)
                    count += 1

        return count


concreteSessionStore = SessionStore
