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
from typing import Any, Dict, Optional
from datetime import datetime, timezone
import secrets
import json
import redis


class abstractSessionStore(ABC):
    """Abstract interface defining stateful session creation, retrieval, extension, and invalidation."""

    @abstractmethod
    def create_session(
        self,
        user_id: str,
        session_data: Optional[Dict[str, Any]] = None,
        ttl_seconds: int = 3600,
    ) -> str:
        """
        Initialize and store a new active session for a user, returning a unique session ID.

        Args:
            user_id: The unique identifier of the user logging in.
            session_data: Optional contextual data to attach to the session (e.g., IP address, user agent, login time).
            ttl_seconds: Time-To-Live in seconds before the session expires (default is 1 hour / 3600 seconds).

        Returns:
            A cryptographically secure, high-entropy session identifier string (e.g., UUID4 or 256-bit random hex).

        Edge Cases to Consider:
            - Enforcing maximum concurrent session limits per user (e.g., kicking oldest session).
            - Ensuring session ID generator entropy is sufficient to prevent brute-force guessing.
            - Serializing non-primitive objects within session_data safely.
        """
        ...

    @abstractmethod
    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve session state and metadata by session ID if it is valid and has not expired.

        Args:
            session_id: The unique session identifier string.

        Returns:
            A dictionary of session data (including user_id, timestamps, and custom attributes),
            or None if the session does not exist or has expired.

        Edge Cases to Consider:
            - Passive expiration handling (cleaning up lazily if the underlying store doesn't support native TTLs).
            - Handling corrupted or deserialization-resistant payload data.
        """
        ...

    @abstractmethod
    def update_session_data(self, session_id: str, session_data: Dict[str, Any]) -> bool:
        """
        Update or merge custom data stored inside an existing active session without modifying its TTL.

        Args:
            session_id: The unique session identifier.
            session_data: Dictionary of key-value pairs to update or add.

        Returns:
            True if the session exists and was updated, False if the session was not found or has expired.

        Edge Cases to Consider:
            - Race conditions during concurrent writes from parallel requests belonging to the same session.
            - Deep merging vs. shallow replacement of existing keys.
        """
        ...

    @abstractmethod
    def refresh_session_ttl(self, session_id: str, ttl_seconds: int = 3600) -> bool:
        """
        Extend the expiration time of an active session (sliding expiration).

        Args:
            session_id: The unique session identifier.
            ttl_seconds: The new duration from the current moment until expiration.

        Returns:
            True if the session was successfully refreshed, False if the session does not exist.

        Edge Cases to Consider:
            - Respecting an absolute maximum session lifetime limit regardless of sliding activity extensions.
            - Frequency throttling of TTL refreshes to avoid excessive database/cache writes on high-frequency requests.
        """
        ...

    @abstractmethod
    def delete_session(self, session_id: str) -> bool:
        """
        Explicitly terminate and remove a single session (e.g., during single-device logout).

        Args:
            session_id: The unique session identifier to destroy.

        Returns:
            True if the session existed and was removed, False if it was already absent.

        Edge Cases to Consider:
            - Handling idempotent deletion calls safely without raising errors.
        """
        ...

    @abstractmethod
    def delete_all_user_sessions(self, user_id: str, except_session_id: Optional[str] = None) -> int:
        """
        Invalidate all active sessions belonging to a specific user (e.g., password change, security reset, or 'logout all devices').

        Args:
            user_id: The identifier of the user whose sessions should be terminated.
            except_session_id: Optional session ID to preserve (e.g., keeping the user's current session alive).

        Returns:
            The total number of sessions successfully deleted/invalidated.

        Edge Cases to Consider:
            - Indexing efficiency: quickly discovering all session keys belonging to a specific user without scanning the entire database.
            - Handling partial failures if multiple keys are deleted in a distributed environment.
        """
        ...

class SessionStore(abstractSessionStore):
    def __init__(self,host="localhost",port=6379,db=0,ttl=1800):
        self.r=redis.Redis(host=host,port=port,db=db,decode_responses=True)
        self.ttl=ttl

    def create_session(self,
    user_id:str,
    session_data:Optional[Dict[str,Any]] = None,
    ttl_seconds: int =3600
    ) -> str:

        """Initialize and store a new active session for a user, returning a unique session ID"""
        session_id=secrets.token_urlsafe(32)
        session_key=f"session:{session_id}"

        session_payload={
            "user_id":user_id,
            "created_at":datetime.utcnow().isoformat(),
            "data":json.dumps(session_data or {})
        }

        self.r.hset(session_key,mapping=session_payload)
        self.r.expire(session_key,ttl_seconds)

        user_session_key=f"user_sessions:{user_id}"
        self.r.sadd(user_session_key,session_id)
        self.r.expire(user_session_key,ttl_seconds)
        return session_id
    
    def get_session(self,session_id:str) -> Optional[Dict[str,Any]]:
        """Retrieve session state and metadata by session ID if it is valid and has not expired."""
        session_key=f"session:{session_id}"
        session=self.r.hgetall(session_key)

        if not session:
            return None
        if "data" in session:
            try:
                session["data"]=json.loads(session["data"])
            except (ValueError,TypeError):
                session["data"]={}
        return session
    def update_session_data(self,session_id:str,session_data:Dict[str,Any])->bool:
        """Update or merge custom data stored inside an existing active session without modifying its TTL."""
        session_key=f"session:{session_id}"
        current_session=self.get_session(session_id)

        if not current_session:
            return False
        
        current_data=current_session.get("data",{})
        current_data.update(session_data)
        self.r.hset(session_key,"data",json.dumps(current_data))
        return True
    def refresh_session_ttl(self,session_id:str,ttl_seconds:int=3600)->bool:
        """Extend the expiration time of an active session (sliding expiration)"""
        session_key=f"session:{session_id}"
        ttl_to_apply=ttl_seconds if ttl_seconds is not None else self.ttl
        return bool(self.r.expire(session_key,ttl_to_apply))
    def delete_session(self,session_id:str)->bool:
        """Explicitly terminate and remove a single session (e.g., during single-device logout)"""
        session_key=f"session:{session_id}"
        current=self.get_session(session_id)
        if current and "user_id" in current:
            self.r.srem(f"user_sessions:{current['user_id']}",session_id)
        return bool(self.r.delete(session_key))
    def delete_all_user_sessions(self, user_id: str, except_session_id: Optional[str] = None) -> int:
        """Invalidate all active sessions belonging to a specific user (e.g., password change, security reset, or 'logout all devices')."""
        user_index_key=f"user_sessions{user_id}"
        session_ids=self.r.smembers(user_index_key)
        if not session_ids:
            return 0
        sessions_to_delete=[sid for sid in session_ids if sid != except_session_id]
        if not sessions_to_delete:
            return 0
        keys_to_delete=[f"session:{sid}" for sid in sessions_to_delete]
        pipe=self.r.pipeline()
        pipe.delete(*keys_to_delete)
        pipe.srem(user_index_key,*sessions_to_delete)
        if not except_session_id or len(sessions_to_delete)==len(session_ids):
            pipe.delete(user_index_key)
        
        pipe.execute()
        return len(sessions_to_delete)
        

    

        
