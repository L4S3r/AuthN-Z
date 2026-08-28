"""
Component Role: User Repository (PostgreSQL Async)
-------------------------------------------------
This component acts as the data access layer for user accounts, identities, credential records,
and cryptographic password reset tokens using async SQLAlchemy (asyncpg) against PostgreSQL.

System Relationship:
The Authenticator queries this repository to find users by username, email, or ID to retrieve their
stored credentials and account status during login. The PermissionEvaluator consults it to
load assigned roles, groups, and privileges.
"""

from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
import hashlib
import json
import secrets
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional, Tuple
import uuid

from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from database import get_session_factory
from models import PasswordResetToken
from default_user import User as _DefaultUser
import logging
from config import settings

logger = logging.getLogger("auth_nz.user_repository")


class UserProfileCache:
    """Multi-tiered L1 (In-Memory LRU/TTL) and L2 (Redis) profile and metadata cache."""

    def __init__(self, redis_client: Optional[Any] = None, node_id: Optional[str] = None):
        self._l1_cache: Dict[str, Tuple[Dict[str, Any], float]] = {}
        self._l1_ident_map: Dict[str, Tuple[str, float]] = {}
        self.redis_client = redis_client
        self.node_id = node_id or str(uuid.uuid4())

    def set_redis_client(self, redis_client: Any) -> None:
        self.redis_client = redis_client

    def get_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        if not getattr(settings, "USER_CACHE_ENABLED", True) or not user_id:
            return None
        now = datetime.now(timezone.utc).timestamp()
        uid_str = str(user_id).strip()

        # 1. Check L1 Memory Cache
        entry = self._l1_cache.get(uid_str)
        if entry:
            data, exp = entry
            if now < exp:
                return dict(data)
            self._l1_cache.pop(uid_str, None)

        # 2. Check L2 Redis Cache
        if self.redis_client is not None:
            try:
                cached_json = self.redis_client.get(f"authnz:cache:user:{uid_str}")
                if cached_json:
                    data = json.loads(cached_json)
                    l1_exp = now + getattr(settings, "USER_CACHE_L1_TTL_SECONDS", 30)
                    self._l1_cache[uid_str] = (dict(data), l1_exp)
                    return dict(data)
            except Exception as exc:
                logger.debug("Redis profile cache get error: %s", exc)

        return None

    def get_user_by_identifier(self, identifier: str) -> Optional[Dict[str, Any]]:
        if not getattr(settings, "USER_CACHE_ENABLED", True) or not identifier:
            return None
        now = datetime.now(timezone.utc).timestamp()
        clean_id = identifier.strip().lower()

        # 1. Check L1 Identifier Index
        mapped = self._l1_ident_map.get(clean_id)
        if mapped:
            user_id, exp = mapped
            if now < exp:
                user = self.get_user(user_id)
                if user:
                    return user
            self._l1_ident_map.pop(clean_id, None)

        # 2. Check L2 Redis Identifier Index
        if self.redis_client is not None:
            try:
                user_id = self.redis_client.get(f"authnz:cache:ident:{clean_id}")
                if user_id:
                    user = self.get_user(user_id)
                    if user:
                        l1_exp = now + getattr(settings, "USER_CACHE_L1_TTL_SECONDS", 30)
                        self._l1_ident_map[clean_id] = (user_id, l1_exp)
                        return user
            except Exception as exc:
                logger.debug("Redis ident cache get error: %s", exc)

        return None

    def set_user(self, user_dict: Dict[str, Any]) -> None:
        if not getattr(settings, "USER_CACHE_ENABLED", True) or not user_dict or not user_dict.get("id"):
            return
        user_id = str(user_dict["id"]).strip()
        now = datetime.now(timezone.utc).timestamp()
        l1_exp = now + getattr(settings, "USER_CACHE_L1_TTL_SECONDS", 30)
        data_copy = dict(user_dict)

        self._l1_cache[user_id] = (data_copy, l1_exp)

        username = str(user_dict.get("username", "")).strip().lower()
        email = str(user_dict.get("email", "")).strip().lower()
        if username:
            self._l1_ident_map[username] = (user_id, l1_exp)
        if email:
            self._l1_ident_map[email] = (user_id, l1_exp)

        # Periodic cleanup of expired entries
        if len(self._l1_cache) > 2000:
            self._l1_cache = {k: v for k, v in self._l1_cache.items() if now < v[1]}
            self._l1_ident_map = {k: v for k, v in self._l1_ident_map.items() if now < v[1]}

        # L2 Redis storage
        if self.redis_client is not None:
            try:
                serialized = json.dumps(data_copy, default=str)
                ttl = getattr(settings, "USER_CACHE_TTL_SECONDS", 60)
                pipe = self.redis_client.pipeline()
                pipe.setex(f"authnz:cache:user:{user_id}", ttl, serialized)
                if username:
                    pipe.setex(f"authnz:cache:ident:{username}", ttl, user_id)
                if email:
                    pipe.setex(f"authnz:cache:ident:{email}", ttl, user_id)
                pipe.execute()
            except Exception as exc:
                logger.debug("Redis profile cache set error: %s", exc)

    def invalidate(
        self,
        user_id: Optional[str] = None,
        identifier: Optional[str] = None,
        publish_event: bool = True,
    ) -> None:
        """Invalidate user cache entry across L1, L2, and multi-node pub/sub."""
        if user_id:
            uid_str = str(user_id).strip()
            self._l1_cache.pop(uid_str, None)
            self._l1_ident_map = {k: v for k, v in self._l1_ident_map.items() if v[0] != uid_str}

        if identifier:
            clean_id = identifier.strip().lower()
            self._l1_ident_map.pop(clean_id, None)

        if self.redis_client is not None:
            try:
                keys = []
                if user_id:
                    keys.append(f"authnz:cache:user:{str(user_id).strip()}")
                if identifier:
                    keys.append(f"authnz:cache:ident:{identifier.strip().lower()}")
                if keys:
                    self.redis_client.delete(*keys)
                if publish_event:
                    envelope = {
                        "user_id": str(user_id).strip() if user_id else None,
                        "identifier": str(identifier).strip().lower() if identifier else None,
                        "_origin_node_id": self.node_id,
                    }
                    self.redis_client.publish("authnz:cache:invalidate", json.dumps(envelope))
            except Exception as exc:
                logger.debug("Redis profile cache invalidation error: %s", exc)

    def clear(self) -> None:
        self._l1_cache.clear()
        self._l1_ident_map.clear()


class abstractUserRepository(ABC):
    """Abstract interface defining persistence and retrieval operations for user identities and profile state."""

    @abstractmethod
    async def get_by_id(self, user_id: str, session: Optional[AsyncSession] = None) -> Optional[Dict[str, Any]]:
        """Retrieve a user record by its unique system identifier."""
        ...

    @abstractmethod
    async def get_by_identifier(self, identifier: str, session: Optional[AsyncSession] = None) -> Optional[Dict[str, Any]]:
        """Look up a user record by a unique login identifier such as username or email address."""
        ...

    @abstractmethod
    async def create_user(self, user_data: Dict[str, Any], session: Optional[AsyncSession] = None) -> Dict[str, Any]:
        """Persist a new user record into the data store."""
        ...

    @abstractmethod
    async def update_user(self, user_id: str, updates: Dict[str, Any], session: Optional[AsyncSession] = None) -> bool:
        """Update specific fields of an existing user record."""
        ...

    @abstractmethod
    async def delete_user(self, user_id: str, session: Optional[AsyncSession] = None) -> bool:
        """Remove a user record from the data store."""
        ...

    @abstractmethod
    async def set_status(self, user_id: str, is_active: bool, session: Optional[AsyncSession] = None) -> bool:
        """Activate, suspend, or lock a user account."""
        ...

    @abstractmethod
    async def list_users(
        self,
        is_active: Optional[bool] = None,
        role: Optional[str] = None,
        session: Optional[AsyncSession] = None,
    ) -> List[Dict[str, Any]]:
        """List all users with optional status and role filtering."""
        ...

    @abstractmethod
    async def get_roles(self, user_id: str, session: Optional[AsyncSession] = None) -> List[str]:
        """Retrieve all role strings assigned to a user."""
        ...

    @abstractmethod
    async def add_role(self, user_id: str, role: str, session: Optional[AsyncSession] = None) -> bool:
        """Add a role to a user if not already present."""
        ...

    @abstractmethod
    async def remove_role(self, user_id: str, role: str, session: Optional[AsyncSession] = None) -> bool:
        """Remove a role from a user."""
        ...

    @abstractmethod
    async def create_password_reset_token(
        self,
        user_id: str,
        ip_address: Optional[str] = None,
        expires_in_minutes: int = 15,
        session: Optional[AsyncSession] = None,
    ) -> str:
        """Issue and record a high-entropy password reset token for a user."""
        ...

    @abstractmethod
    async def verify_password_reset_token(self, raw_token: str, session: Optional[AsyncSession] = None) -> Optional[Dict[str, Any]]:
        """Verify token hash against stored active, unexpired, and unused reset records."""
        ...

    @abstractmethod
    async def consume_password_reset_token(
        self, raw_token: str, new_hashed_password: str, session: Optional[AsyncSession] = None
    ) -> Optional[str]:
        """Atomically mark token as consumed and update the user's hashed password."""
        ...


class UserRepository(abstractUserRepository):
    """PostgreSQL Async implementation of the User Repository with pluggable model adapter."""

    def __init__(
        self,
        db_url: Optional[str] = None,
        session_factory: Optional[async_sessionmaker[AsyncSession]] = None,
        user_model: Optional[Any] = None,
        redis_client: Optional[Any] = None,
    ):
        self._custom_session_factory = session_factory
        self._db_url = db_url
        self.user_model = user_model or _DefaultUser
        self.cache = UserProfileCache(redis_client=redis_client)

    @property
    def session_factory(self) -> async_sessionmaker[AsyncSession]:
        if self._custom_session_factory is not None:
            return self._custom_session_factory
        return get_session_factory(self._db_url)

    @session_factory.setter
    def session_factory(self, val: async_sessionmaker[AsyncSession]):
        self._custom_session_factory = val

    @asynccontextmanager
    async def _use_session(self, session: Optional[AsyncSession] = None):
        """Context manager yielding caller-provided session without auto-committing, or self-owned session with auto-commit."""
        if session is not None:
            yield session, False
        else:
            async with self.session_factory() as new_session:
                yield new_session, True

    @staticmethod
    def _format_user(user: Any) -> Dict[str, Any]:
        """Format SQLAlchemy User model instance to dictionary matching previous repository shape."""
        roles = getattr(user, "roles", []) if isinstance(getattr(user, "roles", []), list) else []
        meta = getattr(user, "metadata_", {}) if isinstance(getattr(user, "metadata_", {}), dict) else {}
        created_at = getattr(user, "created_at", datetime.now(timezone.utc))
        created_str = (
            created_at.isoformat()
            if isinstance(created_at, datetime)
            else str(created_at)
        )
        return {
            "id": str(user.id),
            "username": getattr(user, "username", ""),
            "email": getattr(user, "email", ""),
            "hashed_password": getattr(user, "hashed_password", ""),
            "is_active": 1 if getattr(user, "is_active", True) else 0,
            "created_at": created_str,
            "roles": roles,
            "metadata": meta,
        }

    async def create_user(self, user_data: Dict[str, Any], session: Optional[AsyncSession] = None) -> Dict[str, Any]:
        """Safely insert a new user with UUID primary key and JSONB attributes."""
        user_id_raw = user_data.get("id")
        if user_id_raw:
            try:
                user_id = uuid.UUID(str(user_id_raw).strip())
            except (ValueError, AttributeError):
                user_id = uuid.uuid4()
        else:
            user_id = uuid.uuid4()

        username = user_data["username"].strip()
        email = user_data["email"].strip().lower()
        hashed_password = user_data["hashed_password"]
        is_active = bool(user_data.get("is_active", True))

        roles_raw = user_data.get("roles", [])
        if isinstance(roles_raw, str):
            try:
                roles = json.loads(roles_raw)
            except Exception:
                roles = []
        else:
            roles = list(roles_raw or [])

        metadata_raw = user_data.get("metadata", {})
        if isinstance(metadata_raw, str):
            try:
                meta = json.loads(metadata_raw)
            except Exception:
                meta = {}
        else:
            meta = dict(metadata_raw or {})

        new_user = self.user_model(
            id=user_id,
            username=username,
            email=email,
            hashed_password=hashed_password,
            is_active=is_active,
            roles=roles,
            metadata_=meta,
        )

        try:
            async with self._use_session(session) as (sess, should_commit):
                sess.add(new_user)
                if should_commit:
                    await sess.commit()
            created = await self.get_by_id(str(user_id), session=session)  # type: ignore
            if created and session is None:
                self.cache.set_user(created)
            return created
        except IntegrityError as e:
            raise ValueError(f"User with this username or email address already exists: {e}")

    async def get_by_id(self, user_id: str, session: Optional[AsyncSession] = None) -> Optional[Dict[str, Any]]:
        """Fetch a user record by UUID with L1/L2 caching."""
        if not user_id:
            return None
        try:
            uid = uuid.UUID(str(user_id).strip())
        except (ValueError, AttributeError):
            return None

        # Check cache if query is not bound to an existing session
        if session is None:
            cached = self.cache.get_user(str(uid))
            if cached is not None:
                return cached

        async with self._use_session(session) as (sess, _):
            stmt = select(self.user_model).where(self.user_model.id == uid)
            result = await sess.execute(stmt)
            user = result.scalars().first()
            formatted = self._format_user(user) if user else None

        if formatted is not None and session is None:
            self.cache.set_user(formatted)

        return formatted

    async def get_by_identifier(self, identifier: str, session: Optional[AsyncSession] = None) -> Optional[Dict[str, Any]]:
        """Lookup a user by case-insensitive username or email with L1/L2 caching."""
        clean_id = (identifier or "").strip().lower()
        if not clean_id:
            return None

        if session is None:
            cached = self.cache.get_user_by_identifier(clean_id)
            if cached is not None:
                return cached

        async with self._use_session(session) as (sess, _):
            stmt = select(self.user_model).where(
                or_(
                    func.lower(self.user_model.username) == clean_id,
                    func.lower(self.user_model.email) == clean_id,
                )
            )
            result = await sess.execute(stmt)
            user = result.scalars().first()
            formatted = self._format_user(user) if user else None

        if formatted is not None and session is None:
            self.cache.set_user(formatted)

        return formatted

    async def update_user(self, user_id: str, updates: Dict[str, Any], session: Optional[AsyncSession] = None) -> bool:
        """Atomically update user fields."""
        if not user_id:
            return False
        try:
            uid = uuid.UUID(str(user_id).strip())
        except (ValueError, AttributeError):
            return False

        allowed_fields = {"username", "email", "hashed_password", "is_active", "roles", "metadata"}
        filtered_updates: Dict[str, Any] = {}

        for key, value in updates.items():
            if key in allowed_fields:
                if key == "email" and isinstance(value, str):
                    filtered_updates["email"] = value.strip().lower()
                elif key == "roles":
                    if isinstance(value, str):
                        try:
                            filtered_updates["roles"] = json.loads(value)
                        except Exception:
                            filtered_updates["roles"] = []
                    else:
                        filtered_updates["roles"] = list(value or [])
                elif key == "metadata":
                    if isinstance(value, str):
                        try:
                            filtered_updates["metadata_"] = json.loads(value)
                        except Exception:
                            filtered_updates["metadata_"] = {}
                    else:
                        filtered_updates["metadata_"] = dict(value or {})
                elif key == "is_active":
                    filtered_updates["is_active"] = bool(value)
                else:
                    filtered_updates[key] = value

        if not filtered_updates:
            return False

        try:
            async with self._use_session(session) as (sess, should_commit):
                stmt = update(self.user_model).where(self.user_model.id == uid).values(**filtered_updates)
                result = await sess.execute(stmt)
                if should_commit:
                    await sess.commit()
                if (result.rowcount or 0) > 0:
                    self.cache.invalidate(user_id=str(uid))
                    return True
                return False
        except IntegrityError as e:
            raise ValueError(f"Update failed due to unique constraint: {e}")

    async def delete_user(self, user_id: str, session: Optional[AsyncSession] = None) -> bool:
        """Permanently delete a user record."""
        if not user_id:
            return False
        try:
            uid = uuid.UUID(str(user_id).strip())
        except (ValueError, AttributeError):
            return False

        async with self._use_session(session) as (sess, should_commit):
            stmt = delete(self.user_model).where(self.user_model.id == uid)
            result = await sess.execute(stmt)
            if should_commit:
                await sess.commit()
            if (result.rowcount or 0) > 0:
                self.cache.invalidate(user_id=str(uid))
                return True
            return False

    async def set_status(self, user_id: str, is_active: bool, session: Optional[AsyncSession] = None) -> bool:
        """Activate or suspend a user account."""
        if not user_id:
            return False
        try:
            uid = uuid.UUID(str(user_id).strip())
        except (ValueError, AttributeError):
            return False

        async with self._use_session(session) as (sess, should_commit):
            stmt = update(self.user_model).where(self.user_model.id == uid).values(is_active=bool(is_active))
            result = await sess.execute(stmt)
            if should_commit:
                await sess.commit()
            if (result.rowcount or 0) > 0:
                self.cache.invalidate(user_id=str(uid))
                return True
            return False

    async def list_users(
        self,
        is_active: Optional[bool] = None,
        role: Optional[str] = None,
        session: Optional[AsyncSession] = None,
    ) -> List[Dict[str, Any]]:
        """List all users with optional status and role filtering."""
        async with self._use_session(session) as (sess, _):
            stmt = select(self.user_model).order_by(self.user_model.created_at.asc())
            if is_active is not None:
                stmt = stmt.where(self.user_model.is_active == bool(is_active))
            result = await sess.execute(stmt)
            users = result.scalars().all()

        results: List[Dict[str, Any]] = []
        for u in users:
            data = self._format_user(u)
            if role:
                user_roles = [str(r).strip().lower() for r in (data.get("roles") or [])]
                if role.strip().lower() not in user_roles:
                    continue
            results.append(data)
        return results

    async def get_roles(self, user_id: str, session: Optional[AsyncSession] = None) -> List[str]:
        """Retrieve all role strings assigned to a user."""
        user = await self.get_by_id(user_id, session=session)
        if not user:
            return []
        raw_roles = user.get("roles", [])
        if isinstance(raw_roles, str):
            try:
                return json.loads(raw_roles)
            except Exception:
                return []
        return list(raw_roles) if isinstance(raw_roles, list) else []

    async def add_role(self, user_id: str, role: str, session: Optional[AsyncSession] = None) -> bool:
        """Add a role to a user if not already present."""
        clean_role = role.strip().lower()
        user = await self.get_by_id(user_id, session=session)
        if not user:
            return False

        roles = await self.get_roles(user_id, session=session)
        if clean_role not in roles:
            roles.append(clean_role)
            return await self.update_user(user_id, {"roles": roles}, session=session)
        return True

    async def remove_role(self, user_id: str, role: str, session: Optional[AsyncSession] = None) -> bool:
        """Remove a role from a user."""
        clean_role = role.strip().lower()
        user = await self.get_by_id(user_id, session=session)
        if not user:
            return False

        roles = await self.get_roles(user_id, session=session)
        if clean_role in roles:
            roles = [r for r in roles if r != clean_role]
            return await self.update_user(user_id, {"roles": roles}, session=session)
        return True

    @staticmethod
    def _hash_reset_token(raw_token: str) -> str:
        """Compute SHA-256 digest of a raw reset token."""
        return hashlib.sha256((raw_token or "").strip().encode("utf-8")).hexdigest()

    async def create_password_reset_token(
        self,
        user_id: str,
        ip_address: Optional[str] = None,
        expires_in_minutes: int = 15,
        session: Optional[AsyncSession] = None,
    ) -> str:
        """Issue and record a high-entropy password reset token, invalidating prior tokens for the user."""
        try:
            uid = uuid.UUID(str(user_id).strip())
        except (ValueError, AttributeError):
            raise ValueError(f"Invalid user_id for password reset: {user_id}")

        raw_token = secrets.token_urlsafe(32)
        token_hash = self._hash_reset_token(raw_token)
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(minutes=expires_in_minutes)
        token_id = uuid.uuid4()

        async with self._use_session(session) as (sess, should_commit):
            # Invalidate any previously unused reset tokens for this user
            await sess.execute(
                update(PasswordResetToken)
                .where(
                    PasswordResetToken.user_id == uid,
                    PasswordResetToken.used_at.is_(None),
                )
                .values(used_at=now)
            )

            new_token = PasswordResetToken(
                id=token_id,
                user_id=uid,
                token_hash=token_hash,
                expires_at=expires_at,
                created_at=now,
                used_at=None,
                ip_address=ip_address or "",
            )
            sess.add(new_token)
            if should_commit:
                await sess.commit()

        return raw_token

    async def verify_password_reset_token(self, raw_token: str, session: Optional[AsyncSession] = None) -> Optional[Dict[str, Any]]:
        """Verify token hash against stored active, unexpired, and unused reset records."""
        clean_token = (raw_token or "").strip()
        if not clean_token:
            return None

        token_hash = self._hash_reset_token(clean_token)
        now_utc = datetime.now(timezone.utc)

        async with self._use_session(session) as (sess, _):
            stmt = (
                select(PasswordResetToken, self.user_model)
                .join(self.user_model, PasswordResetToken.user_id == self.user_model.id)
                .where(
                    PasswordResetToken.token_hash == token_hash,
                    PasswordResetToken.used_at.is_(None),
                )
            )
            result = await sess.execute(stmt)
            row = result.first()
            if not row:
                return None

            prt, user = row
            if not getattr(user, "is_active", True):
                return None

            if prt.expires_at:
                exp_dt = (
                    prt.expires_at
                    if prt.expires_at.tzinfo
                    else prt.expires_at.replace(tzinfo=timezone.utc)
                )
                if now_utc > exp_dt:
                    return None

            return {
                "id": str(prt.id),
                "user_id": str(prt.user_id),
                "expires_at": prt.expires_at.isoformat() if prt.expires_at else "",
                "created_at": prt.created_at.isoformat() if prt.created_at else "",
                "used_at": prt.used_at.isoformat() if prt.used_at else None,
                "ip_address": prt.ip_address,
                "username": getattr(user, "username", ""),
                "email": getattr(user, "email", ""),
                "is_active": 1 if getattr(user, "is_active", True) else 0,
            }

    async def consume_password_reset_token(
        self, raw_token: str, new_hashed_password: str, session: Optional[AsyncSession] = None
    ) -> Optional[str]:
        """Atomically mark token as consumed and update the user's hashed password."""
        verified = await self.verify_password_reset_token(raw_token, session=session)
        if not verified:
            return None

        user_id = verified["user_id"]
        token_id = verified["id"]
        now = datetime.now(timezone.utc)

        try:
            uid = uuid.UUID(user_id)
            tid = uuid.UUID(token_id)
        except (ValueError, AttributeError):
            return None

        async with self._use_session(session) as (sess, should_commit):
            # Atomically consume token
            stmt = (
                update(PasswordResetToken)
                .where(
                    PasswordResetToken.id == tid,
                    PasswordResetToken.used_at.is_(None),
                )
                .values(used_at=now)
            )
            res = await sess.execute(stmt)
            if (res.rowcount or 0) == 0:
                if should_commit:
                    await sess.rollback()
                return None

            # Update password
            await sess.execute(
                update(self.user_model)
                .where(self.user_model.id == uid)
                .values(hashed_password=new_hashed_password)
            )
            if should_commit:
                await sess.commit()
            self.cache.invalidate(user_id=str(uid))
            return str(user_id)


concreteUserRepository = UserRepository