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
from typing import Any, Dict, List, Optional
import uuid

from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from database import get_session_factory
from models import PasswordResetToken, User


class abstractUserRepository(ABC):
    """Abstract interface defining persistence and retrieval operations for user identities and profile state."""

    @abstractmethod
    async def get_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a user record by its unique system identifier."""
        ...

    @abstractmethod
    async def get_by_identifier(self, identifier: str) -> Optional[Dict[str, Any]]:
        """Look up a user record by a unique login identifier such as username or email address."""
        ...

    @abstractmethod
    async def create_user(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Persist a new user record into the data store."""
        ...

    @abstractmethod
    async def update_user(self, user_id: str, updates: Dict[str, Any]) -> bool:
        """Update specific fields of an existing user record."""
        ...

    @abstractmethod
    async def delete_user(self, user_id: str) -> bool:
        """Remove a user record from the data store."""
        ...

    @abstractmethod
    async def set_status(self, user_id: str, is_active: bool) -> bool:
        """Activate, suspend, or lock a user account."""
        ...

    @abstractmethod
    async def list_users(
        self,
        is_active: Optional[bool] = None,
        role: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List all users with optional status and role filtering."""
        ...

    @abstractmethod
    async def get_roles(self, user_id: str) -> List[str]:
        """Retrieve all role strings assigned to a user."""
        ...

    @abstractmethod
    async def add_role(self, user_id: str, role: str) -> bool:
        """Add a role to a user if not already present."""
        ...

    @abstractmethod
    async def remove_role(self, user_id: str, role: str) -> bool:
        """Remove a role from a user."""
        ...

    @abstractmethod
    async def create_password_reset_token(
        self,
        user_id: str,
        ip_address: Optional[str] = None,
        expires_in_minutes: int = 15,
    ) -> str:
        """Issue and record a high-entropy password reset token for a user."""
        ...

    @abstractmethod
    async def verify_password_reset_token(self, raw_token: str) -> Optional[Dict[str, Any]]:
        """Verify token hash against stored active, unexpired, and unused reset records."""
        ...

    @abstractmethod
    async def consume_password_reset_token(
        self, raw_token: str, new_hashed_password: str
    ) -> Optional[str]:
        """Atomically mark token as consumed and update the user's hashed password."""
        ...


class UserRepository(abstractUserRepository):
    """PostgreSQL Async implementation of the User Repository."""

    def __init__(
        self,
        db_url: Optional[str] = None,
        session_factory: Optional[async_sessionmaker[AsyncSession]] = None,
    ):
        self._custom_session_factory = session_factory
        self._db_url = db_url

    @property
    def session_factory(self) -> async_sessionmaker[AsyncSession]:
        if self._custom_session_factory is not None:
            return self._custom_session_factory
        return get_session_factory(self._db_url)

    @session_factory.setter
    def session_factory(self, val: async_sessionmaker[AsyncSession]):
        self._custom_session_factory = val

    @staticmethod
    def _format_user(user: User) -> Dict[str, Any]:
        """Format SQLAlchemy User model instance to dictionary matching previous repository shape."""
        roles = user.roles if isinstance(user.roles, list) else []
        meta = user.metadata_ if isinstance(user.metadata_, dict) else {}
        created_str = (
            user.created_at.isoformat()
            if isinstance(user.created_at, datetime)
            else str(user.created_at)
        )
        return {
            "id": str(user.id),
            "username": user.username,
            "email": user.email,
            "hashed_password": user.hashed_password,
            "is_active": 1 if user.is_active else 0,
            "created_at": created_str,
            "roles": roles,
            "metadata": meta,
        }

    async def create_user(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
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

        new_user = User(
            id=user_id,
            username=username,
            email=email,
            hashed_password=hashed_password,
            is_active=is_active,
            roles=roles,
            metadata_=meta,
        )

        try:
            async with self.session_factory() as session:
                session.add(new_user)
                await session.commit()
            return await self.get_by_id(str(user_id))  # type: ignore
        except IntegrityError as e:
            raise ValueError(f"User with this username or email address already exists: {e}")

    async def get_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a user record by UUID."""
        if not user_id:
            return None
        try:
            uid = uuid.UUID(str(user_id).strip())
        except (ValueError, AttributeError):
            return None

        async with self.session_factory() as session:
            stmt = select(User).where(User.id == uid)
            result = await session.execute(stmt)
            user = result.scalars().first()
            return self._format_user(user) if user else None

    async def get_by_identifier(self, identifier: str) -> Optional[Dict[str, Any]]:
        """Lookup a user by case-insensitive username or email."""
        clean_id = (identifier or "").strip().lower()
        if not clean_id:
            return None

        async with self.session_factory() as session:
            stmt = select(User).where(
                or_(
                    func.lower(User.username) == clean_id,
                    func.lower(User.email) == clean_id,
                )
            )
            result = await session.execute(stmt)
            user = result.scalars().first()
            return self._format_user(user) if user else None

    async def update_user(self, user_id: str, updates: Dict[str, Any]) -> bool:
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
            async with self.session_factory() as session:
                stmt = update(User).where(User.id == uid).values(**filtered_updates)
                result = await session.execute(stmt)
                await session.commit()
                return (result.rowcount or 0) > 0
        except IntegrityError as e:
            raise ValueError(f"Update failed due to unique constraint: {e}")

    async def delete_user(self, user_id: str) -> bool:
        """Permanently delete a user record."""
        if not user_id:
            return False
        try:
            uid = uuid.UUID(str(user_id).strip())
        except (ValueError, AttributeError):
            return False

        async with self.session_factory() as session:
            stmt = delete(User).where(User.id == uid)
            result = await session.execute(stmt)
            await session.commit()
            return (result.rowcount or 0) > 0

    async def set_status(self, user_id: str, is_active: bool) -> bool:
        """Activate or suspend a user account."""
        if not user_id:
            return False
        try:
            uid = uuid.UUID(str(user_id).strip())
        except (ValueError, AttributeError):
            return False

        async with self.session_factory() as session:
            stmt = update(User).where(User.id == uid).values(is_active=bool(is_active))
            result = await session.execute(stmt)
            await session.commit()
            return (result.rowcount or 0) > 0

    async def list_users(
        self,
        is_active: Optional[bool] = None,
        role: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List all users with optional status and role filtering."""
        async with self.session_factory() as session:
            stmt = select(User).order_by(User.created_at.asc())
            if is_active is not None:
                stmt = stmt.where(User.is_active == bool(is_active))
            result = await session.execute(stmt)
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

    async def get_roles(self, user_id: str) -> List[str]:
        """Retrieve all role strings assigned to a user."""
        user = await self.get_by_id(user_id)
        if not user:
            return []
        raw_roles = user.get("roles", [])
        if isinstance(raw_roles, str):
            try:
                return json.loads(raw_roles)
            except Exception:
                return []
        return list(raw_roles) if isinstance(raw_roles, list) else []

    async def add_role(self, user_id: str, role: str) -> bool:
        """Add a role to a user if not already present."""
        clean_role = role.strip().lower()
        user = await self.get_by_id(user_id)
        if not user:
            return False

        roles = await self.get_roles(user_id)
        if clean_role not in roles:
            roles.append(clean_role)
            return await self.update_user(user_id, {"roles": roles})
        return True

    async def remove_role(self, user_id: str, role: str) -> bool:
        """Remove a role from a user."""
        clean_role = role.strip().lower()
        user = await self.get_by_id(user_id)
        if not user:
            return False

        roles = await self.get_roles(user_id)
        if clean_role in roles:
            roles = [r for r in roles if r != clean_role]
            return await self.update_user(user_id, {"roles": roles})
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

        async with self.session_factory() as session:
            # Invalidate any previously unused reset tokens for this user
            await session.execute(
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
            session.add(new_token)
            await session.commit()

        return raw_token

    async def verify_password_reset_token(self, raw_token: str) -> Optional[Dict[str, Any]]:
        """Verify token hash against stored active, unexpired, and unused reset records."""
        clean_token = (raw_token or "").strip()
        if not clean_token:
            return None

        token_hash = self._hash_reset_token(clean_token)
        now_utc = datetime.now(timezone.utc)

        async with self.session_factory() as session:
            stmt = (
                select(PasswordResetToken, User)
                .join(User, PasswordResetToken.user_id == User.id)
                .where(
                    PasswordResetToken.token_hash == token_hash,
                    PasswordResetToken.used_at.is_(None),
                )
            )
            result = await session.execute(stmt)
            row = result.first()
            if not row:
                return None

            prt, user = row
            if not user.is_active:
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
                "username": user.username,
                "email": user.email,
                "is_active": 1 if user.is_active else 0,
            }

    async def consume_password_reset_token(
        self, raw_token: str, new_hashed_password: str
    ) -> Optional[str]:
        """Atomically mark token as consumed and update the user's hashed password."""
        verified = await self.verify_password_reset_token(raw_token)
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

        async with self.session_factory() as session:
            # Atomically consume token
            stmt = (
                update(PasswordResetToken)
                .where(
                    PasswordResetToken.id == tid,
                    PasswordResetToken.used_at.is_(None),
                )
                .values(used_at=now)
            )
            res = await session.execute(stmt)
            if (res.rowcount or 0) == 0:
                await session.rollback()
                return None

            # Update password
            await session.execute(
                update(User)
                .where(User.id == uid)
                .values(hashed_password=new_hashed_password)
            )
            await session.commit()
            return str(user_id)


concreteUserRepository = UserRepository