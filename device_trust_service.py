"""
Auth N&Z - Device Trust & Remember-Device Service (PostgreSQL Async)
-------------------------------------------------------------------
Manages scoped, high-entropy trusted device tokens for second-factor (MFA) bypass scoping
using async SQLAlchemy (asyncpg). Tokens are stored at-rest as one-way SHA-256 digests.
Includes device label parsing (User-Agent), TTL bounding, and user-facing revocation.
"""

from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
import hashlib
import json
import logging
import secrets
from typing import Any, Dict, List, Optional, Tuple
import uuid

from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from database import get_session_factory
from models import TrustedDevice

logger = logging.getLogger("auth_nz.device_trust")


def parse_device_label(user_agent: Optional[str]) -> str:
    """Parse User-Agent string into a clean, human-readable device label."""
    if not user_agent:
        return "Unknown Browser / Device"

    ua = user_agent.lower()

    # Detect OS
    os_name = "Unknown OS"
    if "windows nt 10" in ua or "windows nt 11" in ua or "windows" in ua:
        os_name = "Windows"
    elif "macintosh" in ua or "mac os x" in ua:
        os_name = "macOS"
    elif "iphone" in ua or "ipad" in ua:
        os_name = "iOS"
    elif "android" in ua:
        os_name = "Android"
    elif "linux" in ua:
        os_name = "Linux"

    # Detect Browser
    browser_name = "Browser"
    if "edg/" in ua or "edge" in ua:
        browser_name = "Microsoft Edge"
    elif "chrome" in ua and "safari" in ua and "edg" not in ua:
        browser_name = "Google Chrome"
    elif "safari" in ua and "chrome" not in ua:
        browser_name = "Apple Safari"
    elif "firefox" in ua:
        browser_name = "Mozilla Firefox"
    elif "opera" in ua or "opr/" in ua:
        browser_name = "Opera"

    return f"{browser_name} on {os_name}"


class abstractDeviceTrustService(ABC):
    """Abstract interface defining trusted device provisioning, verification, and revocation."""

    @abstractmethod
    async def create_trusted_device(
        self,
        user_id: str,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
        days_valid: int = 30,
    ) -> Tuple[Dict[str, Any], str]:
        """Issue and record a high-entropy device trust token for a user."""
        ...

    @abstractmethod
    async def verify_trusted_device(
        self,
        user_id: str,
        raw_token: str,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Verify device trust token digest and validate active expiration."""
        ...

    @abstractmethod
    async def list_trusted_devices(
        self,
        user_id: str,
        current_token: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List active trusted devices for a user with current device indicator."""
        ...

    @abstractmethod
    async def revoke_trusted_device(self, user_id: str, device_id: str) -> bool:
        """Revoke a specific trusted device."""
        ...

    @abstractmethod
    async def revoke_all_trusted_devices(self, user_id: str) -> int:
        """Revoke all trusted devices for a user."""
        ...


class DeviceTrustService(abstractDeviceTrustService):
    """PostgreSQL Async implementation of Device Trust Service."""

    def __init__(
        self,
        db_url: Optional[str] = None,
        session_factory: Optional[async_sessionmaker[AsyncSession]] = None,
    ):
        self.session_factory = session_factory or get_session_factory(db_url)

    @staticmethod
    def _hash_token(token: str) -> str:
        """Compute SHA-256 digest of a raw device token for secure at-rest storage."""
        return hashlib.sha256((token or "").strip().encode("utf-8")).hexdigest()

    async def create_trusted_device(
        self,
        user_id: str,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
        days_valid: int = 30,
    ) -> Tuple[Dict[str, Any], str]:
        """Issue and record a high-entropy device trust token for a user."""
        try:
            uid = uuid.UUID(str(user_id).strip())
        except (ValueError, AttributeError):
            raise ValueError(f"Invalid user_id for trusted device: {user_id}")

        device_id = uuid.uuid4()
        raw_token = secrets.token_urlsafe(32)
        token_hash = self._hash_token(raw_token)

        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(days=days_valid)
        device_label = parse_device_label(user_agent)

        new_device = TrustedDevice(
            id=device_id,
            user_id=uid,
            token_hash=token_hash,
            device_label=device_label,
            user_agent=user_agent or "",
            ip_address=ip_address or "",
            created_at=now,
            expires_at=expires_at,
            last_used_at=now,
        )

        async with self.session_factory() as session:
            session.add(new_device)
            await session.commit()

        device_record = {
            "id": str(device_id),
            "user_id": str(uid),
            "device_label": device_label,
            "ip_address": ip_address,
            "created_at": now.isoformat(),
            "expires_at": expires_at.isoformat(),
            "last_used_at": now.isoformat(),
        }
        return device_record, raw_token

    async def verify_trusted_device(
        self,
        user_id: str,
        raw_token: str,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Verify device trust token digest and validate active expiration."""
        clean_token = (raw_token or "").strip()
        if not clean_token or not user_id:
            return None

        try:
            uid = uuid.UUID(str(user_id).strip())
        except (ValueError, AttributeError):
            return None

        token_hash = self._hash_token(clean_token)
        now_utc = datetime.now(timezone.utc)

        async with self.session_factory() as session:
            stmt = select(TrustedDevice).where(
                TrustedDevice.user_id == uid,
                TrustedDevice.token_hash == token_hash,
            )
            result = await session.execute(stmt)
            device = result.scalars().first()
            if not device:
                return None

            # Check expiration
            exp_dt = (
                device.expires_at
                if device.expires_at.tzinfo
                else device.expires_at.replace(tzinfo=timezone.utc)
            )
            if now_utc > exp_dt:
                # Expired: clean up
                await session.execute(
                    delete(TrustedDevice).where(TrustedDevice.id == device.id)
                )
                await session.commit()
                return None

            # Device binding: Verify presented User-Agent matches enrolled device profile
            stored_ua = (device.user_agent or "").strip()
            presented_ua = (user_agent or "").strip()
            if stored_ua:
                if stored_ua != presented_ua:
                    stored_label = parse_device_label(stored_ua)
                    presented_label = parse_device_label(presented_ua)
                    if (
                        stored_label != presented_label
                        or presented_label == "Unknown Browser / Device"
                    ):
                        logger.warning(
                            "Trusted device user-agent mismatch for user %s (stored: '%s' [%s], presented: '%s' [%s]). Rejecting trust.",
                            user_id,
                            stored_ua,
                            stored_label,
                            presented_ua,
                            presented_label,
                        )
                        return None

            # Update last_used_at and IP
            update_values: Dict[str, Any] = {"last_used_at": now_utc}
            if ip_address:
                update_values["ip_address"] = ip_address

            await session.execute(
                update(TrustedDevice)
                .where(TrustedDevice.id == device.id)
                .values(**update_values)
            )
            await session.commit()

            created_str = (
                device.created_at.isoformat()
                if isinstance(device.created_at, datetime)
                else str(device.created_at)
            )
            expires_str = (
                device.expires_at.isoformat()
                if isinstance(device.expires_at, datetime)
                else str(device.expires_at)
            )

            return {
                "id": str(device.id),
                "user_id": str(device.user_id),
                "device_label": device.device_label,
                "ip_address": ip_address or device.ip_address,
                "created_at": created_str,
                "expires_at": expires_str,
                "last_used_at": now_utc.isoformat(),
            }

    async def list_trusted_devices(
        self,
        user_id: str,
        current_token: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List active trusted devices for a user with current device indicator."""
        if not user_id:
            return []
        try:
            uid = uuid.UUID(str(user_id).strip())
        except (ValueError, AttributeError):
            return []

        current_hash = self._hash_token(current_token) if current_token else None
        now_utc = datetime.now(timezone.utc)

        async with self.session_factory() as session:
            stmt = (
                select(TrustedDevice)
                .where(TrustedDevice.user_id == uid)
                .order_by(TrustedDevice.last_used_at.desc())
            )
            result = await session.execute(stmt)
            rows = result.scalars().all()

        devices = []
        for d in rows:
            exp_dt = (
                d.expires_at
                if d.expires_at.tzinfo
                else d.expires_at.replace(tzinfo=timezone.utc)
            )
            if now_utc > exp_dt:
                continue

            is_current = bool(current_hash and d.token_hash == current_hash)
            created_str = (
                d.created_at.isoformat()
                if isinstance(d.created_at, datetime)
                else str(d.created_at)
            )
            expires_str = (
                d.expires_at.isoformat()
                if isinstance(d.expires_at, datetime)
                else str(d.expires_at)
            )
            last_used_str = (
                d.last_used_at.isoformat()
                if isinstance(d.last_used_at, datetime)
                else str(d.last_used_at)
            )

            devices.append({
                "id": str(d.id),
                "user_id": str(d.user_id),
                "device_label": d.device_label,
                "ip_address": d.ip_address,
                "created_at": created_str,
                "expires_at": expires_str,
                "last_used_at": last_used_str,
                "is_current_device": is_current,
            })

        return devices

    async def revoke_trusted_device(self, user_id: str, device_id: str) -> bool:
        """Revoke a specific trusted device belonging to the user."""
        if not user_id or not device_id:
            return False
        try:
            uid = uuid.UUID(str(user_id).strip())
            did = uuid.UUID(str(device_id).strip())
        except (ValueError, AttributeError):
            return False

        async with self.session_factory() as session:
            stmt = delete(TrustedDevice).where(
                TrustedDevice.id == did,
                TrustedDevice.user_id == uid,
            )
            result = await session.execute(stmt)
            await session.commit()
            return (result.rowcount or 0) > 0

    async def revoke_all_trusted_devices(self, user_id: str) -> int:
        """Revoke all trusted devices for a user."""
        if not user_id:
            return 0
        try:
            uid = uuid.UUID(str(user_id).strip())
        except (ValueError, AttributeError):
            return 0

        async with self.session_factory() as session:
            stmt = delete(TrustedDevice).where(TrustedDevice.user_id == uid)
            result = await session.execute(stmt)
            await session.commit()
            return int(result.rowcount or 0)
