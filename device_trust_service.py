"""
Auth N&Z - Device Trust & Remember-Device Service (device_trust_service.py)
--------------------------------------------------------------------------
Manages scoped, high-entropy trusted device tokens for second-factor (MFA) bypass scoping.
Tokens are stored at-rest as one-way SHA-256 digests.
Includes device label parsing (User-Agent), TTL bounding, and user-facing revocation.
"""

from abc import ABC, abstractmethod
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import json
import logging
import re
import secrets
import sqlite3
from typing import Any, Dict, List, Optional, Tuple
import uuid

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
    def create_trusted_device(
        self,
        user_id: str,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
        days_valid: int = 30,
    ) -> Tuple[Dict[str, Any], str]:
        """Issue and record a high-entropy device trust token for a user."""
        ...

    @abstractmethod
    def verify_trusted_device(
        self,
        user_id: str,
        raw_token: str,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Verify device trust token digest and validate active expiration."""
        ...

    @abstractmethod
    def list_trusted_devices(
        self,
        user_id: str,
        current_token: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List active trusted devices for a user with current device indicator."""
        ...

    @abstractmethod
    def revoke_trusted_device(self, user_id: str, device_id: str) -> bool:
        """Revoke a specific trusted device."""
        ...

    @abstractmethod
    def revoke_all_trusted_devices(self, user_id: str) -> int:
        """Revoke all trusted devices for a user."""
        ...


class DeviceTrustService(abstractDeviceTrustService):
    def __init__(self, db_file: str = "DATABASE.db"):
        self.db_file = db_file
        self._init_db()

    @contextmanager
    def _get_connection(self):
        conn = sqlite3.connect(self.db_file, timeout=10.0)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        """Initialize trusted_devices table with WAL mode and indices."""
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS trusted_devices (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    token_hash TEXT NOT NULL UNIQUE,
                    device_label TEXT NOT NULL,
                    user_agent TEXT,
                    ip_address TEXT,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    last_used_at TEXT NOT NULL
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_td_user ON trusted_devices(user_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_td_token ON trusted_devices(token_hash);")
            conn.commit()

    @staticmethod
    def _hash_token(token: str) -> str:
        """Compute SHA-256 digest of a raw device token for secure at-rest storage."""
        return hashlib.sha256((token or "").strip().encode("utf-8")).hexdigest()

    def create_trusted_device(
        self,
        user_id: str,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
        days_valid: int = 30,
    ) -> Tuple[Dict[str, Any], str]:
        """Issue and record a high-entropy device trust token for a user."""
        device_id = f"dev_{uuid.uuid4().hex[:16]}"
        raw_token = secrets.token_urlsafe(32)
        token_hash = self._hash_token(raw_token)

        now = datetime.now(timezone.utc)
        expires_at = (now + timedelta(days=days_valid)).isoformat()
        now_str = now.isoformat()
        device_label = parse_device_label(user_agent)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO trusted_devices (
                    id, user_id, token_hash, device_label, user_agent, ip_address,
                    created_at, expires_at, last_used_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                device_id,
                user_id,
                token_hash,
                device_label,
                user_agent or "",
                ip_address or "",
                now_str,
                expires_at,
                now_str,
            ))
            conn.commit()

        device_record = {
            "id": device_id,
            "user_id": user_id,
            "device_label": device_label,
            "ip_address": ip_address,
            "created_at": now_str,
            "expires_at": expires_at,
            "last_used_at": now_str,
        }
        return device_record, raw_token

    def verify_trusted_device(
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

        token_hash = self._hash_token(clean_token)
        now_str = datetime.now(timezone.utc).isoformat()

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM trusted_devices
                WHERE user_id = ? AND token_hash = ?
            """, (user_id, token_hash))
            row = cursor.fetchone()
            if not row:
                return None

            device = dict(row)
            expires_at = device.get("expires_at")
            if expires_at:
                try:
                    exp_dt = datetime.fromisoformat(expires_at)
                    if datetime.now(timezone.utc) > exp_dt:
                        # Expired: clean up
                        cursor.execute("DELETE FROM trusted_devices WHERE id = ?", (device["id"],))
                        conn.commit()
                        return None
                except Exception:
                    return None

            # Update last_used_at and IP
            cursor.execute("""
                UPDATE trusted_devices
                SET last_used_at = ?, ip_address = COALESCE(?, ip_address)
                WHERE id = ?
            """, (now_str, ip_address, device["id"]))
            conn.commit()

            device["last_used_at"] = now_str
            if ip_address:
                device["ip_address"] = ip_address
            device.pop("token_hash", None)
            return device

    def list_trusted_devices(
        self,
        user_id: str,
        current_token: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List active trusted devices for a user with current device indicator."""
        current_hash = self._hash_token(current_token) if current_token else None
        now_utc = datetime.now(timezone.utc)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, user_id, token_hash, device_label, ip_address, created_at, expires_at, last_used_at
                FROM trusted_devices
                WHERE user_id = ?
                ORDER BY datetime(last_used_at) DESC
            """, (user_id,))
            rows = cursor.fetchall()

            devices = []
            for r in rows:
                item = dict(r)
                expires_at = item.get("expires_at")
                if expires_at:
                    try:
                        exp_dt = datetime.fromisoformat(expires_at)
                        if now_utc > exp_dt:
                            continue  # Filter out expired
                    except Exception:
                        pass

                is_current = bool(current_hash and item.get("token_hash") == current_hash)
                item["is_current_device"] = is_current
                item.pop("token_hash", None)
                devices.append(item)

            return devices

    def revoke_trusted_device(self, user_id: str, device_id: str) -> bool:
        """Revoke a specific trusted device belonging to the user."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                DELETE FROM trusted_devices
                WHERE id = ? AND user_id = ?
            """, (device_id.strip(), user_id))
            conn.commit()
            return cursor.rowcount > 0

    def revoke_all_trusted_devices(self, user_id: str) -> int:
        """Revoke all trusted devices for a user."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM trusted_devices WHERE user_id = ?", (user_id,))
            conn.commit()
            return cursor.rowcount
