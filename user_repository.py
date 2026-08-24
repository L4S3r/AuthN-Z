"""
Component Role: User Repository
------------------------------
This component acts as the data access layer for user accounts, identities, and credential records.

System Relationship:
The Authenticator queries this repository to find users by username, email, or ID to retrieve their
stored credentials and account status during login. The PermissionEvaluator may also consult it to
load assigned roles, groups, and privileges. It isolates the rest of the authentication/authorization
system from specific database engines (e.g., PostgreSQL, MongoDB, DynamoDB).
"""

from abc import ABC, abstractmethod
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import json
import secrets
import sqlite3
from typing import Any, Dict, List, Optional, Tuple
import uuid

class abstractUserRepository(ABC):
    """Abstract interface defining persistence and retrieval operations for user identities and profile state."""

    @abstractmethod
    def get_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve a user record by its unique system identifier.

        Args:
            user_id: The unique primary key or UUID of the user.

        Returns:
            A dictionary containing the user's data (e.g., ID, username, email, hashed credentials,
            status, roles, metadata), or None if no matching user exists.

        Edge Cases to Consider:
            - Malformed or invalid user ID formats (e.g., non-UUID strings if UUIDs are expected).
            - Soft-deleted users vs. permanently deleted users.
            - Database connection timeouts or query failures.
        """
        ...

    @abstractmethod
    def get_by_identifier(self, identifier: str) -> Optional[Dict[str, Any]]:
        """
        Look up a user record by a unique login identifier such as username or email address.

        Args:
            identifier: The case-insensitive or normalized login string (username, email, phone number).

        Returns:
            A dictionary containing user data, or None if no user is found with that identifier.

        Edge Cases to Consider:
            - Case-sensitivity nuances (e.g., matching 'User@Example.com' with 'user@example.com').
            - Whitespace trimming and Unicode normalization.
            - Ambiguity if multiple identifiers overlap (e.g., email vs. username collision).
        """
        ...

    @abstractmethod
    def create_user(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Persist a new user record into the data store.

        Args:
            user_data: Dictionary containing fields for the new user (e.g., username, email,
                       hashed password, creation timestamp, initial roles).

        Returns:
            The created user record dictionary, including the newly assigned unique user ID.

        Edge Cases to Consider:
            - Unique constraint violations (duplicate username or email already exists).
            - Missing mandatory fields (e.g., missing email, password hash, or username).
            - Schema validation failures.
        """
        ...

    @abstractmethod
    def update_user(self, user_id: str, updates: Dict[str, Any]) -> bool:
        """
        Update specific fields of an existing user record.

        Args:
            user_id: The unique identifier of the user to update.
            updates: Dictionary of key-value pairs representing modified fields.

        Returns:
            True if the update was applied successfully, False if the user was not found or no changes were made.

        Edge Cases to Consider:
            - Attempting to update immutable fields (such as user_id or creation date).
            - Updating unique fields (e.g., changing email to one that already belongs to another user).
            - Optimistic concurrency control (handling simultaneous conflicting writes).
        """
        ...

    @abstractmethod
    def delete_user(self, user_id: str) -> bool:
        """
        Remove or soft-delete a user record from the data store.

        Args:
            user_id: The unique identifier of the user to delete.

        Returns:
            True if the user was found and deleted, False otherwise.

        Edge Cases to Consider:
            - Handling cascading deletes vs. soft-deletion flags (e.g., is_deleted=True).
            - Ensuring associated tokens, sessions, or role assignments are cleaned up or invalidated.
        """
        ...

    @abstractmethod
    def set_status(self, user_id: str, is_active: bool) -> bool:
        """
        Activate, suspend, or lock a user account.

        Args:
            user_id: The unique identifier of the user.
            is_active: Boolean flag indicating whether the account is enabled for login/access.

        Returns:
            True if the status was successfully updated, False if the user does not exist.

        Edge Cases to Consider:
            - Revoking active sessions or tokens immediately upon locking/deactivating an account.
            - Preventing self-lockout or locking the final remaining super-administrator.
        """
        ...

    @abstractmethod
    def create_password_reset_token(
        self,
        user_id: str,
        ip_address: Optional[str] = None,
        expires_in_minutes: int = 15,
    ) -> str:
        """Issue and record a high-entropy password reset token for a user."""
        ...

    @abstractmethod
    def verify_password_reset_token(self, raw_token: str) -> Optional[Dict[str, Any]]:
        """Verify token hash against stored active, unexpired, and unused reset records."""
        ...

    @abstractmethod
    def consume_password_reset_token(self, raw_token: str, new_hashed_password: str) -> Optional[str]:
        """Atomically mark token as consumed and update the user's hashed password."""
        ...

class UserRepository(abstractUserRepository):
    def __init__(self, db_file: str = "DATABASE.db"):
        self.db_file = db_file
        self._init_db()

    @contextmanager
    def _get_connection(self):
        """Yield a configured SQLite connection with WAL mode and foreign key support."""
        conn = sqlite3.connect(self.db_file, timeout=10.0)
        conn.row_factory = sqlite3.Row
        try:
            if self.db_file != ":memory:":
                conn.execute("PRAGMA journal_mode=WAL;")
                conn.execute("PRAGMA synchronous=NORMAL;")
            conn.execute("PRAGMA foreign_keys=ON;")
            yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        """Create the user and password reset tables and configure concurrent WAL journal mode."""
        users_query = """
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            hashed_password TEXT NOT NULL,
            is_active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            roles TEXT DEFAULT '[]',
            metadata TEXT DEFAULT '{}'
        );
        """
        reset_tokens_query = """
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            used_at TEXT,
            ip_address TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        """
        with self._get_connection() as conn:
            conn.execute(users_query)
            conn.execute(reset_tokens_query)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_prt_user ON password_reset_tokens(user_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_prt_hash ON password_reset_tokens(token_hash);")
            conn.commit()

    def create_user(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Safely insert a new user using a parameterized query."""
        user_id = user_data.get("id") or str(uuid.uuid4())
        username = user_data["username"]
        email = user_data["email"].strip().lower()
        hashed_password = user_data["hashed_password"]
        is_active = int(user_data.get("is_active", 1))
        roles_json = json.dumps(user_data.get("roles", []))
        metadata_json = json.dumps(user_data.get("metadata", {}))
        query = """INSERT INTO users (
                        id, 
                        username,
                        email,
                        hashed_password,
                        is_active,
                        roles,
                        metadata
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)"""

        try:
            with self._get_connection() as conn:
                conn.execute(
                    query,
                    (user_id, username, email, hashed_password, is_active, roles_json, metadata_json)
                )
                conn.commit()
            return self.get_by_id(user_id)
        except sqlite3.IntegrityError as e:
            raise ValueError(f"User with this username or email address already exists: {e}")

    def get_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a user's name and email using their UUID."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            query = "SELECT * FROM users WHERE id = ?"
            cursor.execute(query, (str(user_id),))
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_by_identifier(self, identifier: str) -> Optional[Dict[str, Any]]:
        """Lookup a user by case-insensitive username or email."""
        clean_id = identifier.strip().lower()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            query = "SELECT * FROM users WHERE LOWER(username) = ? OR LOWER(email) = ?"
            cursor.execute(query, (clean_id, clean_id))
            row = cursor.fetchone()
            return dict(row) if row else None

    def update_user(self, user_id: str, updates: Dict[str, Any]) -> bool:
        """Atomically update user fields using a single transaction."""
        allowed_fields = {"username", "email", "hashed_password", "is_active", "roles", "metadata"}
        filtered_updates = {}
        for key, value in updates.items():
            if key in allowed_fields:
                if key == "email" and isinstance(value, str):
                    filtered_updates[key] = value.strip().lower()
                elif key in ("roles", "metadata") and not isinstance(value, str):
                    filtered_updates[key] = json.dumps(value)
                else:
                    filtered_updates[key] = value
        if not filtered_updates:
            return False

        set_clause = ", ".join(f"{field} = ?" for field in filtered_updates.keys())
        query = f"UPDATE users SET {set_clause} WHERE id = ?"
        params = list(filtered_updates.values()) + [str(user_id)]
        try:
            with self._get_connection() as conn:
                cursor = conn.execute(query, params)
                conn.commit()
                return cursor.rowcount > 0
        except sqlite3.IntegrityError as e:
            raise ValueError(f"Update failed due to unique constraint: {e}")

    def delete_user(self, user_id: str) -> bool:
        """Permanently delete a user record."""
        query = "DELETE FROM users WHERE id = ?"
        with self._get_connection() as conn:
            cursor = conn.execute(query, (str(user_id),))
            conn.commit()
            return cursor.rowcount > 0

    def set_status(self, user_id: str, is_active: bool) -> bool:
        """Activate or deactivate/suspend a user account (soft-delete)."""
        query = "UPDATE users SET is_active = ? WHERE id = ?"
        status_int = 1 if is_active else 0
        with self._get_connection() as conn:
            cursor = conn.execute(query, (status_int, str(user_id)))
            conn.commit()
            return cursor.rowcount > 0

    def list_users(
        self,
        is_active: Optional[bool] = None,
        role: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List all users with optional status and role filtering."""
        query = "SELECT * FROM users WHERE 1=1"
        params: List[Any] = []

        if is_active is not None:
            query += " AND is_active = ?"
            params.append(1 if is_active else 0)

        query += " ORDER BY datetime(created_at) ASC"

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            users = []
            for r in rows:
                u = dict(r)
                if isinstance(u.get("roles"), str):
                    try:
                        u["roles"] = json.loads(u["roles"])
                    except Exception:
                        u["roles"] = []
                if isinstance(u.get("metadata"), str):
                    try:
                        u["metadata"] = json.loads(u["metadata"])
                    except Exception:
                        u["metadata"] = {}

                if role:
                    user_roles = [str(rl).strip().lower() for rl in u.get("roles", [])]
                    if role.strip().lower() not in user_roles:
                        continue

                users.append(u)
            return users

    def get_roles(self, user_id: str) -> List[str]:
        """Retrieve all role strings assigned to a user."""
        user = self.get_by_id(user_id)
        if not user:
            return []
        raw_roles = user.get("roles", [])
        if isinstance(raw_roles, str):
            try:
                return json.loads(raw_roles)
            except Exception:
                return []
        return raw_roles if isinstance(raw_roles, list) else []

    def add_role(self, user_id: str, role: str) -> bool:
        """Add a role to a user if not already present."""
        clean_role = role.strip().lower()
        user = self.get_by_id(user_id)
        if not user:
            return False

        roles = self.get_roles(user_id)
        if clean_role not in roles:
            roles.append(clean_role)
            return self.update_user(user_id, {"roles": roles})
        return True

    def remove_role(self, user_id: str, role: str) -> bool:
        """Remove a role from a user."""
        clean_role = role.strip().lower()
        user = self.get_by_id(user_id)
        if not user:
            return False

        roles = self.get_roles(user_id)
        if clean_role in roles:
            roles = [r for r in roles if r != clean_role]
            return self.update_user(user_id, {"roles": roles})
        return True

    @staticmethod
    def _hash_reset_token(raw_token: str) -> str:
        """Compute SHA-256 digest of a raw reset token."""
        return hashlib.sha256((raw_token or "").strip().encode("utf-8")).hexdigest()

    def create_password_reset_token(
        self,
        user_id: str,
        ip_address: Optional[str] = None,
        expires_in_minutes: int = 15,
    ) -> str:
        """Issue and record a high-entropy password reset token, invalidating prior tokens for the user."""
        raw_token = secrets.token_urlsafe(32)
        token_hash = self._hash_reset_token(raw_token)
        now = datetime.now(timezone.utc)
        now_str = now.isoformat()
        expires_at = (now + timedelta(minutes=expires_in_minutes)).isoformat()
        token_id = f"prt_{uuid.uuid4().hex[:16]}"

        with self._get_connection() as conn:
            # Invalidate any previously unused reset tokens for this user
            conn.execute(
                "UPDATE password_reset_tokens SET used_at = ? WHERE user_id = ? AND used_at IS NULL",
                (now_str, str(user_id)),
            )
            conn.execute(
                """
                INSERT INTO password_reset_tokens (
                    id, user_id, token_hash, expires_at, created_at, used_at, ip_address
                ) VALUES (?, ?, ?, ?, ?, NULL, ?)
                """,
                (token_id, str(user_id), token_hash, expires_at, now_str, ip_address or ""),
            )
            conn.commit()

        return raw_token

    def verify_password_reset_token(self, raw_token: str) -> Optional[Dict[str, Any]]:
        """Verify token hash against stored active, unexpired, and unused reset records."""
        clean_token = (raw_token or "").strip()
        if not clean_token:
            return None

        token_hash = self._hash_reset_token(clean_token)
        now_utc = datetime.now(timezone.utc)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            query = """
                SELECT prt.id, prt.user_id, prt.expires_at, prt.created_at, prt.used_at,
                       u.username, u.email, u.is_active
                FROM password_reset_tokens prt
                JOIN users u ON prt.user_id = u.id
                WHERE prt.token_hash = ? AND prt.used_at IS NULL
            """
            cursor.execute(query, (token_hash,))
            row = cursor.fetchone()
            if not row:
                return None

            record = dict(row)
            if not record.get("is_active", 1):
                return None

            expires_at_str = record.get("expires_at")
            if expires_at_str:
                try:
                    exp_dt = datetime.fromisoformat(expires_at_str)
                    if now_utc > exp_dt:
                        return None
                except Exception:
                    return None

            return record

    def consume_password_reset_token(self, raw_token: str, new_hashed_password: str) -> Optional[str]:
        """Atomically mark token as consumed and update the user's hashed password."""
        verified = self.verify_password_reset_token(raw_token)
        if not verified:
            return None

        user_id = verified["user_id"]
        token_id = verified["id"]
        now_str = datetime.now(timezone.utc).isoformat()

        try:
            with self._get_connection() as conn:
                cursor = conn.execute(
                    "UPDATE password_reset_tokens SET used_at = ? WHERE id = ? AND used_at IS NULL",
                    (now_str, token_id),
                )
                if cursor.rowcount == 0:
                    return None

                conn.execute(
                    "UPDATE users SET hashed_password = ? WHERE id = ?",
                    (new_hashed_password, str(user_id)),
                )
                conn.commit()
            return str(user_id)
        except sqlite3.Error:
            return None


concreteUserRepository = UserRepository