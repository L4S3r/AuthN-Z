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
from typing import Any, Dict, Optional
import sqlite3
import uuid
import json

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

class UserRepository(abstractUserRepository):
    def __init__(self, db_file: str = "DATABASE.db"):
        self.db_file = db_file
        try:
            # Use ":memory:" instead of a file name to create a temporary database in RAM
            self.conn = sqlite3.connect(self.db_file, check_same_thread=False)
            self.conn.row_factory = sqlite3.Row
            self._create_table()
            print(f"Connected successfully to SQLite version: {sqlite3.sqlite_version}")
        except sqlite3.Error as e:
            print(f"Connection error: {e}")
            raise

    def _create_table(self) -> None:
        """Create the user table if it doesn't already exist."""

        query="""
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
        with self.conn:
            self.conn.execute(query)
    
    def create_user(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Safely insert a new user using a parameterized query."""
        user_id=user_data.get("id") or str(uuid.uuid4())
        username=user_data["username"]
        email=user_data["email"].strip().lower()
        hashed_password=user_data["hashed_password"]
        is_active = int(user_data.get("is_active",1))
        roles_json=json.dumps(user_data.get("roles",[]))
        metadata_json = json.dumps(user_data.get("metadata",{}))
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
            with self.conn:
                self.conn.execute(
                    query,
                    (user_id,username,email,hashed_password,is_active,roles_json,metadata_json)
                )
            return self.get_by_id(user_id) #Returns full record including created at
        except sqlite3.IntegrityError as e:
            raise ValueError(f"User with this username or emaill address already exists: {e}")

    def get_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a user's name and email using their UUID."""
        cursor=self.conn.cursor()
        query="SELECT * FROM users WHERE id = ?"
        cursor.execute(query,(str(user_id),))
        row=cursor.fetchone()
        return dict(row) if row else None
    
    def get_by_identifier(self, identifier: str) -> Optional[Dict[str, Any]]:
        """Lookup a user by case-insensitive username or email."""
        clean_id=identifier.strip().lower()
        cursor=self.conn.cursor()
        query= "SELECT * FROM users WHERE LOWER(username) = ? OR LOWER(email) = ?"
        cursor.execute(query,(clean_id,clean_id))
        row = cursor.fetchone()
        return dict(row) if row else None
    
    
    def update_user(self, user_id: str, updates: Dict[str, Any]) -> bool:
        """Atomically update user fields using a single transaction."""
        allowed_fields={"username","email","hashed_password","is_active","roles","metadata"}
        filtered_updates = {}
        for key,value in updates.items():
            if key in allowed_fields:
                if key == "email" and isinstance(value,str):
                    filtered_updates[key]=value.strip().lower()
                elif key in ("roles","metadata") and not isinstance(value,str):
                    filtered_updates[key] = json.dumps(value)
                else:
                    filtered_updates[key] = value
        if not filtered_updates:
            return False

        set_clause= ", ".join(f"{field} = ?" for field in filtered_updates.keys())
        query= f"UPDATE users SET {set_clause} WHERE id =?"        
        params=list(filtered_updates.values()) + [str(user_id)]
        try:
            with self.conn:
                cursor=self.conn.execute(query,params)
                return cursor.rowcount > 0
        except sqlite3.IntegrityError as e:
            raise ValueError(f"Update failed due to unique constraint: {e}")
            

    def delete_user(self, user_id: str) -> bool:
        """Permanently delete a user record."""
        query="DELETE FROM users WHERE id= ?"
        with self.conn:
            cursor=self.conn.execute(query,(str(user_id),))
            return cursor.rowcount>0
    
    def set_status(self, user_id: str, is_active: bool) -> bool:
        """Activate or deactivate/suspend a user account(soft-delete)."""
        query="UPDATE users SET is_active = ? WHERE id = ?"
        status_int = 1 if is_active else 0
        with self.conn:
            cursor = self.conn.execute(query,(status_int, str(user_id)))
            return cursor.rowcount > 0