"""
Auth N&Z - Workspace and Multi-Tenancy Repository (workspace_repository.py)
-------------------------------------------------------------------------
This component provides modular, persistent SQLite storage for multi-tenant workspaces,
workspace memberships, role assignments, and team invitations.
Uses SQLite WAL mode for high-concurrency multi-process read/write operations.
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
from typing import Any, Dict, List, Optional, Set
import uuid

logger = logging.getLogger("auth_nz.workspace_repository")


class abstractWorkspaceRepository(ABC):
    """Abstract interface defining persistence operations for workspaces and scoped memberships."""

    @abstractmethod
    def create_workspace(
        self,
        name: str,
        created_by: str,
        slug: Optional[str] = None,
        description: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a new workspace and automatically assign creator as workspace admin."""
        pass

    @abstractmethod
    def get_workspace(self, workspace_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a workspace by its unique primary identifier."""
        pass

    @abstractmethod
    def get_workspace_by_slug(self, slug: str) -> Optional[Dict[str, Any]]:
        """Retrieve a workspace by its URL slug identifier."""
        pass

    @abstractmethod
    def list_workspaces_for_user(
        self,
        user_id: str,
        email: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List all workspaces where the given user is an active member or pending invitee."""
        pass

    @abstractmethod
    def list_all_workspaces(self) -> List[Dict[str, Any]]:
        """List all registered workspaces across the system."""
        pass

    @abstractmethod
    def update_workspace(
        self,
        workspace_id: str,
        updates: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """Update workspace metadata (name, slug, description)."""
        pass

    @abstractmethod
    def delete_workspace(self, workspace_id: str) -> bool:
        """Delete a workspace and cascade deletion of its members and tasks."""
        pass

    @abstractmethod
    def add_member(
        self,
        workspace_id: str,
        email: str,
        user_id: Optional[str] = None,
        name: Optional[str] = None,
        role: str = "viewer",
        department: str = "General",
        status: str = "active",
        invited_by: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Directly add or link an active member to a workspace."""
        pass

    @abstractmethod
    def invite_member(
        self,
        workspace_id: str,
        email: str,
        name: Optional[str] = None,
        role: str = "viewer",
        department: str = "General",
        invited_by: str = "Admin",
        expires_days: int = 7,
    ) -> Dict[str, Any]:
        """Issue a cryptographic single-use invitation to join a specific workspace."""
        pass

    @abstractmethod
    def get_member(
        self,
        workspace_id: str,
        user_id: Optional[str] = None,
        email: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Retrieve a member record within a workspace scope by user_id or email."""
        pass

    @abstractmethod
    def list_members(
        self,
        workspace_id: str,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List all members and pending invitations within a specific workspace."""
        pass

    @abstractmethod
    def get_invitation_by_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Resolve and validate an invitation token across all workspaces."""
        pass

    @abstractmethod
    def accept_invitation(
        self,
        token: str,
        user_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Mark an invitation token as consumed, link the user ID, and activate membership."""
        pass

    @abstractmethod
    def update_member_role(
        self,
        workspace_id: str,
        user_id_or_email: str,
        new_role: str,
    ) -> bool:
        """Update a member's clearance role within a specific workspace."""
        pass

    @abstractmethod
    def remove_member(
        self,
        workspace_id: str,
        user_id_or_email: str,
    ) -> bool:
        """Remove a member from a workspace or cancel a pending invitation."""
        pass


class WorkspaceRepository(abstractWorkspaceRepository):
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
            conn.execute("PRAGMA foreign_keys=ON;")
            yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        """Initialize workspaces and workspace_members tables with backward-compatible migrations."""
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS workspaces (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    slug TEXT UNIQUE NOT NULL,
                    description TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS workspace_members (
                    id TEXT PRIMARY KEY,
                    workspace_id TEXT NOT NULL,
                    user_id TEXT,
                    email TEXT NOT NULL,
                    name TEXT,
                    role TEXT NOT NULL DEFAULT 'viewer',
                    department TEXT NOT NULL DEFAULT 'General',
                    status TEXT NOT NULL DEFAULT 'active',
                    invited_by TEXT,
                    invite_token TEXT,
                    expires_at TEXT,
                    invited_at TEXT NOT NULL,
                    FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
                    UNIQUE (workspace_id, email)
                );
            """)

            conn.execute("CREATE INDEX IF NOT EXISTS idx_wm_token ON workspace_members(invite_token);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ws_slug ON workspaces(slug);")

            # Migration: Ensure tasks table has workspace_id column
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(tasks);")
            task_columns = [row["name"] for row in cursor.fetchall()]
            if task_columns and "workspace_id" not in task_columns:
                cursor.execute("ALTER TABLE tasks ADD COLUMN workspace_id TEXT DEFAULT 'ws_default';")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_tasks_ws ON tasks(workspace_id);")

            conn.commit()

        # Ensure default workspace exists and migrate existing records
        self._ensure_default_workspace_migration()

    @staticmethod
    def _hash_token(token: str) -> str:
        """Compute SHA-256 digest of an invitation token for secure at-rest storage."""
        return hashlib.sha256((token or "").strip().encode("utf-8")).hexdigest()

    def _slugify(self, text: str) -> str:
        """Generate a clean URL slug from a display name."""
        text = text.lower().strip()
        text = re.sub(r"[^\w\s-]", "", text)
        text = re.sub(r"[\s_-]+", "-", text)
        return text or f"workspace-{secrets.token_hex(3)}"

    def _ensure_default_workspace_migration(self) -> None:
        """Auto-provision default workspace and migrate legacy team_members and tasks."""
        now = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Check if default workspace exists
            cursor.execute("SELECT id FROM workspaces WHERE id = 'ws_default' OR slug = 'default'")
            default_ws = cursor.fetchone()

            # Check if users table exists before attempting user migration
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
            has_users_table = cursor.fetchone() is not None

            if not default_ws:
                creator_id = "system"
                if has_users_table:
                    cursor.execute("SELECT id, email, username FROM users ORDER BY created_at ASC LIMIT 1")
                    first_user = cursor.fetchone()
                    if first_user:
                        creator_id = first_user["id"]

                cursor.execute("""
                    INSERT OR IGNORE INTO workspaces (id, name, slug, description, created_by, created_at, updated_at)
                    VALUES ('ws_default', 'Default Workspace', 'default', 'Primary workspace for team collaboration.', ?, ?, ?)
                """, (creator_id, now, now))

            # Migrate legacy team_members table into workspace_members if team_members exists
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='team_members'")
            if cursor.fetchone():
                cursor.execute("SELECT * FROM team_members")
                legacy_members = cursor.fetchall()
                for lm in legacy_members:
                    lm_dict = dict(lm)
                    email = lm_dict.get("email", "").strip().lower()
                    if not email:
                        continue

                    # Lookup user_id if registered
                    cursor.execute("SELECT id FROM users WHERE LOWER(email) = LOWER(?)", (email,))
                    user_row = cursor.fetchone()
                    user_id = user_row["id"] if user_row else None

                    cursor.execute("""
                        INSERT OR IGNORE INTO workspace_members (
                            id, workspace_id, user_id, email, name, role, department,
                            status, invited_by, invite_token, expires_at, invited_at
                        ) VALUES (?, 'ws_default', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        lm_dict.get("id") or str(uuid.uuid4()),
                        user_id,
                        email,
                        lm_dict.get("name"),
                        lm_dict.get("role", "viewer"),
                        lm_dict.get("department", "General"),
                        lm_dict.get("status", "active"),
                        lm_dict.get("invited_by", "system"),
                        lm_dict.get("invite_token"),
                        lm_dict.get("expires_at"),
                        lm_dict.get("invited_at") or now,
                    ))

            # Migrate legacy tasks without workspace_id
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='tasks'")
            if cursor.fetchone():
                cursor.execute("UPDATE tasks SET workspace_id = 'ws_default' WHERE workspace_id IS NULL OR workspace_id = ''")

            conn.commit()

    # =========================================================================
    # Workspace Operations
    # =========================================================================

    def create_workspace(
        self,
        name: str,
        created_by: str,
        slug: Optional[str] = None,
        description: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a new workspace and automatically enroll the creator as an Admin member."""
        workspace_id = f"ws_{secrets.token_hex(6)}"
        clean_name = name.strip()
        base_slug = self._slugify(slug or clean_name)
        target_slug = base_slug
        now = datetime.now(timezone.utc).isoformat()

        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Ensure slug uniqueness
            counter = 1
            while True:
                cursor.execute("SELECT id FROM workspaces WHERE slug = ?", (target_slug,))
                if not cursor.fetchone():
                    break
                counter += 1
                target_slug = f"{base_slug}-{counter}"

            cursor.execute("""
                INSERT INTO workspaces (id, name, slug, description, created_by, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (workspace_id, clean_name, target_slug, (description or "").strip(), created_by, now, now))

            # Lookup creator's email & name if users table exists
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
            has_users = cursor.fetchone() is not None
            if has_users:
                cursor.execute("SELECT id, email, username, metadata FROM users WHERE id = ?", (created_by,))
                user = cursor.fetchone()
                if user:
                    user_email = user["email"].strip().lower()
                    meta = {}
                    if user["metadata"]:
                        try:
                            meta = json.loads(user["metadata"])
                        except Exception:
                            pass
                    user_name = meta.get("name") or user["username"]
                    user_dept = meta.get("department", "Management")

                    cursor.execute("""
                        INSERT INTO workspace_members (
                            id, workspace_id, user_id, email, name, role, department, status, invited_by, invited_at
                        ) VALUES (?, ?, ?, ?, ?, 'admin', ?, 'active', ?, ?)
                    """, (str(uuid.uuid4()), workspace_id, created_by, user_email, user_name, user_dept, created_by, now))
            else:
                # Direct enroll if standalone
                cursor.execute("""
                    INSERT INTO workspace_members (
                        id, workspace_id, user_id, email, name, role, department, status, invited_by, invited_at
                    ) VALUES (?, ?, ?, ?, ?, 'admin', 'Management', 'active', ?, ?)
                """, (str(uuid.uuid4()), workspace_id, created_by, f"{created_by}@workspace.local", created_by, created_by, now))

            conn.commit()

        return self.get_workspace(workspace_id)  # type: ignore

    def get_workspace(self, workspace_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve workspace by ID."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM workspaces WHERE id = ?", (workspace_id.strip(),))
            row = cursor.fetchone()
            if not row:
                return None
            return self._format_workspace(dict(row))

    def get_workspace_by_slug(self, slug: str) -> Optional[Dict[str, Any]]:
        """Retrieve workspace by unique URL slug."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM workspaces WHERE LOWER(slug) = LOWER(?)", (slug.strip(),))
            row = cursor.fetchone()
            if not row:
                return None
            return self._format_workspace(dict(row))

    def list_workspaces_for_user(
        self,
        user_id: str,
        email: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List all workspaces where a user is enrolled, including their workspace-scoped role."""
        query = """
            SELECT w.*, wm.role as member_role, wm.status as member_status, wm.department as member_department
            FROM workspaces w
            INNER JOIN workspace_members wm ON w.id = wm.workspace_id
            WHERE wm.user_id = ?
        """
        params: List[Any] = [user_id]
        if email:
            query += " OR LOWER(wm.email) = LOWER(?)"
            params.append(email.strip().lower())

        query += " ORDER BY datetime(w.created_at) ASC"

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [self._format_workspace(dict(r)) for r in rows]

    def list_all_workspaces(self) -> List[Dict[str, Any]]:
        """List all workspaces with member counts."""
        query = """
            SELECT w.*, COUNT(wm.id) as member_count
            FROM workspaces w
            LEFT JOIN workspace_members wm ON w.id = wm.workspace_id
            GROUP BY w.id
            ORDER BY datetime(w.created_at) ASC
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query)
            rows = cursor.fetchall()
            return [self._format_workspace(dict(r)) for r in rows]

    def update_workspace(
        self,
        workspace_id: str,
        updates: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """Update workspace name, slug, or description."""
        fields = []
        params = []
        now = datetime.now(timezone.utc).isoformat()

        if "name" in updates and updates["name"]:
            fields.append("name = ?")
            params.append(updates["name"].strip())

        if "slug" in updates and updates["slug"]:
            clean_slug = self._slugify(updates["slug"])
            # Check slug collision
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT id FROM workspaces WHERE slug = ? AND id != ?", (clean_slug, workspace_id))
                if cursor.fetchone():
                    raise ValueError(f"Workspace slug '{clean_slug}' is already taken.")
            fields.append("slug = ?")
            params.append(clean_slug)

        if "description" in updates:
            fields.append("description = ?")
            params.append(updates["description"].strip() if updates["description"] else None)

        if not fields:
            return self.get_workspace(workspace_id)

        fields.append("updated_at = ?")
        params.append(now)
        params.append(workspace_id)

        query = f"UPDATE workspaces SET {', '.join(fields)} WHERE id = ?"
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            conn.commit()

        return self.get_workspace(workspace_id)

    def delete_workspace(self, workspace_id: str) -> bool:
        """Delete a workspace and cascade delete its members and tasks."""
        if workspace_id == "ws_default":
            raise ValueError("The default workspace ('ws_default') cannot be deleted.")

        with self._get_connection() as conn:
            cursor = conn.cursor()
            # Delete tasks if table exists
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='tasks'")
            if cursor.fetchone():
                cursor.execute("DELETE FROM tasks WHERE workspace_id = ?", (workspace_id,))
            # Delete workspace members
            cursor.execute("DELETE FROM workspace_members WHERE workspace_id = ?", (workspace_id,))
            # Delete workspace
            cursor.execute("DELETE FROM workspaces WHERE id = ?", (workspace_id,))
            conn.commit()
            return cursor.rowcount > 0

    def _format_workspace(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Format workspace record for API response."""
        role = raw.get("member_role") or raw.get("role")
        return {
            "id": raw["id"],
            "name": raw["name"],
            "slug": raw["slug"],
            "description": raw.get("description"),
            "created_by": raw["created_by"],
            "created_at": raw["created_at"],
            "updated_at": raw.get("updated_at", raw["created_at"]),
            "role": role,
            "member_role": role,
            "member_status": raw.get("member_status"),
            "member_department": raw.get("member_department"),
            "member_count": raw.get("member_count"),
        }

    # =========================================================================
    # Workspace Membership & Invitation Operations
    # =========================================================================

    def add_member(
        self,
        workspace_id: str,
        email: str,
        user_id: Optional[str] = None,
        name: Optional[str] = None,
        role: str = "viewer",
        department: str = "General",
        status: str = "active",
        invited_by: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Directly add or link an active member to a workspace."""
        member_id = str(uuid.uuid4())
        clean_email = email.strip().lower()
        now = datetime.now(timezone.utc).isoformat()

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO workspace_members (
                    id, workspace_id, user_id, email, name, role, department, status, invited_by, invited_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(workspace_id, email) DO UPDATE SET
                    user_id=COALESCE(excluded.user_id, workspace_members.user_id),
                    name=COALESCE(excluded.name, workspace_members.name),
                    role=excluded.role,
                    department=excluded.department,
                    status=excluded.status
            """, (
                member_id,
                workspace_id,
                user_id,
                clean_email,
                name.strip() if name else clean_email.split("@")[0],
                role,
                department,
                status,
                invited_by or "admin",
                now,
            ))
            conn.commit()

        return self.get_member(workspace_id, email=clean_email)  # type: ignore

    def invite_member(
        self,
        workspace_id: str,
        email: str,
        name: Optional[str] = None,
        role: str = "viewer",
        department: str = "General",
        invited_by: str = "Admin",
        expires_days: int = 7,
    ) -> Dict[str, Any]:
        """Issue a cryptographic single-use invitation to join a specific workspace."""
        member_id = str(uuid.uuid4())
        invite_token = secrets.token_urlsafe(32)
        token_hash = self._hash_token(invite_token)
        now = datetime.now(timezone.utc)
        expires_at = (now + timedelta(days=expires_days)).isoformat()
        now_str = now.isoformat()
        clean_email = email.strip().lower()
        safe_name = (name or clean_email.split("@")[0]).strip()

        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Check if workspace exists
            cursor.execute("SELECT id, name FROM workspaces WHERE id = ?", (workspace_id,))
            ws = cursor.fetchone()
            if not ws:
                raise ValueError(f"Workspace '{workspace_id}' does not exist.")

            # Check if user with this email already has an account if users table exists
            user_id = None
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
            if cursor.fetchone():
                cursor.execute("SELECT id FROM users WHERE LOWER(email) = LOWER(?)", (clean_email,))
                user_row = cursor.fetchone()
                user_id = user_row["id"] if user_row else None

            cursor.execute("""
                INSERT INTO workspace_members (
                    id, workspace_id, user_id, email, name, role, department, status,
                    invited_by, invite_token, expires_at, invited_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'invited', ?, ?, ?, ?)
                ON CONFLICT(workspace_id, email) DO UPDATE SET
                    name=excluded.name,
                    role=excluded.role,
                    department=excluded.department,
                    status='invited',
                    invite_token=excluded.invite_token,
                    expires_at=excluded.expires_at,
                    invited_by=excluded.invited_by,
                    invited_at=excluded.invited_at
            """, (
                member_id,
                workspace_id,
                user_id,
                clean_email,
                safe_name,
                role,
                department,
                invited_by,
                token_hash,
                expires_at,
                now_str,
            ))
            conn.commit()

        return {
            "id": member_id,
            "workspace_id": workspace_id,
            "workspace_name": ws["name"],
            "email": clean_email,
            "name": safe_name,
            "role": role,
            "department": department,
            "status": "invited",
            "invited_by": invited_by,
            "invite_token": invite_token,
            "expires_at": expires_at,
            "invited_at": now_str,
        }

    def _resolve_ws_id(self, workspace_id_or_slug: str) -> str:
        """Resolve a workspace ID or slug to canonical workspace ID."""
        clean = (workspace_id_or_slug or "").strip()
        if not clean:
            return clean
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM workspaces WHERE id = ? OR slug = ?", (clean, clean))
            row = cursor.fetchone()
            return row["id"] if row else clean

    def get_member(
        self,
        workspace_id: str,
        user_id: Optional[str] = None,
        email: Optional[str] = None,
        identifier: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Retrieve a member record within a workspace scope by user_id, email, username, or membership ID."""
        from urllib.parse import unquote
        ws_id = self._resolve_ws_id(workspace_id)

        lookup_keys = []
        if identifier:
            lookup_keys.append(unquote(identifier).strip())
        if user_id:
            lookup_keys.append(unquote(user_id).strip())
        if email:
            lookup_keys.append(unquote(email).strip().lower())

        if not lookup_keys:
            return None

        with self._get_connection() as conn:
            cursor = conn.cursor()

            extra_user_ids = []
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
            if cursor.fetchone():
                for k in lookup_keys:
                    cursor.execute("SELECT id, email FROM users WHERE id = ? OR LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?)", (k, k, k))
                    u = cursor.fetchone()
                    if u:
                        extra_user_ids.append(u["id"])
                        if u["email"]:
                            extra_user_ids.append(u["email"])

            all_keys = list(set(lookup_keys + extra_user_ids))
            placeholders = ", ".join(["?"] * len(all_keys))

            query = f"""
                SELECT * FROM workspace_members
                WHERE workspace_id = ? AND (
                    id IN ({placeholders})
                    OR user_id IN ({placeholders})
                    OR LOWER(email) IN ({placeholders})
                    OR LOWER(name) IN ({placeholders})
                )
            """
            params = [ws_id] + all_keys + all_keys + [k.lower() for k in all_keys] + [k.lower() for k in all_keys]
            cursor.execute(query, params)
            row = cursor.fetchone()
            return dict(row) if row else None

    def list_members(
        self,
        workspace_id: str,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List all members and invitations for a specific workspace with live user profile resolution."""
        ws_id = self._resolve_ws_id(workspace_id)
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
            has_users = cursor.fetchone() is not None

            if has_users:
                query = """
                    SELECT wm.*, u.username, u.metadata as user_metadata
                    FROM workspace_members wm
                    LEFT JOIN users u ON (wm.user_id = u.id OR LOWER(wm.email) = LOWER(u.email))
                    WHERE wm.workspace_id = ?
                """
            else:
                query = """
                    SELECT wm.*, NULL as username, NULL as user_metadata
                    FROM workspace_members wm
                    WHERE wm.workspace_id = ?
                """
            params: List[Any] = [ws_id]
            if status:
                query += " AND wm.status = ?"
                params.append(status)

            query += " ORDER BY wm.role ASC, datetime(wm.invited_at) ASC"
            cursor.execute(query, params)
            rows = cursor.fetchall()

            result = []
            for r in rows:
                item = dict(r)
                user_meta_name = None
                avatar_url = None
                if item.get("user_metadata"):
                    try:
                        meta = json.loads(item["user_metadata"])
                        if isinstance(meta, dict):
                            user_meta_name = meta.get("name")
                            avatar_url = meta.get("avatar_url")
                    except Exception:
                        pass

                # Priority: user.metadata.name -> wm.name -> u.username -> None
                resolved_name = user_meta_name or item.get("name") or item.get("username")
                item["name"] = resolved_name
                item["avatar_url"] = avatar_url
                item.pop("user_metadata", None)
                result.append(item)

            return result

    def get_invitation_by_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Resolve and validate an active, unconsumed invitation token across all workspaces."""
        clean_token = (token or "").strip()
        if not clean_token:
            return None

        lookup_hash = self._hash_token(clean_token)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT wm.*, w.name as workspace_name, w.slug as workspace_slug
                FROM workspace_members wm
                INNER JOIN workspaces w ON wm.workspace_id = w.id
                WHERE (wm.invite_token = ? OR wm.invite_token = ?) AND wm.status = 'invited'
            """, (lookup_hash, clean_token))
            row = cursor.fetchone()
            if not row:
                return None

            data = dict(row)
            expires_at = data.get("expires_at")
            if expires_at:
                try:
                    exp_dt = datetime.fromisoformat(expires_at)
                    data["is_expired"] = datetime.now(timezone.utc) > exp_dt
                except Exception:
                    data["is_expired"] = False
            else:
                data["is_expired"] = False

            return data

    def accept_invitation(
        self,
        token: str,
        user_id: Optional[str] = None,
        name: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Atomically consume invitation token, activate workspace clearance, synchronize name, and prevent replay."""
        clean_token = (token or "").strip()
        if not clean_token:
            return None

        invite = self.get_invitation_by_token(clean_token)
        if not invite or invite.get("is_expired"):
            return None

        lookup_hash = self._hash_token(clean_token)

        with self._get_connection() as conn:
            cursor = conn.cursor()

            resolved_name = name
            if not resolved_name and user_id:
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
                if cursor.fetchone():
                    cursor.execute("SELECT username, metadata FROM users WHERE id = ?", (user_id,))
                    u_row = cursor.fetchone()
                    if u_row:
                        u_meta = {}
                        if u_row["metadata"]:
                            try:
                                u_meta = json.loads(u_row["metadata"])
                            except Exception:
                                pass
                        resolved_name = u_meta.get("name") or u_row["username"]

            cursor.execute("""
                UPDATE workspace_members
                SET status = 'active',
                    invite_token = NULL,
                    expires_at = NULL,
                    user_id = COALESCE(?, user_id),
                    name = COALESCE(?, name)
                WHERE (invite_token = ? OR invite_token = ?) AND status = 'invited'
            """, (user_id, resolved_name, lookup_hash, clean_token))
            conn.commit()

            # Guard against concurrent consumption
            if cursor.rowcount == 0:
                return None

        return self.get_member(invite["workspace_id"], user_id=user_id, email=invite["email"])

    def update_member_role(
        self,
        workspace_id: str,
        user_id_or_email: str,
        new_role: str,
    ) -> bool:
        """Update a member's role (admin, developer, editor, viewer) within a specific workspace."""
        if new_role not in ("admin", "developer", "editor", "viewer"):
            raise ValueError(f"Invalid role '{new_role}'. Must be admin, developer, editor, or viewer.")

        from urllib.parse import unquote
        ws_id = self._resolve_ws_id(workspace_id)
        raw_ident = (user_id_or_email or "").strip()
        if not raw_ident:
            return False
        clean_ident = unquote(raw_ident).strip()

        with self._get_connection() as conn:
            cursor = conn.cursor()

            extra_ids = [clean_ident]
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
            if cursor.fetchone():
                cursor.execute("SELECT id, email FROM users WHERE id = ? OR LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?)", (clean_ident, clean_ident, clean_ident))
                u = cursor.fetchone()
                if u:
                    extra_ids.append(u["id"])
                    if u["email"]:
                        extra_ids.append(u["email"])

            all_keys = list(set(extra_ids))
            placeholders = ", ".join(["?"] * len(all_keys))

            query = f"""
                UPDATE workspace_members
                SET role = ?
                WHERE workspace_id = ? AND (
                    id IN ({placeholders})
                    OR user_id IN ({placeholders})
                    OR LOWER(email) IN ({placeholders})
                    OR LOWER(name) IN ({placeholders})
                )
            """
            params = [new_role, ws_id] + all_keys + all_keys + [k.lower() for k in all_keys] + [k.lower() for k in all_keys]
            cursor.execute(query, params)
            conn.commit()
            return cursor.rowcount > 0

    def remove_member(
        self,
        workspace_id: str,
        user_id_or_email: str,
    ) -> bool:
        """Remove a member from a workspace or revoke their invitation."""
        from urllib.parse import unquote
        ws_id = self._resolve_ws_id(workspace_id)
        raw_ident = (user_id_or_email or "").strip()
        if not raw_ident:
            return False
        clean_ident = unquote(raw_ident).strip()

        with self._get_connection() as conn:
            cursor = conn.cursor()

            extra_ids = [clean_ident]
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
            if cursor.fetchone():
                cursor.execute("SELECT id, email FROM users WHERE id = ? OR LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?)", (clean_ident, clean_ident, clean_ident))
                u = cursor.fetchone()
                if u:
                    extra_ids.append(u["id"])
                    if u["email"]:
                        extra_ids.append(u["email"])

            all_keys = list(set(extra_ids))
            placeholders = ", ".join(["?"] * len(all_keys))

            query = f"""
                DELETE FROM workspace_members
                WHERE workspace_id = ? AND (
                    id IN ({placeholders})
                    OR user_id IN ({placeholders})
                    OR LOWER(email) IN ({placeholders})
                    OR LOWER(name) IN ({placeholders})
                )
            """
            params = [ws_id] + all_keys + all_keys + [k.lower() for k in all_keys] + [k.lower() for k in all_keys]
            cursor.execute(query, params)
            conn.commit()
            return cursor.rowcount > 0

    def count_members(self, workspace_id: str) -> Dict[str, int]:
        """Return member count breakdown by role and status for a workspace."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT
                    COUNT(*) as total,
                    SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as active,
                    SUM(CASE WHEN status = 'invited' THEN 1 ELSE 0 END) as invited,
                    SUM(CASE WHEN role = 'admin' THEN 1 ELSE 0 END) as admins,
                    SUM(CASE WHEN role = 'editor' THEN 1 ELSE 0 END) as editors,
                    SUM(CASE WHEN role = 'viewer' THEN 1 ELSE 0 END) as viewers
                FROM workspace_members
                WHERE workspace_id = ?
            """, (workspace_id,))
            row = cursor.fetchone()
            if not row:
                return {"total": 0, "active": 0, "invited": 0, "admins": 0, "editors": 0, "viewers": 0}
            return {
                "total": row["total"] or 0,
                "active": row["active"] or 0,
                "invited": row["invited"] or 0,
                "admins": row["admins"] or 0,
                "editors": row["editors"] or 0,
                "viewers": row["viewers"] or 0,
            }


concreteWorkspaceRepository = WorkspaceRepository
