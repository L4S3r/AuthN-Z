"""
Auth N&Z - Task and Team Repository (task_repository.py)
-------------------------------------------------------
Persistent SQLite storage for team tasks, sprints, members, and invitations.
Uses WAL mode for high-concurrency multi-process read/write operations.
"""

from datetime import datetime, timedelta, timezone
import json
import logging
import secrets
import sqlite3
from typing import Any, Dict, List, Optional
import uuid

logger = logging.getLogger("auth_nz.task_repository")


class TaskRepository:
    def __init__(self, db_file: str = "DATABASE.db"):
        self.db_file = db_file
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_file, timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _init_db(self) -> None:
        """Initialize tasks and team_members database tables with migration checks."""
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS tasks (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    description TEXT,
                    status TEXT NOT NULL DEFAULT 'todo',
                    priority TEXT NOT NULL DEFAULT 'medium',
                    assignee_email TEXT,
                    assignee_name TEXT,
                    created_by TEXT NOT NULL,
                    tags TEXT DEFAULT '[]',
                    due_date TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS team_members (
                    id TEXT PRIMARY KEY,
                    email TEXT NOT NULL UNIQUE,
                    name TEXT,
                    role TEXT NOT NULL DEFAULT 'viewer',
                    department TEXT NOT NULL DEFAULT 'General',
                    status TEXT NOT NULL DEFAULT 'active',
                    invited_by TEXT,
                    invite_token TEXT,
                    expires_at TEXT,
                    invited_at TEXT NOT NULL
                );
            """)

            # Column migrations for existing databases
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(team_members);")
            columns = [row["name"] for row in cursor.fetchall()]
            if "invite_token" not in columns:
                cursor.execute("ALTER TABLE team_members ADD COLUMN invite_token TEXT;")
            if "expires_at" not in columns:
                cursor.execute("ALTER TABLE team_members ADD COLUMN expires_at TEXT;")

            conn.commit()

    # =========================================================================
    # Task Operations
    # =========================================================================

    def list_tasks(
        self,
        status: Optional[str] = None,
        priority: Optional[str] = None,
        assignee_email: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List tasks with optional filtering."""
        query = "SELECT * FROM tasks WHERE 1=1"
        params: List[Any] = []

        if status:
            query += " AND status = ?"
            params.append(status)
        if priority:
            query += " AND priority = ?"
            params.append(priority)
        if assignee_email:
            query += " AND assignee_email = ?"
            params.append(assignee_email)

        query += " ORDER BY datetime(created_at) DESC"

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [self._format_task(dict(r)) for r in rows]

    def get_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM tasks WHERE id = ?", (task_id,))
            row = cursor.fetchone()
            return self._format_task(dict(row)) if row else None

    def create_task(self, data: Dict[str, Any]) -> Dict[str, Any]:
        task_id = data.get("id") or str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        tags_json = json.dumps(data.get("tags", []))

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO tasks (
                    id, title, description, status, priority,
                    assignee_email, assignee_name, created_by,
                    tags, due_date, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                task_id,
                data.get("title", "").strip(),
                data.get("description", "").strip(),
                data.get("status", "todo"),
                data.get("priority", "medium"),
                data.get("assignee_email"),
                data.get("assignee_name"),
                data.get("created_by", "system"),
                tags_json,
                data.get("due_date"),
                now,
                now,
            ))
            conn.commit()
            return self.get_task(task_id)  # type: ignore

    def update_task(self, task_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        fields = []
        params = []
        now = datetime.now(timezone.utc).isoformat()

        for key in ["title", "description", "status", "priority", "assignee_email", "assignee_name", "due_date"]:
            if key in updates:
                fields.append(f"{key} = ?")
                params.append(updates[key])

        if "tags" in updates:
            fields.append("tags = ?")
            params.append(json.dumps(updates["tags"]))

        if not fields:
            return self.get_task(task_id)

        fields.append("updated_at = ?")
        params.append(now)
        params.append(task_id)

        query = f"UPDATE tasks SET {', '.join(fields)} WHERE id = ?"

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            conn.commit()
            return self.get_task(task_id)

    def delete_task(self, task_id: str) -> bool:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM tasks WHERE id = ?", (task_id,))
            conn.commit()
            return cursor.rowcount > 0

    def _format_task(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        tags = raw.get("tags", "[]")
        if isinstance(tags, str):
            try:
                raw["tags"] = json.loads(tags)
            except Exception:
                raw["tags"] = []
        return raw

    # =========================================================================
    # Team Management & Invitation Operations
    # =========================================================================

    def list_team_members(self) -> List[Dict[str, Any]]:
        """List all team members and registered users combined."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, username, email, roles, metadata, created_at FROM users")
            users = cursor.fetchall()

            cursor.execute("SELECT * FROM team_members")
            invites = cursor.fetchall()

        members_map: Dict[str, Dict[str, Any]] = {}

        for u in users:
            roles = u["roles"]
            if isinstance(roles, str):
                try:
                    roles = json.loads(roles)
                except Exception:
                    roles = []
            role = "admin" if "admin" in roles else ("editor" if "editor" in roles else "viewer")

            metadata = u["metadata"]
            if isinstance(metadata, str):
                try:
                    metadata = json.loads(metadata)
                except Exception:
                    metadata = {}

            dept = metadata.get("department", "General") if isinstance(metadata, dict) else "General"
            name = metadata.get("name", u["username"]) if isinstance(metadata, dict) else u["username"]
            avatar_url = metadata.get("avatar_url") if isinstance(metadata, dict) else None

            members_map[u["email"].lower()] = {
                "id": u["id"],
                "email": u["email"],
                "name": name,
                "role": role,
                "department": dept,
                "avatar_url": avatar_url,
                "status": "active",
                "invited_at": u["created_at"],
            }

        for inv in invites:
            email = inv["email"].lower()
            if email not in members_map:
                members_map[email] = {
                    "id": inv["id"],
                    "email": inv["email"],
                    "name": inv["name"] or email.split("@")[0],
                    "role": inv["role"],
                    "department": inv["department"],
                    "avatar_url": None,
                    "status": inv["status"],
                    "invited_at": inv["invited_at"],
                    "expires_at": inv["expires_at"] if "expires_at" in inv.keys() else None,
                }

        return list(members_map.values())


    def invite_member(
        self,
        email: str,
        name: str,
        role: str = "viewer",
        department: str = "General",
        invited_by: str = "admin",
        expires_days: int = 7,
    ) -> Dict[str, Any]:
        """Record a secure invitation token for a new team member."""
        member_id = str(uuid.uuid4())
        invite_token = secrets.token_urlsafe(32)
        now = datetime.now(timezone.utc)
        expires_at = (now + timedelta(days=expires_days)).isoformat()
        now_str = now.isoformat()

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO team_members (id, email, name, role, department, status, invited_by, invite_token, expires_at, invited_at)
                VALUES (?, ?, ?, ?, ?, 'invited', ?, ?, ?, ?)
                ON CONFLICT(email) DO UPDATE SET
                    name=excluded.name,
                    role=excluded.role,
                    department=excluded.department,
                    invite_token=excluded.invite_token,
                    expires_at=excluded.expires_at,
                    invited_at=excluded.invited_at
            """, (member_id, email.strip().lower(), name.strip(), role, department, invited_by, invite_token, expires_at, now_str))
            conn.commit()

        return {
            "id": member_id,
            "email": email.strip().lower(),
            "name": name.strip(),
            "role": role,
            "department": department,
            "status": "invited",
            "invited_by": invited_by,
            "invite_token": invite_token,
            "expires_at": expires_at,
            "invited_at": now_str,
        }

    def get_invitation_by_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Resolve and validate an invitation by token."""
        if not token:
            return None

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM team_members WHERE invite_token = ?", (token.strip(),))
            row = cursor.fetchone()
            if not row:
                return None

            data = dict(row)
            expires_at = data.get("expires_at")
            if expires_at:
                try:
                    exp_dt = datetime.fromisoformat(expires_at)
                    if datetime.now(timezone.utc) > exp_dt:
                        data["is_expired"] = True
                    else:
                        data["is_expired"] = False
                except Exception:
                    data["is_expired"] = False
            else:
                data["is_expired"] = False

            return data

    def accept_invitation(self, token: str) -> bool:
        """Mark invitation as accepted and active."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE team_members
                SET status = 'active', invite_token = NULL
                WHERE invite_token = ?
            """, (token.strip(),))
            conn.commit()
            return cursor.rowcount > 0

    def remove_member(self, email: str) -> bool:
        """Remove a team member or cancel an invitation."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM team_members WHERE LOWER(email) = LOWER(?)", (email.strip(),))
            conn.commit()
            return cursor.rowcount > 0
