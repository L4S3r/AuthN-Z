"""
Auth N&Z - Task and Team Repository (PostgreSQL Async)
-----------------------------------------------------
Persistent PostgreSQL storage for team tasks, sprints, members, and invitations using
async SQLAlchemy (asyncpg) with connection pooling and non-blocking I/O.
"""

from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
import json
import logging
import secrets
from typing import Any, Dict, List, Optional
import uuid

from sqlalchemy import Text, delete, func, or_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from database import get_session_factory
from workspace_models import Task, TeamMember, Workspace
from default_user import User

logger = logging.getLogger("auth_nz.task_repository")


class TaskRepository:
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

    @asynccontextmanager
    async def _use_session(self, session: Optional[AsyncSession] = None):
        """Context manager yielding caller-provided session without auto-committing, or self-owned session with auto-commit."""
        if session is not None:
            yield session, False
        else:
            async with self.session_factory() as new_session:
                yield new_session, True

    async def _resolve_workspace_id(
        self, session: AsyncSession, ws_input: Optional[str]
    ) -> uuid.UUID:
        """Resolve workspace input string/UUID to a valid workspace UUID, auto-provisioning default if necessary."""
        if ws_input:
            clean_input = str(ws_input).strip()
            # Try parsing as UUID
            try:
                parsed_uid = uuid.UUID(clean_input)
                # Check if workspace exists
                ws_check = await session.execute(
                    select(Workspace.id).where(Workspace.id == parsed_uid)
                )
                if ws_check.scalar_one_or_none():
                    return parsed_uid
            except (ValueError, AttributeError):
                pass

            # Lookup by slug or name
            ws_slug_check = await session.execute(
                select(Workspace.id).where(
                    or_(
                        func.lower(Workspace.slug) == clean_input.lower(),
                        func.lower(Workspace.name) == clean_input.lower(),
                    )
                )
            )
            found_id = ws_slug_check.scalar_one_or_none()
            if found_id:
                return found_id

        # Fallback to existing first workspace if any
        first_ws = await session.execute(
            select(Workspace.id).order_by(Workspace.created_at.asc()).limit(1)
        )
        existing_id = first_ws.scalar_one_or_none()
        if existing_id:
            return existing_id

        raise ValueError("Workspace not found. A valid workspace must be created before managing tasks.")

    @staticmethod
    def _format_task(task: Task) -> Dict[str, Any]:
        """Format SQLAlchemy Task instance into API response dictionary."""
        tags = task.tags if isinstance(task.tags, list) else []
        assignees = task.assignees if isinstance(task.assignees, list) else []

        if not assignees and task.assignee_email:
            assignees = [
                {
                    "email": task.assignee_email,
                    "name": task.assignee_name or task.assignee_email.split("@")[0],
                }
            ]

        primary_email = task.assignee_email or (
            assignees[0]["email"] if assignees else None
        )
        primary_name = task.assignee_name or (
            assignees[0]["name"] if assignees else None
        )

        created_str = (
            task.created_at.isoformat()
            if isinstance(task.created_at, datetime)
            else str(task.created_at)
        )
        updated_str = (
            task.updated_at.isoformat()
            if isinstance(task.updated_at, datetime)
            else str(task.updated_at)
        )

        return {
            "id": str(task.id),
            "workspace_id": str(task.workspace_id),
            "title": task.title,
            "description": task.description or "",
            "status": task.status,
            "priority": task.priority,
            "assignee_email": primary_email,
            "assignee_name": primary_name,
            "assignees": assignees,
            "created_by": task.created_by,
            "tags": tags,
            "due_date": task.due_date,
            "created_at": created_str,
            "updated_at": updated_str,
        }

    # =========================================================================
    # Task Operations
    # =========================================================================

    async def list_tasks(
        self,
        workspace_id: Optional[str] = None,
        workspace_ids: Optional[List[uuid.UUID]] = None,
        status: Optional[str] = None,
        priority: Optional[str] = None,
        assignee_email: Optional[str] = None,
        limit: Optional[int] = None,
        offset: int = 0,
        session: Optional[AsyncSession] = None,
    ) -> Dict[str, Any]:
        """List tasks with optional workspace, status, priority, and assignee filtering and DB-level pagination."""
        if workspace_id is not None and workspace_ids is not None:
            raise ValueError("Cannot provide both 'workspace_id' and 'workspace_ids'.")

        async with self._use_session(session) as (sess, _):
            stmt = select(Task)

            if workspace_id:
                try:
                    ws_uid = uuid.UUID(str(workspace_id).strip())
                    stmt = stmt.where(Task.workspace_id == ws_uid)
                except (ValueError, AttributeError):
                    # Lookup by workspace slug
                    ws_res = await sess.execute(
                        select(Workspace.id).where(
                            func.lower(Workspace.slug) == workspace_id.strip().lower()
                        )
                    )
                    found_ws_id = ws_res.scalar_one_or_none()
                    if found_ws_id:
                        stmt = stmt.where(Task.workspace_id == found_ws_id)
            elif workspace_ids is not None:
                stmt = stmt.where(Task.workspace_id.in_(workspace_ids))

            if status:
                stmt = stmt.where(Task.status == status.strip())
            if priority:
                stmt = stmt.where(Task.priority == priority.strip())
            if assignee_email:
                target_email = assignee_email.strip().lower()
                escaped_email = (
                    target_email.replace("\\", "\\\\")
                    .replace("%", "\\%")
                    .replace("_", "\\_")
                )
                stmt = stmt.where(
                    or_(
                        func.lower(Task.assignee_email) == target_email,
                        Task.assignees.cast(Text).ilike(f'%"{escaped_email}"%', escape="\\"),
                    )
                )

            # Compute total count matching all filters before pagination
            count_stmt = select(func.count()).select_from(stmt.subquery())
            total_count = (await sess.execute(count_stmt)).scalar() or 0

            # Apply deterministic ordering and DB pagination
            stmt = stmt.order_by(Task.created_at.desc(), Task.id.asc()).offset(offset)
            if limit is not None:
                stmt = stmt.limit(limit)

            result = await sess.execute(stmt)
            tasks = result.scalars().all()

        formatted = [self._format_task(t) for t in tasks]
        return {"tasks": formatted, "total": total_count}

    async def get_task(
        self, task_id: str, session: Optional[AsyncSession] = None
    ) -> Optional[Dict[str, Any]]:
        """Fetch a task record by UUID."""
        if not task_id:
            return None
        try:
            tid = uuid.UUID(str(task_id).strip())
        except (ValueError, AttributeError):
            return None

        async with self._use_session(session) as (sess, _):
            stmt = select(Task).where(Task.id == tid)
            result = await sess.execute(stmt)
            task = result.scalars().first()
            return self._format_task(task) if task else None

    async def create_task(
        self, data: Dict[str, Any], session: Optional[AsyncSession] = None
    ) -> Dict[str, Any]:
        """Insert a new sprint task card."""
        task_id_raw = data.get("id")
        if task_id_raw:
            try:
                task_id = uuid.UUID(str(task_id_raw).strip())
            except (ValueError, AttributeError):
                task_id = uuid.uuid4()
        else:
            task_id = uuid.uuid4()

        tags_raw = data.get("tags", [])
        if isinstance(tags_raw, str):
            try:
                tags = json.loads(tags_raw)
            except Exception:
                tags = []
        else:
            tags = list(tags_raw or [])

        assignees_raw = data.get("assignees") or []
        if isinstance(assignees_raw, str):
            try:
                assignees = json.loads(assignees_raw)
            except Exception:
                assignees = []
        else:
            assignees = list(assignees_raw or [])

        if not assignees and data.get("assignee_email"):
            assignees = [
                {
                    "email": data["assignee_email"],
                    "name": data.get("assignee_name")
                    or data["assignee_email"].split("@")[0],
                    "avatar_url": data.get("assignee_avatar"),
                }
            ]

        primary_email = data.get("assignee_email") or (
            assignees[0]["email"] if assignees else None
        )
        primary_name = data.get("assignee_name") or (
            assignees[0]["name"] if assignees else None
        )

        async with self._use_session(session) as (sess, should_commit):
            ws_id = await self._resolve_workspace_id(sess, data.get("workspace_id"))
            new_task = Task(
                id=task_id,
                workspace_id=ws_id,
                title=data.get("title", "").strip(),
                description=(data.get("description") or "").strip() or None,
                status=data.get("status", "todo"),
                priority=data.get("priority", "medium"),
                assignee_email=primary_email,
                assignee_name=primary_name,
                assignees=assignees,
                created_by=data.get("created_by", "system"),
                tags=tags,
                due_date=data.get("due_date"),
            )
            sess.add(new_task)
            if should_commit:
                await sess.commit()

        return await self.get_task(str(task_id), session=session)  # type: ignore

    async def update_task(
        self,
        task_id: str,
        updates: Dict[str, Any],
        session: Optional[AsyncSession] = None,
    ) -> Optional[Dict[str, Any]]:
        """Update fields of an existing task."""
        if not task_id:
            return None
        try:
            tid = uuid.UUID(str(task_id).strip())
        except (ValueError, AttributeError):
            return None

        allowed_fields = {
            "title",
            "description",
            "status",
            "priority",
            "assignee_email",
            "assignee_name",
            "due_date",
            "workspace_id",
            "tags",
            "assignees",
        }
        filtered: Dict[str, Any] = {}

        for key, value in updates.items():
            if key in allowed_fields:
                if key == "tags":
                    if isinstance(value, str):
                        try:
                            filtered["tags"] = json.loads(value)
                        except Exception:
                            filtered["tags"] = []
                    else:
                        filtered["tags"] = list(value or [])
                elif key == "assignees":
                    if isinstance(value, str):
                        try:
                            assignees_data = json.loads(value)
                        except Exception:
                            assignees_data = []
                    else:
                        assignees_data = list(value or [])
                    filtered["assignees"] = assignees_data
                    if assignees_data:
                        if "assignee_email" not in updates:
                            filtered["assignee_email"] = assignees_data[0].get("email")
                        if "assignee_name" not in updates:
                            filtered["assignee_name"] = assignees_data[0].get("name")
                else:
                    filtered[key] = value

        if not filtered:
            return await self.get_task(task_id, session=session)

        async with self._use_session(session) as (sess, should_commit):
            if "workspace_id" in filtered:
                filtered["workspace_id"] = await self._resolve_workspace_id(
                    sess, filtered["workspace_id"]
                )

            stmt = (
                update(Task)
                .where(Task.id == tid)
                .values(**filtered, updated_at=func.now())
            )
            result = await sess.execute(stmt)
            if should_commit:
                await sess.commit()
            if (result.rowcount or 0) == 0:
                return None

        return await self.get_task(task_id, session=session)

    async def delete_task(
        self, task_id: str, session: Optional[AsyncSession] = None
    ) -> bool:
        """Permanently remove a task card."""
        if not task_id:
            return False
        try:
            tid = uuid.UUID(str(task_id).strip())
        except (ValueError, AttributeError):
            return False

        async with self._use_session(session) as (sess, should_commit):
            stmt = delete(Task).where(Task.id == tid)
            result = await sess.execute(stmt)
            if should_commit:
                await sess.commit()
            return (result.rowcount or 0) > 0

    # =========================================================================
    # Team Management & Invitation Operations
    # =========================================================================

    async def list_team_members(
        self, session: Optional[AsyncSession] = None
    ) -> List[Dict[str, Any]]:
        """List all registered users and pending team members combined."""
        async with self._use_session(session) as (sess, _):
            users_res = await sess.execute(select(User))
            users = users_res.scalars().all()

            tm_res = await sess.execute(select(TeamMember))
            invites = tm_res.scalars().all()

        members_map: Dict[str, Dict[str, Any]] = {}

        for u in users:
            roles = u.roles if isinstance(u.roles, list) else []
            role = (
                "admin"
                if "admin" in roles
                else ("editor" if "editor" in roles else "viewer")
            )

            meta = u.metadata_ if isinstance(u.metadata_, dict) else {}
            dept = (
                meta.get("department", "General")
                if isinstance(meta, dict)
                else "General"
            )
            name = (
                meta.get("name", u.username)
                if isinstance(meta, dict)
                else u.username
            )
            avatar_url = meta.get("avatar_url") if isinstance(meta, dict) else None

            created_str = (
                u.created_at.isoformat()
                if isinstance(u.created_at, datetime)
                else str(u.created_at)
            )

            members_map[u.email.lower()] = {
                "id": str(u.id),
                "email": u.email,
                "name": name,
                "role": role,
                "department": dept,
                "avatar_url": avatar_url,
                "status": "active",
                "invited_at": created_str,
            }

        for inv in invites:
            email = inv.email.lower()
            if email not in members_map:
                inv_created = (
                    inv.invited_at.isoformat()
                    if isinstance(inv.invited_at, datetime)
                    else str(inv.invited_at)
                )
                exp_str = (
                    inv.expires_at.isoformat() if inv.expires_at else None
                )
                members_map[email] = {
                    "id": str(inv.id),
                    "email": inv.email,
                    "name": inv.name or email.split("@")[0],
                    "role": inv.role,
                    "department": inv.department,
                    "avatar_url": None,
                    "status": inv.status,
                    "invited_at": inv_created,
                    "expires_at": exp_str,
                }

        return list(members_map.values())

    async def invite_member(
        self,
        email: str,
        name: str,
        role: str = "viewer",
        department: str = "General",
        invited_by: str = "admin",
        expires_days: int = 7,
        session: Optional[AsyncSession] = None,
    ) -> Dict[str, Any]:
        """Record a secure invitation token for a new team member using ON CONFLICT DO UPDATE."""
        clean_email = email.strip().lower()
        clean_name = name.strip()
        member_id = uuid.uuid4()
        invite_token = secrets.token_urlsafe(32)
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(days=expires_days)

        stmt = pg_insert(TeamMember).values(
            id=member_id,
            email=clean_email,
            name=clean_name,
            role=role,
            department=department,
            status="invited",
            invited_by=invited_by,
            invite_token=invite_token,
            expires_at=expires_at,
            invited_at=now,
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=[TeamMember.email],
            set_={
                "name": stmt.excluded.name,
                "role": stmt.excluded.role,
                "department": stmt.excluded.department,
                "invite_token": stmt.excluded.invite_token,
                "expires_at": stmt.excluded.expires_at,
                "invited_at": stmt.excluded.invited_at,
                "status": "invited",
            },
        )

        async with self._use_session(session) as (sess, should_commit):
            await sess.execute(stmt)
            if should_commit:
                await sess.commit()

        return {
            "id": str(member_id),
            "email": clean_email,
            "name": clean_name,
            "role": role,
            "department": department,
            "status": "invited",
            "invited_by": invited_by,
            "invite_token": invite_token,
            "expires_at": expires_at.isoformat(),
            "invited_at": now.isoformat(),
        }

    async def get_invitation_by_token(
        self, token: str, session: Optional[AsyncSession] = None
    ) -> Optional[Dict[str, Any]]:
        """Resolve and validate an invitation by token."""
        clean_token = (token or "").strip()
        if not clean_token:
            return None

        async with self._use_session(session) as (sess, _):
            stmt = select(TeamMember).where(TeamMember.invite_token == clean_token)
            result = await sess.execute(stmt)
            inv = result.scalars().first()
            if not inv:
                return None

            inv_created = (
                inv.invited_at.isoformat()
                if isinstance(inv.invited_at, datetime)
                else str(inv.invited_at)
            )
            exp_str = inv.expires_at.isoformat() if inv.expires_at else None

            data: Dict[str, Any] = {
                "id": str(inv.id),
                "email": inv.email,
                "name": inv.name,
                "role": inv.role,
                "department": inv.department,
                "status": inv.status,
                "invited_by": inv.invited_by,
                "invite_token": inv.invite_token,
                "expires_at": exp_str,
                "invited_at": inv_created,
            }

            if inv.expires_at:
                exp_dt = (
                    inv.expires_at
                    if inv.expires_at.tzinfo
                    else inv.expires_at.replace(tzinfo=timezone.utc)
                )
                data["is_expired"] = datetime.now(timezone.utc) > exp_dt
            else:
                data["is_expired"] = False

            return data

    async def accept_invitation(
        self, token: str, session: Optional[AsyncSession] = None
    ) -> bool:
        """Mark invitation as accepted and active."""
        clean_token = (token or "").strip()
        if not clean_token:
            return False

        async with self._use_session(session) as (sess, should_commit):
            stmt = (
                update(TeamMember)
                .where(TeamMember.invite_token == clean_token)
                .values(status="active", invite_token=None)
            )
            result = await sess.execute(stmt)
            if should_commit:
                await sess.commit()
            return (result.rowcount or 0) > 0

    async def remove_member(
        self, email: str, session: Optional[AsyncSession] = None
    ) -> bool:
        """Remove a team member or cancel an invitation."""
        clean_email = (email or "").strip().lower()
        if not clean_email:
            return False

        async with self._use_session(session) as (sess, should_commit):
            stmt = delete(TeamMember).where(
                func.lower(TeamMember.email) == clean_email
            )
            result = await sess.execute(stmt)
            if should_commit:
                await sess.commit()
            return (result.rowcount or 0) > 0
