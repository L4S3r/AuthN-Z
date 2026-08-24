"""
Auth N&Z - Workspace and Multi-Tenancy Repository (PostgreSQL Async)
-------------------------------------------------------------------
This component provides modular, persistent PostgreSQL storage for multi-tenant workspaces,
workspace memberships, role assignments, and team invitations using async SQLAlchemy (asyncpg).
"""

from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
import hashlib
import json
import logging
import re
import secrets
from typing import Any, Dict, List, Optional
from urllib.parse import unquote
import uuid

from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from database import get_session_factory
from models import Task, TeamMember, User, Workspace, WorkspaceMember

logger = logging.getLogger("auth_nz.workspace_repository")


class abstractWorkspaceRepository(ABC):
    """Abstract interface defining persistence operations for workspaces and scoped memberships."""

    @abstractmethod
    async def create_workspace(
        self,
        name: str,
        created_by: str,
        slug: Optional[str] = None,
        description: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a new workspace and automatically assign creator as workspace admin."""
        pass

    @abstractmethod
    async def get_workspace(self, workspace_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a workspace by its unique primary identifier."""
        pass

    @abstractmethod
    async def get_workspace_by_slug(self, slug: str) -> Optional[Dict[str, Any]]:
        """Retrieve a workspace by its URL slug identifier."""
        pass

    @abstractmethod
    async def list_workspaces_for_user(
        self,
        user_id: str,
        email: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List all workspaces where the given user is an active member or pending invitee."""
        pass

    @abstractmethod
    async def list_all_workspaces(self) -> List[Dict[str, Any]]:
        """List all registered workspaces across the system."""
        pass

    @abstractmethod
    async def update_workspace(
        self,
        workspace_id: str,
        updates: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """Update workspace metadata (name, slug, description)."""
        pass

    @abstractmethod
    async def delete_workspace(self, workspace_id: str) -> bool:
        """Delete a workspace and cascade deletion of its members and tasks."""
        pass

    @abstractmethod
    async def add_member(
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
    async def invite_member(
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
    async def get_member(
        self,
        workspace_id: str,
        user_id: Optional[str] = None,
        email: Optional[str] = None,
        identifier: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Retrieve a member record within a workspace scope by user_id or email."""
        pass

    @abstractmethod
    async def list_members(
        self,
        workspace_id: str,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List all members and pending invitations within a specific workspace."""
        pass

    @abstractmethod
    async def get_invitation_by_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Resolve and validate an invitation token across all workspaces."""
        pass

    @abstractmethod
    async def accept_invitation(
        self,
        token: str,
        user_id: Optional[str] = None,
        name: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Mark an invitation token as consumed, link the user ID, and activate membership."""
        pass

    @abstractmethod
    async def update_member_role(
        self,
        workspace_id: str,
        user_id_or_email: str,
        new_role: str,
    ) -> bool:
        """Update a member's clearance role within a specific workspace."""
        pass

    @abstractmethod
    async def remove_member(
        self,
        workspace_id: str,
        user_id_or_email: str,
    ) -> bool:
        """Remove a member from a workspace or cancel a pending invitation."""
        pass


class WorkspaceRepository(abstractWorkspaceRepository):
    """PostgreSQL Async implementation of Workspace and Membership repository."""

    def __init__(
        self,
        db_url: Optional[str] = None,
        session_factory: Optional[async_sessionmaker[AsyncSession]] = None,
    ):
        self.session_factory = session_factory or get_session_factory(db_url)

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

    async def _resolve_ws_uuid(
        self, session: AsyncSession, workspace_id_or_slug: str
    ) -> Optional[uuid.UUID]:
        """Resolve workspace ID or slug to canonical Workspace UUID."""
        if not workspace_id_or_slug:
            return None
        clean = str(workspace_id_or_slug).strip()
        try:
            parsed_uid = uuid.UUID(clean)
            ws_check = await session.execute(
                select(Workspace.id).where(Workspace.id == parsed_uid)
            )
            if ws_check.scalar_one_or_none():
                return parsed_uid
        except (ValueError, AttributeError):
            pass

        ws_slug_check = await session.execute(
            select(Workspace.id).where(
                or_(
                    func.lower(Workspace.slug) == clean.lower(),
                    func.lower(Workspace.name) == clean.lower(),
                )
            )
        )
        return ws_slug_check.scalar_one_or_none()

    @staticmethod
    def _format_workspace(raw: Dict[str, Any]) -> Dict[str, Any]:
        """Format workspace record for API response."""
        role = raw.get("member_role") or raw.get("role")
        return {
            "id": str(raw["id"]),
            "name": raw["name"],
            "slug": raw["slug"],
            "description": raw.get("description"),
            "created_by": str(raw["created_by"]),
            "created_at": (
                raw["created_at"].isoformat()
                if isinstance(raw["created_at"], datetime)
                else str(raw["created_at"])
            ),
            "updated_at": (
                raw.get("updated_at", raw["created_at"]).isoformat()
                if isinstance(raw.get("updated_at", raw["created_at"]), datetime)
                else str(raw.get("updated_at", raw["created_at"]))
            ),
            "role": role,
            "member_role": role,
            "member_status": raw.get("member_status"),
            "member_department": raw.get("member_department"),
            "member_count": raw.get("member_count"),
        }

    # =========================================================================
    # Workspace Operations
    # =========================================================================

    async def create_workspace(
        self,
        name: str,
        created_by: str,
        slug: Optional[str] = None,
        description: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a new workspace and automatically enroll the creator as an Admin member."""
        workspace_id = uuid.uuid4()
        clean_name = name.strip()
        base_slug = self._slugify(slug or clean_name)
        now = datetime.now(timezone.utc)

        async with self.session_factory() as session:
            # Ensure slug uniqueness
            target_slug = base_slug
            counter = 1
            while True:
                slug_check = await session.execute(
                    select(Workspace.id).where(Workspace.slug == target_slug)
                )
                if not slug_check.scalar_one_or_none():
                    break
                counter += 1
                target_slug = f"{base_slug}-{counter}"

            new_ws = Workspace(
                id=workspace_id,
                name=clean_name,
                slug=target_slug,
                description=(description or "").strip() or None,
                created_by=str(created_by),
                created_at=now,
                updated_at=now,
            )
            session.add(new_ws)
            await session.flush()

            # Lookup creator user info if creator is a UUID
            creator_user = None
            try:
                creator_uid = uuid.UUID(str(created_by).strip())
                user_res = await session.execute(
                    select(User).where(User.id == creator_uid)
                )
                creator_user = user_res.scalars().first()
            except (ValueError, AttributeError):
                pass

            if creator_user:
                user_email = creator_user.email.strip().lower()
                meta = creator_user.metadata_ or {}
                user_name = meta.get("name") or creator_user.username
                user_dept = meta.get("department", "Management")
                member = WorkspaceMember(
                    id=uuid.uuid4(),
                    workspace_id=workspace_id,
                    user_id=creator_user.id,
                    email=user_email,
                    name=user_name,
                    role="admin",
                    department=user_dept,
                    status="active",
                    invited_by=str(created_by),
                    invited_at=now,
                )
            else:
                member = WorkspaceMember(
                    id=uuid.uuid4(),
                    workspace_id=workspace_id,
                    user_id=None,
                    email=f"{created_by}@workspace.local",
                    name=str(created_by),
                    role="admin",
                    department="Management",
                    status="active",
                    invited_by=str(created_by),
                    invited_at=now,
                )
            session.add(member)
            await session.commit()

        ws_dict = await self.get_workspace(str(workspace_id))
        if ws_dict:
            ws_dict["role"] = "admin"
            ws_dict["member_role"] = "admin"
            ws_dict["member_status"] = "active"
        return ws_dict  # type: ignore

    async def get_workspace(self, workspace_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve workspace by UUID."""
        if not workspace_id:
            return None
        try:
            wid = uuid.UUID(str(workspace_id).strip())
        except (ValueError, AttributeError):
            return None

        async with self.session_factory() as session:
            stmt = select(Workspace).where(Workspace.id == wid)
            result = await session.execute(stmt)
            ws = result.scalars().first()
            if not ws:
                return None
            return self._format_workspace({
                "id": ws.id,
                "name": ws.name,
                "slug": ws.slug,
                "description": ws.description,
                "created_by": ws.created_by,
                "created_at": ws.created_at,
                "updated_at": ws.updated_at,
            })

    async def get_workspace_by_slug(self, slug: str) -> Optional[Dict[str, Any]]:
        """Retrieve workspace by unique URL slug."""
        if not slug:
            return None
        clean_slug = slug.strip().lower()

        async with self.session_factory() as session:
            stmt = select(Workspace).where(func.lower(Workspace.slug) == clean_slug)
            result = await session.execute(stmt)
            ws = result.scalars().first()
            if not ws:
                return None
            return self._format_workspace({
                "id": ws.id,
                "name": ws.name,
                "slug": ws.slug,
                "description": ws.description,
                "created_by": ws.created_by,
                "created_at": ws.created_at,
                "updated_at": ws.updated_at,
            })

    async def list_workspaces_for_user(
        self,
        user_id: str,
        email: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List all workspaces where a user is enrolled, including their workspace-scoped role."""
        async with self.session_factory() as session:
            stmt = (
                select(Workspace, WorkspaceMember)
                .join(WorkspaceMember, Workspace.id == WorkspaceMember.workspace_id)
                .order_by(Workspace.created_at.asc())
            )

            conditions = []
            if user_id:
                try:
                    uid = uuid.UUID(str(user_id).strip())
                    conditions.append(WorkspaceMember.user_id == uid)
                except (ValueError, AttributeError):
                    pass

            if email:
                clean_email = email.strip().lower()
                conditions.append(func.lower(WorkspaceMember.email) == clean_email)

            if not conditions:
                return []

            stmt = stmt.where(or_(*conditions))
            result = await session.execute(stmt)
            rows = result.all()

        results: List[Dict[str, Any]] = []
        for ws, wm in rows:
            results.append(
                self._format_workspace({
                    "id": ws.id,
                    "name": ws.name,
                    "slug": ws.slug,
                    "description": ws.description,
                    "created_by": ws.created_by,
                    "created_at": ws.created_at,
                    "updated_at": ws.updated_at,
                    "member_role": wm.role,
                    "member_status": wm.status,
                    "member_department": wm.department,
                })
            )
        return results

    async def list_all_workspaces(self) -> List[Dict[str, Any]]:
        """List all workspaces with member counts."""
        async with self.session_factory() as session:
            stmt = (
                select(
                    Workspace,
                    func.count(WorkspaceMember.id).label("member_count"),
                )
                .outerjoin(
                    WorkspaceMember, Workspace.id == WorkspaceMember.workspace_id
                )
                .group_by(Workspace.id)
                .order_by(Workspace.created_at.asc())
            )
            result = await session.execute(stmt)
            rows = result.all()

        results: List[Dict[str, Any]] = []
        for ws, count in rows:
            results.append(
                self._format_workspace({
                    "id": ws.id,
                    "name": ws.name,
                    "slug": ws.slug,
                    "description": ws.description,
                    "created_by": ws.created_by,
                    "created_at": ws.created_at,
                    "updated_at": ws.updated_at,
                    "member_count": count,
                })
            )
        return results

    async def update_workspace(
        self,
        workspace_id: str,
        updates: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """Update workspace name, slug, or description."""
        if not workspace_id:
            return None
        try:
            wid = uuid.UUID(str(workspace_id).strip())
        except (ValueError, AttributeError):
            return None

        filtered: Dict[str, Any] = {}
        if "name" in updates and updates["name"]:
            filtered["name"] = updates["name"].strip()

        if "description" in updates:
            desc = updates["description"]
            filtered["description"] = desc.strip() if desc else None

        async with self.session_factory() as session:
            if "slug" in updates and updates["slug"]:
                clean_slug = self._slugify(updates["slug"])
                collision = await session.execute(
                    select(Workspace.id).where(
                        Workspace.slug == clean_slug, Workspace.id != wid
                    )
                )
                if collision.scalar_one_or_none():
                    raise ValueError(
                        f"Workspace slug '{clean_slug}' is already taken."
                    )
                filtered["slug"] = clean_slug

            if not filtered:
                return await self.get_workspace(workspace_id)

            stmt = (
                update(Workspace)
                .where(Workspace.id == wid)
                .values(**filtered, updated_at=func.now())
            )
            result = await session.execute(stmt)
            await session.commit()
            if (result.rowcount or 0) == 0:
                return None

        return await self.get_workspace(workspace_id)

    async def delete_workspace(self, workspace_id: str) -> bool:
        """Delete a workspace and cascade delete its members and tasks."""
        if not workspace_id:
            return False
        try:
            wid = uuid.UUID(str(workspace_id).strip())
        except (ValueError, AttributeError):
            return False

        async with self.session_factory() as session:
            stmt = delete(Workspace).where(Workspace.id == wid)
            result = await session.execute(stmt)
            await session.commit()
            return (result.rowcount or 0) > 0

    # =========================================================================
    # Workspace Membership & Invitation Operations
    # =========================================================================

    async def add_member(
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
        """Directly add or link an active member to a workspace using ON CONFLICT DO UPDATE."""
        member_id = uuid.uuid4()
        clean_email = email.strip().lower()
        now = datetime.now(timezone.utc)
        safe_name = name.strip() if name else clean_email.split("@")[0]

        async with self.session_factory() as session:
            ws_uuid = await self._resolve_ws_uuid(session, workspace_id)
            if not ws_uuid:
                raise ValueError(f"Workspace '{workspace_id}' does not exist.")

            parsed_uid = None
            if user_id:
                try:
                    parsed_uid = uuid.UUID(str(user_id).strip())
                except (ValueError, AttributeError):
                    pass

            stmt = pg_insert(WorkspaceMember).values(
                id=member_id,
                workspace_id=ws_uuid,
                user_id=parsed_uid,
                email=clean_email,
                name=safe_name,
                role=role,
                department=department,
                status=status,
                invited_by=invited_by or "admin",
                invited_at=now,
            )
            stmt = stmt.on_conflict_do_update(
                constraint="uq_workspace_members_workspace_email",
                set_={
                    "user_id": func.coalesce(
                        stmt.excluded.user_id, WorkspaceMember.user_id
                    ),
                    "name": func.coalesce(stmt.excluded.name, WorkspaceMember.name),
                    "role": stmt.excluded.role,
                    "department": stmt.excluded.department,
                    "status": stmt.excluded.status,
                },
            )
            await session.execute(stmt)
            await session.commit()

        return await self.get_member(str(ws_uuid), email=clean_email)  # type: ignore

    async def invite_member(
        self,
        workspace_id: str,
        email: str,
        name: Optional[str] = None,
        role: str = "viewer",
        department: str = "General",
        invited_by: str = "Admin",
        expires_days: int = 7,
    ) -> Dict[str, Any]:
        """Issue a cryptographic single-use invitation to join a workspace using ON CONFLICT DO UPDATE."""
        member_id = uuid.uuid4()
        invite_token = secrets.token_urlsafe(32)
        token_hash = self._hash_token(invite_token)
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(days=expires_days)
        clean_email = email.strip().lower()
        safe_name = (name or clean_email.split("@")[0]).strip()

        async with self.session_factory() as session:
            ws_uuid = await self._resolve_ws_uuid(session, workspace_id)
            if not ws_uuid:
                raise ValueError(f"Workspace '{workspace_id}' does not exist.")

            ws_row = await session.execute(
                select(Workspace).where(Workspace.id == ws_uuid)
            )
            ws = ws_row.scalars().first()
            if not ws:
                raise ValueError(f"Workspace '{workspace_id}' does not exist.")

            user_res = await session.execute(
                select(User.id).where(func.lower(User.email) == clean_email)
            )
            user_id = user_res.scalar_one_or_none()

            stmt = pg_insert(WorkspaceMember).values(
                id=member_id,
                workspace_id=ws_uuid,
                user_id=user_id,
                email=clean_email,
                name=safe_name,
                role=role,
                department=department,
                status="invited",
                invited_by=invited_by,
                invite_token=token_hash,
                expires_at=expires_at,
                invited_at=now,
            )
            stmt = stmt.on_conflict_do_update(
                constraint="uq_workspace_members_workspace_email",
                set_={
                    "name": stmt.excluded.name,
                    "role": stmt.excluded.role,
                    "department": stmt.excluded.department,
                    "status": "invited",
                    "invite_token": stmt.excluded.invite_token,
                    "expires_at": stmt.excluded.expires_at,
                    "invited_by": stmt.excluded.invited_by,
                    "invited_at": stmt.excluded.invited_at,
                },
            )
            await session.execute(stmt)
            await session.commit()

            ws_name = ws.name

        return {
            "id": str(member_id),
            "workspace_id": str(ws_uuid),
            "workspace_name": ws_name,
            "email": clean_email,
            "name": safe_name,
            "role": role,
            "department": department,
            "status": "invited",
            "invited_by": invited_by,
            "invite_token": invite_token,
            "expires_at": expires_at.isoformat(),
            "invited_at": now.isoformat(),
        }

    async def get_member(
        self,
        workspace_id: str,
        user_id: Optional[str] = None,
        email: Optional[str] = None,
        identifier: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Retrieve a member record within a workspace scope by user_id, email, username, or membership ID."""
        lookup_keys = []
        if identifier:
            lookup_keys.append(unquote(identifier).strip())
        if user_id:
            lookup_keys.append(unquote(user_id).strip())
        if email:
            lookup_keys.append(unquote(email).strip().lower())

        if not lookup_keys:
            return None

        async with self.session_factory() as session:
            ws_uuid = await self._resolve_ws_uuid(session, workspace_id)
            if not ws_uuid:
                return None

            # Look up corresponding users for identifier mapping
            extra_user_ids = []
            for k in lookup_keys:
                try:
                    uid = uuid.UUID(k)
                    user_lookup = await session.execute(
                        select(User).where(User.id == uid)
                    )
                except (ValueError, AttributeError):
                    user_lookup = await session.execute(
                        select(User).where(
                            or_(
                                func.lower(User.username) == k.lower(),
                                func.lower(User.email) == k.lower(),
                            )
                        )
                    )
                u = user_lookup.scalars().first()
                if u:
                    extra_user_ids.append(u.id)
                    if u.email:
                        lookup_keys.append(u.email.lower())

            conditions = []
            for k in lookup_keys:
                try:
                    kid = uuid.UUID(k)
                    conditions.append(WorkspaceMember.id == kid)
                    conditions.append(WorkspaceMember.user_id == kid)
                except (ValueError, AttributeError):
                    pass
                conditions.append(func.lower(WorkspaceMember.email) == k.lower())
                conditions.append(func.lower(WorkspaceMember.name) == k.lower())

            for uid in extra_user_ids:
                conditions.append(WorkspaceMember.user_id == uid)

            stmt = select(WorkspaceMember).where(
                WorkspaceMember.workspace_id == ws_uuid,
                or_(*conditions),
            )
            result = await session.execute(stmt)
            wm = result.scalars().first()
            if not wm:
                return None

            exp_str = wm.expires_at.isoformat() if wm.expires_at else None
            inv_str = (
                wm.invited_at.isoformat()
                if isinstance(wm.invited_at, datetime)
                else str(wm.invited_at)
            )

            return {
                "id": str(wm.id),
                "workspace_id": str(wm.workspace_id),
                "user_id": str(wm.user_id) if wm.user_id else None,
                "email": wm.email,
                "name": wm.name,
                "role": wm.role,
                "department": wm.department,
                "status": wm.status,
                "invited_by": wm.invited_by,
                "invite_token": wm.invite_token,
                "expires_at": exp_str,
                "invited_at": inv_str,
            }

    async def list_members(
        self,
        workspace_id: str,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List all members and invitations for a workspace with live user profile resolution."""
        async with self.session_factory() as session:
            ws_uuid = await self._resolve_ws_uuid(session, workspace_id)
            if not ws_uuid:
                return []

            stmt = (
                select(WorkspaceMember, User)
                .outerjoin(
                    User,
                    or_(
                        WorkspaceMember.user_id == User.id,
                        func.lower(WorkspaceMember.email) == func.lower(User.email),
                    ),
                )
                .where(WorkspaceMember.workspace_id == ws_uuid)
                .order_by(
                    WorkspaceMember.role.asc(), WorkspaceMember.invited_at.asc()
                )
            )

            if status:
                stmt = stmt.where(WorkspaceMember.status == status.strip())

            result = await session.execute(stmt)
            rows = result.all()

        members: List[Dict[str, Any]] = []
        for wm, u in rows:
            user_meta_name = None
            avatar_url = None
            if u:
                meta = u.metadata_ or {}
                if isinstance(meta, dict):
                    user_meta_name = meta.get("name")
                    avatar_url = meta.get("avatar_url")

            resolved_name = (
                user_meta_name
                or wm.name
                or (u.username if u else None)
                or wm.email.split("@")[0]
            )
            exp_str = wm.expires_at.isoformat() if wm.expires_at else None
            inv_str = (
                wm.invited_at.isoformat()
                if isinstance(wm.invited_at, datetime)
                else str(wm.invited_at)
            )

            members.append({
                "id": str(wm.id),
                "workspace_id": str(wm.workspace_id),
                "user_id": str(wm.user_id) if wm.user_id else None,
                "email": wm.email,
                "name": resolved_name,
                "role": wm.role,
                "department": wm.department,
                "status": wm.status,
                "invited_by": wm.invited_by,
                "invite_token": wm.invite_token,
                "expires_at": exp_str,
                "invited_at": inv_str,
                "username": u.username if u else None,
                "avatar_url": avatar_url,
            })
        return members

    async def get_invitation_by_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Resolve and validate an active invitation token across all workspaces."""
        clean_token = (token or "").strip()
        if not clean_token:
            return None

        lookup_hash = self._hash_token(clean_token)

        async with self.session_factory() as session:
            stmt = (
                select(WorkspaceMember, Workspace)
                .join(
                    Workspace, WorkspaceMember.workspace_id == Workspace.id
                )
                .where(
                    or_(
                        WorkspaceMember.invite_token == lookup_hash,
                        WorkspaceMember.invite_token == clean_token,
                    ),
                    WorkspaceMember.status == "invited",
                )
            )
            result = await session.execute(stmt)
            row = result.first()
            if not row:
                return None

            wm, ws = row
            exp_str = wm.expires_at.isoformat() if wm.expires_at else None
            inv_str = (
                wm.invited_at.isoformat()
                if isinstance(wm.invited_at, datetime)
                else str(wm.invited_at)
            )

            data: Dict[str, Any] = {
                "id": str(wm.id),
                "workspace_id": str(wm.workspace_id),
                "workspace_name": ws.name,
                "workspace_slug": ws.slug,
                "user_id": str(wm.user_id) if wm.user_id else None,
                "email": wm.email,
                "name": wm.name,
                "role": wm.role,
                "department": wm.department,
                "status": wm.status,
                "invited_by": wm.invited_by,
                "invite_token": wm.invite_token,
                "expires_at": exp_str,
                "invited_at": inv_str,
            }

            if wm.expires_at:
                exp_dt = (
                    wm.expires_at
                    if wm.expires_at.tzinfo
                    else wm.expires_at.replace(tzinfo=timezone.utc)
                )
                data["is_expired"] = datetime.now(timezone.utc) > exp_dt
            else:
                data["is_expired"] = False

            return data

    async def accept_invitation(
        self,
        token: str,
        user_id: Optional[str] = None,
        name: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Atomically consume invitation token, activate workspace clearance, and link user ID."""
        clean_token = (token or "").strip()
        if not clean_token:
            return None

        invite = await self.get_invitation_by_token(clean_token)
        if not invite or invite.get("is_expired"):
            return None

        lookup_hash = self._hash_token(clean_token)

        async with self.session_factory() as session:
            resolved_name = name
            parsed_uid = None
            if user_id:
                try:
                    parsed_uid = uuid.UUID(str(user_id).strip())
                    if not resolved_name:
                        u_res = await session.execute(
                            select(User).where(User.id == parsed_uid)
                        )
                        u = u_res.scalars().first()
                        if u:
                            meta = u.metadata_ or {}
                            resolved_name = (
                                meta.get("name") if isinstance(meta, dict) else None
                            ) or u.username
                except (ValueError, AttributeError):
                    pass

            stmt = (
                update(WorkspaceMember)
                .where(
                    or_(
                        WorkspaceMember.invite_token == lookup_hash,
                        WorkspaceMember.invite_token == clean_token,
                    ),
                    WorkspaceMember.status == "invited",
                )
                .values(
                    status="active",
                    invite_token=None,
                    expires_at=None,
                    user_id=func.coalesce(parsed_uid, WorkspaceMember.user_id),
                    name=func.coalesce(resolved_name, WorkspaceMember.name),
                )
            )
            result = await session.execute(stmt)
            await session.commit()
            if (result.rowcount or 0) == 0:
                return None

        return await self.get_member(
            invite["workspace_id"], user_id=user_id, email=invite["email"]
        )

    async def update_member_role(
        self,
        workspace_id: str,
        user_id_or_email: str,
        new_role: str,
    ) -> bool:
        """Update a member's role within a workspace."""
        if new_role not in ("admin", "developer", "editor", "viewer"):
            raise ValueError(
                f"Invalid role '{new_role}'. Must be admin, developer, editor, or viewer."
            )

        raw_ident = (user_id_or_email or "").strip()
        if not raw_ident:
            return False
        clean_ident = unquote(raw_ident).strip()

        async with self.session_factory() as session:
            ws_uuid = await self._resolve_ws_uuid(session, workspace_id)
            if not ws_uuid:
                return False

            conditions = [
                func.lower(WorkspaceMember.email) == clean_ident.lower(),
                func.lower(WorkspaceMember.name) == clean_ident.lower(),
            ]
            try:
                kid = uuid.UUID(clean_ident)
                conditions.append(WorkspaceMember.id == kid)
                conditions.append(WorkspaceMember.user_id == kid)
            except (ValueError, AttributeError):
                user_res = await session.execute(
                    select(User.id).where(
                        or_(
                            func.lower(User.username) == clean_ident.lower(),
                            func.lower(User.email) == clean_ident.lower(),
                        )
                    )
                )
                found_uids = user_res.scalars().all()
                for uid in found_uids:
                    conditions.append(WorkspaceMember.user_id == uid)

            stmt = (
                update(WorkspaceMember)
                .where(
                    WorkspaceMember.workspace_id == ws_uuid,
                    or_(*conditions),
                )
                .values(role=new_role)
            )
            result = await session.execute(stmt)
            await session.commit()
            return (result.rowcount or 0) > 0

    async def remove_member(
        self,
        workspace_id: str,
        user_id_or_email: str,
    ) -> bool:
        """Remove a member from a workspace or revoke their invitation."""
        raw_ident = (user_id_or_email or "").strip()
        if not raw_ident:
            return False
        clean_ident = unquote(raw_ident).strip()

        async with self.session_factory() as session:
            ws_uuid = await self._resolve_ws_uuid(session, workspace_id)
            if not ws_uuid:
                return False

            conditions = [
                func.lower(WorkspaceMember.email) == clean_ident.lower(),
                func.lower(WorkspaceMember.name) == clean_ident.lower(),
            ]
            try:
                kid = uuid.UUID(clean_ident)
                conditions.append(WorkspaceMember.id == kid)
                conditions.append(WorkspaceMember.user_id == kid)
            except (ValueError, AttributeError):
                user_res = await session.execute(
                    select(User.id).where(
                        or_(
                            func.lower(User.username) == clean_ident.lower(),
                            func.lower(User.email) == clean_ident.lower(),
                        )
                    )
                )
                found_uids = user_res.scalars().all()
                for uid in found_uids:
                    conditions.append(WorkspaceMember.user_id == uid)

            stmt = delete(WorkspaceMember).where(
                WorkspaceMember.workspace_id == ws_uuid,
                or_(*conditions),
            )
            result = await session.execute(stmt)
            deleted = (result.rowcount or 0) > 0
            await session.commit()
            return deleted

    async def count_members(self, workspace_id: str) -> Dict[str, int]:
        """Return member count breakdown by role and status for a workspace."""
        async with self.session_factory() as session:
            ws_uuid = await self._resolve_ws_uuid(session, workspace_id)
            if not ws_uuid:
                return {
                    "total": 0,
                    "active": 0,
                    "invited": 0,
                    "admins": 0,
                    "editors": 0,
                    "viewers": 0,
                }

            stmt = select(
                func.count().label("total"),
                func.sum(
                    func.case((WorkspaceMember.status == "active", 1), else_=0)
                ).label("active"),
                func.sum(
                    func.case((WorkspaceMember.status == "invited", 1), else_=0)
                ).label("invited"),
                func.sum(
                    func.case((WorkspaceMember.role == "admin", 1), else_=0)
                ).label("admins"),
                func.sum(
                    func.case((WorkspaceMember.role == "editor", 1), else_=0)
                ).label("editors"),
                func.sum(
                    func.case((WorkspaceMember.role == "viewer", 1), else_=0)
                ).label("viewers"),
            ).where(WorkspaceMember.workspace_id == ws_uuid)
            result = await session.execute(stmt)
            row = result.first()
            if not row:
                return {
                    "total": 0,
                    "active": 0,
                    "invited": 0,
                    "admins": 0,
                    "editors": 0,
                    "viewers": 0,
                }

            return {
                "total": int(row.total or 0),
                "active": int(row.active or 0),
                "invited": int(row.invited or 0),
                "admins": int(row.admins or 0),
                "editors": int(row.editors or 0),
                "viewers": int(row.viewers or 0),
            }


concreteWorkspaceRepository = WorkspaceRepository
