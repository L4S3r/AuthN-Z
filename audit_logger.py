"""
Component Role: Security Audit Logger (PostgreSQL Async)
--------------------------------------------------------
Provides structured, tamper-evident recording of security-critical identity,
authentication, authorization, and multi-tenant workspace events using async SQLAlchemy (asyncpg).
"""

from abc import ABC, abstractmethod
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import json
import logging
from typing import Any, Dict, List, Optional
import uuid

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from database import get_session_factory
from workspace_models import AuditLog, Workspace

logger = logging.getLogger("auth_nz.audit_logger")


class abstractAuditLogger(ABC):
    """Abstract interface defining structured audit event logging, security telemetry, and historical querying."""

    @abstractmethod
    async def record_auth_success(
        self,
        subject_id: str,
        method: str = "password",
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        workspace_id: Optional[str] = None,
        auth_method: Optional[str] = None,
        session: Optional[AsyncSession] = None,
    ) -> None:
        """Record a successful authentication event."""
        pass

    @abstractmethod
    async def record_auth_failure(
        self,
        identifier: str,
        reason: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        workspace_id: Optional[str] = None,
        session: Optional[AsyncSession] = None,
    ) -> None:
        """Record a failed authentication attempt."""
        pass

    @abstractmethod
    async def record_access_denial(
        self,
        subject_id: str,
        action: str,
        resource: str,
        reason: str,
        metadata: Optional[Dict[str, Any]] = None,
        workspace_id: Optional[str] = None,
        session: Optional[AsyncSession] = None,
    ) -> None:
        """Record an authorization denial (403 Forbidden event)."""
        pass

    @abstractmethod
    async def record_security_event(
        self,
        event_name: str,
        severity: str,
        details: Dict[str, Any],
        workspace_id: Optional[str] = None,
        session: Optional[AsyncSession] = None,
    ) -> None:
        """Record general security events (e.g., privilege escalation, invitations, workspace CRUD)."""
        pass

    @abstractmethod
    async def query_events(
        self,
        filter_criteria: Optional[Dict[str, Any]] = None,
        limit: int = 100,
        offset: int = 0,
        include_global: bool = False,
        session: Optional[AsyncSession] = None,
    ) -> List[Dict[str, Any]]:
        """Retrieve historical audit log records matching specific filtering criteria."""
        pass


class AuditLogger(abstractAuditLogger):
    """PostgreSQL Async implementation of Security Audit Logger."""

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

    async def _resolve_workspace_uuid(
        self, session: AsyncSession, ws_input: Optional[str]
    ) -> Optional[uuid.UUID]:
        """Resolve workspace input string/UUID to a valid workspace UUID, or None."""
        if not ws_input:
            return None
        clean = str(ws_input).strip()
        try:
            parsed_uid = uuid.UUID(clean)
            check = await session.execute(
                select(Workspace.id).where(Workspace.id == parsed_uid)
            )
            if check.scalar_one_or_none():
                return parsed_uid
        except (ValueError, AttributeError):
            pass

        # Lookup by slug
        slug_check = await session.execute(
            select(Workspace.id).where(func.lower(Workspace.slug) == clean.lower())
        )
        return slug_check.scalar_one_or_none()

    @staticmethod
    def _format_log(log: AuditLog) -> Dict[str, Any]:
        """Format SQLAlchemy AuditLog instance into dictionary matching previous repository shape."""
        meta = log.metadata_ if isinstance(log.metadata_, dict) else {}
        ts_str = (
            log.timestamp.isoformat()
            if isinstance(log.timestamp, datetime)
            else str(log.timestamp)
        )
        return {
            "id": str(log.id),
            "workspace_id": str(log.workspace_id) if log.workspace_id else None,
            "event_type": log.event_type,
            "severity": log.severity,
            "subject_id": log.subject_id,
            "action": log.action,
            "resource": log.resource,
            "reason": log.reason,
            "ip_address": log.ip_address,
            "user_agent": log.user_agent,
            "metadata": meta,
            "timestamp": ts_str,
        }

    async def _insert_event(
        self,
        event_type: str,
        severity: str,
        subject_id: Optional[str] = None,
        action: Optional[str] = None,
        resource: Optional[str] = None,
        reason: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        workspace_id: Optional[str] = None,
        session: Optional[AsyncSession] = None,
    ) -> None:
        """Insert a structured audit record into PostgreSQL."""
        meta = dict(metadata or {})
        ws_raw = workspace_id or meta.get("workspace_id")

        async with self._use_session(session) as (sess, should_commit):
            ws_uid = await self._resolve_workspace_uuid(sess, ws_raw)

            log_entry = AuditLog(
                id=uuid.uuid4(),
                workspace_id=ws_uid,
                event_type=event_type,
                severity=severity,
                subject_id=subject_id,
                action=action,
                resource=resource,
                reason=reason,
                ip_address=ip_address,
                user_agent=user_agent,
                metadata_=meta,
                timestamp=datetime.now(timezone.utc),
            )
            sess.add(log_entry)
            if should_commit:
                await sess.commit()

    async def record_auth_success(
        self,
        subject_id: str,
        method: str = "password",
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        workspace_id: Optional[str] = None,
        auth_method: Optional[str] = None,
        session: Optional[AsyncSession] = None,
    ) -> None:
        """Record a successful authentication event."""
        effective_method = auth_method or method or "password"
        extra_meta = dict(metadata or {})
        extra_meta["auth_method"] = effective_method
        await self._insert_event(
            event_type="AUTH_SUCCESS",
            severity="INFO",
            subject_id=subject_id,
            action="login",
            resource="auth_system",
            ip_address=ip_address,
            user_agent=user_agent,
            metadata=extra_meta,
            workspace_id=workspace_id,
            session=session,
        )

    async def record_auth_failure(
        self,
        identifier: str,
        reason: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        workspace_id: Optional[str] = None,
        session: Optional[AsyncSession] = None,
    ) -> None:
        """Record a failed authentication attempt."""
        await self._insert_event(
            event_type="AUTH_FAILED",
            severity="WARNING",
            subject_id=identifier,
            action="login",
            resource="auth_system",
            reason=reason,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata=metadata or {},
            workspace_id=workspace_id,
            session=session,
        )

    async def record_access_denial(
        self,
        subject_id: str,
        action: str,
        resource: str,
        reason: str,
        metadata: Optional[Dict[str, Any]] = None,
        workspace_id: Optional[str] = None,
        session: Optional[AsyncSession] = None,
    ) -> None:
        """Record an authorization denial (403 Forbidden event)."""
        await self._insert_event(
            event_type="ACCESS_DENIAL",
            severity="WARNING",
            subject_id=subject_id,
            action=action,
            resource=resource,
            reason=reason,
            metadata=metadata or {},
            workspace_id=workspace_id,
            session=session,
        )

    async def record_security_event(
        self,
        event_name: str,
        severity: str,
        details: Dict[str, Any],
        workspace_id: Optional[str] = None,
        session: Optional[AsyncSession] = None,
    ) -> None:
        """Record general security events (e.g., account lockouts, privilege changes, password changes)."""
        ws_id = workspace_id or details.get("workspace_id")
        await self._insert_event(
            event_type=event_name,
            severity=severity.upper(),
            subject_id=details.get("user_id") or details.get("subject_id"),
            action=details.get("action", event_name.lower()),
            resource=details.get("resource", "system"),
            reason=details.get("reason"),
            ip_address=details.get("ip_address"),
            user_agent=details.get("user_agent"),
            metadata=details,
            workspace_id=ws_id,
            session=session,
        )

    async def query_events(
        self,
        filter_criteria: Optional[Dict[str, Any]] = None,
        limit: int = 100,
        offset: int = 0,
        include_global: bool = False,
        session: Optional[AsyncSession] = None,
    ) -> List[Dict[str, Any]]:
        """Retrieve historical audit log records matching specific filtering criteria."""
        criteria = dict(filter_criteria or {})
        inc_global = include_global or criteria.pop("include_global", False)

        async with self._use_session(session) as (sess, _):
            stmt = select(AuditLog).order_by(AuditLog.timestamp.desc())

            conditions = []
            if "workspace_id" in criteria:
                ws_filter = criteria.pop("workspace_id")
                if ws_filter is not None:
                    ws_uid = await self._resolve_workspace_uuid(sess, ws_filter)
                    if inc_global:
                        conditions.append(
                            or_(
                                AuditLog.workspace_id == ws_uid,
                                AuditLog.workspace_id.is_(None),
                            )
                        )
                    else:
                        conditions.append(AuditLog.workspace_id == ws_uid)

            if "event_type" in criteria and criteria["event_type"]:
                raw_event_type = str(criteria["event_type"]).strip()
                escaped_event_type = (
                    raw_event_type.replace("\\", "\\\\")
                    .replace("%", "\\%")
                    .replace("_", "\\_")
                )
                conditions.append(
                    AuditLog.event_type.ilike(f"%{escaped_event_type}%", escape="\\")
                )

            if "severity" in criteria and criteria["severity"]:
                conditions.append(
                    func.upper(AuditLog.severity) == criteria["severity"].strip().upper()
                )

            if "subject_id" in criteria and criteria["subject_id"]:
                conditions.append(
                    AuditLog.subject_id == str(criteria["subject_id"]).strip()
                )

            if "action" in criteria and criteria["action"]:
                conditions.append(AuditLog.action == criteria["action"].strip())

            if "resource" in criteria and criteria["resource"]:
                conditions.append(AuditLog.resource == criteria["resource"].strip())

            if "ip_address" in criteria and criteria["ip_address"]:
                conditions.append(
                    AuditLog.ip_address == criteria["ip_address"].strip()
                )

            if conditions:
                stmt = stmt.where(*conditions)

            stmt = stmt.limit(limit).offset(offset)
            result = await sess.execute(stmt)
            logs = result.scalars().all()

        return [self._format_log(log) for log in logs]


concreteAuditLogger = AuditLogger