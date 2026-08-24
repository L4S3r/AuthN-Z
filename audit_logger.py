"""
Component Role: Security Audit Logger (audit_logger.py)
------------------------------------------------------
Provides structured, tamper-evident recording of security-critical identity,
authentication, authorization, and multi-tenant workspace events.
"""

from abc import ABC, abstractmethod
from contextlib import contextmanager
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
import json
import sqlite3
import uuid


class abstractAuditLogger(ABC):
    """Abstract interface defining structured audit event logging, security telemetry, and historical querying."""

    @abstractmethod
    def record_auth_success(
        self,
        subject_id: str,
        method: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        workspace_id: Optional[str] = None,
    ) -> None:
        """Record a successful authentication event."""
        pass

    @abstractmethod
    def record_auth_failure(
        self,
        identifier: str,
        reason: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        workspace_id: Optional[str] = None,
    ) -> None:
        """Record a failed authentication attempt."""
        pass

    @abstractmethod
    def record_access_denial(
        self,
        subject_id: str,
        action: str,
        resource: str,
        reason: str,
        metadata: Optional[Dict[str, Any]] = None,
        workspace_id: Optional[str] = None,
    ) -> None:
        """Record an authorization denial (403 Forbidden event)."""
        pass

    @abstractmethod
    def record_security_event(
        self,
        event_name: str,
        severity: str,
        details: Dict[str, Any],
        workspace_id: Optional[str] = None,
    ) -> None:
        """Record general security events (e.g., privilege escalation, invitations, workspace CRUD)."""
        pass

    @abstractmethod
    def query_events(
        self,
        filter_criteria: Dict[str, Any],
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Retrieve historical audit log records matching specific filtering criteria."""
        pass


class AuditLogger(abstractAuditLogger):
    def __init__(self, db_file: str = "DATABASE.db"):
        self.db_file = db_file
        self._create_table()

    @contextmanager
    def _get_connection(self):
        conn = sqlite3.connect(self.db_file, timeout=10.0)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def _create_table(self) -> None:
        """Create audit_logs table, configure WAL mode, and ensure workspace_id column exists."""
        with self._get_connection() as conn:
            if self.db_file != ":memory:":
                conn.execute("PRAGMA journal_mode=WAL;")
                conn.execute("PRAGMA synchronous=NORMAL;")
            conn.executescript("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id TEXT PRIMARY KEY,
                workspace_id TEXT,
                event_type TEXT NOT NULL,
                severity TEXT DEFAULT 'INFO',
                subject_id TEXT,
                action TEXT,
                resource TEXT,
                reason TEXT,
                ip_address TEXT,
                user_agent TEXT,
                metadata TEXT DEFAULT '{}',
                timestamp TEXT DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS idx_audit_subject ON audit_logs(subject_id);
            CREATE INDEX IF NOT EXISTS idx_audit_event ON audit_logs(event_type);
            CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);
            """)

            # Schema migration check: ensure workspace_id column exists in pre-existing DBs
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(audit_logs)")
            cols = [c["name"] for c in cursor.fetchall()]
            if "workspace_id" not in cols:
                cursor.execute("ALTER TABLE audit_logs ADD COLUMN workspace_id TEXT")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_workspace ON audit_logs(workspace_id)")
            conn.commit()

    def _insert_event(
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
    ) -> None:
        """Helper to insert a structured audit record."""
        meta = dict(metadata or {})
        ws_id = workspace_id or meta.get("workspace_id")
        meta_json = json.dumps(meta)

        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO audit_logs (
                    id, workspace_id, event_type, severity, subject_id, action, resource, reason,
                    ip_address, user_agent, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()),
                    ws_id,
                    event_type,
                    severity,
                    subject_id,
                    action,
                    resource,
                    reason,
                    ip_address,
                    user_agent,
                    meta_json,
                ),
            )
            conn.commit()

    def record_auth_success(
        self,
        subject_id: str,
        method: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        workspace_id: Optional[str] = None,
    ) -> None:
        """Record a successful authentication event."""
        extra_meta = dict(metadata or {})
        extra_meta["auth_method"] = method
        self._insert_event(
            event_type="AUTH_SUCCESS",
            severity="INFO",
            subject_id=subject_id,
            action="login",
            resource="auth_system",
            ip_address=ip_address,
            user_agent=user_agent,
            metadata=extra_meta,
            workspace_id=workspace_id,
        )

    def record_auth_failure(
        self,
        identifier: str,
        reason: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        workspace_id: Optional[str] = None,
    ) -> None:
        """Record a failed authentication attempt."""
        self._insert_event(
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
        )

    def record_access_denial(
        self,
        subject_id: str,
        action: str,
        resource: str,
        reason: str,
        metadata: Optional[Dict[str, Any]] = None,
        workspace_id: Optional[str] = None,
    ) -> None:
        """Record an authorization denial (403 Forbidden event)."""
        self._insert_event(
            event_type="ACCESS_DENIAL",
            severity="WARNING",
            subject_id=subject_id,
            action=action,
            resource=resource,
            reason=reason,
            metadata=metadata or {},
            workspace_id=workspace_id,
        )

    def record_security_event(
        self,
        event_name: str,
        severity: str,
        details: Dict[str, Any],
        workspace_id: Optional[str] = None,
    ) -> None:
        """Record general security events (e.g., account lockouts, privilege changes, password changes)."""
        ws_id = workspace_id or details.get("workspace_id")
        self._insert_event(
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
        )

    def query_events(
        self,
        filter_criteria: Dict[str, Any],
        limit: int = 100,
        offset: int = 0,
        include_global: bool = False,
    ) -> List[Dict[str, Any]]:
        """Retrieve historical audit log records matching specific filtering criteria."""
        allowed_columns = {
            "workspace_id",
            "event_type",
            "severity",
            "subject_id",
            "action",
            "resource",
            "reason",
            "ip_address",
        }
        query = "SELECT * FROM audit_logs"
        conditions = []
        params = []

        inc_global = include_global or (filter_criteria and filter_criteria.get("include_global", False))

        for key, val in (filter_criteria or {}).items():
            if key == "include_global":
                continue
            if key == "workspace_id" and val is not None:
                if inc_global:
                    conditions.append("(workspace_id = ? OR workspace_id IS NULL OR workspace_id = '')")
                    params.append(val)
                else:
                    conditions.append("workspace_id = ?")
                    params.append(val)
            elif key in allowed_columns and val is not None:
                conditions.append(f"{key} = ?")
                params.append(val)

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        # Reverse-chronological order
        query += " ORDER BY datetime(timestamp) DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with self._get_connection() as conn:
            rows = conn.execute(query, params).fetchall()
            results = []
            for row in rows:
                record = dict(row)
                if isinstance(record.get("metadata"), str):
                    try:
                        record["metadata"] = json.loads(record["metadata"])
                    except Exception:
                        pass
                results.append(record)
        return results


concreteAuditLogger = AuditLogger