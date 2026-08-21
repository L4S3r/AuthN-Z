"""
Component Role: Security Audit Logger
-------------------------------------
This component provides structured, tamper-evident recording of security-critical identity,
authentication, and authorization events for compliance, incident response, and anomaly detection.

System Relationship:
Both the Authenticator (login attempts, logouts, MFA challenges, account lockouts) and the
PermissionEvaluator (access denials, privileged actions) trigger this component to record events.
It sits alongside all operational components to ensure comprehensive visibility without coupling
to storage mechanisms (e.g., SIEM, Elasticsearch, CloudWatch, append-only logs).
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from datetime import datetime,timezone
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
    ) -> None:
        """
        Record a successful authentication event.

        Args:
            subject_id: Unique identifier of the authenticated user.
            method: The authentication mechanism used (e.g., 'password', 'oauth2_google', 'session_cookie', 'mfa_totp').
            ip_address: Client IP address from which the request originated.
            user_agent: Client user-agent string.
            metadata: Additional non-sensitive operational details (e.g., tenant ID, session ID).

        Edge Cases to Consider:
            - Masking or excluding sensitive parameters (NEVER log plaintext passwords, session tokens, or OTP codes).
            - Asynchronous emission to ensure auditing does not introduce significant latency to the login path.
        """
        ...

    @abstractmethod
    def record_auth_failure(
        self,
        identifier: str,
        reason: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Record a failed authentication attempt.

        Args:
            identifier: The claimed username, email, or identity handle attempted.
            reason: Specific code or description of failure (e.g., 'INVALID_PASSWORD', 'USER_NOT_FOUND', 'MFA_TIMEOUT').
            ip_address: Client IP address from which the request originated.
            user_agent: Client user-agent string.
            metadata: Additional context for forensics.

        Edge Cases to Consider:
            - User enumeration risks: Ensure internal failure details logged here are distinct from user-facing generic errors.
            - Defense against log injection attacks (sanitizing malformed input in identifier).
        """
        ...

    @abstractmethod
    def record_access_denial(
        self,
        subject_id: str,
        action: str,
        resource: str,
        reason: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Record an authorization denial (403 Forbidden event) when a subject attempts an unauthorized operation.

        Args:
            subject_id: The identifier of the requesting user.
            action: The attempted action (e.g., 'delete_database', 'export_financial_records').
            resource: The resource identifier or URI targeted.
            reason: Policy reason for denial (e.g., 'MISSING_ROLE_ADMIN', 'DEPARTMENT_MISMATCH').
            metadata: Contextual attributes (e.g., IP address, request payload summary).

        Edge Cases to Consider:
            - High volume denial events caused by automated scanners/crawlers (sampling vs. full logging).
            - Capturing sufficient context to reproduce access control policy evaluation issues.
        """
        ...

    @abstractmethod
    def record_security_event(
        self,
        event_name: str,
        severity: str,
        details: Dict[str, Any],
    ) -> None:
        """
        Record general security events (e.g., account lockouts, privilege escalation, password changes, token revocations).

        Args:
            event_name: Standardized event descriptor (e.g., 'ACCOUNT_LOCKED', 'ROLE_GRANTED', 'PASSWORD_RESET').
            severity: Event severity level ('INFO', 'WARNING', 'ERROR', 'CRITICAL').
            details: Structured dictionary of event-specific payload information.

        Edge Cases to Consider:
            - Alert triggering: Routing CRITICAL severity events to real-time alerting systems.
            - Structured JSON formatting for seamless ingestion into log aggregators and SIEM tools.
        """
        ...

    @abstractmethod
    def query_events(
        self,
        filter_criteria: Dict[str, Any],
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """
        Retrieve historical audit log records matching specific filtering criteria.

        Args:
            filter_criteria: Dictionary of filter keys (e.g., {'subject_id': '123', 'event_name': 'AUTH_FAILURE'}).
            limit: Maximum number of records to return.
            offset: Pagination offset.

        Returns:
            A list of matching audit event records in reverse-chronological order.

        Edge Cases to Consider:
            - Access control on the audit log itself: Only authorized compliance/security roles should query this method.
            - Handling large result sets efficiently via streaming or cursor-based pagination.
        """
        ...

class AuditLogger(abstractAuditLogger):
    def __init__(self, db_file: str = "DATABASE.db"):
        self.db_file = db_file
        self._create_table()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_file, timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _create_table(self) -> None:
        """Create audit_logs table and configure WAL mode if it doesn't already exist."""
        with self._get_connection() as conn:
            if self.db_file != ":memory:":
                conn.execute("PRAGMA journal_mode=WAL;")
                conn.execute("PRAGMA synchronous=NORMAL;")
            conn.executescript("""
        CREATE TABLE IF NOT EXISTS audit_logs(
            id TEXT PRIMARY KEY,
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


    def _insert_event(
        self,
        event_type:str,
        severity:str,
        subject_id:Optional[str]=None,
        action:Optional[str]=None,
        resource:Optional[str]=None,
        reason:Optional[str]=None,
        ip_address:Optional[str]=None,
        user_agent:Optional[str]=None,
        metadata:Optional[Dict[str,Any]]=None
    )-> None:
        """Helper to insert a structured audit record."""
        meta_json=json.dumps(metadata or {})
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO audit_logs(
                id,event_type,severity,subject_id,action,resource,reason,
                ip_address,user_agent,metadata
                ) VALUES (?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    str(uuid.uuid4()),
                    event_type,
                    severity,
                    subject_id,
                    action,
                    resource,
                    reason,
                    ip_address,
                    user_agent,
                    meta_json
                ),
            )
    def record_auth_success(
        self,
        subject_id: str,
        method: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Record a successful authentication event."""
        extra_meta=dict(metadata or {})
        extra_meta["auth_method"]=method
        self._insert_event(
            event_type="AUTH_SUCCESS",
            severity="INFO",
            subject_id=subject_id,
            action="login",
            resource="auth_system",
            ip_address=ip_address,
            user_agent=user_agent,
            metadata=extra_meta
        )
    def record_auth_failure(
        self,
        identifier: str,
        reason: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
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
            metadata=metadata or {}
        )
    def record_access_denial(
        self,
        subject_id: str,
        action: str,
        resource: str,
        reason: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Record an authorization denial (403 Forbidden event) when a subject attempts an unauthorized operation."""
        self._insert_event(
            event_type="ACCESS_DENIAL",
            severity="WARNING",
            subject_id=subject_id,
            action=action,
            resource=resource,
            reason=reason,
            metadata=metadata or {}
        )
    def record_security_event(
        self,
        event_name: str,
        severity: str,
        details: Dict[str, Any],
    ) -> None:
        """Record general security events (e.g., account lockouts, privilege escalation, password changes, token revocations)."""
        self._insert_event(
            event_type=event_name,
            severity=severity.upper(),
            subject_id=details.get("user_id") or details.get("subject_id"),
            action=details.get("action",event_name.lower()),
            resource=details.get("resource","system"),
            reason=details.get("reason"),
            ip_address=details.get("ip_address"),
            user_agent=details.get("user_agent"),
            metadata=details 
        )
    def query_events(
        self,
        filter_criteria: Dict[str, Any],
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Retrieve historical audit log records matching specific filtering criteria."""
        allowed_columns={
            "event_type",
            "severity",
            "subject_id",
            "action",
            "resource",
            "reason",
            "ip_address"
        }
        query="SELECT * FROM audit_logs"
        conditions=[]
        params=[]
        for key,val in (filter_criteria or {}).items():
            if key in allowed_columns and val is not None:
                conditions.append(f"{key}=?")
                params.append(val)
        if conditions:
            query+= " WHERE "+" AND ".join(conditions)
        #reverse-chronological order
        query+=" ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit,offset])
        with self._get_connection() as conn:
            rows=conn.execute(query,params).fetchall()
            results=[]
            for row in rows:
                record=dict(row)
                #parse json metadata string
                if isinstance(record.get("metadata"),str):
                    try:
                        record["metadata"]=json.loads(record["metadata"])
                    except Exception:
                        pass
                results.append(record)
        return results


concreteAuditLogger = AuditLogger