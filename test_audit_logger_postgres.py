"""
Standalone Verification Test Suite: PostgreSQL Async AuditLogger
================================================================
Exercises every method and querying edge case on AuditLogger against the PostgreSQL database.
"""

import asyncio
import os
import sys
import uuid

from audit_logger import AuditLogger


async def run_acceptance_tests():
    print("=" * 75)
    print("  PostgreSQL Async AuditLogger Test Suite")
    print("=" * 75)

    logger = AuditLogger()
    test_subject = f"usr_{uuid.uuid4().hex[:8]}"

    # -------------------------------------------------------------------------
    # 1. record_auth_success
    # -------------------------------------------------------------------------
    print("\n[1/5] Testing record_auth_success...")
    await logger.record_auth_success(
        subject_id=test_subject,
        method="password",
        ip_address="192.168.1.50",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        metadata={"session_mode": "cookie", "device": "trusted"},
    )
    print("  ✓ Authentication success logged")

    # -------------------------------------------------------------------------
    # 2. record_auth_failure
    # -------------------------------------------------------------------------
    print("\n[2/5] Testing record_auth_failure...")
    await logger.record_auth_failure(
        identifier=test_subject,
        reason="INVALID_PASSWORD",
        ip_address="192.168.1.50",
        user_agent="Mozilla/5.0",
        metadata={"attempts": 3},
    )
    print("  ✓ Authentication failure logged")

    # -------------------------------------------------------------------------
    # 3. record_access_denial
    # -------------------------------------------------------------------------
    print("\n[3/5] Testing record_access_denial...")
    await logger.record_access_denial(
        subject_id=test_subject,
        action="delete",
        resource="workspace_settings",
        reason="INSUFFICIENT_CLEARANCE",
        metadata={"required_role": "admin", "current_role": "viewer"},
    )
    print("  ✓ Access denial logged")

    # -------------------------------------------------------------------------
    # 4. record_security_event
    # -------------------------------------------------------------------------
    print("\n[4/5] Testing record_security_event...")
    await logger.record_security_event(
        event_name="MFA_ENABLED",
        severity="INFO",
        details={"user_id": test_subject, "method": "totp"},
    )
    print("  ✓ Generic security event logged")

    # -------------------------------------------------------------------------
    # 5. query_events and Filtering
    # -------------------------------------------------------------------------
    print("\n[5/5] Testing query_events and attribute filtering...")
    # Query all events for this subject
    events = await logger.query_events({"subject_id": test_subject}, limit=10)
    assert len(events) >= 4, f"Expected at least 4 events for {test_subject}, got {len(events)}"

    event_types = [e["event_type"] for e in events]
    assert "AUTH_SUCCESS" in event_types
    assert "AUTH_FAILED" in event_types
    assert "ACCESS_DENIAL" in event_types
    assert "MFA_ENABLED" in event_types
    print(f"  ✓ Found all recorded events: {event_types}")

    # Severity filtering
    warning_events = await logger.query_events({
        "subject_id": test_subject,
        "severity": "WARNING",
    })
    assert all(e["severity"] == "WARNING" for e in warning_events)
    assert len(warning_events) >= 2  # AUTH_FAILED and ACCESS_DENIAL
    print("  ✓ Severity filtering verified")

    # Event substring filtering
    auth_events = await logger.query_events({
        "subject_id": test_subject,
        "event_type": "AUTH",
    })
    assert all("AUTH" in e["event_type"] for e in auth_events)
    print("  ✓ Substring event_type filtering verified")

    # Pagination test
    page1 = await logger.query_events({"subject_id": test_subject}, limit=2, offset=0)
    page2 = await logger.query_events({"subject_id": test_subject}, limit=2, offset=2)
    assert len(page1) == 2
    assert len(page2) >= 2
    assert page1[0]["id"] != page2[0]["id"], "Offset pagination must return different items"
    print("  ✓ Pagination limit and offset verified")

    print("\n" + "=" * 75)
    print("  ALL AUDIT LOGGER TESTS PASSED WITH 100% SUCCESS!")
    print("=" * 75 + "\n")


if __name__ == "__main__":
    asyncio.run(run_acceptance_tests())
