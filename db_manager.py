"""
Auth N&Z - Database Management & Inspection CLI (db_manager.py)
--------------------------------------------------------------
Inspect, query, and safely manage database tables live on your server.
Works safely with SQLite in WAL mode without requiring service stoppage.

Usage:
    python db_manager.py stats
    python db_manager.py audit [-n 25] [-w WORKSPACE] [-s SEVERITY] [-e EVENT] [-u USER] [--json]
    python db_manager.py workspaces
    python db_manager.py members [-w WORKSPACE]
    python db_manager.py devices [-u USER]
    python db_manager.py users [-r ROLE]
    python db_manager.py tasks [-w WORKSPACE]
    python db_manager.py purge-audit
    python db_manager.py purge-devices
    python db_manager.py purge-tasks
    python db_manager.py purge-all
    python db_manager.py reset-db
"""

import argparse
import json
import os
import sqlite3
import sys
from typing import Any, Dict, List, Optional

DB_FILE = os.getenv("AUTH_NZ_DB_PATH", "DATABASE.db")


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_FILE, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn


def show_stats() -> None:
    """Print high-level statistics across all database tables."""
    print("=" * 65)
    print(f"  Auth N&Z Database Overview: {DB_FILE}")
    print("=" * 65)

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [r["name"] for r in cursor.fetchall() if not r["name"].startswith("sqlite_")]

        for table in sorted(tables):
            cursor.execute(f"SELECT COUNT(*) as count FROM {table};")
            count = cursor.fetchone()["count"]
            print(f"  * Table '{table}': {count:>5} records")

    print("=" * 65)


def list_audit_logs(
    limit: int = 25,
    workspace_id: Optional[str] = None,
    severity: Optional[str] = None,
    event_type: Optional[str] = None,
    subject_id: Optional[str] = None,
    output_json: bool = False,
) -> None:
    """Display and filter security telemetry audit entries from the database."""
    query = "SELECT * FROM audit_logs WHERE 1=1"
    params: List[Any] = []

    if workspace_id:
        # Resolve slug or workspace_id
        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT id FROM workspaces WHERE id = ? OR slug = ?", (workspace_id, workspace_id))
            row = c.fetchone()
            resolved_ws = row["id"] if row else workspace_id
        query += " AND (workspace_id = ? OR workspace_id IS NULL)"
        params.append(resolved_ws)

    if severity:
        query += " AND UPPER(severity) = UPPER(?)"
        params.append(severity.strip())

    if event_type:
        query += " AND UPPER(event_type) LIKE UPPER(?)"
        params.append(f"%{event_type.strip()}%")

    if subject_id:
        query += " AND (subject_id = ? OR LOWER(metadata) LIKE LOWER(?))"
        params.extend([subject_id.strip(), f"%{subject_id.strip()}%"])

    query += " ORDER BY datetime(timestamp) DESC LIMIT ?"
    params.append(limit)

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()

    if output_json:
        results = [dict(r) for r in rows]
        for r in results:
            if isinstance(r.get("metadata"), str):
                try:
                    r["metadata"] = json.loads(r["metadata"])
                except Exception:
                    pass
        print(json.dumps(results, indent=2))
        return

    print("\n" + "=" * 80)
    print(f"  Security Audit Telemetry Logs (Showing up to {limit} entries)")
    print("=" * 80)

    if not rows:
        print("  No audit logs found matching criteria.")
        print("=" * 80 + "\n")
        return

    for r in rows:
        timestamp = r["timestamp"]
        sev = (r["severity"] or "INFO").upper()
        event = r["event_type"]
        ws = r["workspace_id"] or "global"
        subject = r["subject_id"] or "system"
        action = r["action"] or "-"
        resource = r["resource"] or "-"
        ip = r["ip_address"] or "-"
        meta_raw = r["metadata"]

        # Severity tag formatting
        sev_tag = f"[{sev}]"
        if sev == "CRITICAL":
            sev_tag = "[CRITICAL!]"
        elif sev == "WARNING":
            sev_tag = "[WARN]"

        print(f"{timestamp}  {sev_tag:<12} {event:<32} WS: {ws}")
        print(f"    * Subject:   {subject}")
        if action != "-":
            print(f"    * Action:    {action}")
        if resource != "-":
            print(f"    * Resource:  {resource}")
        if ip != "-":
            print(f"    * IP / Host: {ip}")

        if meta_raw and meta_raw != "{}":
            try:
                meta_obj = json.loads(meta_raw)
                meta_str = json.dumps(meta_obj)
                if len(meta_str) > 100:
                    meta_str = meta_str[:97] + "..."
                print(f"    * Metadata:  {meta_str}")
            except Exception:
                print(f"    * Metadata:  {meta_raw}")

        print("-" * 80)

    print()


def list_workspaces() -> None:
    """List all workspaces, slug endpoints, creators, and membership counts."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT w.*,
                   (SELECT COUNT(*) FROM workspace_members wm WHERE wm.workspace_id = w.id AND wm.status = 'active') as active_members,
                   (SELECT COUNT(*) FROM workspace_members wm WHERE wm.workspace_id = w.id AND wm.status = 'invited') as invited_members,
                   (SELECT COUNT(*) FROM tasks t WHERE t.workspace_id = w.id) as task_count
            FROM workspaces w
            ORDER BY datetime(w.created_at) ASC;
        """)
        rows = cursor.fetchall()

    print("\n" + "=" * 75)
    print("  Registered Multi-Tenant Workspaces")
    print("=" * 75)

    if not rows:
        print("  No workspaces found.")
        print("=" * 75 + "\n")
        return

    for r in rows:
        print(f"Workspace: '{r['name']}' (Slug: /{r['slug']})")
        print(f"  ID:          {r['id']}")
        print(f"  Description: {r['description'] or 'None'}")
        print(f"  Members:     {r['active_members']} active ({r['invited_members']} pending invites)")
        print(f"  Tasks:       {r['task_count']} sprint tasks")
        print(f"  Created By:  {r['created_by']} at {r['created_at']}")
        print("-" * 75)
    print()


def list_workspace_members(workspace_id: Optional[str] = None) -> None:
    """List members and invitations across workspaces."""
    query = """
        SELECT wm.*, w.name as workspace_name, w.slug as workspace_slug, u.username
        FROM workspace_members wm
        INNER JOIN workspaces w ON wm.workspace_id = w.id
        LEFT JOIN users u ON wm.user_id = u.id
        WHERE 1=1
    """
    params: List[Any] = []
    if workspace_id:
        query += " AND (wm.workspace_id = ? OR w.slug = ?)"
        params.extend([workspace_id.strip(), workspace_id.strip()])

    query += " ORDER BY wm.workspace_id, wm.status, wm.role ASC;"

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()

    print("\n" + "=" * 75)
    print("  Workspace Members & Invitations")
    print("=" * 75)

    if not rows:
        print("  No members found matching criteria.")
        print("=" * 75 + "\n")
        return

    current_ws = None
    for r in rows:
        if r["workspace_name"] != current_ws:
            current_ws = r["workspace_name"]
            print(f"\n>> Workspace: {current_ws} (/{r['workspace_slug']})")

        status_tag = "[ACTIVE]" if r["status"] == "active" else "[INVITED]"
        username = f"(@{r['username']})" if r["username"] else ""
        print(f"  {status_tag:<10} {r['name']} {username} <{r['email']}>")
        print(f"    * Member ID:   {r['id']}")
        print(f"    * Role:        {r['role'].upper()} (Dept: {r['department']})")
        if r["status"] == "invited":
            print(f"    * Token Hash:  {r['invite_token'][:16]}... (Expires: {r['expires_at']})")
            print(f"    * Invited By:  {r['invited_by']} at {r['invited_at']}")
        print("  " + "-" * 70)
    print()


def list_trusted_devices(user_filter: Optional[str] = None) -> None:
    """List all registered trusted devices for MFA scoping."""
    query = """
        SELECT td.*, u.username, u.email
        FROM trusted_devices td
        LEFT JOIN users u ON td.user_id = u.id
        WHERE 1=1
    """
    params: List[Any] = []
    if user_filter:
        query += " AND (td.user_id = ? OR LOWER(u.username) = LOWER(?) OR LOWER(u.email) = LOWER(?))"
        params.extend([user_filter.strip(), user_filter.strip(), user_filter.strip()])

    query += " ORDER BY datetime(td.last_used_at) DESC;"

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='trusted_devices'")
        if not cursor.fetchone():
            print("\nNo trusted_devices table found in database.")
            return

        cursor.execute(query, params)
        rows = cursor.fetchall()

    print("\n" + "=" * 75)
    print("  Recognized Trusted Devices (MFA Bypass Scopes)")
    print("=" * 75)

    if not rows:
        print("  No trusted devices found.")
        print("=" * 75 + "\n")
        return

    for r in rows:
        user_display = f"@{r['username']} ({r['email']})" if r["username"] else r["user_id"]
        print(f"Device: {r['device_label']}")
        print(f"  ID:          {r['id']}")
        print(f"  User:        {user_display}")
        print(f"  IP Address:  {r['ip_address'] or 'Unknown'}")
        print(f"  Created:     {r['created_at']}")
        print(f"  Expires:     {r['expires_at']}")
        print(f"  Last Used:   {r['last_used_at']}")
        print("-" * 75)
    print()


def list_users(role_filter: Optional[str] = None) -> None:
    """List all registered user accounts and security clearances."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, email, roles, is_active, metadata, created_at FROM users ORDER BY datetime(created_at) ASC;")
        rows = cursor.fetchall()

    print("\n" + "=" * 75)
    print("  Registered User Accounts")
    print("=" * 75)

    if not rows:
        print("  No users found.")
        print("=" * 75 + "\n")
        return

    count = 0
    for r in rows:
        roles = r["roles"]
        if isinstance(roles, str):
            try:
                roles = json.loads(roles)
            except Exception:
                roles = []

        if role_filter and role_filter.lower() not in [x.lower() for x in roles]:
            continue

        count += 1
        meta = r["metadata"]
        if isinstance(meta, str):
            try:
                meta = json.loads(meta)
            except Exception:
                meta = {}

        mfa_status = "Active" if meta.get("mfa_enabled") else "Disabled"
        dept = meta.get("department", "General")
        clearance = meta.get("clearance", 1)

        print(f"User: @{r['username']} <{r['email']}>")
        print(f"  ID:          {r['id']}")
        print(f"  Roles:       {roles}")
        print(f"  Department:  {dept} (Clearance: {clearance})")
        print(f"  MFA (2FA):   {mfa_status}")
        print(f"  Account:     {'Active' if r['is_active'] else 'Suspended/Inactive'}")
        print(f"  Created At:  {r['created_at']}")
        print("-" * 75)

    if role_filter and count == 0:
        print(f"  No users found with role '{role_filter}'.")
        print("=" * 75 + "\n")
    print()


def list_tasks(workspace_id: Optional[str] = None) -> None:
    """List all sprint deliverables and task cards with workspace scope."""
    query = """
        SELECT t.*, w.name as workspace_name, w.slug as workspace_slug
        FROM tasks t
        LEFT JOIN workspaces w ON t.workspace_id = w.id
        WHERE 1=1
    """
    params: List[Any] = []
    if workspace_id:
        query += " AND (t.workspace_id = ? OR w.slug = ?)"
        params.extend([workspace_id.strip(), workspace_id.strip()])

    query += " ORDER BY datetime(t.created_at) DESC;"

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()

    print("\n" + "=" * 75)
    print("  Sprint Tasks & Deliverables")
    print("=" * 75)

    if not rows:
        print("  No tasks found.")
        print("=" * 75 + "\n")
        return

    for r in rows:
        ws_info = f"[{r['workspace_name'] or r['workspace_id'] or 'General'}]"
        print(f"{ws_info} [{r['status'].upper()}] ({r['priority']}) {r['title']}")
        print(f"  Task ID:     {r['id']}")
        print(f"  Assignee:    {r['assignee_email'] or 'Unassigned'}")
        print(f"  Created By:  {r['created_by']} at {r['created_at']}")
        if r["due_date"]:
            print(f"  Due Date:    {r['due_date']}")
        print("-" * 75)
    print()


def purge_audit_logs() -> None:
    """Purge all security audit telemetry logs."""
    confirm = input("Are you sure you want to PURGE ALL AUDIT LOGS? (yes/no): ").strip().lower()
    if confirm != "yes":
        print("Aborted.")
        return

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM audit_logs;")
        count = cursor.rowcount
        conn.commit()
    print(f"Successfully purged {count} audit log record(s).")


def purge_trusted_devices() -> None:
    """Purge all remembered trusted devices (forcing MFA for all users)."""
    confirm = input("Are you sure you want to REVOKE ALL TRUSTED DEVICES? (yes/no): ").strip().lower()
    if confirm != "yes":
        print("Aborted.")
        return

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='trusted_devices'")
        if cursor.fetchone():
            cursor.execute("DELETE FROM trusted_devices;")
            count = cursor.rowcount
            conn.commit()
            print(f"Successfully revoked {count} trusted device(s).")
        else:
            print("trusted_devices table does not exist.")


def purge_tasks() -> None:
    """Delete all task cards from the database."""
    confirm = input("Are you sure you want to PURGE ALL TASKS? (yes/no): ").strip().lower()
    if confirm != "yes":
        print("Aborted.")
        return

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM tasks;")
        deleted = cursor.rowcount
        conn.commit()
    print(f"Successfully deleted {deleted} task records.")


def purge_all() -> None:
    """Purge tasks, audit logs, trusted devices, and workspaces while keeping root users."""
    confirm = input("Are you sure you want to PURGE tasks, audit logs, devices, and workspaces? (yes/no): ").strip().lower()
    if confirm != "yes":
        print("Aborted.")
        return

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM tasks;")
        tasks_count = cursor.rowcount
        cursor.execute("DELETE FROM audit_logs;")
        audit_count = cursor.rowcount

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='trusted_devices'")
        devices_count = 0
        if cursor.fetchone():
            cursor.execute("DELETE FROM trusted_devices;")
            devices_count = cursor.rowcount

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='workspace_members'")
        members_count = 0
        if cursor.fetchone():
            cursor.execute("DELETE FROM workspace_members;")
            members_count = cursor.rowcount

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='workspaces'")
        ws_count = 0
        if cursor.fetchone():
            cursor.execute("DELETE FROM workspaces WHERE id != 'ws_default';")
            ws_count = cursor.rowcount

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='team_members'")
        team_count = 0
        if cursor.fetchone():
            cursor.execute("DELETE FROM team_members;")
            team_count = cursor.rowcount

        conn.commit()

    print(f"Purge complete: {tasks_count} tasks, {audit_count} audit logs, {devices_count} devices, {members_count} members, and {ws_count} workspaces deleted.")


def reset_entire_database() -> None:
    """Completely wipe all records from all tables."""
    confirm = input("CRITICAL: This will wipe ALL USERS, WORKSPACES, TASKS, LOGS, AND DEVICES. Proceed? (yes/no): ").strip().lower()
    if confirm != "yes":
        print("Aborted.")
        return

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [r["name"] for r in cursor.fetchall() if not r["name"].startswith("sqlite_")]
        for t in tables:
            cursor.execute(f"DELETE FROM {t};")
        conn.commit()

    print("Entire database wiped clean. Run 'python seed_admin.py' to bootstrap a new admin user.")


def main():
    parser = argparse.ArgumentParser(
        description="Auth N&Z Database Management & Telemetry Inspection CLI"
    )
    subparsers = parser.add_subparsers(dest="action", help="Action to perform on the database")

    # stats
    subparsers.add_parser("stats", help="Show database overview and record counts")

    # audit
    audit_p = subparsers.add_parser("audit", help="Inspect security audit telemetry logs")
    audit_p.add_argument("-n", "--limit", type=int, default=25, help="Number of records to show (default: 25)")
    audit_p.add_argument("-w", "--workspace", type=str, help="Filter by workspace ID or slug")
    audit_p.add_argument("-s", "--severity", type=str, help="Filter by severity (INFO, WARNING, CRITICAL)")
    audit_p.add_argument("-e", "--event", type=str, help="Filter by event type substring (e.g. LOGIN, WORKSPACE)")
    audit_p.add_argument("-u", "--user", type=str, help="Filter by subject ID or user email")
    audit_p.add_argument("--json", action="store_true", help="Output raw JSON format")

    # workspaces
    subparsers.add_parser("workspaces", help="List all registered workspaces")

    # members
    members_p = subparsers.add_parser("members", help="List workspace members and invitations")
    members_p.add_argument("-w", "--workspace", type=str, help="Filter by workspace ID or slug")

    # devices
    devices_p = subparsers.add_parser("devices", help="List recognized trusted devices (remember-device scopes)")
    devices_p.add_argument("-u", "--user", type=str, help="Filter by user ID, username, or email")

    # users
    users_p = subparsers.add_parser("users", help="List registered user accounts")
    users_p.add_argument("-r", "--role", type=str, help="Filter by role (superadmin, admin, developer, editor, viewer)")

    # tasks
    tasks_p = subparsers.add_parser("tasks", help="List sprint tasks")
    tasks_p.add_argument("-w", "--workspace", type=str, help="Filter by workspace ID or slug")

    # Purges
    subparsers.add_parser("purge-audit", help="Purge all audit telemetry logs")
    subparsers.add_parser("purge-devices", help="Revoke all trusted devices")
    subparsers.add_parser("purge-tasks", help="Purge all sprint tasks")
    subparsers.add_parser("purge-all", help="Purge tasks, audit logs, devices, and workspaces (retaining users)")
    subparsers.add_parser("reset-db", help="Completely wipe all records from all tables")

    args = parser.parse_args()

    if not args.action:
        parser.print_help()
        sys.exit(0)

    if args.action == "stats":
        show_stats()
    elif args.action == "audit":
        list_audit_logs(
            limit=args.limit,
            workspace_id=args.workspace,
            severity=args.severity,
            event_type=args.event,
            subject_id=args.user,
            output_json=args.json,
        )
    elif args.action == "workspaces":
        list_workspaces()
    elif args.action == "members":
        list_workspace_members(workspace_id=args.workspace)
    elif args.action == "devices":
        list_trusted_devices(user_filter=args.user)
    elif args.action == "users":
        list_users(role_filter=args.role)
    elif args.action == "tasks":
        list_tasks(workspace_id=args.workspace)
    elif args.action == "purge-audit":
        purge_audit_logs()
    elif args.action == "purge-devices":
        purge_trusted_devices()
    elif args.action == "purge-tasks":
        purge_tasks()
    elif args.action == "purge-all":
        purge_all()
    elif args.action == "reset-db":
        reset_entire_database()


if __name__ == "__main__":
    main()
