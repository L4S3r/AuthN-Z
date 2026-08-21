"""
Auth N&Z - Database Management & Inspection CLI (db_manager.py)
--------------------------------------------------------------
Inspect, query, and safely purge database tables live on your server.
Works safely with SQLite in WAL mode without requiring service stoppage.

Usage:
    python db_manager.py stats
    python db_manager.py users
    python db_manager.py tasks
    python db_manager.py audit
    python db_manager.py purge-tasks
    python db_manager.py purge-all
    python db_manager.py reset-db
"""

import argparse
import json
import os
import sqlite3
import sys
from typing import Any, Dict, List

DB_FILE = os.getenv("AUTH_NZ_DB_PATH", "DATABASE.db")


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_FILE, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


def show_stats() -> None:
    """Print high-level statistics across all tables."""
    print("=" * 60)
    print(f"Auth N&Z Database Overview: {DB_FILE}")
    print("=" * 60)

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [r["name"] for r in cursor.fetchall() if not r["name"].startswith("sqlite_")]

        for table in tables:
            cursor.execute(f"SELECT COUNT(*) as count FROM {table};")
            count = cursor.fetchone()["count"]
            print(f"  * Table '{table}': {count} records")

    print("=" * 60)


def list_users() -> None:
    """List all registered user accounts and security claims."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, email, roles, is_active, metadata, created_at FROM users;")
        rows = cursor.fetchall()

    print("\n--- Registered Users ---")
    if not rows:
        print("No users found.")
        return

    for r in rows:
        meta = r["metadata"]
        if isinstance(meta, str):
            try:
                meta = json.loads(meta)
            except Exception:
                meta = {}
        mfa_status = "Enabled" if meta.get("mfa_enabled") else "Disabled"
        dept = meta.get("department", "General")
        clearance = meta.get("clearance", 1)

        print(f"ID: {r['id']}")
        print(f"  Username:    {r['username']}")
        print(f"  Email:       {r['email']}")
        print(f"  Roles:       {r['roles']}")
        print(f"  Department:  {dept} (Clearance: {clearance})")
        print(f"  2FA Status:  {mfa_status}")
        print(f"  Active:      {'Yes' if r['is_active'] else 'No'}")
        print(f"  Created:     {r['created_at']}")
        print("-" * 50)


def list_tasks() -> None:
    """List all sprint deliverables and task cards."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, title, status, priority, assignee_email, created_by, created_at FROM tasks ORDER BY datetime(created_at) DESC;")
        rows = cursor.fetchall()

    print("\n--- Workspace Tasks ---")
    if not rows:
        print("No tasks found.")
        return

    for r in rows:
        print(f"[{r['status'].upper()}] ({r['priority']}) {r['title']}")
        print(f"  ID:          {r['id']}")
        print(f"  Assignee:    {r['assignee_email'] or 'Unassigned'}")
        print(f"  Created By:  {r['created_by']} at {r['created_at']}")
        print("-" * 50)


def list_audit_logs(limit: int = 15) -> None:
    """Display latest security telemetry audit entries."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(f"SELECT * FROM audit_logs ORDER BY datetime(timestamp) DESC LIMIT {limit};")
        rows = cursor.fetchall()

    print(f"\n--- Latest {limit} Audit Telemetry Logs ---")
    if not rows:
        print("No audit logs found.")
        return

    for r in rows:
        print(f"[{r['timestamp']}] ({r['event_type']}) User: {r['user_id']} | Outcome: {r['status']}")
        if r["details"]:
            print(f"  Details: {r['details']}")
        print("-" * 50)


def purge_tasks() -> None:
    """Delete all task cards from the workspace."""
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
    """Purge tasks, audit logs, and team invitations while keeping root users."""
    confirm = input("Are you sure you want to PURGE tasks, audit logs, and team invites? (yes/no): ").strip().lower()
    if confirm != "yes":
        print("Aborted.")
        return

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM tasks;")
        tasks_count = cursor.rowcount
        cursor.execute("DELETE FROM audit_logs;")
        audit_count = cursor.rowcount
        cursor.execute("DELETE FROM team_members;")
        team_count = cursor.rowcount
        conn.commit()

    print(f"Purge complete: {tasks_count} tasks, {audit_count} audit logs, and {team_count} invites deleted.")


def reset_entire_database() -> None:
    """Completely wipe all records from all tables."""
    confirm = input("CRITICAL: This will wipe ALL USERS, TASKS, LOGS, AND INVITES. Proceed? (yes/no): ").strip().lower()
    if confirm != "yes":
        print("Aborted.")
        return

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM tasks;")
        cursor.execute("DELETE FROM audit_logs;")
        cursor.execute("DELETE FROM team_members;")
        cursor.execute("DELETE FROM users;")
        conn.commit()

    print("Entire database wiped clean. Run 'python seed_admin.py' to bootstrap a new admin user.")


def main():
    parser = argparse.ArgumentParser(description="Auth N&Z Database Management CLI")
    parser.add_argument(
        "action",
        choices=["stats", "users", "tasks", "audit", "purge-tasks", "purge-all", "reset-db"],
        help="Action to perform on the database",
    )
    args = parser.parse_args()

    if args.action == "stats":
        show_stats()
    elif args.action == "users":
        list_users()
    elif args.action == "tasks":
        list_tasks()
    elif args.action == "audit":
        list_audit_logs()
    elif args.action == "purge-tasks":
        purge_tasks()
    elif args.action == "purge-all":
        purge_all()
    elif args.action == "reset-db":
        reset_entire_database()


if __name__ == "__main__":
    main()
