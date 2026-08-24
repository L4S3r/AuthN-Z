"""
Auth N&Z - PostgreSQL Database Management & Inspection CLI (db_manager.py)
-------------------------------------------------------------------------
Inspect, query, and safely manage PostgreSQL tables live on your server.
Uses async SQLAlchemy and the configured connection pool.

Usage:
    python db_manager.py stats
    python db_manager.py audit [-n 25] [-w WORKSPACE] [-s SEVERITY] [-e EVENT] [-u USER] [--json]
    python db_manager.py workspaces
    python db_manager.py members [-w WORKSPACE]
    python db_manager.py devices [-u USER]
    python db_manager.py users [-r ROLE]
    python db_manager.py tasks [-w WORKSPACE]
    python db_manager.py purge-audit [--yes]
    python db_manager.py purge-devices [--yes]
    python db_manager.py purge-tasks [--yes]
    python db_manager.py purge-all [--yes]
    python db_manager.py reset-db [--yes]
"""

import argparse
import asyncio
import asyncpg
import json
import os
import sys
import uuid
from typing import Any, Dict, List, Optional

from sqlalchemy import select, func, delete, text
from database import get_session_factory, get_engine
from models import (
    User,
    Workspace,
    WorkspaceMember,
    Task,
    TeamMember,
    TrustedDevice,
    PasswordResetToken,
    Notification,
    AuditLog,
)


async def show_stats() -> None:
    """Print high-level statistics across all PostgreSQL database tables."""
    print("=" * 65)
    print("  Auth N&Z PostgreSQL Database Overview")
    print("=" * 65)

    session_factory = get_session_factory()
    models = [
        ("users", User),
        ("workspaces", Workspace),
        ("workspace_members", WorkspaceMember),
        ("tasks", Task),
        ("team_members", TeamMember),
        ("trusted_devices", TrustedDevice),
        ("password_reset_tokens", PasswordResetToken),
        ("notifications", Notification),
        ("audit_logs", AuditLog),
    ]

    async with session_factory() as session:
        for tbl_name, model_cls in models:
            res = await session.execute(select(func.count(model_cls.id)))
            count = res.scalar_one() or 0
            print(f"  * Table '{tbl_name}': {count:>5} records")

    print("=" * 65)


async def list_audit_logs(
    limit: int = 25,
    workspace_id: Optional[str] = None,
    severity: Optional[str] = None,
    event_type: Optional[str] = None,
    subject_id: Optional[str] = None,
    output_json: bool = False,
) -> None:
    """Display and filter security telemetry audit entries from PostgreSQL."""
    session_factory = get_session_factory()
    async with session_factory() as session:
        stmt = select(AuditLog).order_by(AuditLog.timestamp.desc())

        if workspace_id:
            try:
                ws_uuid = uuid.UUID(workspace_id.strip())
                stmt = stmt.where(AuditLog.workspace_id == ws_uuid)
            except Exception:
                stmt = stmt.where(AuditLog.workspace_slug == workspace_id.strip())

        if severity:
            stmt = stmt.where(AuditLog.severity == severity.strip().upper())

        if event_type:
            stmt = stmt.where(AuditLog.event_type.ilike(f"%{event_type.strip()}%"))

        if subject_id:
            stmt = stmt.where(AuditLog.subject_id == subject_id.strip())

        stmt = stmt.limit(limit)
        result = await session.execute(stmt)
        rows = result.scalars().all()

    if output_json:
        data = [
            {
                "id": str(r.id),
                "timestamp": r.timestamp.isoformat() if r.timestamp else None,
                "event_type": r.event_type,
                "severity": r.severity,
                "subject_id": r.subject_id,
                "workspace_id": str(r.workspace_id) if r.workspace_id else None,
                "workspace_slug": r.workspace_slug,
                "metadata": r.metadata_payload,
            }
            for r in rows
        ]
        print(json.dumps(data, indent=2))
        return

    print("=" * 115)
    print(f"{'TIMESTAMP (UTC)':<24} | {'SEVERITY':<8} | {'EVENT TYPE':<28} | {'SUBJECT':<20} | {'WORKSPACE'}")
    print("-" * 115)

    for r in rows:
        ts = r.timestamp.strftime("%Y-%m-%d %H:%M:%S") if r.timestamp else "N/A"
        ws_info = r.workspace_slug or (str(r.workspace_id)[:8] if r.workspace_id else "global")
        subj = (r.subject_id or "system")[:20]
        print(f"{ts:<24} | {r.severity:<8} | {r.event_type:<28} | {subj:<20} | {ws_info}")

    print("=" * 115)
    print(f"Total shown: {len(rows)}")


async def list_workspaces() -> None:
    """Display all workspaces with member counts and creation dates."""
    session_factory = get_session_factory()
    async with session_factory() as session:
        stmt = (
            select(
                Workspace.id,
                Workspace.name,
                Workspace.slug,
                Workspace.created_at,
                func.count(WorkspaceMember.id).label("member_count"),
            )
            .outerjoin(WorkspaceMember, Workspace.id == WorkspaceMember.workspace_id)
            .group_by(Workspace.id, Workspace.name, Workspace.slug, Workspace.created_at)
            .order_by(Workspace.created_at.asc())
        )
        result = await session.execute(stmt)
        rows = result.all()

    print("=" * 95)
    print(f"{'ID':<38} | {'SLUG':<20} | {'MEMBERS':<7} | {'NAME'}")
    print("-" * 95)

    for r in rows:
        print(f"{str(r.id):<38} | {r.slug:<20} | {r.member_count:<7} | {r.name}")

    print("=" * 95)
    print(f"Total workspaces: {len(rows)}")


async def list_members(workspace_id: Optional[str] = None) -> None:
    """Display members across workspaces."""
    session_factory = get_session_factory()
    async with session_factory() as session:
        stmt = (
            select(
                WorkspaceMember.id,
                WorkspaceMember.workspace_id,
                Workspace.name.label("workspace_name"),
                WorkspaceMember.user_id,
                WorkspaceMember.email,
                WorkspaceMember.role,
                WorkspaceMember.status,
            )
            .join(Workspace, WorkspaceMember.workspace_id == Workspace.id)
            .order_by(Workspace.name.asc(), WorkspaceMember.role.asc())
        )

        if workspace_id:
            try:
                ws_uuid = uuid.UUID(workspace_id.strip())
                stmt = stmt.where(WorkspaceMember.workspace_id == ws_uuid)
            except Exception:
                stmt = stmt.where(Workspace.slug == workspace_id.strip())

        result = await session.execute(stmt)
        rows = result.all()

    print("=" * 115)
    print(f"{'WORKSPACE':<22} | {'EMAIL':<30} | {'ROLE':<12} | {'STATUS':<8} | {'USER ID'}")
    print("-" * 115)

    for r in rows:
        uid_str = str(r.user_id) if r.user_id else "pending"
        print(f"{r.workspace_name[:20]:<22} | {r.email:<30} | {r.role:<12} | {r.status:<8} | {uid_str}")

    print("=" * 115)
    print(f"Total members: {len(rows)}")


async def list_users(role_filter: Optional[str] = None) -> None:
    """Display registered users and their role assignments."""
    session_factory = get_session_factory()
    async with session_factory() as session:
        stmt = select(User).order_by(User.created_at.asc())
        result = await session.execute(stmt)
        rows = result.scalars().all()

    print("=" * 110)
    print(f"{'ID':<38} | {'USERNAME':<18} | {'EMAIL':<28} | {'ROLES'}")
    print("-" * 110)

    count = 0
    for u in rows:
        roles_list = u.roles if isinstance(u.roles, list) else []
        if role_filter and role_filter.lower() not in [str(r).lower() for r in roles_list]:
            continue
        count += 1
        roles_str = ", ".join(roles_list)
        print(f"{str(u.id):<38} | {u.username:<18} | {u.email:<28} | {roles_str}")

    print("=" * 110)
    print(f"Total users: {count}")


async def list_tasks(workspace_id: Optional[str] = None) -> None:
    """Display tasks."""
    session_factory = get_session_factory()
    async with session_factory() as session:
        stmt = select(Task).order_by(Task.created_at.desc())
        if workspace_id:
            try:
                ws_uuid = uuid.UUID(workspace_id.strip())
                stmt = stmt.where(Task.workspace_id == ws_uuid)
            except Exception:
                pass
        result = await session.execute(stmt)
        rows = result.scalars().all()

    print("=" * 105)
    print(f"{'ID':<38} | {'STATUS':<12} | {'PRIORITY':<8} | {'ASSIGNEE':<20} | {'TITLE'}")
    print("-" * 105)

    for t in rows:
        assignee = (t.assignee_email or "Unassigned")[:20]
        print(f"{str(t.id):<38} | {t.status:<12} | {t.priority:<8} | {assignee:<20} | {t.title}")

    print("=" * 105)
    print(f"Total tasks: {len(rows)}")


async def purge_audit_logs() -> None:
    """Purge all security audit telemetry logs."""
    session_factory = get_session_factory()
    async with session_factory() as session:
        await session.execute(delete(AuditLog))
        await session.commit()
    print("[SUCCESS] Audit logs table purged successfully.")


async def purge_trusted_devices() -> None:
    """Purge all enrolled trusted devices."""
    session_factory = get_session_factory()
    async with session_factory() as session:
        await session.execute(delete(TrustedDevice))
        await session.commit()
    print("[SUCCESS] Trusted devices table purged successfully.")


async def purge_tasks() -> None:
    """Purge all tasks."""
    session_factory = get_session_factory()
    async with session_factory() as session:
        await session.execute(delete(Task))
        await session.commit()
    print("[SUCCESS] Tasks table purged successfully.")


async def purge_all_data() -> None:
    """Purge all tables in PostgreSQL with CASCADE."""
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.execute(text(
            "TRUNCATE TABLE tasks, team_members, workspace_members, workspaces, trusted_devices, password_reset_tokens, notifications, audit_logs, users CASCADE;"
        ))
    print("[SUCCESS] All PostgreSQL application tables have been purged clean.")


def main():
    parser = argparse.ArgumentParser(
        description="Auth N&Z - PostgreSQL Database Management CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", help="Available sub-commands")

    # stats
    subparsers.add_parser("stats", help="Display record counts across all tables")

    # audit
    p_audit = subparsers.add_parser("audit", help="Query and filter security audit telemetry logs")
    p_audit.add_argument("-n", "--limit", type=int, default=25, help="Number of records to display (default: 25)")
    p_audit.add_argument("-w", "--workspace", type=str, help="Filter by workspace ID or slug")
    p_audit.add_argument("-s", "--severity", type=str, help="Filter by severity (INFO, WARNING, CRITICAL)")
    p_audit.add_argument("-e", "--event", type=str, help="Filter by event type substring")
    p_audit.add_argument("-u", "--user", type=str, help="Filter by subject user ID")
    p_audit.add_argument("--json", action="store_true", help="Output results in JSON format")

    # workspaces
    subparsers.add_parser("workspaces", help="List all workspaces")

    # members
    p_members = subparsers.add_parser("members", help="List workspace members")
    p_members.add_argument("-w", "--workspace", type=str, help="Filter by workspace ID or slug")

    # devices
    p_devices = subparsers.add_parser("devices", help="List active trusted devices")
    p_devices.add_argument("-u", "--user", type=str, help="Filter by user ID")

    # users
    p_users = subparsers.add_parser("users", help="List registered users")
    p_users.add_argument("-r", "--role", type=str, help="Filter by role")

    # tasks
    p_tasks = subparsers.add_parser("tasks", help="List tasks")
    p_tasks.add_argument("-w", "--workspace", type=str, help="Filter by workspace ID")

    # purge commands
    p_purge_audit = subparsers.add_parser("purge-audit", help="Delete all audit logs")
    p_purge_audit.add_argument("--yes", action="store_true", help="Skip confirmation prompt")

    p_purge_dev = subparsers.add_parser("purge-devices", help="Delete all trusted devices")
    p_purge_dev.add_argument("--yes", action="store_true", help="Skip confirmation prompt")

    p_purge_tasks = subparsers.add_parser("purge-tasks", help="Delete all tasks")
    p_purge_tasks.add_argument("--yes", action="store_true", help="Skip confirmation prompt")

    p_purge_all = subparsers.add_parser("purge-all", help="Purge all tables in PostgreSQL (full reset)")
    p_purge_all.add_argument("--yes", action="store_true", help="Skip confirmation prompt")

    p_reset = subparsers.add_parser("reset-db", help="Purge all tables and bootstrap default admin account")
    p_reset.add_argument("--yes", action="store_true", help="Skip confirmation prompt")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.command == "stats":
        asyncio.run(show_stats())
    elif args.command == "audit":
        asyncio.run(list_audit_logs(
            limit=args.limit,
            workspace_id=args.workspace,
            severity=args.severity,
            event_type=args.event,
            subject_id=args.user,
            output_json=args.json,
        ))
    elif args.command == "workspaces":
        asyncio.run(list_workspaces())
    elif args.command == "members":
        asyncio.run(list_members(workspace_id=args.workspace))
    elif args.command == "users":
        asyncio.run(list_users(role_filter=args.role))
    elif args.command == "tasks":
        asyncio.run(list_tasks(workspace_id=args.workspace))
    elif args.command == "purge-audit":
        if not args.yes:
            conf = input("Are you sure you want to purge all audit logs? (y/N): ").strip().lower()
            if conf != "y":
                print("Aborted.")
                return
        asyncio.run(purge_audit_logs())
    elif args.command == "purge-devices":
        if not args.yes:
            conf = input("Are you sure you want to purge all trusted devices? (y/N): ").strip().lower()
            if conf != "y":
                print("Aborted.")
                return
        asyncio.run(purge_trusted_devices())
    elif args.command == "purge-tasks":
        if not args.yes:
            conf = input("Are you sure you want to purge all tasks? (y/N): ").strip().lower()
            if conf != "y":
                print("Aborted.")
                return
        asyncio.run(purge_tasks())
    elif args.command == "purge-all":
        if not args.yes:
            conf = input("CAUTION: This will purge ALL data in PostgreSQL. Are you sure? (y/N): ").strip().lower()
            if conf != "y":
                print("Aborted.")
                return
        asyncio.run(purge_all_data())
    elif args.command == "reset-db":
        if not args.yes:
            conf = input("This will purge all data and prepare for admin seeding. Proceed? (y/N): ").strip().lower()
            if conf != "y":
                print("Aborted.")
                return
        asyncio.run(purge_all_data())
        from seed_admin import interactive_prompt
        interactive_prompt()


if __name__ == "__main__":
    main()
