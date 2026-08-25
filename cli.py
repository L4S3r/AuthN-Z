"""
Auth N&Z - Command-Line Administration Control Plane (cli.py)
-------------------------------------------------------------
CLI management utility for operator user provisioning, workspace management,
credential resets, security audit inspection, and health diagnostics.

Usage:
    python cli.py users list
    python cli.py users create --username admin --email admin@example.com --password SecretPassword123! --role superadmin
    python cli.py users reset-password --email user@example.com --password NewSecretPassword123!
    python cli.py workspaces list
    python cli.py workspaces create --name "Acme Corp" --slug "acme"
    python cli.py audit tail --limit 20
    python cli.py health check
    python cli.py metrics dump
"""

import argparse
import asyncio
import json
import sys
import time
from typing import Any, Dict, List, Optional

from config import settings
from password_hasher import PasswordHasher
from user_repository import UserRepository
from workspace_repository import WorkspaceRepository
from audit_logger import AuditLogger
from metrics import metrics_collector


async def _cmd_users_list(args):
    repo = UserRepository()
    users = await repo.list_users(limit=args.limit)
    print(f"\n--- User Accounts ({len(users)}) ---")
    print(f"{'ID':<38} {'Username':<20} {'Email':<30} {'Roles':<20} {'Active':<8}")
    print("-" * 120)
    for u in users:
        roles_str = ",".join(u.get("roles", [])) if isinstance(u.get("roles"), list) else str(u.get("roles", ""))
        active_str = "Yes" if u.get("is_active", 1) else "No"
        print(f"{str(u['id']):<38} {u['username']:<20} {u['email']:<30} {roles_str:<20} {active_str:<8}")
    print()


async def _cmd_users_create(args):
    repo = UserRepository()
    hasher = PasswordHasher()

    existing = await repo.get_by_identifier(args.email)
    if existing:
        print(f"[ERROR] A user with email '{args.email}' already exists.")
        sys.exit(1)

    hashed_pw = hasher.hash(args.password)
    user = await repo.create_user({
        "username": args.username,
        "email": args.email.lower().strip(),
        "hashed_password": hashed_pw,
        "roles": [args.role],
        "metadata": {
            "department": args.department or "General",
            "clearance": args.clearance or 1,
            "name": args.name or args.username,
        },
    })
    print(f"\n[SUCCESS] User created successfully!")
    print(f"  User ID:  {user['id']}")
    print(f"  Username: {user['username']}")
    print(f"  Email:    {user['email']}")
    print(f"  Role:     {args.role}\n")


async def _cmd_users_reset_password(args):
    repo = UserRepository()
    hasher = PasswordHasher()

    user = await repo.get_by_identifier(args.email.lower().strip())
    if not user:
        print(f"[ERROR] User with email '{args.email}' not found.")
        sys.exit(1)

    new_hash = hasher.hash(args.password)
    await repo.update_user(user["id"], {"hashed_password": new_hash})
    print(f"\n[SUCCESS] Password updated for user '{user['username']}' ({user['email']}).\n")


async def _cmd_users_delete(args):
    repo = UserRepository()
    user = await repo.get_by_identifier(args.email.lower().strip())
    if not user:
        print(f"[ERROR] User with email '{args.email}' not found.")
        sys.exit(1)

    await repo.delete_user(user["id"])
    print(f"\n[SUCCESS] User '{user['username']}' ({user['email']}) deleted.\n")


async def _cmd_workspaces_list(args):
    ws_repo = WorkspaceRepository()
    workspaces = await ws_repo.list_all_workspaces()
    print(f"\n--- Workspaces ({len(workspaces)}) ---")
    print(f"{'ID':<38} {'Slug':<20} {'Name':<30} {'Created By':<25}")
    print("-" * 120)
    for w in workspaces:
        print(f"{str(w['id']):<38} {w.get('slug', ''):<20} {w.get('name', ''):<30} {w.get('created_by', ''):<25}")
    print()


async def _cmd_workspaces_create(args):
    ws_repo = WorkspaceRepository()
    try:
        ws = await ws_repo.create_workspace(
            name=args.name,
            slug=args.slug,
            created_by=args.created_by or "system_admin",
            description=args.description or "",
        )
        print(f"\n[SUCCESS] Workspace created successfully!")
        print(f"  ID:   {ws['id']}")
        print(f"  Slug: {ws['slug']}")
        print(f"  Name: {ws['name']}\n")
    except ValueError as exc:
        print(f"[ERROR] Failed to create workspace: {exc}")
        sys.exit(1)


async def _cmd_audit_tail(args):
    audit = AuditLogger()
    filters = {}
    if args.severity:
        filters["severity"] = args.severity.upper()
    logs = await audit.query_events(filters, limit=args.limit)
    print(f"\n--- Recent Security Audit Telemetry ({len(logs)}) ---")
    print(f"{'Timestamp':<25} {'Severity':<10} {'Event Name':<32} {'Subject ID':<25}")
    print("-" * 100)
    for log in logs:
        ts = log.get("timestamp", "")
        sev = log.get("severity", "INFO")
        evt = log.get("event_name", "")
        sub = log.get("subject_id", "") or "anonymous"
        print(f"{ts:<25} {sev:<10} {evt:<32} {sub:<25}")
    print()


def _cmd_health_check(args):
    print("\n--- Auth N&Z Diagnostics ---")
    print(f"  Environment:       {settings.ENVIRONMENT}")
    print(f"  Password Engine:   {settings.PASSWORD_HASH_ALGORITHM}")
    print(f"  Bcrypt Workfactor: {settings.BCRYPT_WORK_FACTOR}")
    print(f"  JWT Algorithm:     {settings.JWT_ALGORITHM}")
    print(f"  PostgreSQL Target: {settings.POSTGRES_HOST}:{settings.POSTGRES_PORT}/{settings.POSTGRES_DB}")
    print(f"  Redis Target:      {settings.REDIS_HOST}:{settings.REDIS_PORT}")
    print(f"  Status:            ONLINE\n")


def _cmd_metrics_dump(args):
    print(metrics_collector.generate_prometheus_metrics())


def main():
    parser = argparse.ArgumentParser(
        prog="authnz",
        description="Auth N&Z - Command-Line Administration Control Plane",
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Management domain")

    # Users
    users_parser = subparsers.add_parser("users", help="User account administration")
    users_sub = users_parser.add_subparsers(dest="action")

    # users list
    u_list = users_sub.add_parser("list", help="List user accounts")
    u_list.add_argument("--limit", type=int, default=50, help="Max users to display")

    # users create
    u_create = users_sub.add_parser("create", help="Create a user account")
    u_create.add_argument("--username", required=True, help="Unique username")
    u_create.add_argument("--email", required=True, help="User email address")
    u_create.add_argument("--password", required=True, help="Initial password")
    u_create.add_argument("--role", default="viewer", help="Assigned role: superadmin, admin, editor, viewer")
    u_create.add_argument("--name", help="Display name")
    u_create.add_argument("--department", default="General", help="Department")
    u_create.add_argument("--clearance", type=int, default=1, help="Clearance level (1-3)")

    # users reset-password
    u_reset = users_sub.add_parser("reset-password", help="Reset a user's password")
    u_reset.add_argument("--email", required=True, help="User email address")
    u_reset.add_argument("--password", required=True, help="New password")

    # users delete
    u_del = users_sub.add_parser("delete", help="Delete a user account")
    u_del.add_argument("--email", required=True, help="User email address")

    # Workspaces
    ws_parser = subparsers.add_parser("workspaces", help="Workspace tenant administration")
    ws_sub = ws_parser.add_subparsers(dest="action")

    # workspaces list
    ws_list = ws_sub.add_parser("list", help="List tenant workspaces")

    # workspaces create
    ws_create = ws_sub.add_parser("create", help="Create a tenant workspace")
    ws_create.add_argument("--name", required=True, help="Workspace display name")
    ws_create.add_argument("--slug", help="URL slug (auto-generated if omitted)")
    ws_create.add_argument("--created-by", help="Admin creator identifier")
    ws_create.add_argument("--description", help="Workspace description")

    # Audit
    audit_parser = subparsers.add_parser("audit", help="Security audit inspection")
    audit_sub = audit_parser.add_subparsers(dest="action")
    a_tail = audit_sub.add_parser("tail", help="Tail recent audit events")
    a_tail.add_argument("--limit", type=int, default=25, help="Number of records to show")
    a_tail.add_argument("--severity", help="Filter by severity (INFO, WARNING, CRITICAL)")

    # Health
    health_parser = subparsers.add_parser("health", help="Health and diagnostic checks")
    health_sub = health_parser.add_subparsers(dest="action")
    health_sub.add_parser("check", help="Run local configuration diagnostic check")

    # Metrics
    metrics_parser = subparsers.add_parser("metrics", help="Telemetry & metrics export")
    metrics_sub = metrics_parser.add_subparsers(dest="action")
    metrics_sub.add_parser("dump", help="Dump Prometheus metrics text")

    args = parser.parse_args()

    if not args.subcommand:
        parser.print_help()
        sys.exit(0)

    if args.subcommand == "users":
        if args.action == "list":
            asyncio.run(_cmd_users_list(args))
        elif args.action == "create":
            asyncio.run(_cmd_users_create(args))
        elif args.action == "reset-password":
            asyncio.run(_cmd_users_reset_password(args))
        elif args.action == "delete":
            asyncio.run(_cmd_users_delete(args))
        else:
            users_parser.print_help()

    elif args.subcommand == "workspaces":
        if args.action == "list":
            asyncio.run(_cmd_workspaces_list(args))
        elif args.action == "create":
            asyncio.run(_cmd_workspaces_create(args))
        else:
            ws_parser.print_help()

    elif args.subcommand == "audit":
        if args.action == "tail":
            asyncio.run(_cmd_audit_tail(args))
        else:
            audit_parser.print_help()

    elif args.subcommand == "health":
        if args.action == "check":
            _cmd_health_check(args)
        else:
            health_parser.print_help()

    elif args.subcommand == "metrics":
        if args.action == "dump":
            _cmd_metrics_dump(args)
        else:
            metrics_parser.print_help()


if __name__ == "__main__":
    main()
