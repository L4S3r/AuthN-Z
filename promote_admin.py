"""
Auth N&Z - User Promotion Utility (promote_admin.py) (PostgreSQL Async)
-----------------------------------------------------------------------
Promotes an existing registered user account to Superadmin or Administrator role,
assigns security clearance, and records a structured audit event in PostgreSQL.

Usage (Interactive):
    python promote_admin.py

Usage (CLI Arguments):
    python promote_admin.py -i admin@l4s3r.site --super
    python promote_admin.py -i user@l4s3r.site --role superadmin --clearance 3 --department Security
"""

import argparse
import asyncio
import json
import sys
from typing import Optional

from user_repository import UserRepository
from audit_logger import AuditLogger


async def promote_user_to_admin(
    identifier: str,
    role: str = "admin",
    department: str = "Security",
    clearance: int = 3,
) -> Optional[dict]:
    """Promote an existing user to administrator or superadmin role with clearance level."""
    clean_id = identifier.strip()
    if not clean_id:
        print("Error: Identifier cannot be empty.", file=sys.stderr)
        return None

    clean_role = role.strip().lower()
    if clean_role in ("super-admin", "super_admin", "superadmin", "root"):
        target_role = "superadmin"
    else:
        target_role = clean_role

    repo = UserRepository()
    audit = AuditLogger()

    user = await repo.get_by_identifier(clean_id)
    if not user:
        print(f"Error: No user found matching '{clean_id}'.", file=sys.stderr)
        return None

    roles = user.get("roles", [])
    if isinstance(roles, str):
        try:
            roles = json.loads(roles)
        except Exception:
            roles = []

    if target_role not in roles:
        roles.append(target_role)

    raw_meta = user.get("metadata", {})
    if isinstance(raw_meta, str):
        try:
            metadata = json.loads(raw_meta)
        except Exception:
            metadata = {}
    elif isinstance(raw_meta, dict):
        metadata = dict(raw_meta)
    else:
        metadata = {}

    metadata["department"] = department
    metadata["clearance"] = clearance

    updated_user = await repo.update_user(
        user["id"],
        {
            "roles": roles,
            "metadata": metadata,
        },
    )

    await audit.record_security_event(
        event_name="USER_PROMOTED_TO_ADMIN",
        severity="WARNING",
        details={
            "user_id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "assigned_role": target_role,
            "department": department,
            "clearance": clearance,
            "all_roles": roles,
        },
    )

    return updated_user


def interactive_prompt():
    print("=" * 60)
    print("  Auth N&Z - User Promotion Utility (PostgreSQL)")
    print("=" * 60)

    identifier = input("Enter username or email of user to promote: ").strip()
    if not identifier:
        print("Aborted: identifier is required.")
        return

    print("\nSelect role:")
    print("  1) admin       - Standard administrator")
    print("  2) superadmin  - Full system superadmin")
    role_choice = input("Enter choice [1/2, default: 1]: ").strip()
    target_role = "superadmin" if role_choice == "2" else "admin"

    dept = input("Enter department [default: Security]: ").strip() or "Security"
    clearance_input = input("Enter clearance level (1-5) [default: 3]: ").strip()
    try:
        clearance = int(clearance_input) if clearance_input else 3
    except ValueError:
        clearance = 3

    print(f"\nPromoting '{identifier}' to {target_role} (Dept: {dept}, Clearance: {clearance})...")
    res = asyncio.run(promote_user_to_admin(
        identifier=identifier,
        role=target_role,
        department=dept,
        clearance=clearance,
    ))

    if res:
        print("\nSUCCESS! User updated successfully.")
        print(f"  User ID:    {res['id']}")
        print(f"  Username:   {res['username']}")
        print(f"  Email:      {res['email']}")
        print(f"  Roles:      {res.get('roles')}")
        print(f"  Metadata:   {res.get('metadata')}")
    else:
        print("\nFAILED: User could not be promoted.")


def main():
    parser = argparse.ArgumentParser(
        description="Promote an existing user to Administrator or Superadmin in PostgreSQL."
    )
    parser.add_argument(
        "-i", "--identifier",
        type=str,
        help="Username or email address of the user to promote.",
    )
    parser.add_argument(
        "--super",
        action="store_true",
        help="Shorthand flag to promote to 'superadmin' role.",
    )
    parser.add_argument(
        "-r", "--role",
        type=str,
        default="admin",
        help="Role to assign: 'admin' or 'superadmin' (default: admin).",
    )
    parser.add_argument(
        "-d", "--department",
        type=str,
        default="Security",
        help="Department metadata (default: Security).",
    )
    parser.add_argument(
        "-c", "--clearance",
        type=int,
        default=3,
        help="Security clearance level 1-5 (default: 3).",
    )

    args = parser.parse_args()

    if not args.identifier:
        interactive_prompt()
        return

    target_role = "superadmin" if args.super else args.role

    res = asyncio.run(promote_user_to_admin(
        identifier=args.identifier,
        role=target_role,
        department=args.department,
        clearance=args.clearance,
    ))

    if res:
        print(f"[SUCCESS] User '{args.identifier}' successfully promoted to '{target_role}'.")
        print(f"  ID:         {res['id']}")
        print(f"  Username:   {res['username']}")
        print(f"  Roles:      {res.get('roles')}")
        print(f"  Metadata:   {res.get('metadata')}")
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
