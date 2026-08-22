"""
Auth N&Z - User Promotion Utility (promote_admin.py)
---------------------------------------------------
Promotes an existing registered user account to Superadmin or Administrator role,
assigns security clearance, and records a structured audit event.

Usage (Interactive):
    python promote_admin.py

Usage (CLI Arguments):
    python promote_admin.py -i admin@l4s3r.site --super
    python promote_admin.py -i user@l4s3r.site --role superadmin --clearance 3 --department Security
"""

import argparse
import json
import sys
from typing import Optional

from user_repository import UserRepository
from audit_logger import AuditLogger


def promote_user_to_admin(
    identifier: str,
    db_file: str = "DATABASE.db",
    role: str = "admin",
    department: str = "Security",
    clearance: int = 3,
) -> Optional[dict]:
    """Promote an existing user to administrator or superadmin role with clearance level."""
    clean_id = identifier.strip()
    if not clean_id:
        print("Error: Identifier cannot be empty.", file=sys.stderr)
        return None

    # Normalize role
    clean_role = role.strip().lower()
    if clean_role in ("super-admin", "super_admin", "superadmin", "root"):
        target_role = "superadmin"
    else:
        target_role = clean_role

    repo = UserRepository(db_file=db_file)
    audit = AuditLogger(db_file=db_file)

    user = repo.get_by_identifier(clean_id)
    if not user:
        print(f"Error: No user found matching '{clean_id}'.", file=sys.stderr)
        return None

    # Parse existing roles
    roles = user.get("roles", [])
    if isinstance(roles, str):
        try:
            roles = json.loads(roles)
        except Exception:
            roles = []

    if target_role not in roles:
        roles.append(target_role)

    # Parse and update metadata
    metadata = user.get("metadata", {})
    if isinstance(metadata, str):
        try:
            metadata = json.loads(metadata)
        except Exception:
            metadata = {}

    metadata["department"] = department
    metadata["clearance"] = clearance

    success = repo.update_user(
        user["id"],
        {
            "roles": roles,
            "metadata": metadata,
            "is_active": 1,
        },
    )

    if not success:
        print("Error: Failed to update user record in database.", file=sys.stderr)
        return None

    # Record security audit event
    audit.record_security_event(
        event_name="ADMIN_ROLE_GRANTED",
        severity="INFO",
        details={
            "user_id": user["id"],
            "username": user["username"],
            "target_role": target_role,
            "roles": roles,
            "clearance": clearance,
            "source": "CLI_PROMOTE_SCRIPT",
        },
    )

    updated_user = repo.get_by_id(user["id"])
    return updated_user


def main():
    parser = argparse.ArgumentParser(
        description="Auth N&Z - Promote Existing User to Superadmin or Administrator"
    )
    parser.add_argument(
        "--identifier",
        "-i",
        type=str,
        help="Username or email address of the existing user",
    )
    parser.add_argument(
        "--role",
        "-r",
        type=str,
        default="admin",
        help="Role to assign: admin, superadmin, developer, editor, viewer (default: admin)",
    )
    parser.add_argument(
        "--super",
        "-s",
        action="store_true",
        help="Shorthand flag to promote directly to superadmin role",
    )
    parser.add_argument(
        "--db",
        type=str,
        default="DATABASE.db",
        help="Path to SQLite database file (default: DATABASE.db)",
    )
    parser.add_argument(
        "--department",
        "-d",
        type=str,
        default="Security",
        help="Department name to assign (default: Security)",
    )
    parser.add_argument(
        "--clearance",
        "-c",
        type=int,
        default=3,
        help="Security clearance level (default: 3)",
    )

    args = parser.parse_args()

    identifier = args.identifier
    if not identifier:
        print("--- Auth N&Z User Promotion Utility ---")
        identifier = input("Enter username or email of existing user: ").strip()

    target_role = "superadmin" if args.super else args.role

    result = promote_user_to_admin(
        identifier=identifier,
        db_file=args.db,
        role=target_role,
        department=args.department,
        clearance=args.clearance,
    )

    if result:
        print(f"\nUser successfully promoted with '{target_role}' clearance.")
        print(f"User ID:     {result['id']}")
        print(f"Username:    {result['username']}")
        print(f"Email:       {result['email']}")
        print(f"Roles:       {result['roles']}")
        print(f"Metadata:    {result['metadata']}")
        print(f"Active:      {bool(result['is_active'])}")
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
