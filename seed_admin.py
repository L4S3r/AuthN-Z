"""
Auth N&Z - Admin Account Bootstrap Script (seed_admin.py) (PostgreSQL Async)
----------------------------------------------------------------------------
Interactive and CLI-argument utility for provisioning the root administrator
account directly in PostgreSQL without exposing any HTTP endpoints.

Usage (Interactive):
    python seed_admin.py

Usage (Non-Interactive / Arguments):
    python seed_admin.py --username rootadmin --email admin@l4s3r.site --password "SuperSecretPass123!"
"""

import argparse
import asyncio
import getpass
import sys
from typing import Optional
from dotenv import load_dotenv

load_dotenv()

from password_hasher import PasswordHasher
from user_repository import UserRepository
from audit_logger import AuditLogger


async def create_admin_user(
    username: str,
    email: str,
    password: str,
    department: str = "Security",
    clearance: int = 3,
) -> Optional[dict]:
    """Create a new root administrator account in PostgreSQL."""
    if len(username) < 3:
        print("Error: Username must be at least 3 characters long.", file=sys.stderr)
        return None

    if len(password) < 8:
        print("Error: Password must be at least 8 characters long.", file=sys.stderr)
        return None

    if "@" not in email or "." not in email:
        print("Error: Invalid email address format.", file=sys.stderr)
        return None

    repo = UserRepository()
    hasher = PasswordHasher()
    audit = AuditLogger()

    # Check for existing user
    existing_user = await repo.get_by_identifier(username) or await repo.get_by_identifier(email)
    if existing_user:
        print(
            f"Error: A user with username '{username}' or email '{email}' already exists.",
            file=sys.stderr,
        )
        return None

    hashed_password = hasher.hash(password)
    new_user = await repo.create_user({
        "username": username,
        "email": email,
        "hashed_password": hashed_password,
        "roles": ["superadmin", "admin"],
        "metadata": {
            "department": department,
            "clearance": clearance,
        },
    })

    # Log security audit event
    await audit.record_security_event(
        event_name="ADMIN_BOOTSTRAP_CREATED",
        severity="WARNING",
        details={
            "user_id": new_user["id"],
            "username": new_user["username"],
            "email": new_user["email"],
            "method": "cli_seed_script",
            "department": department,
            "clearance": clearance,
        },
    )

    return new_user


def interactive_prompt():
    print("=" * 60)
    print("  Auth N&Z - Admin Provisioning Utility (PostgreSQL)")
    print("=" * 60)

    username = input("Enter admin username [default: rootadmin]: ").strip() or "rootadmin"
    email = input("Enter admin email [default: admin@l4s3r.site]: ").strip() or "admin@l4s3r.site"

    while True:
        password = getpass.getpass("Enter strong admin password: ")
        if len(password) < 8:
            print("Password must be at least 8 characters long. Try again.\n")
            continue
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("Passwords do not match. Try again.\n")
            continue
        break

    dept = input("Enter department [default: Security]: ").strip() or "Security"
    clearance_input = input("Enter clearance level (1-5) [default: 3]: ").strip()
    try:
        clearance = int(clearance_input) if clearance_input else 3
    except ValueError:
        clearance = 3

    print("\nCreating administrator account in PostgreSQL...")
    user = asyncio.run(create_admin_user(
        username=username,
        email=email,
        password=password,
        department=dept,
        clearance=clearance,
    ))

    if user:
        print("\nSUCCESS! Admin account created successfully.")
        print(f"  User ID:    {user['id']}")
        print(f"  Username:   {user['username']}")
        print(f"  Email:      {user['email']}")
        print(f"  Roles:      {user['roles']}")
        print(f"  Department: {user['metadata'].get('department')}")
        print(f"  Clearance:  {user['metadata'].get('clearance')}")
    else:
        print("\nFAILED: Admin account creation was unsuccessful.")


def main():
    parser = argparse.ArgumentParser(description="Provision root administrator account in PostgreSQL.")
    parser.add_argument("--username", type=str, help="Administrator username")
    parser.add_argument("--email", type=str, help="Administrator email address")
    parser.add_argument("--password", type=str, help="Administrator password")
    parser.add_argument("--department", type=str, default="Security", help="Department metadata")
    parser.add_argument("--clearance", type=int, default=3, help="Clearance level (1-5)")

    args = parser.parse_args()

    if args.username and args.email and args.password:
        user = asyncio.run(create_admin_user(
            username=args.username,
            email=args.email,
            password=args.password,
            department=args.department,
            clearance=args.clearance,
        ))
        if user:
            print(f"[SUCCESS] Admin account '{user['username']}' provisioned successfully (ID: {user['id']}).")
        else:
            sys.exit(1)
    else:
        interactive_prompt()


if __name__ == "__main__":
    main()
