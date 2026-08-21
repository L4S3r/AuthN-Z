"""
Auth N&Z - Admin Account Bootstrap Script (seed_admin.py)
---------------------------------------------------------
Interactive and CLI-argument utility for provisioning the root administrator
account directly on the server without exposing any HTTP endpoints.

Usage (Interactive):
    python seed_admin.py

Usage (Non-Interactive / Arguments):
    python seed_admin.py --username rootadmin --email admin@l4s3r.site --password "SuperSecretPass123!"
"""

import argparse
import getpass
import sys
from typing import Optional

from password_hasher import PasswordHasher
from user_repository import UserRepository
from audit_logger import AuditLogger


def create_admin_user(
    username: str,
    email: str,
    password: str,
    db_file: str = "DATABASE.db",
    department: str = "Security",
    clearance: int = 3,
) -> Optional[dict]:
    """Create a new root administrator account."""
    if len(username) < 3:
        print("Error: Username must be at least 3 characters long.", file=sys.stderr)
        return None

    if len(password) < 8:
        print("Error: Password must be at least 8 characters long.", file=sys.stderr)
        return None

    if "@" not in email or "." not in email:
        print("Error: Invalid email address format.", file=sys.stderr)
        return None

    repo = UserRepository(db_file=db_file)
    hasher = PasswordHasher()
    audit = AuditLogger(db_file=db_file)

    # Check for existing user
    existing_user = repo.get_by_identifier(username) or repo.get_by_identifier(email)
    if existing_user:
        print(
            f"Error: A user with username '{username}' or email '{email}' already exists.",
            file=sys.stderr,
        )
        return None

    hashed_password = hasher.hash(password)
    new_user = repo.create_user({
        "username": username,
        "email": email,
        "hashed_password": hashed_password,
        "roles": ["admin"],
        "metadata": {
            "department": department,
            "clearance": clearance,
        },
    })

    audit.record_security_event(
        event_name="ADMIN_BOOTSTRAPPED",
        severity="INFO",
        details={
            "user_id": new_user["id"],
            "username": new_user["username"],
            "source": "CLI_SEED_SCRIPT",
        },
    )

    return new_user


def main():
    parser = argparse.ArgumentParser(description="Auth N&Z Administrator Bootstrap Utility")
    parser.add_argument("--username", "-u", type=str, help="Admin username")
    parser.add_argument("--email", "-e", type=str, help="Admin email address")
    parser.add_argument("--password", "-p", type=str, help="Admin password (plain text)")
    parser.add_argument("--db", type=str, default="DATABASE.db", help="Path to SQLite database file")
    parser.add_argument("--department", type=str, default="Security", help="Admin department name")
    parser.add_argument("--clearance", type=int, default=3, help="Security clearance level (default 3)")

    args = parser.parse_args()

    username = args.username
    email = args.email
    password = args.password

    # Interactive mode if arguments are omitted
    if not (username and email and password):
        print("--- Auth N&Z Administrator Provisioning ---")
        if not username:
            username = input("Enter admin username: ").strip()
        if not email:
            email = input("Enter admin email: ").strip()
        if not password:
            password = getpass.getpass("Enter admin password (hidden): ")
            confirm_password = getpass.getpass("Confirm admin password: ")
            if password != confirm_password:
                print("Error: Passwords do not match.", file=sys.stderr)
                sys.exit(1)

    result = create_admin_user(
        username=username,
        email=email,
        password=password,
        db_file=args.db,
        department=args.department,
        clearance=args.clearance,
    )

    if result:
        print("\nAdmin account created successfully.")
        print(f"User ID:    {result['id']}")
        print(f"Username:   {result['username']}")
        print(f"Email:      {result['email']}")
        print(f"Roles:      {result['roles']}")
        print(f"Metadata:   {result['metadata']}")
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
