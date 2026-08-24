"""
Standalone Verification Test Suite: PostgreSQL Async UserRepository
===================================================================
Exercises every method and edge case on UserRepository against the PostgreSQL database.
"""

import asyncio
import os
import sys
import uuid

from user_repository import UserRepository


async def run_acceptance_tests():
    print("=" * 75)
    print("  PostgreSQL Async UserRepository Test Suite")
    print("=" * 75)

    repo = UserRepository()

    # Generate isolated test user data
    uid_suffix = uuid.uuid4().hex[:8]
    test_username = f"testuser_{uid_suffix}"
    test_email = f"test_{uid_suffix}@example.com"
    test_password_hash = "fake_argon2_hash_for_testing"

    # -------------------------------------------------------------------------
    # 1. create_user
    # -------------------------------------------------------------------------
    print("\n[1/10] Testing create_user...")
    user = await repo.create_user({
        "username": test_username,
        "email": test_email,
        "hashed_password": test_password_hash,
        "roles": ["developer"],
        "metadata": {"department": "Engineering", "theme": "dark"},
    })

    assert user is not None, "Created user must not be None"
    assert user["username"] == test_username, f"Username mismatch: {user['username']}"
    assert user["email"] == test_email, f"Email mismatch: {user['email']}"
    assert user["is_active"] == 1, f"is_active mismatch: {user['is_active']}"
    assert user["roles"] == ["developer"], f"Roles mismatch: {user['roles']}"
    assert user["metadata"]["department"] == "Engineering"
    user_id = user["id"]
    print(f"  ✓ User created successfully with ID: {user_id}")

    # -------------------------------------------------------------------------
    # 2. Duplicate constraint errors on create_user
    # -------------------------------------------------------------------------
    print("\n[2/10] Testing duplicate constraint handling (ValueError)...")
    duplicate_email_failed = False
    try:
        await repo.create_user({
            "username": f"another_{uid_suffix}",
            "email": test_email,  # duplicate email
            "hashed_password": "hash",
        })
    except ValueError as e:
        duplicate_email_failed = True
        print(f"  ✓ Caught expected duplicate email ValueError: {e}")
    assert duplicate_email_failed, "Must raise ValueError on duplicate email"

    duplicate_username_failed = False
    try:
        await repo.create_user({
            "username": test_username,  # duplicate username
            "email": f"unique_{uid_suffix}@example.com",
            "hashed_password": "hash",
        })
    except ValueError as e:
        duplicate_username_failed = True
        print(f"  ✓ Caught expected duplicate username ValueError: {e}")
    assert duplicate_username_failed, "Must raise ValueError on duplicate username"

    # -------------------------------------------------------------------------
    # 3. get_by_id and get_by_identifier
    # -------------------------------------------------------------------------
    print("\n[3/10] Testing get_by_id and get_by_identifier...")
    fetched_by_id = await repo.get_by_id(user_id)
    assert fetched_by_id is not None and fetched_by_id["id"] == user_id
    print(f"  ✓ get_by_id returned user: {fetched_by_id['username']}")

    # Non-existent and malformed UUID tests
    assert await repo.get_by_id(str(uuid.uuid4())) is None, "Random UUID should return None"
    assert await repo.get_by_id("malformed-uuid-string") is None, "Malformed UUID should return None safely"
    assert await repo.get_by_id("") is None, "Empty user_id should return None"

    # Case-insensitive identifier lookups
    fetched_by_uname = await repo.get_by_identifier(test_username.upper())
    assert fetched_by_uname is not None and fetched_by_uname["id"] == user_id
    fetched_by_em = await repo.get_by_identifier(test_email.upper())
    assert fetched_by_em is not None and fetched_by_em["id"] == user_id
    assert await repo.get_by_identifier("non_existent_identity") is None
    print("  ✓ Case-insensitive get_by_identifier lookups verified")

    # -------------------------------------------------------------------------
    # 4. update_user
    # -------------------------------------------------------------------------
    print("\n[4/10] Testing update_user...")
    updated = await repo.update_user(user_id, {
        "metadata": {"department": "Security", "clearance": 3},
    })
    assert updated is True, "update_user should return True"
    refetched = await repo.get_by_id(user_id)
    assert refetched["metadata"]["department"] == "Security"
    assert refetched["metadata"]["clearance"] == 3
    print("  ✓ User metadata updated and verified")

    # -------------------------------------------------------------------------
    # 5. Role Management (get_roles, add_role, remove_role)
    # -------------------------------------------------------------------------
    print("\n[5/10] Testing role management (get_roles, add_role, remove_role)...")
    roles = await repo.get_roles(user_id)
    assert "developer" in roles

    await repo.add_role(user_id, "admin")
    roles_after_add = await repo.get_roles(user_id)
    assert "admin" in roles_after_add and "developer" in roles_after_add
    print(f"  ✓ Added role: {roles_after_add}")

    # Idempotent add
    await repo.add_role(user_id, "admin")
    roles_idempotent = await repo.get_roles(user_id)
    assert roles_idempotent.count("admin") == 1, "Duplicate role should not be added"

    # Remove role
    await repo.remove_role(user_id, "developer")
    roles_after_remove = await repo.get_roles(user_id)
    assert "developer" not in roles_after_remove and "admin" in roles_after_remove
    print(f"  ✓ Removed role: {roles_after_remove}")

    # -------------------------------------------------------------------------
    # 6. set_status and list_users
    # -------------------------------------------------------------------------
    print("\n[6/10] Testing set_status and list_users...")
    await repo.set_status(user_id, False)
    deactivated = await repo.get_by_id(user_id)
    assert deactivated["is_active"] == 0, "User should be inactive"

    inactive_list = await repo.list_users(is_active=False)
    assert any(u["id"] == user_id for u in inactive_list)

    # Reactivate
    await repo.set_status(user_id, True)
    reactivated = await repo.get_by_id(user_id)
    assert reactivated["is_active"] == 1, "User should be active"

    admin_users = await repo.list_users(role="admin")
    assert any(u["id"] == user_id for u in admin_users)
    print("  ✓ Status toggling and user filtering verified")

    # -------------------------------------------------------------------------
    # 7. Password Reset Token Lifecycle
    # -------------------------------------------------------------------------
    print("\n[7/10] Testing password reset token lifecycle...")
    token1 = await repo.create_password_reset_token(user_id, ip_address="127.0.0.1", expires_in_minutes=15)
    assert token1 is not None and len(token1) > 20

    # Verify token
    verified1 = await repo.verify_password_reset_token(token1)
    assert verified1 is not None
    assert verified1["user_id"] == user_id
    assert verified1["username"] == test_username
    print("  ✓ Token created and verified")

    # Creating a second token invalidates the first
    token2 = await repo.create_password_reset_token(user_id, ip_address="127.0.0.1", expires_in_minutes=15)
    verified1_again = await repo.verify_password_reset_token(token1)
    assert verified1_again is None, "Prior unused token must be invalidated when a new token is issued"
    verified2 = await repo.verify_password_reset_token(token2)
    assert verified2 is not None and verified2["user_id"] == user_id
    print("  ✓ Prior token auto-invalidation verified")

    # Consume token
    new_password_hash = "newly_updated_argon2_hash"
    consumed_uid = await repo.consume_password_reset_token(token2, new_password_hash)
    assert consumed_uid == user_id, "consume_password_reset_token should return user_id"

    # Token cannot be consumed twice
    consumed_again = await repo.consume_password_reset_token(token2, "another_hash")
    assert consumed_again is None, "Already consumed token cannot be reused"

    # Verify password was updated in DB
    user_after_reset = await repo.get_by_id(user_id)
    assert user_after_reset["hashed_password"] == new_password_hash
    print("  ✓ Token consumption and password update verified")

    # -------------------------------------------------------------------------
    # 8. delete_user
    # -------------------------------------------------------------------------
    print("\n[8/10] Testing delete_user and cascade cleanup...")
    deleted = await repo.delete_user(user_id)
    assert deleted is True, "delete_user should return True"
    assert await repo.get_by_id(user_id) is None, "Deleted user should return None"
    assert await repo.get_by_identifier(test_username) is None
    print("  ✓ User deleted and confirmed absent")

    print("\n" + "=" * 75)
    print("  ALL TESTS PASSED WITH 100% SUCCESS!")
    print("=" * 75 + "\n")


if __name__ == "__main__":
    asyncio.run(run_acceptance_tests())
