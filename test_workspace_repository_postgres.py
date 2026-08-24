"""
Standalone Verification Test Suite: PostgreSQL Async WorkspaceRepository
========================================================================
Exercises every method and edge case on WorkspaceRepository against the PostgreSQL database.
"""

import asyncio
import os
import sys
import uuid

from user_repository import UserRepository
from workspace_repository import WorkspaceRepository


async def run_acceptance_tests():
    print("=" * 75)
    print("  PostgreSQL Async WorkspaceRepository Test Suite")
    print("=" * 75)

    ws_repo = WorkspaceRepository()
    user_repo = UserRepository()
    test_suffix = uuid.uuid4().hex[:8]

    # Create a test creator user
    creator_username = f"creator_{test_suffix}"
    creator_email = f"creator_{test_suffix}@example.com"
    creator = await user_repo.create_user({
        "username": creator_username,
        "email": creator_email,
        "hashed_password": "hash",
        "roles": ["admin"],
        "metadata": {"name": "Test Creator", "department": "Executive"},
    })
    creator_id = creator["id"]

    # -------------------------------------------------------------------------
    # 1. create_workspace
    # -------------------------------------------------------------------------
    print("\n[1/7] Testing create_workspace...")
    ws = await ws_repo.create_workspace(
        name=f"Engineering Hub {test_suffix}",
        created_by=creator_id,
        slug=f"eng-hub-{test_suffix}",
        description="Main workspace for core engineering team",
    )
    assert ws is not None
    ws_id = ws["id"]
    assert ws["name"] == f"Engineering Hub {test_suffix}"
    assert ws["slug"] == f"eng-hub-{test_suffix}"
    assert ws["role"] == "admin"
    print(f"  ✓ Workspace created with ID: {ws_id} (Slug: /{ws['slug']})")

    # -------------------------------------------------------------------------
    # 2. get_workspace and get_workspace_by_slug
    # -------------------------------------------------------------------------
    print("\n[2/7] Testing get_workspace and get_workspace_by_slug...")
    by_id = await ws_repo.get_workspace(ws_id)
    assert by_id is not None and by_id["id"] == ws_id

    by_slug = await ws_repo.get_workspace_by_slug(f"eng-hub-{test_suffix}")
    assert by_slug is not None and by_slug["id"] == ws_id

    assert await ws_repo.get_workspace(str(uuid.uuid4())) is None
    assert await ws_repo.get_workspace("malformed-uuid") is None
    assert await ws_repo.get_workspace_by_slug("nonexistent-slug") is None
    print("  ✓ get_workspace lookups verified")

    # -------------------------------------------------------------------------
    # 3. list_workspaces_for_user and list_all_workspaces
    # -------------------------------------------------------------------------
    print("\n[3/7] Testing list_workspaces_for_user and list_all_workspaces...")
    user_ws = await ws_repo.list_workspaces_for_user(creator_id)
    assert any(w["id"] == ws_id for w in user_ws)

    all_ws = await ws_repo.list_all_workspaces()
    assert any(w["id"] == ws_id for w in all_ws)
    print("  ✓ Workspace listing and membership scoping verified")

    # -------------------------------------------------------------------------
    # 4. update_workspace & Slug Collision Handling
    # -------------------------------------------------------------------------
    print("\n[4/7] Testing update_workspace & slug collisions...")
    updated_ws = await ws_repo.update_workspace(ws_id, {
        "name": f"Core Engineering Hub {test_suffix}",
        "description": "Updated description",
    })
    assert updated_ws["name"] == f"Core Engineering Hub {test_suffix}"
    assert updated_ws["description"] == "Updated description"

    # Create a second workspace to test collision
    ws2 = await ws_repo.create_workspace(
        name=f"Second Workspace {test_suffix}",
        created_by=creator_id,
        slug=f"second-ws-{test_suffix}",
    )
    ws2_id = ws2["id"]

    collision_caught = False
    try:
        # Attempt to rename ws2's slug to ws1's slug
        await ws_repo.update_workspace(ws2_id, {"slug": f"eng-hub-{test_suffix}"})
    except ValueError as e:
        collision_caught = True
        print(f"  ✓ Caught expected slug collision ValueError: {e}")
    assert collision_caught, "Must raise ValueError on duplicate workspace slug"

    # Clean up ws2
    await ws_repo.delete_workspace(ws2_id)

    # -------------------------------------------------------------------------
    # 5. Memberships & ON CONFLICT DO UPDATE (Invite Same Email Twice)
    # -------------------------------------------------------------------------
    print("\n[5/7] Testing invite_member with ON CONFLICT DO UPDATE (invite same email twice)...")
    invite_email = f"developer_{test_suffix}@example.com"

    # First invite
    inv1 = await ws_repo.invite_member(
        workspace_id=ws_id,
        email=invite_email,
        name="Junior Dev",
        role="viewer",
        department="Frontend",
        invited_by="admin",
        expires_days=7,
    )
    assert inv1["email"] == invite_email
    assert inv1["role"] == "viewer"
    token1 = inv1["invite_token"]
    print(f"  ✓ Initial workspace invitation created (Token: {token1[:16]}...)")

    # Re-invite the same email to the same workspace with updated role/dept
    inv2 = await ws_repo.invite_member(
        workspace_id=ws_id,
        email=invite_email,
        name="Senior Dev",
        role="developer",
        department="Backend",
        invited_by="techlead",
        expires_days=14,
    )
    assert inv2["email"] == invite_email
    assert inv2["role"] == "developer"
    assert inv2["name"] == "Senior Dev"
    token2 = inv2["invite_token"]
    print("  ✓ Re-invited same email to same workspace without error (ON CONFLICT DO UPDATE)")

    # Resolve invitation by token
    inv_check = await ws_repo.get_invitation_by_token(token2)
    assert inv_check is not None
    assert inv_check["workspace_id"] == ws_id
    assert inv_check["role"] == "developer"

    # Accept invitation
    member_user = await user_repo.create_user({
        "username": f"devuser_{test_suffix}",
        "email": invite_email,
        "hashed_password": "hash",
        "roles": ["developer"],
        "metadata": {"name": "Senior Dev", "department": "Backend"},
    })
    member_user_id = member_user["id"]

    accepted = await ws_repo.accept_invitation(token2, user_id=member_user_id)
    assert accepted is not None
    assert accepted["status"] == "active"
    assert accepted["user_id"] == member_user_id
    print("  ✓ Invitation accepted and linked to user account")

    # -------------------------------------------------------------------------
    # 6. Member Management & Counts
    # -------------------------------------------------------------------------
    print("\n[6/7] Testing member management, role updates, and counts...")
    # List members
    members = await ws_repo.list_members(ws_id)
    assert len(members) >= 2
    assert any(m["email"] == invite_email for m in members)

    # Get member
    m_record = await ws_repo.get_member(ws_id, email=invite_email)
    assert m_record is not None and m_record["email"] == invite_email

    # Update role
    role_updated = await ws_repo.update_member_role(ws_id, invite_email, "editor")
    assert role_updated is True
    m_record_after = await ws_repo.get_member(ws_id, email=invite_email)
    assert m_record_after["role"] == "editor"

    # Member counts
    counts = await ws_repo.count_members(ws_id)
    assert counts["total"] >= 2
    assert counts["active"] >= 2
    print(f"  ✓ Member counts breakdown verified: {counts}")

    # Remove member
    removed = await ws_repo.remove_member(ws_id, invite_email)
    assert removed is True
    assert await ws_repo.get_member(ws_id, email=invite_email) is None
    print("  ✓ remove_member verified")

    # -------------------------------------------------------------------------
    # 7. delete_workspace and Cascade Cleanup
    # -------------------------------------------------------------------------
    print("\n[7/7] Testing delete_workspace and cascade cleanup...")
    deleted = await ws_repo.delete_workspace(ws_id)
    assert deleted is True, "delete_workspace must return True"
    assert await ws_repo.get_workspace(ws_id) is None
    assert await ws_repo.get_workspace_by_slug(f"eng-hub-{test_suffix}") is None

    # Clean up test users
    await user_repo.delete_user(creator_id)
    await user_repo.delete_user(member_user_id)
    print("  ✓ Workspace and cascaded resources deleted successfully")

    print("\n" + "=" * 75)
    print("  ALL WORKSPACE REPOSITORY TESTS PASSED WITH 100% SUCCESS!")
    print("=" * 75 + "\n")


if __name__ == "__main__":
    asyncio.run(run_acceptance_tests())
