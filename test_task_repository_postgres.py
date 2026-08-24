"""
Standalone Verification Test Suite: PostgreSQL Async TaskRepository
===================================================================
Exercises every method and edge case on TaskRepository against the PostgreSQL database.
"""

import asyncio
import os
import sys
import uuid

from task_repository import TaskRepository


async def run_acceptance_tests():
    print("=" * 75)
    print("  PostgreSQL Async TaskRepository Test Suite")
    print("=" * 75)

    repo = TaskRepository()
    test_suffix = uuid.uuid4().hex[:8]

    # -------------------------------------------------------------------------
    # 1. create_task
    # -------------------------------------------------------------------------
    print("\n[1/6] Testing create_task...")
    task = await repo.create_task({
        "title": f"Deploy auth service {test_suffix}",
        "description": "Ensure PostgreSQL migration is complete",
        "status": "todo",
        "priority": "high",
        "assignee_email": f"dev_{test_suffix}@example.com",
        "assignee_name": "Dev User",
        "tags": ["backend", "postgres", "security"],
        "due_date": "2026-08-30",
        "created_by": "admin",
    })

    assert task is not None, "Created task must not be None"
    task_id = task["id"]
    assert task["title"] == f"Deploy auth service {test_suffix}"
    assert task["status"] == "todo"
    assert task["priority"] == "high"
    assert task["assignee_email"] == f"dev_{test_suffix}@example.com"
    assert task["tags"] == ["backend", "postgres", "security"]
    assert len(task["assignees"]) == 1
    assert task["assignees"][0]["email"] == f"dev_{test_suffix}@example.com"
    print(f"  ✓ Task created successfully with ID: {task_id}")

    # -------------------------------------------------------------------------
    # 2. get_task & list_tasks
    # -------------------------------------------------------------------------
    print("\n[2/6] Testing get_task and list_tasks...")
    fetched = await repo.get_task(task_id)
    assert fetched is not None and fetched["id"] == task_id
    assert await repo.get_task(str(uuid.uuid4())) is None, "Random UUID should return None"
    assert await repo.get_task("invalid-task-id") is None, "Malformed UUID should return None safely"
    assert await repo.get_task("") is None

    # Filtering in list_tasks
    all_tasks = await repo.list_tasks()
    assert any(t["id"] == task_id for t in all_tasks)

    high_tasks = await repo.list_tasks(priority="high")
    assert any(t["id"] == task_id for t in high_tasks)

    email_tasks = await repo.list_tasks(assignee_email=f"dev_{test_suffix}@example.com")
    assert any(t["id"] == task_id for t in email_tasks)

    todo_tasks = await repo.list_tasks(status="todo")
    assert any(t["id"] == task_id for t in todo_tasks)
    print("  ✓ get_task and list_tasks filtering verified")

    # -------------------------------------------------------------------------
    # 3. update_task
    # -------------------------------------------------------------------------
    print("\n[3/6] Testing update_task...")
    updated = await repo.update_task(task_id, {
        "status": "in_progress",
        "priority": "urgent",
        "tags": ["backend", "in-review"],
    })
    assert updated is not None
    assert updated["status"] == "in_progress"
    assert updated["priority"] == "urgent"
    assert updated["tags"] == ["backend", "in-review"]

    refetched = await repo.get_task(task_id)
    assert refetched["status"] == "in_progress"
    assert refetched["priority"] == "urgent"

    # Non-existent task update
    assert await repo.update_task(str(uuid.uuid4()), {"status": "done"}) is None
    assert await repo.update_task("bad-uuid", {"status": "done"}) is None
    print("  ✓ Task update operations verified")

    # -------------------------------------------------------------------------
    # 4. Team Member Invitations & ON CONFLICT DO UPDATE
    # -------------------------------------------------------------------------
    print("\n[4/6] Testing team invitations and ON CONFLICT DO UPDATE...")
    invite_email = f"member_{test_suffix}@example.com"

    # First invite
    inv1 = await repo.invite_member(
        email=invite_email,
        name="Team Member One",
        role="viewer",
        department="QA",
        invited_by="admin",
        expires_days=7,
    )
    assert inv1["email"] == invite_email
    assert inv1["status"] == "invited"
    assert inv1["role"] == "viewer"
    token1 = inv1["invite_token"]
    print(f"  ✓ Initial invitation created for {invite_email}")

    # Re-inviting SAME email with updated role/dept (triggers ON CONFLICT DO UPDATE)
    inv2 = await repo.invite_member(
        email=invite_email,
        name="Team Member Promoted",
        role="editor",
        department="Engineering",
        invited_by="superadmin",
        expires_days=14,
    )
    assert inv2["email"] == invite_email
    assert inv2["role"] == "editor"
    assert inv2["name"] == "Team Member Promoted"
    token2 = inv2["invite_token"]
    assert token2 != token1, "New invitation token should be generated on re-invite"
    print("  ✓ ON CONFLICT DO UPDATE re-invite executed seamlessly")

    # Resolve invitation by token
    inv_check = await repo.get_invitation_by_token(token2)
    assert inv_check is not None
    assert inv_check["email"] == invite_email
    assert inv_check["role"] == "editor"
    assert inv_check["is_expired"] is False

    # Accept invitation
    accepted = await repo.accept_invitation(token2)
    assert accepted is True, "accept_invitation must return True"

    # Token is now consumed
    assert await repo.get_invitation_by_token(token2) is None, "Consumed token should no longer resolve"

    # List team members
    team = await repo.list_team_members()
    assert any(m["email"] == invite_email and m["status"] == "active" for m in team)
    print("  ✓ Invitation verification and acceptance verified")

    # Remove member
    removed = await repo.remove_member(invite_email)
    assert removed is True
    team_after = await repo.list_team_members()
    assert not any(m["email"] == invite_email for m in team_after)
    print("  ✓ remove_member verified")

    # -------------------------------------------------------------------------
    # 5. delete_task
    # -------------------------------------------------------------------------
    print("\n[5/6] Testing delete_task...")
    deleted = await repo.delete_task(task_id)
    assert deleted is True, "delete_task should return True"
    assert await repo.get_task(task_id) is None, "Deleted task must return None"
    assert await repo.delete_task(str(uuid.uuid4())) is False
    assert await repo.delete_task("bad-uuid") is False
    print("  ✓ delete_task verified")

    print("\n" + "=" * 75)
    print("  ALL TASK REPOSITORY TESTS PASSED WITH 100% SUCCESS!")
    print("=" * 75 + "\n")


if __name__ == "__main__":
    asyncio.run(run_acceptance_tests())
