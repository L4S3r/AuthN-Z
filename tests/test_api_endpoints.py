"""
FastAPI REST API & Gateway End-to-End Tests (tests/test_api_endpoints.py)
"""

import uuid
import pytest
import pyotp
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_full_api_auth_and_workspace_lifecycle(async_client: AsyncClient):
    suffix = uuid.uuid4().hex[:8]
    username = f"ci_user_{suffix}"
    email = f"ci_user_{suffix}@example.com"
    password = "CIPassword123!"
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0.0.0 Safari/537.36"

    # 1. Register
    reg_res = await async_client.post("/auth/register", json={
        "username": username,
        "email": email,
        "password": password,
    })
    assert reg_res.status_code in (200, 201), reg_res.text
    user_id = reg_res.json()["user"]["id"]

    # 2. Login
    login_res = await async_client.post(
        "/auth/login",
        json={"identifier": email, "password": password},
        headers={"User-Agent": ua},
    )
    assert login_res.status_code == 200, login_res.text
    login_data = login_res.json()
    assert login_data["status"] == "SUCCESS"
    token = login_data["access_token"]
    auth_headers = {"Authorization": f"Bearer {token}", "User-Agent": ua}

    # 3. GET /auth/me
    me_res = await async_client.get("/auth/me", headers=auth_headers)
    assert me_res.status_code == 200, me_res.text
    assert me_res.json()["email"] == email

    # 4. MFA Setup & Complete
    setup_res = await async_client.post("/auth/mfa/setup", headers=auth_headers)
    assert setup_res.status_code == 200, setup_res.text
    mfa_secret = setup_res.json()["secret"]
    totp = pyotp.TOTP(mfa_secret)

    enable_res = await async_client.post(
        "/auth/mfa/verify-setup",
        json={"code": totp.now()},
        headers=auth_headers,
    )
    assert enable_res.status_code == 200, enable_res.text

    # Login triggers MFA challenge
    mfa_login_res = await async_client.post(
        "/auth/login",
        json={"identifier": email, "password": password},
        headers={"User-Agent": ua},
    )
    assert mfa_login_res.status_code == 200
    mfa_json = mfa_login_res.json()
    assert mfa_json["status"] == "MFA_REQUIRED"
    challenge_id = mfa_json["challenge_id"]

    # Complete MFA challenge
    complete_res = await async_client.post(
        "/auth/mfa/complete",
        json={
            "user_id": user_id,
            "challenge_id": challenge_id,
            "code": totp.now(),
            "remember_device": True,
        },
        headers={"User-Agent": ua},
    )
    assert complete_res.status_code == 200, complete_res.text
    complete_data = complete_res.json()
    assert complete_data["status"] == "SUCCESS"
    token = complete_data["access_token"]
    auth_headers["Authorization"] = f"Bearer {token}"

    # 5. Create Workspace
    create_ws_res = await async_client.post(
        "/workspaces",
        json={
            "name": f"CI Workspace {suffix}",
            "slug": f"ci-ws-{suffix}",
            "description": "Continuous Integration Test Workspace",
        },
        headers=auth_headers,
    )
    assert create_ws_res.status_code in (200, 201), create_ws_res.text
    ws_obj = create_ws_res.json().get("workspace", create_ws_res.json())
    ws_id = ws_obj["id"]

    # 6. Switch Workspace
    switch_res = await async_client.post(
        "/auth/workspaces/switch",
        json={"workspace_id": ws_id},
        headers=auth_headers,
    )
    assert switch_res.status_code == 200, switch_res.text
    switch_data = switch_res.json()
    assert switch_data["active_workspace"]["id"] == ws_id
    if "access_token" in switch_data:
        auth_headers["Authorization"] = f"Bearer {switch_data['access_token']}"

    # 7. Create, Update, Delete Task
    task_res = await async_client.post(
        "/tasks",
        json={
            "title": f"CI Task {suffix}",
            "priority": "high",
            "workspace_id": ws_id,
            "tags": ["ci", "pytest"],
        },
        headers=auth_headers,
    )
    assert task_res.status_code in (200, 201), task_res.text
    task_obj = task_res.json().get("task", task_res.json())
    task_id = task_obj["id"]

    patch_res = await async_client.patch(
        f"/tasks/{task_id}",
        json={"status": "in_progress"},
        headers=auth_headers,
    )
    assert patch_res.status_code == 200, patch_res.text

    del_res = await async_client.delete(f"/tasks/{task_id}", headers=auth_headers)
    assert del_res.status_code == 200, del_res.text
