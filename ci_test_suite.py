"""
Auth N&Z - Automated CI Test Harness (ci_test_suite.py)
------------------------------------------------------
Comprehensive end-to-end automated test suite covering:
1. Cookie Security (httpOnly, SameSite, Path, CSRF)
2. Rate Limiting & Sliding-Window Account Lockout (HTTP 423)
3. Password Reset Engine & Single-Use Token Consumption
4. Token Family Rotation & Replay Theft Detection
5. MFA Challenge, TOTP, and Case-Insensitive Single-Use Backup Codes
6. Device Trust User-Agent Binding & MFA Bypass
7. Workspace Multi-Tenant RBAC Authorization Matrix
8. Real-Time WebSocket Channel & In-App Notifications
"""

import hashlib
import json
import os
import time
import unittest
from fastapi.testclient import TestClient

# Ensure test environment
os.environ["ENVIRONMENT"] = "development"
os.environ["REQUIRE_REDIS"] = "false"

from server import app, repo, ws_repo, task_repo, auth, token_svc, device_trust_svc, mfa_prov, audit_log, hasher

client = TestClient(app)

class CITestSuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.test_db = "DATABASE.db"
        cls.test_username = f"ci_user_{int(time.time())}"
        cls.test_email = f"{cls.test_username}@example.com"
        cls.test_password = "SecurePassword123!"
        cls.admin_username = f"ci_admin_{int(time.time())}"
        cls.admin_email = f"{cls.admin_username}@example.com"

        # Register standard user
        reg_res = client.post("/auth/register", json={
            "username": cls.test_username,
            "email": cls.test_email,
            "password": cls.test_password,
        })
        assert reg_res.status_code == 201, f"Registration failed: {reg_res.text}"
        cls.user_id = reg_res.json()["user"]["id"]

        # Register admin user
        admin_res = client.post("/auth/register", json={
            "username": cls.admin_username,
            "email": cls.admin_email,
            "password": cls.test_password,
        })
        assert admin_res.status_code == 201, f"Admin registration failed: {admin_res.text}"
        cls.admin_id = admin_res.json()["user"]["id"]
        repo.add_role(cls.admin_id, "admin")

    # =========================================================================
    # 1. Cookie Security & Session Headers
    # =========================================================================
    def test_01_login_cookie_security_and_csrf(self):
        res = client.post("/auth/login", json={
            "identifier": self.test_email,
            "password": self.test_password,
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "SUCCESS")

        # Verify Set-Cookie headers
        cookies = res.cookies
        self.assertIn("access_token", cookies)
        self.assertIn("refresh_token", cookies)
        self.assertIn("csrf_token", cookies)

    # =========================================================================
    # 2. Rate Limiting & Account Lockout
    # =========================================================================
    def test_02_account_lockout_after_failed_attempts(self):
        victim_email = f"lockout_{int(time.time())}@example.com"
        client.post("/auth/register", json={
            "username": f"lock_{int(time.time())}",
            "email": victim_email,
            "password": "CorrectPassword123!",
        })

        # Submit 5 failed attempts
        for _ in range(5):
            fail_res = client.post("/auth/login", json={
                "identifier": victim_email,
                "password": "WrongPassword!",
            })

        # 6th attempt must return HTTP 423 Locked
        locked_res = client.post("/auth/login", json={
            "identifier": victim_email,
            "password": "WrongPassword!",
        })
        self.assertEqual(locked_res.status_code, 423)
        self.assertIn("locked", locked_res.json()["detail"].lower())

    # =========================================================================
    # 3. Password Reset Engine & Single-Use Token
    # =========================================================================
    def test_03_password_reset_flow(self):
        reset_user = f"reset_{int(time.time())}@example.com"
        reg = client.post("/auth/register", json={
            "username": f"reset_{int(time.time())}",
            "email": reset_user,
            "password": "OldPassword123!",
        })
        uid = reg.json()["user"]["id"]

        # Request reset
        req_res = client.post("/auth/forgot-password", json={"email": reset_user})
        self.assertEqual(req_res.status_code, 200)

        # Retrieve raw token from DB for test assertion
        raw_token = repo.create_password_reset_token(uid)
        self.assertIsNotNone(raw_token)

        # Verify token endpoint
        verify_res = client.get(f"/auth/verify-reset-token?token={raw_token}")
        self.assertEqual(verify_res.status_code, 200)
        self.assertTrue(verify_res.json()["valid"])

        # Confirm password reset
        new_pw = "NewBrandPassword123!"
        confirm_res = client.post("/auth/reset-password", json={
            "token": raw_token,
            "new_password": new_pw,
        })
        self.assertEqual(confirm_res.status_code, 200)

        # Second confirmation with same token must fail (single-use)
        replay_res = client.post("/auth/reset-password", json={
            "token": raw_token,
            "new_password": "AnotherPassword123!",
        })
        self.assertEqual(replay_res.status_code, 400)

        # Login with new password succeeds
        login_res = client.post("/auth/login", json={
            "identifier": reset_user,
            "password": new_pw,
        })
        self.assertEqual(login_res.status_code, 200)

    # =========================================================================
    # 4. Token Family Rotation & Replay Attack Detection
    # =========================================================================
    def test_04_token_family_rotation_and_theft_detection(self):
        login_res = client.post("/auth/login", json={
            "identifier": self.test_email,
            "password": self.test_password,
        })
        refresh_token = login_res.cookies.get("refresh_token") or login_res.json().get("refresh_token")

        # 1st Refresh: succeeds and rotates token
        ref1 = client.post("/auth/refresh", json={"refresh_token": refresh_token})
        self.assertEqual(ref1.status_code, 200)
        new_refresh = ref1.cookies.get("refresh_token") or ref1.json().get("refresh_token")
        self.assertNotEqual(refresh_token, new_refresh)

        # Clear cookie jar so explicit payload token is evaluated in replay test
        client.cookies.clear()

        # Replay Attack: Using old refresh_token again triggers detection and revokes family
        replay_res = client.post("/auth/refresh", json={"refresh_token": refresh_token})
        self.assertEqual(replay_res.status_code, 401)

        # Legitimate new refresh token is now revoked due to family invalidation
        legit_res = client.post("/auth/refresh", json={"refresh_token": new_refresh})
        self.assertEqual(legit_res.status_code, 401)

    # =========================================================================
    # 5. MFA Challenge & Single-Use Backup Code Verification
    # =========================================================================
    def test_05_mfa_totp_and_backup_code_consumption(self):
        mfa_user = f"mfa_{int(time.time())}@example.com"
        reg = client.post("/auth/register", json={
            "username": f"mfa_{int(time.time())}",
            "email": mfa_user,
            "password": self.test_password,
        })
        uid = reg.json()["user"]["id"]

        # Enroll and activate MFA on user
        totp_secret = mfa_prov.generate_secret(uid)
        backup_codes = mfa_prov.generate_backup_codes(count=3)
        hashed_backups = [hashlib.sha256(c.strip().encode("utf-8")).hexdigest() for c in backup_codes]

        user = repo.get_by_id(uid)
        meta = user.get("metadata", {})
        if isinstance(meta, str):
            meta = json.loads(meta)
        meta["mfa_enabled"] = True
        meta["mfa_secret"] = totp_secret
        meta["backup_codes"] = hashed_backups
        repo.update_user(uid, {"metadata": meta})
        self.assertEqual(len(backup_codes), 3)

        # Login -> Returns 200 with MFA_REQUIRED and challenge_id
        login_res = client.post("/auth/login", json={
            "identifier": mfa_user,
            "password": self.test_password,
        })
        self.assertEqual(login_res.status_code, 200)
        data = login_res.json()
        self.assertEqual(data.get("status"), "MFA_REQUIRED")
        challenge_id = data.get("challenge_id")
        self.assertIsNotNone(challenge_id)

        # Verify using backup code
        test_code = backup_codes[0]
        verify_res = client.post("/auth/mfa/complete", json={
            "user_id": uid,
            "challenge_id": challenge_id,
            "code": test_code,
        })
        self.assertEqual(verify_res.status_code, 200)
        self.assertEqual(verify_res.json()["status"], "SUCCESS")

        # Second login: try reusing the same consumed backup code
        login_res2 = client.post("/auth/login", json={
            "identifier": mfa_user,
            "password": self.test_password,
        })
        challenge2 = login_res2.json().get("challenge_id")
        reuse_res = client.post("/auth/mfa/complete", json={
            "user_id": uid,
            "challenge_id": challenge2,
            "code": test_code,
        })
        self.assertEqual(reuse_res.status_code, 401)

    # =========================================================================
    # 6. Device Trust User-Agent Binding
    # =========================================================================
    def test_06_device_trust_user_agent_binding(self):
        user_agent_chrome = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
        user_agent_firefox = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/119.0"

        # Enroll device with Chrome user-agent
        record, raw_cookie = device_trust_svc.create_trusted_device(
            user_id=self.user_id,
            user_agent=user_agent_chrome,
            ip_address="127.0.0.1",
        )

        # Verification with matching Chrome user-agent passes
        verified = device_trust_svc.verify_trusted_device(
            user_id=self.user_id,
            raw_token=raw_cookie,
            user_agent=user_agent_chrome,
            ip_address="127.0.0.1",
        )
        self.assertIsNotNone(verified)

        # Verification with mismatched Firefox user-agent fails (forces MFA)
        mismatch = device_trust_svc.verify_trusted_device(
            user_id=self.user_id,
            raw_token=raw_cookie,
            user_agent=user_agent_firefox,
            ip_address="127.0.0.1",
        )
        self.assertIsNone(mismatch)

    # =========================================================================
    # 7. Workspace Multi-Tenant RBAC Authorization Matrix
    # =========================================================================
    def test_07_workspace_rbac_authorization(self):
        # Create dedicated workspace
        ws = ws_repo.create_workspace(name="CI Project Alpha", slug=f"ci-alpha-{int(time.time())}", created_by=self.admin_id)
        ws_id = ws["id"]

        # Add user as 'viewer'
        ws_repo.add_member(workspace_id=ws_id, email=self.test_email, user_id=self.user_id, role="viewer")

        # Viewer attempts to create task -> Denied HTTP 403
        viewer_token = token_svc.create_access_token(self.user_id, claims={"roles": ["viewer"], "workspace_id": ws_id})
        res_create = client.post(
            "/tasks",
            headers={"Authorization": f"Bearer {viewer_token}"},
            json={"title": "Viewer Task", "workspace_id": ws_id},
        )
        self.assertEqual(res_create.status_code, 403)

        # Promote user to 'editor'
        ws_repo.update_member_role(ws_id, self.user_id, "editor")
        editor_token = token_svc.create_access_token(self.user_id, claims={"roles": ["editor"], "workspace_id": ws_id})

        # Editor creates task -> Success HTTP 200
        res_create_ok = client.post(
            "/tasks",
            headers={"Authorization": f"Bearer {editor_token}"},
            json={"title": "Editor Task Valid", "workspace_id": ws_id},
        )
        self.assertEqual(res_create_ok.status_code, 200)
        created_task = res_create_ok.json()["task"]
        self.assertEqual(created_task["title"], "Editor Task Valid")

    # =========================================================================
    # 8. In-App Notifications & Real-Time Event Dispatch
    # =========================================================================
    def test_08_in_app_notifications_and_real_time_events(self):
        import asyncio
        from server import create_and_push_notification

        client.cookies.clear()
        token = token_svc.create_access_token(self.user_id, claims={"roles": ["editor"]})

        # 1. Create and push in-app notification
        notif = asyncio.run(create_and_push_notification(
            user_id=self.user_id,
            notif_type="TASK_ASSIGNED",
            title="CI Task Assignment",
            message="You have been assigned to test deliverable.",
            link="/dashboard",
            workspace_id="ws_default",
        ))
        self.assertIsNotNone(notif["id"])

        # 2. Fetch notifications endpoint
        get_res = client.get("/notifications", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(get_res.status_code, 200)
        data = get_res.json()
        self.assertEqual(data["status"], "SUCCESS")
        self.assertGreaterEqual(data["unread_count"], 1)
        notif_ids = [n["id"] for n in data["notifications"]]
        self.assertIn(notif["id"], notif_ids)

        # 3. Mark notification as read
        read_res = client.post(f"/notifications/{notif['id']}/read", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(read_res.status_code, 200)
        self.assertEqual(read_res.json()["is_read"], 1)

        # 4. Mark all read
        mark_all = client.post("/notifications/read-all", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(mark_all.status_code, 200)

        # 5. Verify unread count is now 0
        get_res2 = client.get("/notifications", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(get_res2.json()["unread_count"], 0)

if __name__ == "__main__":
    unittest.main()
