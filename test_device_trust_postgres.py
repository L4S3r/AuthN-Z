"""
Standalone Verification Test Suite: PostgreSQL Async DeviceTrustService
=======================================================================
Exercises every method and security edge case on DeviceTrustService against the PostgreSQL database.
"""

import asyncio
import os
import sys
import uuid

from device_trust_service import DeviceTrustService, parse_device_label
from user_repository import UserRepository


async def run_acceptance_tests():
    print("=" * 75)
    print("  PostgreSQL Async DeviceTrustService Test Suite")
    print("=" * 75)

    user_repo = UserRepository()
    trust_service = DeviceTrustService()
    test_suffix = uuid.uuid4().hex[:8]

    # Create a test user
    user = await user_repo.create_user({
        "username": f"deviceuser_{test_suffix}",
        "email": f"deviceuser_{test_suffix}@example.com",
        "hashed_password": "hash",
        "roles": ["developer"],
        "metadata": {"name": "Device User"},
    })
    user_id = user["id"]

    chrome_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    firefox_ua = "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0"

    # -------------------------------------------------------------------------
    # 1. create_trusted_device
    # -------------------------------------------------------------------------
    print("\n[1/6] Testing create_trusted_device & UA parsing...")
    label = parse_device_label(chrome_ua)
    assert label == "Google Chrome on Windows"

    device_rec, raw_token = await trust_service.create_trusted_device(
        user_id=user_id,
        user_agent=chrome_ua,
        ip_address="10.0.0.1",
        days_valid=30,
    )
    assert device_rec is not None
    assert device_rec["device_label"] == "Google Chrome on Windows"
    assert device_rec["user_id"] == user_id
    device_id = device_rec["id"]
    print(f"  ✓ Trusted device created with ID: {device_id} (Label: {device_rec['device_label']})")

    # -------------------------------------------------------------------------
    # 2. verify_trusted_device (Happy Path & UA Binding)
    # -------------------------------------------------------------------------
    print("\n[2/6] Testing verify_trusted_device and browser fingerprint binding...")
    # Matching User-Agent
    verified = await trust_service.verify_trusted_device(
        user_id=user_id,
        raw_token=raw_token,
        user_agent=chrome_ua,
        ip_address="10.0.0.2",
    )
    assert verified is not None
    assert verified["id"] == device_id
    assert verified["ip_address"] == "10.0.0.2"
    print("  ✓ Verification successful with matching User-Agent")

    # Mismatched User-Agent (hijacking attempt)
    hijack_attempt = await trust_service.verify_trusted_device(
        user_id=user_id,
        raw_token=raw_token,
        user_agent=firefox_ua,  # Different browser/OS
    )
    assert hijack_attempt is None, "Mismatched User-Agent must be rejected"
    print("  ✓ Fingerprint mismatch correctly rejected")

    # Invalid token
    invalid_check = await trust_service.verify_trusted_device(
        user_id=user_id,
        raw_token="invalid_raw_token_xyz",
        user_agent=chrome_ua,
    )
    assert invalid_check is None
    print("  ✓ Invalid token correctly rejected")

    # -------------------------------------------------------------------------
    # 3. list_trusted_devices & Current Device Tagging
    # -------------------------------------------------------------------------
    print("\n[3/6] Testing list_trusted_devices & current device indicator...")
    # Create second device
    dev2_rec, dev2_token = await trust_service.create_trusted_device(
        user_id=user_id,
        user_agent=firefox_ua,
        ip_address="192.168.1.100",
        days_valid=15,
    )
    dev2_id = dev2_rec["id"]

    devices = await trust_service.list_trusted_devices(user_id, current_token=raw_token)
    assert len(devices) == 2

    # Check current device flag
    d1 = next(d for d in devices if d["id"] == device_id)
    d2 = next(d for d in devices if d["id"] == dev2_id)
    assert d1["is_current_device"] is True
    assert d2["is_current_device"] is False
    print("  ✓ list_trusted_devices and is_current_device flags verified")

    # -------------------------------------------------------------------------
    # 4. revoke_trusted_device
    # -------------------------------------------------------------------------
    print("\n[4/6] Testing revoke_trusted_device...")
    revoked = await trust_service.revoke_trusted_device(user_id, dev2_id)
    assert revoked is True
    devices_after_revoke = await trust_service.list_trusted_devices(user_id)
    assert len(devices_after_revoke) == 1
    assert not any(d["id"] == dev2_id for d in devices_after_revoke)
    print("  ✓ Individual device revoked successfully")

    # -------------------------------------------------------------------------
    # 5. revoke_all_trusted_devices
    # -------------------------------------------------------------------------
    print("\n[5/6] Testing revoke_all_trusted_devices...")
    count = await trust_service.revoke_all_trusted_devices(user_id)
    assert count == 1
    devices_empty = await trust_service.list_trusted_devices(user_id)
    assert len(devices_empty) == 0
    print(f"  ✓ All devices revoked (count: {count})")

    # -------------------------------------------------------------------------
    # 6. User Cascade Cleanup
    # -------------------------------------------------------------------------
    print("\n[6/6] Testing user deletion cascade cleanup...")
    # Create a fresh device, then delete the user
    d3_rec, _ = await trust_service.create_trusted_device(user_id=user_id, days_valid=7)
    await user_repo.delete_user(user_id)
    devices_cascaded = await trust_service.list_trusted_devices(user_id)
    assert len(devices_cascaded) == 0
    print("  ✓ User deletion cleanly cascaded to trusted devices")

    print("\n" + "=" * 75)
    print("  ALL DEVICE TRUST SERVICE TESTS PASSED WITH 100% SUCCESS!")
    print("=" * 75 + "\n")


if __name__ == "__main__":
    asyncio.run(run_acceptance_tests())
