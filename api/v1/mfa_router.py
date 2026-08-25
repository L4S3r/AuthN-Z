"""
Auth N&Z - Multi-Factor Authentication Router (api/v1/mfa_router.py)
-------------------------------------------------------------------
Handles TOTP provisioning, QR provisioning URI generation, 6-digit setup verification,
emergency backup code rotation, challenge completion, and MFA disabling.
"""

from typing import Any, Dict
import hashlib
import json
import logging
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from api.dependencies import (
    user_repo,
    mfa_prov,
    auth,
    audit_log,
    device_trust_svc,
    get_current_user,
    set_auth_cookies,
    set_trusted_device_cookie,
    clear_trusted_device_cookie,
)
from api.schemas import MFAVerifySetupRequest, MFACompleteRequest

logger = logging.getLogger("auth_nz.mfa_router")

router = APIRouter(tags=["MFA"])


@router.post("/auth/mfa/setup")
async def setup_mfa(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Generate TOTP secret, provisioning URI, and backup recovery codes for the active user."""
    user_id = current_user["user_id"]
    secret = mfa_prov.generate_secret(user_id)
    backup_codes = mfa_prov.generate_backup_codes(count=8, code_length=10)
    hashed_backups = [hashlib.sha256(c.encode("utf-8")).hexdigest() for c in backup_codes]

    user = await user_repo.get_by_id(user_id)
    metadata = user.get("metadata", {})
    if isinstance(metadata, str):
        metadata = json.loads(metadata)

    metadata["pending_mfa_secret"] = secret
    metadata["pending_backup_codes"] = hashed_backups
    await user_repo.update_user(user_id, {"metadata": metadata})

    uri = mfa_prov.get_provisioning_uri(user_id, secret, user["email"])
    return {
        "status": "SUCCESS",
        "secret": secret,
        "provisioning_uri": uri,
        "backup_codes": backup_codes,
    }


@router.post("/auth/mfa/verify-setup")
async def verify_mfa_setup(
    req: MFAVerifySetupRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Verify the 6-digit TOTP code from authenticator app to finalize and activate 2FA."""
    user_id = current_user["user_id"]
    user = await user_repo.get_by_id(user_id)
    metadata = user.get("metadata", {})
    if isinstance(metadata, str):
        metadata = json.loads(metadata)

    pending_secret = metadata.get("pending_mfa_secret") or metadata.get("mfa_secret")
    if not pending_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No pending MFA enrollment found. Please restart MFA setup.",
        )

    is_valid = mfa_prov.verify_totp_code(pending_secret, req.code.strip())
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid 6-digit verification code. Please check your authenticator clock and try again.",
        )

    metadata["mfa_enabled"] = True
    metadata["mfa_secret"] = pending_secret
    if "pending_backup_codes" in metadata:
        metadata["backup_codes"] = metadata.pop("pending_backup_codes")
    metadata.pop("pending_mfa_secret", None)
    await user_repo.update_user(user_id, {"metadata": metadata})

    await audit_log.record_security_event(
        event_name="MFA_ACTIVATED",
        severity="INFO",
        details={"user_id": user_id},
    )

    return {
        "status": "SUCCESS",
        "message": "Two-factor authentication has been successfully verified and activated.",
    }


@router.post("/auth/mfa/disable")
async def disable_mfa(
    request: Request,
    response: Response,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Disable two-factor authentication for the authenticated user."""
    user_id = current_user["user_id"]
    user = await user_repo.get_by_id(user_id)
    metadata = user.get("metadata", {})
    if isinstance(metadata, str):
        metadata = json.loads(metadata)

    metadata["mfa_enabled"] = False
    metadata.pop("mfa_secret", None)
    metadata.pop("backup_codes", None)
    metadata.pop("pending_mfa_secret", None)
    metadata.pop("pending_backup_codes", None)
    await user_repo.update_user(user_id, {"metadata": metadata})

    await device_trust_svc.revoke_all_trusted_devices(user_id)
    clear_trusted_device_cookie(response, request)

    await audit_log.record_security_event(
        event_name="MFA_DISABLED",
        severity="WARNING",
        details={"user_id": user_id},
    )
    return {"status": "SUCCESS", "message": "Two-factor authentication has been disabled."}


@router.post("/auth/mfa/complete")
async def complete_mfa(req: MFACompleteRequest, request: Request, response: Response):
    """Validate a TOTP code or emergency backup code to finalize an MFA challenge with optional device trust."""
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "")

    res = await auth.complete_mfa_challenge(
        user_id=req.user_id,
        challenge_id=req.challenge_id,
        response_code=req.code,
        remember_device=bool(req.remember_device),
        user_agent=user_agent,
        ip_address=client_ip,
    )

    if res["status"] == "SUCCESS":
        await audit_log.record_auth_success(req.user_id, "mfa_challenge", ip_address=client_ip)

        raw_dev_token = res.pop("trusted_device_token", None) or res.pop("_raw_device_token", None)
        if raw_dev_token:
            dev_rec = res.get("trusted_device", {})
            set_trusted_device_cookie(response, request, raw_dev_token)

            await audit_log.record_security_event(
                event_name="DEVICE_TRUSTED",
                severity="INFO",
                details={
                    "user_id": req.user_id,
                    "device_id": dev_rec.get("id") if isinstance(dev_rec, dict) else "",
                    "device_label": dev_rec.get("device_label") if isinstance(dev_rec, dict) else "",
                    "ip_address": client_ip,
                },
            )

        user = await user_repo.get_by_id(req.user_id)
        if user:
            meta = user.get("metadata", {})
            if isinstance(meta, str):
                try:
                    meta = json.loads(meta)
                except Exception:
                    meta = {}
            safe_meta = dict(meta) if isinstance(meta, dict) else {}
            safe_meta.pop("mfa_secret", None)
            safe_meta.pop("backup_codes", None)
            res["name"] = safe_meta.get("name") or user["username"]
            res["username"] = user["username"]
            res["email"] = user["email"]
            res["avatar_url"] = safe_meta.get("avatar_url")
            if "user" in res and isinstance(res["user"], dict):
                res["user"]["name"] = res["name"]
                res["user"]["avatar_url"] = res["avatar_url"]

        if "access_token" in res:
            set_auth_cookies(response, request, res["access_token"], res.get("refresh_token"))

        return res
    else:
        await audit_log.record_auth_failure(
            identifier=req.user_id,
            reason=res.get("reason", "INVALID_MFA_CODE"),
            ip_address=client_ip,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"MFA verification failed: {res.get('reason', 'Invalid code')}",
        )
