"""
Auth N&Z - Device Trust Router (api/v1/device_trust_router.py)
--------------------------------------------------------------
Endpoints for inspecting trusted device enrollment, single-device revocation,
and global device trust invalidation.
"""

from typing import Any, Dict
import logging
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from api.dependencies import (
    device_trust_svc,
    audit_log,
    get_current_user,
    clear_trusted_device_cookie,
    handle_conditional_response,
)

logger = logging.getLogger("auth_nz.device_trust_router")

router = APIRouter(tags=["Device Trust"])


@router.get("/auth/trusted-devices")
async def list_my_trusted_devices(
    request: Request,
    response: Response,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """List all active trusted devices for the authenticated user."""
    user_id = current_user["user_id"]
    current_token = request.cookies.get("trusted_device")
    if current_token:
        current_token = str(current_token).strip().strip('"').strip("'")
    devices = await device_trust_svc.list_trusted_devices(user_id, current_token=current_token)
    payload = {
        "status": "SUCCESS",
        "devices": devices,
        "count": len(devices),
    }
    return handle_conditional_response(request, response, payload)


@router.delete("/auth/trusted-devices/{device_id}")
async def revoke_my_trusted_device(
    device_id: str,
    request: Request,
    response: Response,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Revoke trust for a specific device."""
    user_id = current_user["user_id"]
    client_ip = request.client.host if request.client else "unknown"

    current_token = request.cookies.get("trusted_device")
    is_current = False
    if current_token:
        clean_curr = str(current_token).strip().strip('"').strip("'")
        verified_curr = await device_trust_svc.verify_trusted_device(user_id, clean_curr)
        if verified_curr and verified_curr.get("id") == device_id.strip():
            is_current = True

    revoked = await device_trust_svc.revoke_trusted_device(user_id, device_id)
    if not revoked:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Trusted device not found.")

    if is_current or current_token:
        clear_trusted_device_cookie(response, request)

    await audit_log.record_security_event(
        event_name="DEVICE_TRUST_REVOKED",
        severity="INFO",
        details={"user_id": user_id, "device_id": device_id, "is_current": is_current, "ip_address": client_ip},
    )
    return {"status": "SUCCESS", "message": "Device trust revoked successfully."}


@router.delete("/auth/trusted-devices")
async def revoke_all_my_trusted_devices(
    request: Request,
    response: Response,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Revoke all trusted devices for the authenticated user."""
    user_id = current_user["user_id"]
    client_ip = request.client.host if request.client else "unknown"
    count = await device_trust_svc.revoke_all_trusted_devices(user_id)
    clear_trusted_device_cookie(response, request)

    await audit_log.record_security_event(
        event_name="ALL_DEVICES_TRUST_REVOKED",
        severity="INFO",
        details={"user_id": user_id, "devices_revoked": count, "ip_address": client_ip},
    )
    return {"status": "SUCCESS", "message": f"Successfully revoked {count} trusted device(s)."}
