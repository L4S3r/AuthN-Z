"""
Auth N&Z - WebAuthn & Passkeys Router (api/v1/webauthn_router.py)
-----------------------------------------------------------------
Provides FIDO2 / WebAuthn Level 3 ceremony endpoints for hardware security keys (YubiKey)
and platform biometric authenticators (Apple Touch ID/Face ID, Windows Hello, Android Biometrics).
"""

from typing import Any, Dict, List, Optional
import json
import logging
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from api.dependencies import (
    user_repo,
    webauthn_svc,
    token_svc,
    sess_store,
    audit_log,
    get_current_user,
    set_auth_cookies,
)
from api.schemas import (
    WebAuthnRegisterVerifyRequest,
    WebAuthnAuthOptionsRequest,
    WebAuthnAuthVerifyRequest,
)

logger = logging.getLogger("auth_nz.webauthn_router")

router = APIRouter(prefix="/auth/webauthn", tags=["WebAuthn / Passkeys"])


@router.post("/register/options")
async def get_registration_options(
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Generate PublicKeyCredentialCreationOptions challenge for passkey creation."""
    user = await user_repo.get_by_id(current_user["user_id"])
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    metadata = user.get("metadata", {})
    if isinstance(metadata, str):
        try:
            metadata = json.loads(metadata)
        except Exception:
            metadata = {}

    existing_passkeys = metadata.get("passkeys", [])

    options = webauthn_svc.generate_registration_options(
        user_id=str(user["id"]),
        username=user["username"],
        email=user["email"],
        display_name=metadata.get("name") or user["username"],
        existing_credentials=existing_passkeys,
    )

    return {"status": "SUCCESS", "options": options}


@router.post("/register/verify")
async def verify_registration(
    req: WebAuthnRegisterVerifyRequest,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Complete passkey registration and store public credential metadata."""
    user_id = current_user["user_id"]
    user = await user_repo.get_by_id(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    client_ip = request.client.host if request.client else "unknown"

    try:
        verification = webauthn_svc.verify_registration_response(
            user_id=user_id,
            client_data_json_b64=req.client_data_json,
            attestation_object_b64=req.attestation_object,
            credential_id_b64=req.credential_id,
            device_label=req.device_label,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    metadata = user.get("metadata", {})
    if isinstance(metadata, str):
        try:
            metadata = json.loads(metadata)
        except Exception:
            metadata = {}

    passkeys = metadata.setdefault("passkeys", [])
    passkeys.append(verification["passkey"])

    await user_repo.update_user(user_id, {"metadata": metadata})

    await audit_log.record_security_event(
        event_name="WEBAUTHN_PASSKEY_REGISTERED",
        severity="INFO",
        details={
            "user_id": user_id,
            "credential_id": verification["passkey"]["credential_id"],
            "device_label": req.device_label,
            "ip_address": client_ip,
        },
    )

    return {
        "status": "SUCCESS",
        "message": "Passkey registered successfully.",
        "passkey": verification["passkey"],
    }


@router.post("/authenticate/options")
async def get_authentication_options(
    req: Optional[WebAuthnAuthOptionsRequest] = None,
):
    """Generate PublicKeyCredentialRequestOptions challenge for passwordless passkey login."""
    user_passkeys = []
    user_id = None

    if req and req.identifier:
        user = await user_repo.get_by_identifier(req.identifier.strip().lower())
        if user:
            user_id = str(user["id"])
            metadata = user.get("metadata", {})
            if isinstance(metadata, str):
                try:
                    metadata = json.loads(metadata)
                except Exception:
                    metadata = {}
            user_passkeys = metadata.get("passkeys", [])

    options = webauthn_svc.generate_authentication_options(
        user_id=user_id,
        user_passkeys=user_passkeys,
    )

    return {"status": "SUCCESS", "options": options}


@router.post("/authenticate/verify")
async def verify_authentication(
    req: WebAuthnAuthVerifyRequest,
    request: Request,
    response: Response,
):
    """Verify passkey signature and issue authenticated JWT tokens & session."""
    client_ip = request.client.host if request.client else "unknown"

    # 1. Look up user by identifier or search by credential ID
    user = None
    if req.identifier:
        user = await user_repo.get_by_identifier(req.identifier.strip().lower())

    if not user:
        # Fallback: scan active users to match credential_id
        all_users = await user_repo.list_users(limit=500)
        for u in all_users:
            meta = u.get("metadata", {})
            if isinstance(meta, str):
                try:
                    meta = json.loads(meta)
                except Exception:
                    meta = {}
            for pk in meta.get("passkeys", []):
                if pk.get("credential_id") == req.credential_id:
                    user = u
                    break
            if user:
                break

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No account found matching this passkey.",
        )

    if not user.get("is_active", 1):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is inactive.",
        )

    metadata = user.get("metadata", {})
    if isinstance(metadata, str):
        try:
            metadata = json.loads(metadata)
        except Exception:
            metadata = {}

    user_passkeys = metadata.get("passkeys", [])

    try:
        verification = webauthn_svc.verify_authentication_response(
            client_data_json_b64=req.client_data_json,
            credential_id_b64=req.credential_id,
            user_passkeys=user_passkeys,
        )
    except ValueError as e:
        await audit_log.record_auth_failure(
            identifier=user["email"],
            reason=f"WEBAUTHN_AUTH_FAILED: {str(e)}",
            ip_address=client_ip,
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))

    # Update last_used_at and sign count on passkey
    await user_repo.update_user(user["id"], {"metadata": metadata})

    roles = user.get("roles", [])
    if isinstance(roles, str):
        try:
            roles = json.loads(roles)
        except Exception:
            roles = []

    access_token = token_svc.create_access_token(user["id"], claims={"roles": roles})
    refresh_token = token_svc.create_refresh_token(user["id"], claims={"roles": roles})
    session_id = sess_store.create_session(user["id"], session_data={"roles": roles})

    set_auth_cookies(response, request, access_token, refresh_token)

    await audit_log.record_auth_success(
        subject_id=user["id"],
        auth_method="webauthn_passkey",
        ip_address=client_ip,
    )

    safe_meta = dict(metadata)
    safe_meta.pop("mfa_secret", None)
    safe_meta.pop("backup_codes", None)

    return {
        "status": "SUCCESS",
        "message": "Passkey authentication successful.",
        "user_id": user["id"],
        "access_token": access_token,
        "refresh_token": refresh_token,
        "session_id": session_id,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "roles": roles,
            "metadata": safe_meta,
        },
    }


@router.get("/credentials")
async def list_registered_credentials(
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """List all registered passkeys and hardware keys for the current user."""
    user = await user_repo.get_by_id(current_user["user_id"])
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    metadata = user.get("metadata", {})
    if isinstance(metadata, str):
        try:
            metadata = json.loads(metadata)
        except Exception:
            metadata = {}

    passkeys = metadata.get("passkeys", [])
    return {"status": "SUCCESS", "count": len(passkeys), "passkeys": passkeys}


@router.delete("/credentials/{credential_id}")
async def delete_registered_credential(
    credential_id: str,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Delete a registered passkey from the user's account."""
    user_id = current_user["user_id"]
    user = await user_repo.get_by_id(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    metadata = user.get("metadata", {})
    if isinstance(metadata, str):
        try:
            metadata = json.loads(metadata)
        except Exception:
            metadata = {}

    passkeys = metadata.get("passkeys", [])
    initial_len = len(passkeys)
    filtered = [p for p in passkeys if p.get("credential_id") != credential_id]

    if len(filtered) == initial_len:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Passkey not found.")

    metadata["passkeys"] = filtered
    await user_repo.update_user(user_id, {"metadata": metadata})

    client_ip = request.client.host if request.client else "unknown"
    await audit_log.record_security_event(
        event_name="WEBAUTHN_PASSKEY_REMOVED",
        severity="WARNING",
        details={
            "user_id": user_id,
            "credential_id": credential_id,
            "ip_address": client_ip,
        },
    )

    return {"status": "SUCCESS", "message": "Passkey removed successfully."}
