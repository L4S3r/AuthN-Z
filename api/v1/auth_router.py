"""
Auth N&Z - Core Authentication Router (api/v1/auth_router.py)
-------------------------------------------------------------
Endpoints for user registration, admin provisioning, primary login,
token refresh rotation, session termination, password reset, and identity profile.
"""

from typing import Any, Dict, List, Optional
import json
import logging
import jwt
from fastapi import APIRouter, Body, Depends, HTTPException, Request, Response, status

from api.dependencies import (
    hasher,
    user_repo,
    ws_repo,
    audit_log,
    email_svc,
    perm_eval,
    auth,
    token_svc,
    sess_store,
    device_trust_svc,
    get_current_user,
    set_auth_cookies,
    clear_auth_cookies,
    set_trusted_device_cookie,
    clear_trusted_device_cookie,
    check_rate_limit,
    handle_conditional_response,
)
from api.schemas import (
    RegisterRequest,
    AdminCreateUserRequest,
    LoginRequest,
    RefreshRequest,
    LogoutRequest,
    ForgotPasswordRequest,
    ResetPasswordRequest,
)

logger = logging.getLogger("auth_nz.auth_router")
DUMMY_BCRYPT_HASH = "$2b$12$e8YkZ7G4t9I1mPqLwK9ZCe8YkZ7G4t9I1mPqLwK9ZCe8YkZ7G4t9I"

router = APIRouter(tags=["Authentication"])


@router.post("/auth/register", status_code=status.HTTP_201_CREATED)
async def register(req: RegisterRequest, request: Request):
    """Public registration: always assigns default unprivileged 'viewer' role and clearance 1."""
    try:
        hashed_password = hasher.hash(req.password)
        new_user = await user_repo.create_user({
            "username": req.username,
            "email": req.email,
            "hashed_password": hashed_password,
            "roles": ["viewer"],
            "metadata": {
                "department": "General",
                "clearance": 1,
            },
        })

        client_ip = request.client.host if request.client else "unknown"
        await audit_log.record_security_event(
            event_name="USER_REGISTERED",
            severity="INFO",
            details={
                "user_id": new_user["id"],
                "username": new_user["username"],
                "ip_address": client_ip,
            },
        )
        return {"status": "SUCCESS", "user": new_user}
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.post("/admin/users", tags=["Administration"], status_code=status.HTTP_201_CREATED)
async def admin_create_user(
    req: AdminCreateUserRequest,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Admin-only endpoint: Provision new accounts with custom roles and security clearance."""
    if not await perm_eval.has_role(current_user["user_id"], "admin"):
        await audit_log.record_access_denial(
            subject_id=current_user["user_id"],
            action="create_user",
            resource="admin/users",
            reason="ADMIN_ROLE_REQUIRED",
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Admin privileges required to provision custom roles.",
        )

    requested_roles = [str(r).strip().lower() for r in (req.roles or [])]
    if any(r in ("superadmin", "super-admin", "super_admin") for r in requested_roles):
        if not await perm_eval.has_role(current_user["user_id"], "superadmin"):
            await audit_log.record_access_denial(
                subject_id=current_user["user_id"],
                action="create_superadmin_user",
                resource="admin/users",
                reason="SUPERADMIN_ROLE_REQUIRED",
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: Superadmin privileges required to grant superadmin role.",
            )

    try:
        hashed_password = hasher.hash(req.password)
        new_user = await user_repo.create_user({
            "username": req.username,
            "email": req.email,
            "hashed_password": hashed_password,
            "roles": req.roles,
            "metadata": {
                "department": req.department,
                "clearance": req.clearance,
            },
        })
        client_ip = request.client.host if request.client else "unknown"
        await audit_log.record_security_event(
            event_name="ADMIN_USER_PROVISIONED",
            severity="INFO",
            details={
                "created_by": current_user["user_id"],
                "new_user_id": new_user["id"],
                "roles": req.roles,
                "ip_address": client_ip,
            },
        )
        return {"status": "SUCCESS", "user": new_user}
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.post("/auth/login")
async def login(req: LoginRequest, request: Request, response: Response):
    """Primary credential authentication with rate limiting, constant-time execution, and trusted device MFA bypass."""
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "")
    clean_ident = req.identifier.strip().lower()

    if not check_rate_limit(f"login_ip:{client_ip}", max_requests=30, window_seconds=60) or \
       not check_rate_limit(f"login_user:{clean_ident}", max_requests=10, window_seconds=60):
        await audit_log.record_security_event(
            event_name="LOGIN_RATE_LIMITED",
            severity="WARNING",
            details={"identifier": req.identifier, "ip_address": client_ip},
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Please wait 60 seconds before trying again.",
        )

    cand_token = request.cookies.get("trusted_device")
    clean_token = str(cand_token).strip().strip('"').strip("'") if cand_token else None

    res = await auth.authenticate_credentials(
        req.identifier,
        req.password,
        trusted_device_token=clean_token,
        user_agent=user_agent,
        ip_address=client_ip,
    )

    if res["status"] == "SUCCESS":
        if res.get("mfa_skipped"):
            trusted_dev = res.get("trusted_device", {})
            await audit_log.record_security_event(
                event_name="MFA_SKIPPED_TRUSTED_DEVICE",
                severity="INFO",
                details={
                    "user_id": res["user_id"],
                    "device_id": trusted_dev.get("id") if isinstance(trusted_dev, dict) else "",
                    "device_label": trusted_dev.get("device_label") if isinstance(trusted_dev, dict) else "",
                    "ip_address": client_ip,
                },
            )
            if clean_token:
                set_trusted_device_cookie(response, request, clean_token)
        else:
            await audit_log.record_auth_success(res["user_id"], "password", ip_address=client_ip)

        res.pop("trusted_device_token", None)
        res.pop("_raw_device_token", None)

        user = await user_repo.get_by_id(res["user_id"])
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
            user_name = safe_meta.get("name") or user.get("username", "")
            user_avatar = safe_meta.get("avatar_url")
            res["name"] = user_name
            res["username"] = user.get("username", "")
            res["email"] = user.get("email", "")
            res["avatar_url"] = user_avatar
            if "user" in res and isinstance(res["user"], dict):
                res["user"]["name"] = user_name
                res["user"]["avatar_url"] = user_avatar

        if "access_token" in res:
            set_auth_cookies(response, request, res["access_token"], res.get("refresh_token"))

        return res
    elif res["status"] == "MFA_REQUIRED":
        return res
    elif res["status"] == "LOCKED":
        user_id = res.get("user_id")
        await audit_log.record_security_event(
            event_name="ACCOUNT_LOCKOUT",
            severity="CRITICAL",
            details={
                "identifier": req.identifier,
                "user_id": user_id,
                "lockout_seconds": res.get("lockout_seconds"),
                "ip_address": client_ip,
            },
        )
        if user_id and res.get("newly_locked"):
            user = await user_repo.get_by_id(user_id)
            if user:
                try:
                    email_svc.send_security_alert_email(
                        recipient_email=user["email"],
                        recipient_name=user.get("username", "User"),
                        event_name="Account Temporarily Locked",
                        severity="CRITICAL",
                        details={
                            "reason": f"Account temporarily locked due to {res.get('attempts', 5)} consecutive failed login attempts.",
                            "lockout_duration": f"{res.get('lockout_minutes', 15)} minutes",
                            "ip_address": client_ip,
                        },
                        ip_address=client_ip,
                    )
                except Exception as exc:
                    logger.warning("Failed to dispatch account lockout email: %s", exc)

        lockout_mins = res.get("lockout_minutes", 15)
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail=f"Account is temporarily locked due to excessive failed login attempts. Please try again in {lockout_mins} minute(s) or reset your password.",
            headers={"Retry-After": str(res.get("lockout_seconds", 900))},
        )
    else:
        await audit_log.record_auth_failure(
            identifier=req.identifier,
            reason=res.get("reason", "INVALID_CREDENTIALS"),
            ip_address=client_ip,
        )
        remaining = res.get("remaining_attempts")
        detail = "Invalid credentials provided."
        if remaining is not None and remaining <= 3 and remaining > 0:
            detail = f"Invalid credentials provided. Warning: {remaining} attempt(s) remaining before temporary account lockout."
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
        )


@router.post("/auth/refresh")
async def refresh_tokens(
    request: Request,
    response: Response,
    req: Optional[RefreshRequest] = Body(None),
):
    """Exchange a valid refresh token for a new access token and rotated refresh token."""
    client_ip = request.client.host if request.client else "unknown"
    raw_token = (req.refresh_token if req and req.refresh_token else None) or request.cookies.get("refresh_token")

    if not raw_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing refresh token (refresh_token cookie or payload required).",
        )

    clean_token = str(raw_token).strip().strip('"').strip("'")
    try:
        payload = jwt.decode(
            clean_token,
            token_svc.secret_key,
            algorithms=[token_svc.algorithm],
            options={"require": ["sub", "exp", "iat", "jti"]},
        )
    except jwt.ExpiredSignatureError:
        clear_auth_cookies(response, request)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has expired.",
        )
    except jwt.InvalidTokenError as e:
        clear_auth_cookies(response, request)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid refresh token: {str(e)}",
        )

    if payload.get("type") != "refresh":
        clear_auth_cookies(response, request)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Provided token is not a refresh token.",
        )

    user_id = payload.get("sub")
    jti = payload.get("jti")
    family_id = payload.get("family_id")

    if family_id and token_svc.is_family_revoked(family_id):
        clear_auth_cookies(response, request)
        await audit_log.record_security_event(
            event_name="REVOKED_TOKEN_FAMILY_ATTEMPT",
            severity="CRITICAL",
            details={"user_id": user_id, "family_id": family_id, "ip_address": client_ip},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token family revoked due to previous security violation.",
        )

    if jti and token_svc.is_token_revoked(jti):
        if family_id:
            token_svc.revoke_family(family_id)
        if user_id:
            sess_store.delete_all_user_sessions(user_id)

        clear_auth_cookies(response, request)
        await audit_log.record_security_event(
            event_name="REFRESH_TOKEN_REUSE_DETECTED",
            severity="CRITICAL",
            details={
                "user_id": user_id,
                "jti": jti,
                "family_id": family_id,
                "ip_address": client_ip,
            },
        )

        user = await user_repo.get_by_id(user_id) if user_id else None
        if user:
            try:
                email_svc.send_security_alert_email(
                    recipient_email=user["email"],
                    recipient_name=user.get("username", "User"),
                    event_name="Suspicious Authentication Activity Detected",
                    severity="CRITICAL",
                    details={
                        "reason": "An attempt was made to reuse an already-rotated refresh token. All active sessions in this family were revoked for your security.",
                        "ip_address": client_ip,
                    },
                    ip_address=client_ip,
                )
            except Exception as exc:
                logger.warning("Failed to dispatch token reuse alert email: %s", exc)

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Security violation: Refresh token reuse detected. All tokens in this family have been revoked.",
        )

    user = await user_repo.get_by_id(user_id)
    if not user or not user.get("is_active", 1):
        clear_auth_cookies(response, request)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is inactive or no longer exists.",
        )

    if jti:
        token_svc.revoke_token(jti, expires_at=int(payload.get("exp", 0)))

    roles = user.get("roles", [])
    if isinstance(roles, str):
        try:
            roles = json.loads(roles)
        except Exception:
            roles = []

    new_access_token = token_svc.create_access_token(user_id, claims={"roles": roles})
    new_refresh_token = token_svc.create_refresh_token(user_id, claims={"roles": roles}, family_id=family_id)

    set_auth_cookies(response, request, new_access_token, new_refresh_token)

    await audit_log.record_security_event(
        event_name="TOKEN_REFRESHED",
        severity="INFO",
        details={"user_id": user_id, "family_id": family_id, "ip_address": client_ip},
    )

    return {
        "status": "SUCCESS",
        "access_token": new_access_token,
        "refresh_token": new_refresh_token,
        "user_id": user_id,
    }


@router.post("/auth/logout")
async def logout(
    request: Request,
    response: Response,
    req: LogoutRequest = LogoutRequest(),
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Invalidate caller's JWT access token, clear httpOnly cookies, and delete active session."""
    user_id = current_user["user_id"]
    claims = current_user.get("claims", {})
    client_ip = request.client.host if request and request.client else "unknown"

    jti = claims.get("jti")
    if jti:
        token_svc.revoke_token(jti, expires_at=int(claims.get("exp", 0)))

    clear_auth_cookies(response, request)

    sessions_deleted = 0
    if req.logout_all_devices:
        sessions_deleted = sess_store.delete_all_user_sessions(user_id)
        await device_trust_svc.revoke_all_trusted_devices(user_id)
        clear_trusted_device_cookie(response, request)
    elif req.session_id:
        sess_store.delete_session(req.session_id)
        sessions_deleted = 1

    await audit_log.record_security_event(
        event_name="USER_LOGGED_OUT",
        severity="INFO",
        details={
            "user_id": user_id,
            "jti_revoked": jti,
            "logout_all_devices": req.logout_all_devices,
            "sessions_deleted": sessions_deleted,
            "ip_address": client_ip,
        },
    )

    return {
        "status": "SUCCESS",
        "message": "Successfully logged out.",
        "jti_revoked": jti,
        "logout_all_devices": req.logout_all_devices,
        "sessions_deleted": sessions_deleted,
    }


@router.post("/auth/forgot-password")
async def forgot_password(req: ForgotPasswordRequest, request: Request):
    """Initiate self-service password reset flow with constant-time response and rate limiting."""
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "")
    clean_email = req.email.strip().lower()

    if not check_rate_limit(f"forgot_pw_ip:{client_ip}", max_requests=5, window_seconds=60) or \
       not check_rate_limit(f"forgot_pw_email:{clean_email}", max_requests=3, window_seconds=60):
        await audit_log.record_security_event(
            event_name="FORGOT_PASSWORD_RATE_LIMITED",
            severity="WARNING",
            details={"email": clean_email, "ip_address": client_ip},
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many password reset requests. Please wait a few moments before trying again.",
        )

    user = await user_repo.get_by_identifier(clean_email)
    if user and user.get("is_active", 1):
        raw_token = await user_repo.create_password_reset_token(
            user_id=user["id"],
            ip_address=client_ip,
            expires_in_minutes=15,
        )
        try:
            email_svc.send_password_reset_email(
                recipient_email=user["email"],
                recipient_name=user.get("username"),
                reset_token=raw_token,
                expires_in_minutes=15,
                ip_address=client_ip,
                user_agent=user_agent,
            )
        except Exception as exc:
            logger.warning("Failed to dispatch password reset email: %s", exc)

        await audit_log.record_security_event(
            event_name="PASSWORD_RESET_REQUESTED",
            severity="INFO",
            details={"user_id": user["id"], "email": clean_email, "ip_address": client_ip},
        )
    else:
        hasher.verify("dummy_password_timing_pad", DUMMY_BCRYPT_HASH)

    return {
        "status": "SUCCESS",
        "message": "If an account matching that email address exists, password reset instructions have been sent.",
    }


@router.get("/auth/verify-reset-token")
async def verify_reset_token(token: str):
    """Verify if a password reset token is valid, active, and unexpired."""
    record = await user_repo.verify_password_reset_token(token)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password reset link is invalid, expired, or has already been used.",
        )

    raw_email = record.get("email", "")
    parts = raw_email.split("@")
    if len(parts) == 2:
        masked_user = parts[0][:2] + "***" if len(parts[0]) > 2 else "***"
        masked_email = f"{masked_user}@{parts[1]}"
    else:
        masked_email = "***"

    return {
        "status": "SUCCESS",
        "valid": True,
        "username": record.get("username", ""),
        "masked_email": masked_email,
    }


@router.post("/auth/reset-password")
async def reset_password(req: ResetPasswordRequest, request: Request, response: Response):
    """Consume a valid password reset token and update account password with session invalidation."""
    client_ip = request.client.host if request.client else "unknown"

    if not check_rate_limit(f"reset_pw_ip:{client_ip}", max_requests=10, window_seconds=60):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many password reset attempts. Please wait before retrying.",
        )

    if len(req.new_password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 8 characters long.",
        )

    token_record = await user_repo.verify_password_reset_token(req.token)
    if not token_record:
        await audit_log.record_security_event(
            event_name="PASSWORD_RESET_FAILED",
            severity="WARNING",
            details={"reason": "INVALID_OR_EXPIRED_TOKEN", "ip_address": client_ip},
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password reset link is invalid, expired, or has already been used.",
        )

    user_id = token_record["user_id"]
    new_hashed_password = hasher.hash(req.new_password)

    consumed_user_id = await user_repo.consume_password_reset_token(req.token, new_hashed_password)
    if not consumed_user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to apply password reset. The token may have already been consumed.",
        )

    sess_store.delete_all_user_sessions(user_id)
    await device_trust_svc.revoke_all_trusted_devices(user_id)
    auth.unlock_account(user_id)
    clear_trusted_device_cookie(response, request)
    clear_auth_cookies(response, request)

    try:
        email_svc.send_security_alert_email(
            recipient_email=token_record["email"],
            recipient_name=token_record.get("username"),
            event_name="Password Successfully Reset",
            severity="HIGH",
            details={"ip_address": client_ip, "action": "Password changed via reset token"},
            ip_address=client_ip,
        )
    except Exception as exc:
        logger.warning("Failed to send password reset confirmation alert email: %s", exc)

    await audit_log.record_security_event(
        event_name="PASSWORD_RESET_SUCCESS",
        severity="INFO",
        details={"user_id": user_id, "ip_address": client_ip},
    )

    return {
        "status": "SUCCESS",
        "message": "Your password has been successfully reset. Please sign in with your new credentials.",
    }


@router.get("/auth/me", tags=["User Context"])
async def get_my_profile(
    request: Request,
    response: Response,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Retrieve identity context of the authenticated user."""
    user = await user_repo.get_by_id(current_user["user_id"])
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    meta = user.get("metadata", {})
    if isinstance(meta, str):
        try:
            meta = json.loads(meta)
        except Exception:
            meta = {}
    safe_meta = dict(meta) if isinstance(meta, dict) else {}
    safe_meta.pop("mfa_secret", None)
    safe_meta.pop("backup_codes", None)

    roles = user.get("roles", [])
    if isinstance(roles, str):
        try:
            roles = json.loads(roles)
        except Exception:
            roles = []

    safe_name = safe_meta.get("name") or user.get("name") or user["username"]
    safe_avatar = safe_meta.get("avatar_url") or user.get("avatar_url")

    safe_user = {
        "id": user["id"],
        "name": safe_name,
        "username": user["username"],
        "email": user["email"],
        "avatar_url": safe_avatar,
        "roles": roles,
        "metadata": safe_meta,
        "created_at": user.get("created_at"),
    }
    payload = {
        "status": "SUCCESS",
        "user_id": user["id"],
        "name": safe_name,
        "username": user["username"],
        "email": user["email"],
        "avatar_url": safe_avatar,
        "roles": roles,
        "metadata": safe_meta,
        "user": safe_user,
    }
    return handle_conditional_response(request, response, payload)
