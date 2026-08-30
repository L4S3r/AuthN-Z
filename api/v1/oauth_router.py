"""
Auth N&Z - OAuth2 & OpenID Connect (OIDC) Social Login Router (api/v1/oauth_router.py)
-------------------------------------------------------------------------------------
Handles third-party social authentication (Google OIDC, GitHub OAuth) with PKCE code
exchange, account linking, automated JIT user provisioning, and MFA integration.
"""

from typing import Any, Dict, Optional
import json
import logging
import os
import secrets
import uuid
from fastapi import APIRouter, HTTPException, Request, Response, status
from sqlalchemy import func, or_, update as sql_update

from api.dependencies import (
    hasher,
    user_repo,
    oauth_mgr,
    audit_log,
    token_svc,
    sess_store,
    device_trust_svc,
    auth,
    set_auth_cookies,
    set_trusted_device_cookie,
)
from api.schemas import OAuthExchangeRequest
from oauth_provider import generate_pkce_pair, generate_oauth_state
from database import get_session_factory
from workspace_models import WorkspaceMember

logger = logging.getLogger("auth_nz.oauth_router")

router = APIRouter(tags=["OAuth2 / Social Login"])


async def resolve_or_create_oauth_user(
    profile: Dict[str, Any],
    client_ip: str,
    request: Optional[Request] = None,
    response: Optional[Response] = None,
    user_agent: Optional[str] = None,
) -> Dict[str, Any]:
    """Link an external OAuth profile to an existing account or auto-provision a new user."""
    email = profile.get("email")
    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OAuth identity provider did not provide a valid email address.",
        )

    provider = profile.get("provider", "oauth")
    provider_uid = profile.get("provider_user_id")
    display_name = profile.get("name")
    avatar_url = profile.get("picture")

    user = await user_repo.get_by_identifier(email)
    if user:
        if not user.get("is_active", 1):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Account associated with this email is inactive.",
            )

        metadata = user.get("metadata", {})
        if isinstance(metadata, str):
            try:
                metadata = json.loads(metadata)
            except Exception:
                metadata = {}

        oauth_map = metadata.setdefault("oauth_providers", {})
        oauth_map[provider] = provider_uid
        if avatar_url:
            metadata["avatar_url"] = avatar_url
        if display_name:
            metadata["name"] = display_name

        update_fields = {"metadata": metadata}

        clean_preferred = None
        if profile.get("username"):
            clean_preferred = "".join(c for c in profile["username"].lower() if c.isalnum() or c in ("_", "-"))
        elif display_name:
            clean_preferred = "".join(c for c in display_name.replace(" ", "_").lower() if c.isalnum() or c in ("_", "-"))

        curr_username = user.get("username", "")
        if clean_preferred and len(clean_preferred) >= 3 and (curr_username == email.split("@")[0].lower() or curr_username.startswith("user_")):
            existing_target = await user_repo.get_by_identifier(clean_preferred)
            if not existing_target or existing_target["id"] == user["id"]:
                update_fields["username"] = clean_preferred

        await user_repo.update_user(user["id"], update_fields)
        user = await user_repo.get_by_id(user["id"])

        if display_name:
            try:
                session_factory = get_session_factory()
                async with session_factory() as session:
                    parsed_user_uuid = uuid.UUID(str(user["id"]).strip())
                    clean_email = email.lower().strip()
                    stmt = (
                        sql_update(WorkspaceMember)
                        .where(
                            or_(
                                WorkspaceMember.user_id == parsed_user_uuid,
                                func.lower(WorkspaceMember.email) == clean_email,
                            )
                        )
                        .values(
                            user_id=parsed_user_uuid,
                            name=func.coalesce(display_name, WorkspaceMember.name),
                        )
                    )
                    await session.execute(stmt)
                    await session.commit()
            except Exception as exc:
                logger.warning("Failed to sync oauth display name to workspace members: %s", exc)
    else:
        # Check if host application registered a BYOU OAuth provisioning hook
        from api.dependencies import oauth_provision_hook
        hook_handled = False
        if oauth_provision_hook is not None:
            import inspect
            hook_res = oauth_provision_hook(profile, client_ip)
            if inspect.isawaitable(hook_res):
                hook_res = await hook_res
            if hook_res:
                if isinstance(hook_res, dict) and "id" in hook_res:
                    user = hook_res
                    hook_handled = True
                else:
                    # Hook handled registration request or returned custom status dict (e.g., PENDING_APPROVAL)
                    return hook_res
            else:
                user = await user_repo.get_by_identifier(email)
                if user:
                    hook_handled = True

        if not user:
            raw_preferred = profile.get("username")
            if not raw_preferred and display_name:
                raw_preferred = display_name.strip().replace(" ", "_")
            if not raw_preferred:
                raw_preferred = email.split("@")[0]

            base_username = str(raw_preferred).strip().lower()
            clean_username = "".join(c for c in base_username if c.isalnum() or c in ("_", "-"))
            if len(clean_username) < 3:
                clean_username = f"user_{secrets.token_hex(4)}"

            if await user_repo.get_by_identifier(clean_username):
                clean_username = f"{clean_username}_{secrets.token_hex(3)}"

            dummy_password = secrets.token_urlsafe(32)
            hashed_pw = hasher.hash(dummy_password)

            user = await user_repo.create_user({
                "username": clean_username,
                "email": email,
                "hashed_password": hashed_pw,
                "roles": ["viewer"],
                "metadata": {
                    "name": display_name or clean_username,
                    "department": "General",
                    "clearance": 1,
                    "oauth_providers": {provider: provider_uid},
                    "avatar_url": avatar_url,
                },
            })

            await audit_log.record_security_event(
                event_name="USER_OAUTH_PROVISIONED",
                severity="INFO",
                details={
                    "user_id": user["id"],
                    "email": email,
                    "provider": provider,
                    "ip_address": client_ip,
                },
            )

    user_meta = user.get("metadata", {})
    if isinstance(user_meta, str):
        try:
            user_meta = json.loads(user_meta)
        except Exception:
            user_meta = {}

    mfa_skipped = False
    trusted_dev = None
    clean_token = None
    if user_meta.get("mfa_enabled") and user_meta.get("mfa_secret"):
        cand_token = request.cookies.get("trusted_device") if request else None
        if cand_token:
            clean_token = str(cand_token).strip().strip('"').strip("'")

        if clean_token and device_trust_svc:
            trusted_dev = await device_trust_svc.verify_trusted_device(
                user_id=user["id"],
                raw_token=clean_token,
                user_agent=user_agent,
                ip_address=client_ip,
            )
            if trusted_dev:
                mfa_skipped = True

        if not mfa_skipped:
            challenge = await auth.initiate_mfa_challenge(user["id"], challenge_type="totp")
            return {
                "status": "MFA_REQUIRED",
                "user_id": user["id"],
                "challenge_id": challenge["challenge_id"],
            }

    roles = user.get("roles", [])
    if isinstance(roles, str):
        try:
            roles = json.loads(roles)
        except Exception:
            roles = []

    access_token = token_svc.create_access_token(user["id"], claims={"roles": roles})
    refresh_token = token_svc.create_refresh_token(user["id"], claims={"roles": roles})
    session_id = sess_store.create_session(user["id"], session_data={"roles": roles})

    safe_metadata = dict(user_meta) if isinstance(user_meta, dict) else {}
    safe_metadata.pop("mfa_secret", None)
    safe_metadata.pop("backup_codes", None)

    if mfa_skipped:
        await audit_log.record_security_event(
            event_name="MFA_SKIPPED_TRUSTED_DEVICE",
            severity="INFO",
            details={
                "user_id": user["id"],
                "device_id": trusted_dev.get("id") if isinstance(trusted_dev, dict) else "",
                "device_label": trusted_dev.get("device_label") if isinstance(trusted_dev, dict) else "",
                "ip_address": client_ip,
            },
        )
        await audit_log.record_auth_success(user["id"], f"oauth_{provider}+trusted_device", ip_address=client_ip)
        if response and request and clean_token:
            set_trusted_device_cookie(response, request, clean_token)
    else:
        await audit_log.record_auth_success(user["id"], f"oauth_{provider}", ip_address=client_ip)

    user_name = safe_metadata.get("name") or display_name or user["username"]
    user_avatar = safe_metadata.get("avatar_url") or avatar_url

    resp = {
        "status": "SUCCESS",
        "user_id": user["id"],
        "name": user_name,
        "username": user["username"],
        "email": user["email"],
        "avatar_url": user_avatar,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "session_id": session_id,
        "user": {
            "id": user["id"],
            "name": user_name,
            "username": user["username"],
            "email": user["email"],
            "avatar_url": user_avatar,
            "roles": roles,
            "metadata": safe_metadata,
        },
    }
    if mfa_skipped and trusted_dev:
        resp["mfa_skipped"] = True
        resp["trusted_device"] = {
            "id": trusted_dev.get("id"),
            "device_label": trusted_dev.get("device_label"),
            "created_at": trusted_dev.get("created_at"),
            "expires_at": trusted_dev.get("expires_at"),
        }

    if response and request and access_token:
        set_auth_cookies(response, request, access_token, refresh_token)

    return resp


@router.get("/auth/oauth/providers")
async def list_oauth_providers():
    """List configured and available OAuth identity providers."""
    return {
        "status": "SUCCESS",
        "available_providers": list(oauth_mgr.providers.keys()),
    }


@router.get("/auth/oauth/{provider}/login")
async def oauth_login(
    provider: str,
    request: Request,
    redirect_uri: Optional[str] = None,
    target_app_url: Optional[str] = None,
):
    """Initiate PKCE-protected OAuth authorization flow for web or mobile clients."""
    prov_instance = oauth_mgr.get_provider(provider)
    if not prov_instance:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"OAuth provider '{provider}' is not configured on this server.",
        )

    env_redirect = os.getenv(f"{provider.upper()}_REDIRECT_URI")
    default_redirect = env_redirect or f"{str(request.base_url).rstrip('/')}/api/v1/auth/oauth/{provider}/callback"
    final_redirect = redirect_uri or default_redirect

    referer = request.headers.get("referer", "").strip()
    referer_origin = None
    if referer:
        import urllib.parse
        parsed = urllib.parse.urlparse(referer)
        if parsed.scheme and parsed.netloc:
            referer_origin = f"{parsed.scheme}://{parsed.netloc}"

    computed_target_app = (
        target_app_url
        or request.headers.get("origin")
        or referer_origin
        or os.getenv("FRONTEND_URL")
        or os.getenv("WEBAUTHN_ORIGIN")
        or "https://falqyn.l4s3r.site"
    )

    code_verifier, code_challenge = generate_pkce_pair()
    state = generate_oauth_state()

    oauth_mgr.save_state(
        state=state,
        data={
            "provider": provider,
            "code_verifier": code_verifier,
            "redirect_uri": final_redirect,
            "target_app_url": computed_target_app,
        },
        ttl_seconds=600,
    )

    auth_url = prov_instance.get_authorization_url(
        redirect_uri=final_redirect,
        state=state,
        code_challenge=code_challenge,
    )

    return {
        "status": "SUCCESS",
        "provider": provider,
        "authorization_url": auth_url,
        "state": state,
        "code_verifier": code_verifier,
    }


@router.get("/auth/oauth/{provider}/callback")
async def oauth_callback(
    provider: str,
    code: str,
    state: str,
    request: Request,
    response: Response,
):
    """Handle OAuth authorization code redirect and return issued tokens."""
    state_data = oauth_mgr.consume_state(state)
    if not state_data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired OAuth state parameter.",
        )

    prov_instance = oauth_mgr.get_provider(provider)
    if not prov_instance:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"OAuth provider '{provider}' is not configured.",
        )

    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "")
    try:
        profile = await prov_instance.exchange_code(
            code=code,
            redirect_uri=state_data.get("redirect_uri"),
            code_verifier=state_data.get("code_verifier"),
        )
    except Exception as exc:
        await audit_log.record_auth_failure(
            identifier=f"oauth_{provider}",
            reason=str(exc),
            ip_address=client_ip,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"OAuth code exchange failed: {str(exc)}",
        )

    res_dict = await resolve_or_create_oauth_user(
        profile,
        client_ip=client_ip,
        request=request,
        response=response,
        user_agent=user_agent,
    )

    computed_fallback = (
        request.headers.get("origin")
        or os.getenv("FRONTEND_URL")
        or os.getenv("WEBAUTHN_ORIGIN")
        or "https://falqyn.l4s3r.site"
    )

    if isinstance(res_dict, dict) and res_dict.get("access_token"):
        target_app = state_data.get("target_app_url") or computed_fallback
        token = res_dict["access_token"]
        refresh_token = res_dict.get("refresh_token")
        is_new_user = (
            res_dict.get("status") == "SUCCESS"
            and res_dict.get("user", {}).get("metadata", {}).get("department") == "General"
        )

        redirect_url = f"{target_app.rstrip('/')}/?access_token={token}&is_new_user={str(is_new_user).lower()}"
        from fastapi.responses import RedirectResponse
        redirect_resp = RedirectResponse(url=redirect_url, status_code=302)
        if request and token:
            set_auth_cookies(redirect_resp, request, token, refresh_token)
        return redirect_resp

    if isinstance(res_dict, dict) and res_dict.get("status") == "PENDING_APPROVAL":
        target_app = state_data.get("target_app_url") or computed_fallback
        msg = res_dict.get("detail", "Registration request pending Superadmin approval.")
        import urllib.parse
        encoded_msg = urllib.parse.quote(msg)
        redirect_url = f"{target_app.rstrip('/')}/?pending_approval=true&message={encoded_msg}"
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url=redirect_url, status_code=302)

    return res_dict


@router.post("/auth/oauth/{provider}/exchange")
async def oauth_exchange_code(
    provider: str,
    req: OAuthExchangeRequest,
    request: Request,
    response: Response,
):
    """Direct authorization code exchange for native mobile applications and SPAs."""
    prov_instance = oauth_mgr.get_provider(provider)
    if not prov_instance:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"OAuth provider '{provider}' is not configured.",
        )

    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "")
    env_redirect = os.getenv(f"{provider.upper()}_REDIRECT_URI")
    default_redirect = env_redirect or f"{str(request.base_url).rstrip('/')}/api/v1/auth/oauth/{provider}/callback"
    redirect_uri = req.redirect_uri or default_redirect

    try:
        profile = await prov_instance.exchange_code(
            code=req.code,
            redirect_uri=redirect_uri,
            code_verifier=req.code_verifier,
        )
    except Exception as exc:
        await audit_log.record_auth_failure(
            identifier=f"oauth_{provider}",
            reason=str(exc),
            ip_address=client_ip,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"OAuth exchange failed: {str(exc)}",
        )

    return await resolve_or_create_oauth_user(
        profile,
        client_ip=client_ip,
        request=request,
        response=response,
        user_agent=user_agent,
    )
