"""
Component Role: Authenticator
----------------------------
This component acts as the primary orchestrator for verifying user identity across various
mechanisms (primary credentials, stateless bearer tokens, stateful session cookies, and MFA challenges).

System Relationship:
The Authenticator sits at the front entry door of the authentication layer. It coordinates between
the UserRepository (to look up user identity and account status), the PasswordHasher (to verify secrets),
the MFAProvider (to handle second-factor verification), and the TokenService / SessionStore (to issue
authenticated artifacts on success). It also reports outcomes to the AuditLogger.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional
from datetime import datetime,timezone,timedelta
import secrets
from typing import Any,Dict,Optional
import uuid
import json

from password_hasher import PasswordHasher
from user_repository import UserRepository
from token_service import TokenService
from session_store import SessionStore
from mfa_provider import MFAProvider
from device_trust_service import DeviceTrustService


class abstractAuthenticator(ABC):
    """Abstract interface orchestrating authentication flows across credentials, sessions, tokens, and MFA."""

    @abstractmethod
    def authenticate_credentials(
        self,
        identifier: str,
        plain_password: str,
        trusted_device_token: Optional[str] = None,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Verify primary identity credentials (username/email and password).

        Args:
            identifier: The username, email, or identity handle submitted by the user.
            plain_password: The raw password submitted by the user.

        Returns:
            A dictionary describing the authentication outcome. For example:
            - On success (MFA not required): {'status': 'SUCCESS', 'user_id': '...', 'user_data': {...}}
            - On success (MFA required): {'status': 'MFA_REQUIRED', 'user_id': '...', 'challenge_id': '...'}
            - On failure: {'status': 'FAILED', 'reason': 'INVALID_CREDENTIALS'}

        Edge Cases to Consider:
            - Account locked, suspended, or inactive states.
            - Rate limiting / brute-force throttling across repeated failures.
            - Consistent response times to avoid user enumeration via timing discrepancies.
            - Identifying whether the user's password hash requires upgrading upon successful verification.
        """
        ...

    @abstractmethod
    def authenticate_token(self, token: str) -> Dict[str, Any]:
        """
        Validate a bearer token and produce the authenticated subject's execution context.

        Args:
            token: The raw access token extracted from the Authorization HTTP header.

        Returns:
            A dictionary containing the authenticated subject's context (e.g., {'status': 'SUCCESS', 'user_id': '...', 'claims': {...}}),
            or a failure status dictionary if invalid, expired, or revoked.

        Edge Cases to Consider:
            - Stripping 'Bearer ' prefix correctly if included.
            - Blacklisted / revoked tokens.
            - Handling token expiration vs. invalid signature distinctly in telemetry while returning safe errors to callers.
        """
        ...

    @abstractmethod
    def authenticate_session(self, session_id: str) -> Dict[str, Any]:
        """
        Validate an active session ID and resolve the current authenticated user context.

        Args:
            session_id: The session ID cookie string passed by the client.

        Returns:
            A dictionary containing the session data and associated user identifier, or failure details if expired or invalid.

        Edge Cases to Consider:
            - Inactive or expired session IDs.
            - Automatic sliding session TTL extension upon valid access.
            - Handling concurrent access by suspended accounts.
        """
        ...

    @abstractmethod
    def initiate_mfa_challenge(
        self,
        user_id: str,
        challenge_type: str = "totp",
    ) -> Dict[str, Any]:
        """
        Create and record an active pending MFA challenge during an in-progress authentication flow.

        Args:
            user_id: The identifier of the user who passed primary authentication.
            challenge_type: The type of secondary factor (e.g., 'totp', 'sms_otp', 'email_otp').

        Returns:
            A dictionary containing challenge metadata (e.g., challenge_id, expiry_timestamp, masked destination).

        Edge Cases to Consider:
            - Preventing duplicate concurrent challenges from spamming users.
            - Setting an appropriate short lifetime for the challenge (e.g., 3-5 minutes).
            - Verifying that the user actually has the requested factor enrolled.
        """
        ...

    @abstractmethod
    def complete_mfa_challenge(
        self,
        user_id: str,
        challenge_id: str,
        response_code: str,
        remember_device: bool = False,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Validate a submitted second-factor code to finalize an authentication workflow.

        Args:
            user_id: The identifier of the user completing the challenge.
            challenge_id: The identifier of the pending challenge being answered.
            response_code: The 6-8 digit code or backup code submitted by the user.
            remember_device: Whether to issue and persist a 30-day trusted device token.
            user_agent: The browser User-Agent header of the caller.
            ip_address: The client IP address.

        Returns:
            A dictionary indicating final authentication success (with user context/tokens) or failure with retry details.

        Edge Cases to Consider:
            - Maximum attempt limits per challenge before invalidating the entire login attempt.
            - Expired challenges.
            - Distinguishing between standard TOTP codes and emergency backup codes.
        """
        ...

import logging

logger = logging.getLogger("auth_nz.authenticator")

DUMMY_BCRYPT_HASH = "$2b$12$e8YkZ7G4t9I1mPqLwK9ZCe8YkZ7G4t9I1mPqLwK9ZCe8YkZ7G4t9I"


class Authenticator(abstractAuthenticator):
    def __init__(
        self,
        user_repo: Optional[UserRepository] = None,
        hasher: Optional[PasswordHasher] = None,
        token_service: Optional[TokenService] = None,
        session_store: Optional[SessionStore] = None,
        mfa_provider: Optional[MFAProvider] = None,
        device_trust_service: Optional[DeviceTrustService] = None,
    ):
        self.user_repo = user_repo or UserRepository()
        self.hasher = hasher or PasswordHasher()
        self.token_service = token_service or TokenService()
        self.session_store = session_store or SessionStore()
        self.mfa_provider = mfa_provider or MFAProvider()
        self.device_trust_service = device_trust_service or DeviceTrustService()
        self._pending_mfa_challenges: Dict[str, Dict[str, Any]] = {}
        self._in_memory_failed_attempts: Dict[str, int] = {}
        self._in_memory_lockouts: Dict[str, int] = {}

    def _get_redis(self):
        """Helper to get active Redis connection if available."""
        if self.session_store and getattr(self.session_store, "r", None):
            return self.session_store.r
        return None

    def _check_account_lockout(self, user_id: str) -> Optional[int]:
        """Check if account is currently locked. Returns remaining seconds if locked, else None."""
        r = self._get_redis()
        lock_key = f"lockout:{user_id}"
        if r is not None:
            try:
                ttl = r.ttl(lock_key)
                if ttl > 0:
                    return ttl
            except Exception:
                pass
        
        lock_exp = self._in_memory_lockouts.get(user_id)
        if lock_exp:
            now_ts = int(datetime.now(timezone.utc).timestamp())
            if lock_exp > now_ts:
                return lock_exp - now_ts
            else:
                self._in_memory_lockouts.pop(user_id, None)
        return None

    def _record_failed_attempt(self, user_id: str) -> Dict[str, Any]:
        """Increment failed attempts for a user; apply exponential lockout if threshold exceeded."""
        r = self._get_redis()
        fail_key = f"failed_logins:{user_id}"
        lock_key = f"lockout:{user_id}"
        window_seconds = 300  # 5 minute sliding window for counting failures

        attempts = 1
        if r is not None:
            try:
                attempts = r.incr(fail_key)
                if attempts == 1:
                    r.expire(fail_key, window_seconds)
            except Exception:
                attempts = self._in_memory_failed_attempts.get(user_id, 0) + 1
                self._in_memory_failed_attempts[user_id] = attempts
        else:
            attempts = self._in_memory_failed_attempts.get(user_id, 0) + 1
            self._in_memory_failed_attempts[user_id] = attempts

        locked = False
        newly_locked = False
        lockout_seconds = 0
        if attempts >= 5:
            # 5-9 attempts: 15 mins (900s); 10+ attempts: 60 mins (3600s)
            lockout_seconds = 900 if attempts < 10 else 3600
            locked = True
            if attempts == 5 or attempts == 10:
                newly_locked = True
            if r is not None:
                try:
                    r.set(lock_key, str(attempts), ex=lockout_seconds)
                except Exception:
                    pass
            now_ts = int(datetime.now(timezone.utc).timestamp())
            self._in_memory_lockouts[user_id] = now_ts + lockout_seconds

        return {
            "locked": locked,
            "newly_locked": newly_locked,
            "attempts": attempts,
            "lockout_seconds": lockout_seconds,
        }

    def _clear_failed_attempts(self, user_id: str) -> None:
        """Clear failed login attempts and lockout state upon successful authentication or password reset."""
        r = self._get_redis()
        if r is not None:
            try:
                r.delete(f"failed_logins:{user_id}", f"lockout:{user_id}")
            except Exception:
                pass
        self._in_memory_failed_attempts.pop(user_id, None)
        self._in_memory_lockouts.pop(user_id, None)

    def unlock_account(self, user_id: str) -> bool:
        """Explicitly unlock an account by clearing lockout flags."""
        self._clear_failed_attempts(user_id)
        return True

    def _get_mfa_challenge(self, challenge_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve challenge data from Redis with fallback to in-memory store."""
        if self.session_store and getattr(self.session_store, "r", None):
            try:
                raw = self.session_store.r.get(f"mfa_challenge:{challenge_id}")
                if raw:
                    return json.loads(raw)
            except Exception as exc:
                logger.warning(
                    "Failed to query MFA challenge from Redis (%s). Falling back to in-memory dictionary.",
                    exc,
                )
        return self._pending_mfa_challenges.get(challenge_id)

    def _save_mfa_challenge(self, challenge_id: str, data: Dict[str, Any], ttl_seconds: int = 300) -> None:
        """Store challenge data in Redis with 5-minute TTL, fallback to memory."""
        if self.session_store and getattr(self.session_store, "r", None):
            try:
                self.session_store.r.set(f"mfa_challenge:{challenge_id}", json.dumps(data), ex=ttl_seconds)
                return
            except Exception as exc:
                logger.warning(
                    "Failed to store MFA challenge in Redis (%s). Falling back to in-memory dictionary.",
                    exc,
                )
        self._pending_mfa_challenges[challenge_id] = data

    def _delete_mfa_challenge(self, challenge_id: str) -> None:
        """Purge completed or expired challenge from Redis and memory."""
        if self.session_store and getattr(self.session_store, "r", None):
            try:
                self.session_store.r.delete(f"mfa_challenge:{challenge_id}")
            except Exception as exc:
                logger.warning("Failed to delete MFA challenge from Redis (%s).", exc)
        self._pending_mfa_challenges.pop(challenge_id, None)


    def authenticate_credentials(
        self,
        identifier: str,
        plain_password: str,
        trusted_device_token: Optional[str] = None,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Verify primary identity credentials (username/email and password) with lockout protection."""
        user = self.user_repo.get_by_identifier(identifier)

        # Constant-time side-channel mitigation: verify against dummy hash if user is absent
        if not user:
            self.hasher.verify(plain_password, DUMMY_BCRYPT_HASH)
            return {
                "status": "FAILED",
                "reason": "INVALID_CREDENTIALS",
            }

        # Check if account is active
        if not user.get("is_active", 1):
            return {
                "status": "FAILED",
                "reason": "ACCOUNT_INACTIVE",
            }

        # Check if account is currently locked due to prior excessive failed attempts
        remaining_lock = self._check_account_lockout(user["id"])
        if remaining_lock is not None and remaining_lock > 0:
            remaining_mins = max(1, (remaining_lock + 59) // 60)
            return {
                "status": "LOCKED",
                "reason": "ACCOUNT_LOCKED",
                "user_id": user["id"],
                "lockout_seconds": remaining_lock,
                "lockout_minutes": remaining_mins,
                "newly_locked": False,
            }

        # Verify password
        if not self.hasher.verify(plain_password, user["hashed_password"]):
            lockout_info = self._record_failed_attempt(user["id"])
            if lockout_info["locked"]:
                remaining_mins = max(1, (lockout_info["lockout_seconds"] + 59) // 60)
                return {
                    "status": "LOCKED",
                    "reason": "ACCOUNT_LOCKED",
                    "user_id": user["id"],
                    "lockout_seconds": lockout_info["lockout_seconds"],
                    "lockout_minutes": remaining_mins,
                    "attempts": lockout_info["attempts"],
                    "newly_locked": lockout_info["newly_locked"],
                }
            return {
                "status": "FAILED",
                "reason": "INVALID_CREDENTIALS",
                "attempts": lockout_info["attempts"],
                "remaining_attempts": max(0, 5 - lockout_info["attempts"]),
            }

        # Password is correct! Clear failed attempts
        self._clear_failed_attempts(user["id"])

        # Check if password needs rehash
        if self.hasher.needs_rehash(user["hashed_password"]):
            new_hash = self.hasher.hash(plain_password)
            self.user_repo.update_user(user["id"], {"hashed_password": new_hash})

        # Check MFA requirement
        metadata = user.get("metadata", {})
        if isinstance(metadata, str):
            try:
                metadata = json.loads(metadata)
            except Exception:
                metadata = {}

        mfa_skipped = False
        trusted_dev_rec = None
        if metadata.get("mfa_enabled") and metadata.get("mfa_secret"):
            if trusted_device_token and self.device_trust_service:
                trusted_dev_rec = self.device_trust_service.verify_trusted_device(
                    user_id=user["id"],
                    raw_token=trusted_device_token,
                    user_agent=user_agent,
                    ip_address=ip_address,
                )
                if trusted_dev_rec:
                    mfa_skipped = True

            if not mfa_skipped:
                challenge = self.initiate_mfa_challenge(user["id"], challenge_type="totp")
                return {
                    "status": "MFA_REQUIRED",
                    "user_id": user["id"],
                    "challenge_id": challenge["challenge_id"],
                }

        # Issue tokens and session
        roles = user.get("roles", [])
        if isinstance(roles, str):
            try:
                roles = json.loads(roles)
            except Exception:
                roles = []

        access_token = self.token_service.create_access_token(user["id"], claims={"roles": roles})
        refresh_token = self.token_service.create_refresh_token(user["id"], claims={"roles": roles})
        session_id = self.session_store.create_session(user["id"], session_data={"roles": roles})

        # Sanitize metadata for response
        safe_metadata = dict(metadata) if isinstance(metadata, dict) else {}
        safe_metadata.pop("mfa_secret", None)
        safe_metadata.pop("backup_codes", None)

        resp = {
            "status": "SUCCESS",
            "user_id": user["id"],
            "access_token": access_token,
            "refresh_token": refresh_token,
            "session_id": session_id,
            "user": {
                "id": user["id"],
                "username": user["username"],
                "email": user["email"],
                "roles": roles,
                "metadata": safe_metadata,
            },
        }
        if mfa_skipped and trusted_dev_rec:
            resp["mfa_skipped"] = True
            resp["trusted_device"] = {
                "id": trusted_dev_rec.get("id"),
                "device_label": trusted_dev_rec.get("device_label"),
                "created_at": trusted_dev_rec.get("created_at"),
                "expires_at": trusted_dev_rec.get("expires_at"),
            }

        return resp


    def authenticate_token(self, token: str) -> Dict[str, Any]:
        """Validate a bearer token and produce the authenticated subject's execution context."""
        if not token or not isinstance(token, str):
            return {
                "status": "FAILED",
                "reason": "MISSING_TOKEN",
            }

        # Sanitize bearer prefix
        clean_token = token.strip()
        if clean_token.lower().startswith("bearer "):
            clean_token = clean_token[7:].strip()

        # Decode and verify claims
        try:
            payload = self.token_service.decode_and_verify(clean_token)
        except ValueError as e:
            error_message = str(e).lower()
            if "expired" in error_message:
                reason = "TOKEN_EXPIRED"
            elif "revoked" in error_message:
                reason = "TOKEN_REVOKED"
            else:
                reason = "TOKEN_INVALID"
            return {
                "status": "FAILED",
                "reason": reason,
                "detail": str(e),
            }
        except Exception as e:
            return {
                "status": "FAILED",
                "reason": "TOKEN_ERROR",
                "detail": str(e),
            }

        # Ensure token is access token not refresh token
        if payload.get("type") != "access":
            return {
                "status": "FAILED",
                "reason": "INVALID_TOKEN_TYPE",
            }

        # Check if user account is still active in the database
        user_id = payload.get("sub")
        user = self.user_repo.get_by_id(user_id)
        if not user:
            return {
                "status": "FAILED",
                "reason": "USER_NOT_FOUND",
            }
        if not user.get("is_active", 1):
            return {
                "status": "FAILED",
                "reason": "ACCOUNT_INACTIVE",
            }

        return {
            "status": "SUCCESS",
            "user_id": user_id,
            "username": user.get("username"),
            "roles": payload.get("roles", user.get("roles", [])),
            "claims": payload,
        }

    def authenticate_session(self, session_id: str) -> Dict[str, Any]:
        """Validate an active session ID and resolve the current authenticated user context."""
        if not session_id or not isinstance(session_id, str):
            return {
                "status": "FAILED",
                "reason": "MISSING_SESSION_ID",
            }

        session = self.session_store.get_session(session_id)
        if not session:
            return {
                "status": "FAILED",
                "reason": "SESSION_EXPIRED",
            }

        user_id = session.get("user_id")
        user = self.user_repo.get_by_id(user_id)
        if not user:
            return {
                "status": "FAILED",
                "reason": "USER_NOT_FOUND",
            }
        if not user.get("is_active", 1):
            return {
                "status": "FAILED",
                "reason": "ACCOUNT_INACTIVE",
            }

        self.session_store.refresh_session_ttl(session_id)
        return {
            "status": "SUCCESS",
            "user_id": user_id,
            "username": user.get("username"),
            "created_at": session.get("created_at"),
            "data": session.get("data", {}),
        }

    def initiate_mfa_challenge(
        self,
        user_id: str,
        challenge_type: str = "totp",
    ) -> Dict[str, Any]:
        """Create and record an active pending MFA challenge in Redis with 5-minute TTL."""
        user = self.user_repo.get_by_id(user_id)
        if not user:
            raise ValueError("User not found")

        metadata = user.get("metadata", {})
        if isinstance(metadata, str):
            try:
                metadata = json.loads(metadata)
            except Exception:
                metadata = {}

        if not metadata.get("mfa_secret"):
            raise ValueError("User does not have MFA configured")

        challenge_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(minutes=5)

        challenge_data = {
            "user_id": str(user_id),
            "challenge_type": challenge_type,
            "created_at": now.isoformat(),
            "expires_at": expires_at.isoformat(),
            "attempts": 0,
        }

        # Store challenge in Redis with 300s TTL
        self._save_mfa_challenge(challenge_id, challenge_data, ttl_seconds=300)

        return {
            "challenge_id": challenge_id,
            "expires_at": expires_at.isoformat(),
            "challenge_type": challenge_type,
        }

    def complete_mfa_challenge(
        self,
        user_id: str,
        challenge_id: str,
        response_code: str,
        remember_device: bool = False,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Validate a submitted second-factor code against the Redis-backed challenge."""
        user = self.user_repo.get_by_id(user_id)
        if not user:
            return {
                "status": "FAILED",
                "reason": "USER_NOT_FOUND",
            }

        challenge = self._get_mfa_challenge(challenge_id)
        if not challenge:
            return {
                "status": "FAILED",
                "reason": "MFA_CHALLENGE_DOES_NOT_EXIST",
            }

        if challenge["user_id"] != str(user_id):
            return {
                "status": "FAILED",
                "reason": "CHALLENGE_USER_MISMATCH",
            }

        now = datetime.now(timezone.utc)
        expires_at = datetime.fromisoformat(challenge["expires_at"])
        if now > expires_at:
            self._delete_mfa_challenge(challenge_id)
            return {
                "status": "FAILED",
                "reason": "MFA_CHALLENGE_EXPIRED",
            }

        metadata = user.get("metadata", {})
        if isinstance(metadata, str):
            try:
                metadata = json.loads(metadata)
            except Exception:
                metadata = {}

        if not metadata.get("mfa_secret"):
            return {
                "status": "FAILED",
                "reason": "MFA_NOT_CONFIGURED",
            }

        backup_codes = metadata.get("backup_codes", [])
        is_valid = self.mfa_provider.verify_totp_code(metadata["mfa_secret"], response_code)

        if not is_valid and backup_codes:
            is_valid, remaining_codes = self.mfa_provider.verify_and_consume_backup_code(
                response_code, backup_codes
            )
            if is_valid:
                metadata["backup_codes"] = remaining_codes
                self.user_repo.update_user(user["id"], {"metadata": metadata})

        if not is_valid:
            challenge["attempts"] += 1
            if challenge["attempts"] >= 3:
                self._delete_mfa_challenge(challenge_id)
                return {
                    "status": "FAILED",
                    "reason": "MFA_ATTEMPTS_EXCEEDED",
                }
            self._save_mfa_challenge(challenge_id, challenge, ttl_seconds=300)
            return {
                "status": "FAILED",
                "reason": "INVALID_MFA_CODE",
            }

        # Challenge passed: delete challenge record
        self._delete_mfa_challenge(challenge_id)

        roles = user.get("roles", [])
        if isinstance(roles, str):
            try:
                roles = json.loads(roles)
            except Exception:
                roles = []

        access_token = self.token_service.create_access_token(user["id"], claims={"roles": roles})
        refresh_token = self.token_service.create_refresh_token(user["id"], claims={"roles": roles})
        session_id = self.session_store.create_session(user["id"], session_data={"roles": roles})

        # Provision trusted device if requested
        raw_dev_token = None
        dev_rec = None
        if remember_device and self.device_trust_service:
            dev_rec, raw_dev_token = self.device_trust_service.create_trusted_device(
                user_id=user["id"],
                user_agent=user_agent,
                ip_address=ip_address,
            )

        # Sanitize metadata for response
        safe_metadata = dict(metadata) if isinstance(metadata, dict) else {}
        safe_metadata.pop("mfa_secret", None)
        safe_metadata.pop("backup_codes", None)

        resp = {
            "status": "SUCCESS",
            "user_id": user["id"],
            "access_token": access_token,
            "refresh_token": refresh_token,
            "session_id": session_id,
            "user": {
                "id": user["id"],
                "username": user["username"],
                "email": user["email"],
                "roles": roles,
                "metadata": safe_metadata,
            },
        }
        if dev_rec:
            resp["trusted_device"] = {
                "id": dev_rec.get("id"),
                "device_label": dev_rec.get("device_label"),
                "created_at": dev_rec.get("created_at"),
                "expires_at": dev_rec.get("expires_at"),
            }
        if raw_dev_token:
            resp["_raw_device_token"] = raw_dev_token

        return resp

        
