"""
Auth N&Z - FIDO2 / WebAuthn Passkeys & Hardware Keys Service (webauthn_service.py)
----------------------------------------------------------------------------------
Implements W3C WebAuthn Level 3 / FIDO2 ceremonies for biometric passkeys (Touch ID,
Face ID, Windows Hello) and physical security keys (YubiKey) with real cryptographic
attestation parsing, signature verification, and sign-counter clone detection.
"""

from typing import Any, Dict, List, Optional, Union
import base64
from datetime import datetime, timezone
import hashlib
import json
import logging
import secrets
import urllib.parse

from fido2 import cbor
from fido2.cose import ES256, RS256, EdDSA, CoseKey
from fido2.rpid import verify_rp_id
from fido2.server import Fido2Server
from fido2.webauthn import (
    AttestationObject,
    AttestedCredentialData,
    AuthenticatorData,
    CollectedClientData,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialParameters,
    PublicKeyCredentialRequestOptions,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialType,
    PublicKeyCredentialUserEntity,
    RegistrationResponse,
    AuthenticationResponse,
    UserVerificationRequirement,
)

from config import settings

logger = logging.getLogger("auth_nz.webauthn_service")


def _b64url_encode(data: bytes) -> str:
    """Encode bytes to base64url string without padding."""
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _b64url_decode(s: str) -> bytes:
    """Decode base64url string with flexible padding."""
    s = s.strip()
    padding = 4 - (len(s) % 4)
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def _to_webauthn_dict(obj: Any) -> Any:
    """Recursively convert FIDO2 dataclasses, bytes, and mappings to JSON-serializable dictionaries."""
    if isinstance(obj, bytes):
        return _b64url_encode(obj)
    elif hasattr(obj, "items"):
        return {k: _to_webauthn_dict(v) for k, v in obj.items() if v is not None}
    elif isinstance(obj, (list, tuple, set)):
        return [_to_webauthn_dict(x) for x in obj]
    elif hasattr(obj, "value"):
        return obj.value
    return obj


class WebAuthnService:
    def __init__(
        self,
        redis_client: Optional[Any] = None,
        rp_id: Optional[str] = None,
        rp_name: str = "Auth N&Z",
    ):
        self.rp_name = rp_name
        self.r = redis_client
        self._in_memory_challenges: Dict[str, Dict[str, Any]] = {}

        if rp_id:
            self.rp_id = rp_id
        else:
            try:
                parsed = urllib.parse.urlparse(settings.FRONTEND_URL)
                self.rp_id = parsed.hostname or "localhost"
            except Exception:
                self.rp_id = "localhost"

        # Initialize real Fido2Server with RP Entity and origin validation
        self.server = Fido2Server(
            PublicKeyCredentialRpEntity(id=self.rp_id, name=self.rp_name),
            verify_origin=self._verify_origin,
        )

    def _verify_origin(self, origin: str) -> bool:
        """Validate client origin against RP ID and configured allowed CORS origins."""
        if verify_rp_id(self.rp_id, origin):
            return True
        for allowed in settings.CORS_ALLOWED_ORIGINS:
            if origin.rstrip("/") == allowed.rstrip("/"):
                return True
        return False

    def _save_challenge(self, challenge_id: str, data: Dict[str, Any], ttl_seconds: int = 300) -> None:
        """Store pending WebAuthn ceremony session data with TTL."""
        if self.r is not None:
            try:
                self.r.set(f"webauthn_challenge:{challenge_id}", json.dumps(data), ex=ttl_seconds)
                return
            except Exception as exc:
                logger.warning("Failed to store WebAuthn challenge in Redis: %s", exc)
        self._in_memory_challenges[challenge_id] = {
            **data,
            "_expires_at": int(datetime.now(timezone.utc).timestamp()) + ttl_seconds,
        }

    def _consume_challenge(self, challenge_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve and immediately delete pending WebAuthn challenge."""
        if self.r is not None:
            try:
                raw = self.r.get(f"webauthn_challenge:{challenge_id}")
                if raw:
                    self.r.delete(f"webauthn_challenge:{challenge_id}")
                    return json.loads(raw)
            except Exception as exc:
                logger.warning("Failed to consume WebAuthn challenge from Redis: %s", exc)

        data = self._in_memory_challenges.pop(challenge_id, None)
        if data:
            now_ts = int(datetime.now(timezone.utc).timestamp())
            if data.get("_expires_at", 0) >= now_ts:
                return data
        return None

    def generate_registration_options(
        self,
        user_id: str,
        username: str,
        email: str,
        display_name: Optional[str] = None,
        existing_credentials: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Generate PublicKeyCredentialCreationOptions using Fido2Server.
        """
        user_id_bytes = user_id.encode("utf-8") if isinstance(user_id, str) else user_id
        user_entity = PublicKeyCredentialUserEntity(
            id=user_id_bytes,
            name=email or username,
            display_name=display_name or username or email,
        )

        exclude_descriptors = []
        if existing_credentials:
            for cred in existing_credentials:
                cred_id = cred.get("credential_id")
                if cred_id:
                    try:
                        exclude_descriptors.append(
                            PublicKeyCredentialDescriptor(
                                type=PublicKeyCredentialType.PUBLIC_KEY,
                                id=_b64url_decode(cred_id),
                            )
                        )
                    except Exception:
                        pass

        options, state = self.server.register_begin(
            user=user_entity,
            credentials=exclude_descriptors or None,
            user_verification=UserVerificationRequirement.PREFERRED,
        )

        challenge_str = state["challenge"]

        self._save_challenge(
            challenge_str,
            {
                "type": "registration",
                "user_id": user_id,
                "state": state,
            },
            ttl_seconds=300,
        )

        opts_dict = _to_webauthn_dict(options)
        pk_dict = opts_dict.get("publicKey", opts_dict)
        result = dict(pk_dict)
        result["publicKey"] = pk_dict
        return result

    def verify_registration_response(
        self,
        user_id: str,
        client_data_json_b64: str,
        attestation_object_b64: str,
        credential_id_b64: Optional[str] = None,
        device_label: Optional[str] = None,
        transports: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Parse attestationObject, cryptographically verify attestation and clientDataJSON,
        extract COSE public key, and store passkey record.
        """
        if not attestation_object_b64:
            raise ValueError("Missing attestationObject in WebAuthn registration response.")

        try:
            client_data_raw = _b64url_decode(client_data_json_b64)
            client_data = json.loads(client_data_raw.decode("utf-8"))
        except Exception as exc:
            raise ValueError(f"Invalid clientDataJSON encoding: {exc}")

        challenge_received = client_data.get("challenge")
        if not challenge_received:
            raise ValueError("Missing challenge in clientDataJSON.")

        session_data = self._consume_challenge(challenge_received)
        if (
            not session_data
            or session_data.get("type") != "registration"
            or session_data.get("user_id") != user_id
        ):
            raise ValueError("Invalid or expired WebAuthn registration challenge.")

        # Parse attestationObject to extract credential ID if not provided
        att_obj_bytes = _b64url_decode(attestation_object_b64)
        try:
            att_obj = AttestationObject(att_obj_bytes)
            if not att_obj.auth_data.credential_data:
                raise ValueError("AttestationObject does not contain credential data.")
            extracted_cred_id = att_obj.auth_data.credential_data.credential_id
            cred_id_str = _b64url_encode(extracted_cred_id)
        except Exception as exc:
            raise ValueError(f"Failed to parse AttestationObject: {exc}")

        effective_cred_id_b64 = credential_id_b64 or cred_id_str

        reg_payload = {
            "id": effective_cred_id_b64,
            "rawId": effective_cred_id_b64,
            "type": "public-key",
            "response": {
                "clientDataJSON": client_data_json_b64,
                "attestationObject": attestation_object_b64,
            },
        }

        try:
            auth_data = self.server.register_complete(session_data["state"], reg_payload)
        except Exception as exc:
            raise ValueError(f"Cryptographic attestation verification failed: {exc}")

        att_cred_data = auth_data.credential_data
        if not att_cred_data:
            raise ValueError("No attested credential data extracted from verified response.")

        public_key_b64 = _b64url_encode(bytes(att_cred_data))
        registered_at = datetime.now(timezone.utc).isoformat()

        passkey_record = {
            "credential_id": _b64url_encode(att_cred_data.credential_id),
            "public_key": public_key_b64,
            "device_label": device_label or "Biometric Passkey / Security Key",
            "created_at": registered_at,
            "last_used_at": registered_at,
            "sign_count": auth_data.counter,
            "transports": transports or ["internal", "hybrid", "usb"],
            "aaguid": str(att_cred_data.aaguid),
        }

        return {
            "status": "SUCCESS",
            "user_id": user_id,
            "passkey": passkey_record,
        }

    def generate_authentication_options(
        self,
        user_id: Optional[str] = None,
        user_passkeys: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Generate PublicKeyCredentialRequestOptions using Fido2Server.
        """
        allow_descriptors = []
        if user_passkeys:
            for pk in user_passkeys:
                cid = pk.get("credential_id")
                if cid:
                    try:
                        allow_descriptors.append(
                            PublicKeyCredentialDescriptor(
                                type=PublicKeyCredentialType.PUBLIC_KEY,
                                id=_b64url_decode(cid),
                                transports=pk.get("transports"),
                            )
                        )
                    except Exception:
                        pass

        options, state = self.server.authenticate_begin(
            credentials=allow_descriptors or None,
            user_verification=UserVerificationRequirement.PREFERRED,
        )

        challenge_str = state["challenge"]

        self._save_challenge(
            challenge_str,
            {
                "type": "authentication",
                "user_id": user_id,
                "state": state,
            },
            ttl_seconds=300,
        )

        opts_dict = _to_webauthn_dict(options)
        pk_dict = opts_dict.get("publicKey", opts_dict)
        result = dict(pk_dict)
        result["publicKey"] = pk_dict
        return result

    def verify_authentication_response(
        self,
        client_data_json_b64: str,
        credential_id_b64: str,
        authenticator_data_b64: str,
        signature_b64: str,
        user_passkeys: List[Dict[str, Any]],
        user_handle_b64: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Cryptographically verify WebAuthn assertion signature against stored COSE public key,
        validate challenge, origin, and perform sign-counter clone detection.
        """
        try:
            client_data_raw = _b64url_decode(client_data_json_b64)
            client_data = json.loads(client_data_raw.decode("utf-8"))
        except Exception as exc:
            raise ValueError(f"Invalid clientDataJSON encoding: {exc}")

        challenge_received = client_data.get("challenge")
        if not challenge_received:
            raise ValueError("Missing challenge in clientDataJSON.")

        session_data = self._consume_challenge(challenge_received)
        if not session_data or session_data.get("type") != "authentication":
            raise ValueError("Invalid or expired WebAuthn authentication challenge.")

        matched_passkey = None
        for pk in user_passkeys:
            if pk.get("credential_id") == credential_id_b64:
                matched_passkey = pk
                break

        if not matched_passkey:
            raise ValueError("Credential ID not registered for this account.")

        pub_key_b64 = matched_passkey.get("public_key")
        if not pub_key_b64:
            raise ValueError("No cryptographic public key registered for this credential.")

        try:
            stored_cred, _ = AttestedCredentialData.unpack_from(_b64url_decode(pub_key_b64))
        except Exception as exc:
            raise ValueError(f"Failed to unpack stored public key: {exc}")

        # Sign Counter Clone Detection
        try:
            incoming_auth_data = AuthenticatorData(_b64url_decode(authenticator_data_b64))
            incoming_counter = incoming_auth_data.counter
        except Exception as exc:
            raise ValueError(f"Invalid authenticatorData: {exc}")

        stored_counter = int(matched_passkey.get("sign_count", 0))

        # If either counter is > 0, incoming must be strictly greater than stored counter
        if incoming_counter > 0 or stored_counter > 0:
            if incoming_counter <= stored_counter:
                raise ValueError(
                    f"WebAuthn sign counter regression detected: incoming counter ({incoming_counter}) "
                    f"<= stored counter ({stored_counter}). Authenticator clone detected!"
                )

        auth_payload = {
            "id": credential_id_b64,
            "rawId": credential_id_b64,
            "type": "public-key",
            "response": {
                "clientDataJSON": client_data_json_b64,
                "authenticatorData": authenticator_data_b64,
                "signature": signature_b64,
                "userHandle": user_handle_b64,
            },
        }

        try:
            self.server.authenticate_complete(
                session_data["state"],
                [stored_cred],
                auth_payload,
            )
        except Exception as exc:
            raise ValueError(f"Cryptographic signature verification failed: {exc}")

        matched_passkey["last_used_at"] = datetime.now(timezone.utc).isoformat()
        matched_passkey["sign_count"] = incoming_counter if incoming_counter > 0 else stored_counter + 1

        return {
            "status": "SUCCESS",
            "matched_passkey": matched_passkey,
            "user_id": session_data.get("user_id"),
        }
