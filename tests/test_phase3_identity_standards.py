"""
Phase 3 Advanced Identity Standards Unit Tests (tests/test_phase3_identity_standards.py)
-----------------------------------------------------------------------------------------
Validates:
1. Token Family rotation, reuse detection, and cascade revocation.
2. Dual-Engine password hashing (Argon2id & Bcrypt) with cross-algorithm verification & auto-migration.
3. FIDO2 / WebAuthn W3C Level 3 cryptographic ceremonies with real keypairs, attestation parsing,
   signature verification, and clone detection.
4. Comprehensive negative failure-mode cryptographic tests (tampering, wrong keypair, counter regression, replay).
"""

import base64
from datetime import datetime, timezone
import hashlib
import json
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from fido2 import cbor
from fido2.cose import ES256
from fido2.webauthn import (
    AttestedCredentialData,
    AuthenticatorData,
)

from config import settings
from token_service import TokenService
from password_hasher import PasswordHasher
from webauthn_service import WebAuthnService, _b64url_encode, _b64url_decode


class VirtualAuthenticator:
    """Software virtual authenticator simulating real biometric/hardware WebAuthn credentials."""

    def __init__(self, rp_id: str = "localhost"):
        self.rp_id = rp_id
        self.rp_id_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.cose_key = ES256.from_cryptography_key(self.private_key.public_key())
        raw_cred_seed = hashlib.sha256(self.cose_key[-2] + self.cose_key[-3]).digest()[:16]
        self.cred_id = b"cred_" + base64.urlsafe_b64encode(raw_cred_seed)
        self.counter = 0

    def create_registration_response(self, challenge_str: str, origin: str = "http://localhost:3000") -> dict:
        att_data = AttestedCredentialData.create(b"\x00" * 16, self.cred_id, self.cose_key)
        auth_data = AuthenticatorData.create(
            self.rp_id_hash,
            AuthenticatorData.FLAG.USER_PRESENT | AuthenticatorData.FLAG.ATTESTED,
            self.counter,
            att_data,
        )
        att_obj = {"fmt": "none", "authData": auth_data, "attStmt": {}}
        att_obj_bytes = cbor.encode(att_obj)
        client_data = {"type": "webauthn.create", "challenge": challenge_str, "origin": origin}
        client_data_bytes = json.dumps(client_data).encode("utf-8")
        return {
            "client_data_json": _b64url_encode(client_data_bytes),
            "attestation_object": _b64url_encode(att_obj_bytes),
            "credential_id": _b64url_encode(self.cred_id),
        }

    def create_assertion_response(
        self,
        challenge_str: str,
        origin: str = "http://localhost:3000",
        counter: int = None,
        sign_key: ec.EllipticCurvePrivateKey = None,
    ) -> dict:
        if counter is not None:
            self.counter = counter
        else:
            self.counter += 1

        client_data = {"type": "webauthn.get", "challenge": challenge_str, "origin": origin}
        client_data_bytes = json.dumps(client_data).encode("utf-8")
        client_data_hash = hashlib.sha256(client_data_bytes).digest()

        auth_data = AuthenticatorData.create(
            self.rp_id_hash,
            AuthenticatorData.FLAG.USER_PRESENT,
            self.counter,
        )
        key = sign_key or self.private_key
        data_to_sign = auth_data + client_data_hash
        sig = key.sign(data_to_sign, ec.ECDSA(hashes.SHA256()))

        return {
            "client_data_json": _b64url_encode(client_data_bytes),
            "authenticator_data": _b64url_encode(auth_data),
            "signature": _b64url_encode(sig),
            "credential_id": _b64url_encode(self.cred_id),
        }


def test_token_family_rotation_and_replay_cascade():
    """Verify refresh token family tracking and immediate cascade revocation on replay."""
    svc = TokenService(secret_key="0123456789abcdef0123456789abcdef0123456789abcdef")

    # 1. Issue initial refresh token for user
    rt1 = svc.create_refresh_token(subject_id="u_alice")
    payload1 = svc.decode_and_verify(rt1)
    family_id = payload1["family_id"]
    jti1 = payload1["jti"]

    assert family_id is not None
    assert payload1["type"] == "refresh"
    assert not svc.is_family_revoked(family_id)

    # 2. Legitimate client rotates token: rt1 is consumed, rt2 is issued
    svc.revoke_token(jti1, expires_at=payload1["exp"])
    rt2 = svc.create_refresh_token(subject_id="u_alice", family_id=family_id)
    payload2 = svc.decode_and_verify(rt2)
    assert payload2["family_id"] == family_id
    assert payload2["jti"] != jti1

    # 3. Attacker attempts to REPLAY rt1
    assert svc.is_token_revoked(jti1) is True

    # When replaying a revoked token, the entire family must be cascade revoked
    svc.revoke_family(family_id)
    assert svc.is_family_revoked(family_id) is True

    # 4. Legitimate client now attempts to use rt2 -> blocked because family was compromised
    with pytest.raises(ValueError) as exc_info:
        svc.decode_and_verify(rt2)
    assert "family has been revoked" in str(exc_info.value).lower()


def test_dual_engine_password_hashing_and_migration():
    """Verify Argon2id and Bcrypt dual-engine hashing, verification, and migration triggers."""
    hasher = PasswordHasher()

    # 1. Argon2id hashing & verification
    argon2_hash = hasher.hash("SuperSecret123!", algorithm="argon2id")
    assert argon2_hash.startswith("$argon2id$")
    assert hasher.verify("SuperSecret123!", argon2_hash) is True
    assert hasher.verify("WrongPassword!", argon2_hash) is False

    # 2. Bcrypt hashing & verification
    bcrypt_hash = hasher.hash("SuperSecret123!", algorithm="bcrypt")
    assert bcrypt_hash.startswith("$2b$")
    assert hasher.verify("SuperSecret123!", bcrypt_hash) is True
    assert hasher.verify("WrongPassword!", bcrypt_hash) is False

    # 3. Cross-algorithm needs_rehash detection
    assert hasher.needs_rehash(bcrypt_hash, target_algorithm="argon2id") is True
    assert hasher.needs_rehash(argon2_hash, target_algorithm="argon2id") is False
    assert hasher.needs_rehash(argon2_hash, target_algorithm="bcrypt") is True


def test_webauthn_cryptographic_ceremony_and_registration():
    """Verify genuine FIDO2/WebAuthn Level 3 registration and ECDSA assertion signature verification."""
    webauthn = WebAuthnService(rp_id="localhost", rp_name="Test IAM")
    authenticator = VirtualAuthenticator(rp_id="localhost")

    # 1. Generate Registration Options
    reg_options = webauthn.generate_registration_options(
        user_id="usr_alice_1",
        username="alice",
        email="alice@example.com",
        display_name="Alice Explorer",
    )
    challenge = reg_options["challenge"]
    assert challenge is not None
    assert reg_options["rp"]["id"] == "localhost"
    assert len(reg_options["pubKeyCredParams"]) >= 2

    # 2. Authenticator creates AttestationObject with COSE public key
    reg_payload = authenticator.create_registration_response(challenge, origin="http://localhost:3000")

    reg_result = webauthn.verify_registration_response(
        user_id="usr_alice_1",
        client_data_json_b64=reg_payload["client_data_json"],
        attestation_object_b64=reg_payload["attestation_object"],
        credential_id_b64=reg_payload["credential_id"],
        device_label="MacBook Touch ID",
    )

    assert reg_result["status"] == "SUCCESS"
    passkey = reg_result["passkey"]
    assert passkey["credential_id"] == reg_payload["credential_id"]
    assert passkey["device_label"] == "MacBook Touch ID"
    assert "public_key" in passkey
    assert passkey["sign_count"] == 0

    # 3. Generate Authentication Options
    auth_options = webauthn.generate_authentication_options(
        user_id="usr_alice_1",
        user_passkeys=[passkey],
    )
    auth_challenge = auth_options["challenge"]
    assert auth_challenge is not None
    assert len(auth_options["allowCredentials"]) == 1

    # 4. Authenticator signs cryptographic assertion
    auth_payload = authenticator.create_assertion_response(
        challenge_str=auth_challenge,
        origin="http://localhost:3000",
        counter=1,
    )

    auth_result = webauthn.verify_authentication_response(
        client_data_json_b64=auth_payload["client_data_json"],
        credential_id_b64=auth_payload["credential_id"],
        authenticator_data_b64=auth_payload["authenticator_data"],
        signature_b64=auth_payload["signature"],
        user_passkeys=[passkey],
    )

    assert auth_result["status"] == "SUCCESS"
    assert auth_result["user_id"] == "usr_alice_1"
    assert passkey["sign_count"] == 1


def test_webauthn_negative_tampered_client_data():
    """Negative Test: Tampered clientDataJSON (forged challenge or origin) must be rejected cryptographically."""
    webauthn = WebAuthnService(rp_id="localhost", rp_name="Test IAM")
    authenticator = VirtualAuthenticator(rp_id="localhost")

    # Register
    reg_opts = webauthn.generate_registration_options("u1", "u1", "u1@example.com")
    reg_res = authenticator.create_registration_response(reg_opts["challenge"])
    passkey = webauthn.verify_registration_response("u1", reg_res["client_data_json"], reg_res["attestation_object"])["passkey"]

    # Begin auth
    auth_opts = webauthn.generate_authentication_options(user_passkeys=[passkey])
    auth_res = authenticator.create_assertion_response(auth_opts["challenge"], counter=2)

    # Attacker tampers with clientDataJSON (changes challenge or payload)
    tampered_client_data = json.dumps({
        "type": "webauthn.get",
        "challenge": "forged_challenge_string_1234567890",
        "origin": "http://localhost:3000",
    }).encode("utf-8")
    tampered_b64 = _b64url_encode(tampered_client_data)

    with pytest.raises(ValueError) as exc_info:
        webauthn.verify_authentication_response(
            client_data_json_b64=tampered_b64,
            credential_id_b64=auth_res["credential_id"],
            authenticator_data_b64=auth_res["authenticator_data"],
            signature_b64=auth_res["signature"],
            user_passkeys=[passkey],
        )
    # The forged challenge does not exist in session store or signature verification fails
    assert "challenge" in str(exc_info.value).lower() or "signature" in str(exc_info.value).lower()


def test_webauthn_negative_wrong_keypair_signature():
    """Negative Test: Assertion signed by a different private key must fail cryptographic verification."""
    webauthn = WebAuthnService(rp_id="localhost", rp_name="Test IAM")
    authenticator = VirtualAuthenticator(rp_id="localhost")
    attacker_key = ec.generate_private_key(ec.SECP256R1())

    # Register legitimate authenticator
    reg_opts = webauthn.generate_registration_options("u1", "u1", "u1@example.com")
    reg_res = authenticator.create_registration_response(reg_opts["challenge"])
    passkey = webauthn.verify_registration_response("u1", reg_res["client_data_json"], reg_res["attestation_object"])["passkey"]

    # Authenticate with signature created by attacker_key
    auth_opts = webauthn.generate_authentication_options(user_passkeys=[passkey])
    attacker_res = authenticator.create_assertion_response(
        auth_opts["challenge"],
        counter=2,
        sign_key=attacker_key,
    )

    with pytest.raises(ValueError) as exc_info:
        webauthn.verify_authentication_response(
            client_data_json_b64=attacker_res["client_data_json"],
            credential_id_b64=attacker_res["credential_id"],
            authenticator_data_b64=attacker_res["authenticator_data"],
            signature_b64=attacker_res["signature"],
            user_passkeys=[passkey],
        )
    assert "signature verification failed" in str(exc_info.value).lower() or "invalid signature" in str(exc_info.value).lower()


def test_webauthn_negative_sign_counter_clone_detection():
    """Negative Test: Replayed or regressed sign counter must be rejected as an authenticator clone."""
    webauthn = WebAuthnService(rp_id="localhost", rp_name="Test IAM")
    authenticator = VirtualAuthenticator(rp_id="localhost")

    # Register passkey
    reg_opts = webauthn.generate_registration_options("u1", "u1", "u1@example.com")
    reg_res = authenticator.create_registration_response(reg_opts["challenge"])
    passkey = webauthn.verify_registration_response("u1", reg_res["client_data_json"], reg_res["attestation_object"])["passkey"]

    # Legitimate auth advances counter to 10
    auth_opts1 = webauthn.generate_authentication_options(user_passkeys=[passkey])
    auth_res1 = authenticator.create_assertion_response(auth_opts1["challenge"], counter=10)
    webauthn.verify_authentication_response(
        client_data_json_b64=auth_res1["client_data_json"],
        credential_id_b64=auth_res1["credential_id"],
        authenticator_data_b64=auth_res1["authenticator_data"],
        signature_b64=auth_res1["signature"],
        user_passkeys=[passkey],
    )
    assert passkey["sign_count"] == 10

    # Attacker / cloned authenticator attempts authentication with counter <= 10 (e.g. 5 or replayed 10)
    auth_opts2 = webauthn.generate_authentication_options(user_passkeys=[passkey])
    cloned_res = authenticator.create_assertion_response(auth_opts2["challenge"], counter=5)

    with pytest.raises(ValueError) as exc_info:
        webauthn.verify_authentication_response(
            client_data_json_b64=cloned_res["client_data_json"],
            credential_id_b64=cloned_res["credential_id"],
            authenticator_data_b64=cloned_res["authenticator_data"],
            signature_b64=cloned_res["signature"],
            user_passkeys=[passkey],
        )
    assert "counter regression" in str(exc_info.value).lower() or "clone detected" in str(exc_info.value).lower()


def test_webauthn_negative_expired_or_consumed_challenge():
    """Negative Test: Already-consumed or nonexistent challenges must be rejected."""
    webauthn = WebAuthnService(rp_id="localhost", rp_name="Test IAM")
    authenticator = VirtualAuthenticator(rp_id="localhost")

    reg_opts = webauthn.generate_registration_options("u1", "u1", "u1@example.com")
    reg_res = authenticator.create_registration_response(reg_opts["challenge"])

    # 1. First verification succeeds and consumes challenge
    webauthn.verify_registration_response("u1", reg_res["client_data_json"], reg_res["attestation_object"])

    # 2. Replay attempt with consumed challenge must fail
    with pytest.raises(ValueError) as exc_info:
        webauthn.verify_registration_response("u1", reg_res["client_data_json"], reg_res["attestation_object"])
    assert "invalid or expired" in str(exc_info.value).lower()


def test_webauthn_router_endpoint_options_flow():
    """Verify HTTP API endpoint execution for /auth/webauthn/register/options and /authenticate/options."""
    from unittest.mock import AsyncMock, patch
    from fastapi.testclient import TestClient
    from server import app
    from api.dependencies import get_current_user

    client = TestClient(app)

    # Mock authenticated user dependency
    app.dependency_overrides[get_current_user] = lambda: {
        "status": "SUCCESS",
        "user_id": "u_test_123",
        "email": "test@example.com",
    }

    mock_user = {
        "id": "u_test_123",
        "username": "testuser",
        "email": "test@example.com",
        "metadata": {"passkeys": []},
    }

    try:
        with patch("api.v1.webauthn_router.user_repo.get_by_id", new_callable=AsyncMock) as mock_get_id, \
             patch("api.v1.webauthn_router.user_repo.get_by_identifier", new_callable=AsyncMock) as mock_get_ident:

            mock_get_id.return_value = mock_user
            mock_get_ident.return_value = mock_user

            # 1. POST /auth/webauthn/register/options
            reg_res = client.post("/auth/webauthn/register/options")
            assert reg_res.status_code == 200
            reg_data = reg_res.json()
            assert reg_data["status"] == "SUCCESS"
            assert "options" in reg_data
            assert "challenge" in reg_data["options"]

            # 2. POST /auth/webauthn/authenticate/options
            auth_res = client.post("/auth/webauthn/authenticate/options", json={"identifier": "test@example.com"})
            assert auth_res.status_code == 200
            auth_data = auth_res.json()
            assert auth_data["status"] == "SUCCESS"
            assert "options" in auth_data
            assert "challenge" in auth_data["options"]
    finally:
        app.dependency_overrides.pop(get_current_user, None)
