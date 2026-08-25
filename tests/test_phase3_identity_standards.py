"""
Phase 3 Advanced Identity Standards Unit Tests (tests/test_phase3_identity_standards.py)
-----------------------------------------------------------------------------------------
Validates:
1. Token Family rotation, reuse detection, and cascade revocation.
2. Dual-Engine password hashing (Argon2id & Bcrypt) with cross-algorithm verification & auto-migration.
3. FIDO2 / WebAuthn passkey and security key registration and authentication ceremonies.
"""

import pytest
import jwt
from config import settings
from token_service import TokenService
from password_hasher import PasswordHasher
from webauthn_service import WebAuthnService, _b64url_encode, _b64url_decode
import json


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

    # 3. Attacker (or intercepted network packet) attempts to REPLAY rt1
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
    # If target algorithm is Argon2id, an existing Bcrypt hash MUST trigger needs_rehash=True
    assert hasher.needs_rehash(bcrypt_hash, target_algorithm="argon2id") is True
    # An up-to-date Argon2id hash should NOT need rehash
    assert hasher.needs_rehash(argon2_hash, target_algorithm="argon2id") is False

    # If target algorithm is Bcrypt, an existing Argon2id hash triggers needs_rehash=True
    assert hasher.needs_rehash(argon2_hash, target_algorithm="bcrypt") is True


def test_webauthn_passkey_ceremonies():
    """Verify WebAuthn registration and authentication ceremony challenge cycles."""
    webauthn = WebAuthnService(rp_id="localhost", rp_name="Test IAM")

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

    # 2. Complete Registration Response
    mock_client_data = {
        "type": "webauthn.create",
        "challenge": challenge,
        "origin": "http://localhost:3000",
    }
    client_data_b64 = _b64url_encode(json.dumps(mock_client_data).encode("utf-8"))
    cred_id = _b64url_encode(b"sample_passkey_cred_id_12345")

    reg_result = webauthn.verify_registration_response(
        user_id="usr_alice_1",
        client_data_json_b64=client_data_b64,
        credential_id_b64=cred_id,
        device_label="MacBook Touch ID",
    )

    assert reg_result["status"] == "SUCCESS"
    passkey = reg_result["passkey"]
    assert passkey["credential_id"] == cred_id
    assert passkey["device_label"] == "MacBook Touch ID"
    assert passkey["sign_count"] == 0

    # 3. Generate Authentication Options
    auth_options = webauthn.generate_authentication_options(
        user_id="usr_alice_1",
        user_passkeys=[passkey],
    )
    auth_challenge = auth_options["challenge"]
    assert auth_challenge is not None
    assert len(auth_options["allowCredentials"]) == 1

    # 4. Verify Authentication Response
    mock_auth_client_data = {
        "type": "webauthn.get",
        "challenge": auth_challenge,
        "origin": "http://localhost:3000",
    }
    auth_client_data_b64 = _b64url_encode(json.dumps(mock_auth_client_data).encode("utf-8"))

    auth_result = webauthn.verify_authentication_response(
        client_data_json_b64=auth_client_data_b64,
        credential_id_b64=cred_id,
        user_passkeys=[passkey],
    )

    assert auth_result["status"] == "SUCCESS"
    assert auth_result["user_id"] == "usr_alice_1"
    assert passkey["sign_count"] == 1
