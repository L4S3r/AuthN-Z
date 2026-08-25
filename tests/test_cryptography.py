"""
Cryptographic, Token & Session Services Unit Tests (tests/test_cryptography.py)
"""

import time
import pytest
from password_hasher import PasswordHasher
from token_service import TokenService
from mfa_provider import MFAProvider
from session_store import SessionStore


def test_password_hasher_hashing_and_verification():
    hasher = PasswordHasher()
    plain = "P@ssw0rdSecure!2026"
    hashed = hasher.hash(plain)

    assert hashed != plain
    assert hashed.startswith("$argon2id$") or hashed.startswith("$2b$")
    assert hasher.verify(plain, hashed) is True
    assert hasher.verify("WrongPassword", hashed) is False
    assert hasher.needs_rehash(hashed) is False


def test_password_hasher_empty_and_unicode():
    hasher = PasswordHasher()
    with pytest.raises(ValueError):
        hasher.hash("")

    unicode_pw = "🔒SecurePasswörd_日本語!123"
    hashed = hasher.hash(unicode_pw)
    assert hasher.verify(unicode_pw, hashed) is True


def test_token_service_access_and_refresh_tokens():
    svc = TokenService(secret_key="unit_test_secret_key_1234567890_32bytes")
    user_id = "test-user-uuid-1234"
    roles = ["developer", "editor"]

    access_token = svc.create_access_token(user_id, claims={"roles": roles})
    assert isinstance(access_token, str)

    decoded = svc.decode_and_verify(access_token)
    assert decoded["sub"] == user_id
    assert decoded["type"] == "access"
    assert decoded["roles"] == roles

    refresh_token = svc.create_refresh_token(user_id, claims={"roles": roles})
    decoded_refresh = svc.decode_and_verify(refresh_token)
    assert decoded_refresh["sub"] == user_id
    assert decoded_refresh["type"] == "refresh"


def test_token_service_revocation():
    svc = TokenService(secret_key="unit_test_secret_key_1234567890_32bytes")
    user_id = "test-user-revocation"

    token = svc.create_access_token(user_id)
    assert svc.is_token_revoked(token) is False

    svc.revoke_token(token)
    assert svc.is_token_revoked(token) is True

    with pytest.raises(ValueError):
        svc.decode_and_verify(token)


def test_mfa_provider_totp_and_backup_codes():
    mfa = MFAProvider()
    secret = mfa.generate_secret()
    assert len(secret) >= 16

    uri = mfa.get_provisioning_uri(secret, "admin@example.com", issuer="Auth N&Z")
    assert uri.startswith("otpauth://totp/")
    assert "admin%40example.com" in uri or "admin@example.com" in uri

    backup_codes = mfa.generate_backup_codes(count=5)
    assert len(backup_codes) == 5

    stored_hashes = [mfa._hash_backup_code(c) for c in backup_codes]
    first_code = backup_codes[0]

    verified, remaining_hashes = mfa.verify_and_consume_backup_code(first_code, stored_hashes)
    assert verified is True
    assert len(remaining_hashes) == 4

    # Single-use: same code cannot be consumed again
    verified2, _ = mfa.verify_and_consume_backup_code(first_code, remaining_hashes)
    assert verified2 is False


def test_session_store_lifecycle():
    store = SessionStore()
    user_id = "session-test-user-01"

    session_id = store.create_session(user_id, session_data={"roles": ["admin"]})
    assert session_id is not None

    sess = store.get_session(session_id)
    assert sess is not None
    assert sess["user_id"] == user_id
    assert sess["roles"] == ["admin"]

    store.delete_session(session_id)
    assert store.get_session(session_id) is None
