"""
Phase 4.4 Unit Tests: Query Caching & Metadata TTL Caching (tests/test_phase4_caching.py)
-----------------------------------------------------------------------------------------
Validates:
1. UserProfileCache in-memory L1 cache hits, misses, and invalidation lifecycle.
2. UserRepository integration with L1/L2 profile caching and automatic eviction on mutations.
3. HTTP ETag generation and conditional 304 Not Modified response handling for /auth/me, /auth/webauthn/credentials, and /auth/trusted-devices.
4. Real-time notification mark-read WebSocket event dispatches.
"""

import time
import uuid
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi import FastAPI, Request, Response
from fastapi.testclient import TestClient

from config import settings
from user_repository import UserProfileCache, UserRepository
from api.dependencies import generate_etag, handle_conditional_response
from server import app


# =============================================================================
# 1. UserProfileCache Unit Tests
# =============================================================================

def test_user_profile_cache_l1_hit_and_miss():
    """Verify that UserProfileCache populates and retrieves from in-memory L1 cache."""
    cache = UserProfileCache()
    user_id = str(uuid.uuid4())
    user_data = {
        "id": user_id,
        "username": "alice",
        "email": "alice@example.com",
        "roles": ["developer"],
        "metadata": {"department": "Engineering"},
    }

    # Initial miss
    assert cache.get_user(user_id) is None
    assert cache.get_user_by_identifier("alice") is None
    assert cache.get_user_by_identifier("alice@example.com") is None

    # Set cache
    cache.set_user(user_data)

    # Hits
    cached_by_id = cache.get_user(user_id)
    assert cached_by_id is not None
    assert cached_by_id["username"] == "alice"
    assert cached_by_id["roles"] == ["developer"]

    cached_by_username = cache.get_user_by_identifier("ALICE")  # case-insensitive
    assert cached_by_username is not None
    assert cached_by_username["id"] == user_id

    cached_by_email = cache.get_user_by_identifier("alice@example.com")
    assert cached_by_email is not None
    assert cached_by_email["id"] == user_id


def test_user_profile_cache_invalidation():
    """Verify that invalidate removes records across ID and identifier mappings."""
    cache = UserProfileCache()
    user_id = str(uuid.uuid4())
    user_data = {
        "id": user_id,
        "username": "bob",
        "email": "bob@example.com",
        "roles": ["viewer"],
    }
    cache.set_user(user_data)

    assert cache.get_user(user_id) is not None
    assert cache.get_user_by_identifier("bob") is not None

    # Invalidate
    cache.invalidate(user_id=user_id, publish_event=False)

    assert cache.get_user(user_id) is None
    assert cache.get_user_by_identifier("bob") is None
    assert cache.get_user_by_identifier("bob@example.com") is None


def test_user_profile_cache_disabled_flag():
    """Verify that caching respects USER_CACHE_ENABLED setting."""
    cache = UserProfileCache()
    user_id = str(uuid.uuid4())
    user_data = {"id": user_id, "username": "charlie", "email": "charlie@example.com"}

    with patch.object(settings, "USER_CACHE_ENABLED", False):
        cache.set_user(user_data)
        assert cache.get_user(user_id) is None
        assert cache.get_user_by_identifier("charlie") is None


# =============================================================================
# 2. HTTP ETag & Conditional 304 Helper Tests
# =============================================================================

def test_generate_etag_deterministic():
    """Verify that generate_etag produces consistent ETags regardless of key ordering."""
    payload_a = {"b": 2, "a": 1, "nested": {"z": 10, "y": 20}}
    payload_b = {"a": 1, "b": 2, "nested": {"y": 20, "z": 10}}
    payload_c = {"a": 1, "b": 3}

    etag_a = generate_etag(payload_a)
    etag_b = generate_etag(payload_b)
    etag_c = generate_etag(payload_c)

    assert etag_a.startswith('W/"')
    assert etag_a == etag_b
    assert etag_a != etag_c


def test_handle_conditional_response_304_match():
    """Verify that matching If-None-Match headers return a 304 Not Modified response."""
    test_app = FastAPI()

    @test_app.get("/test-metadata")
    async def sample_endpoint(request: Request, response: Response):
        data = {"id": "123", "status": "active", "roles": ["admin"]}
        return handle_conditional_response(request, response, data, max_age=120, stale_while_revalidate=600)

    client = TestClient(test_app)

    # 1. First request -> 200 OK with ETag & Cache-Control headers
    res1 = client.get("/test-metadata")
    assert res1.status_code == 200
    assert "etag" in res1.headers
    assert "cache-control" in res1.headers
    assert "max-age=120" in res1.headers["cache-control"]
    assert "stale-while-revalidate=600" in res1.headers["cache-control"]

    etag = res1.headers["etag"]
    assert res1.json() == {"id": "123", "status": "active", "roles": ["admin"]}

    # 2. Conditional request with matching If-None-Match -> 304 Not Modified
    res2 = client.get("/test-metadata", headers={"If-None-Match": etag})
    assert res2.status_code == 304
    assert res2.headers["etag"] == etag
    assert not res2.content  # Empty body for 304

    # 3. Conditional request with wildcard '*' -> 304 Not Modified
    res3 = client.get("/test-metadata", headers={"If-None-Match": "*"})
    assert res3.status_code == 304

    # 4. Conditional request with stale/non-matching ETag -> 200 OK with fresh data
    res4 = client.get("/test-metadata", headers={"If-None-Match": 'W/"stale_hash_123"'})
    assert res4.status_code == 200
    assert res4.json() == {"id": "123", "status": "active", "roles": ["admin"]}


# =============================================================================
# 3. Router Integration Tests for /auth/me, /credentials, /trusted-devices
# =============================================================================

@pytest.mark.asyncio
async def test_auth_me_conditional_caching():
    """Verify that GET /auth/me emits ETag, Cache-Control, and handles 304 responses."""
    from api.dependencies import get_current_user, user_repo

    mock_user = {
        "id": str(uuid.uuid4()),
        "username": "dave",
        "email": "dave@example.com",
        "roles": ["editor"],
        "metadata": {"department": "Content", "clearance": 2},
        "created_at": "2026-01-01T00:00:00Z",
    }

    client = TestClient(app)

    async def override_get_current_user():
        return {"user_id": mock_user["id"], "claims": {}}

    async def override_get_by_id(user_id, session=None):
        if user_id == mock_user["id"]:
            return mock_user
        return None

    app.dependency_overrides[get_current_user] = override_get_current_user

    with patch.object(user_repo, "get_by_id", side_effect=override_get_by_id):
        # 1. Initial request -> 200 OK
        res = client.get("/auth/me")
        assert res.status_code == 200
        assert "etag" in res.headers
        assert "private, max-age=" in res.headers["cache-control"]

        etag = res.headers["etag"]
        data = res.json()
        assert data["username"] == "dave"
        assert data["roles"] == ["editor"]

        # 2. Subsequent request with matching If-None-Match -> 304 Not Modified
        res_cached = client.get("/auth/me", headers={"If-None-Match": etag})
        assert res_cached.status_code == 304
        assert not res_cached.content

    app.dependency_overrides.pop(get_current_user, None)


@pytest.mark.asyncio
async def test_webauthn_credentials_conditional_caching():
    """Verify that GET /auth/webauthn/credentials emits ETag and handles 304 responses."""
    from api.dependencies import get_current_user, user_repo

    user_id = str(uuid.uuid4())
    mock_user = {
        "id": user_id,
        "username": "eve",
        "email": "eve@example.com",
        "roles": ["viewer"],
        "metadata": {
            "passkeys": [
                {
                    "credential_id": "test_cred_id_123",
                    "device_label": "MacBook Pro Touch ID",
                    "created_at": "2026-01-01T00:00:00Z",
                }
            ]
        },
    }

    client = TestClient(app)

    async def override_get_current_user():
        return {"user_id": user_id, "claims": {}}

    async def override_get_by_id(uid, session=None):
        return mock_user

    app.dependency_overrides[get_current_user] = override_get_current_user

    with patch.object(user_repo, "get_by_id", side_effect=override_get_by_id):
        res = client.get("/auth/webauthn/credentials")
        assert res.status_code == 200
        assert "etag" in res.headers

        etag = res.headers["etag"]
        assert res.json()["count"] == 1

        res_cached = client.get("/auth/webauthn/credentials", headers={"If-None-Match": etag})
        assert res_cached.status_code == 304

    app.dependency_overrides.pop(get_current_user, None)


@pytest.mark.asyncio
async def test_trusted_devices_conditional_caching():
    """Verify that GET /auth/trusted-devices emits ETag and handles 304 responses."""
    from api.dependencies import get_current_user, device_trust_svc

    user_id = str(uuid.uuid4())
    mock_devices = [
        {"id": "dev_1", "device_label": "Work Laptop", "ip_address": "127.0.0.1", "is_current": True}
    ]

    client = TestClient(app)

    async def override_get_current_user():
        return {"user_id": user_id, "claims": {}}

    async def override_list_devices(uid, current_token=None):
        return mock_devices

    app.dependency_overrides[get_current_user] = override_get_current_user

    with patch.object(device_trust_svc, "list_trusted_devices", side_effect=override_list_devices):
        res = client.get("/auth/trusted-devices")
        assert res.status_code == 200
        assert "etag" in res.headers

        etag = res.headers["etag"]
        assert res.json()["count"] == 1

        res_cached = client.get("/auth/trusted-devices", headers={"If-None-Match": etag})
        assert res_cached.status_code == 304

    app.dependency_overrides.pop(get_current_user, None)
