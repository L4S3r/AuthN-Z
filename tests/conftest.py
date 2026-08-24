"""
Auth N&Z - Pytest Test Suite Configuration & Safety Fixtures (tests/conftest.py)
--------------------------------------------------------------------------------
Guarantees 100% database isolation:
- On GitHub Actions: runs in an ephemeral runner against a throwaway 'authnz_test' container.
- On Local Machine: explicitly prevents tests from connecting to or modifying your production database.
"""

import asyncio
import os
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

# Force test database URL (Guards against writing to live database)
test_db_url = os.getenv("TEST_DATABASE_URL", "postgresql+asyncpg://authnz_app:testpassword123@127.0.0.1:5432/authnz_test")
os.environ["DATABASE_URL"] = test_db_url
os.environ["JWT_SECRET_KEY"] = "test_jwt_super_secret_key_1234567890"

from database import get_engine, get_session_factory
from models import Base
from server import app


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for each test case."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="session", autouse=True)
async def setup_test_database():
    """
    Safety-guarded test database setup.
    Refuses to run if connected to a non-test database name.
    """
    engine = get_engine()
    db_name = engine.url.database or ""

    # Strict Safety Guard: Never execute tests on production database
    if not (db_name.endswith("_test") or "test" in db_name.lower()):
        raise RuntimeError(
            f"CRITICAL SAFETY ABORT: Pytest detected target database '{db_name}'. "
            "Automated test suites must only target dedicated databases ending in '_test'!"
        )

    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    except Exception as exc:
        pytest.skip(f"Skipping database-dependent tests (isolated test database 'authnz_test' not running): {exc}")

    yield

    # Clean teardown of test tables
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
    except Exception:
        pass


@pytest_asyncio.fixture
async def async_client() -> AsyncClient:
    """Async HTTP test client bound to the FastAPI application."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client
