"""
Database Engine & Async Session Management (Auth N&Z)
====================================================
Configures the async SQLAlchemy engine using asyncpg for non-blocking PostgreSQL access.
Provides connection pooling, session lifecycle helpers, loop-aware engine caching, and environment resolution.
"""

import asyncio
import os
from typing import AsyncGenerator, Optional
from dotenv import load_dotenv

load_dotenv()

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)


from config import settings

def get_database_url() -> str:
    """
    Retrieve database URL from centralized settings.
    Converts standard postgresql:// schemes to postgresql+asyncpg:// for async compatibility.
    """
    return settings.get_database_url()


_async_engine: Optional[AsyncEngine] = None
_async_session_factory: Optional[async_sessionmaker[AsyncSession]] = None
_engine_loop: Optional[asyncio.AbstractEventLoop] = None


def get_engine(db_url: Optional[str] = None) -> AsyncEngine:
    """Get or create singleton AsyncEngine instance with event-loop awareness."""
    global _async_engine, _async_session_factory, _engine_loop

    try:
        current_loop = asyncio.get_running_loop()
    except RuntimeError:
        current_loop = None

    if db_url:
        target_url = db_url
        if target_url.startswith("postgresql://"):
            target_url = target_url.replace("postgresql://", "postgresql+asyncpg://", 1)
        elif target_url.startswith("postgres://"):
            target_url = target_url.replace("postgres://", "postgresql+asyncpg://", 1)
        return create_async_engine(
            target_url,
            echo=False,
            pool_pre_ping=True,
            pool_size=10,
            max_overflow=20,
        )

    # Recreate engine if loop changed or was closed
    if _async_engine is None or (_engine_loop is not None and current_loop is not None and _engine_loop != current_loop):
        _engine_loop = current_loop
        _async_engine = create_async_engine(
            get_database_url(),
            echo=False,
            pool_pre_ping=True,
            pool_size=10,
            max_overflow=20,
        )
        _async_session_factory = async_sessionmaker(
            bind=_async_engine,
            expire_on_commit=False,
            class_=AsyncSession,
        )

    return _async_engine


def get_session_factory(db_url: Optional[str] = None) -> async_sessionmaker[AsyncSession]:
    """Get or create singleton async_sessionmaker instance."""
    global _async_session_factory
    if db_url:
        engine = get_engine(db_url)
        return async_sessionmaker(
            bind=engine,
            expire_on_commit=False,
            class_=AsyncSession,
        )

    get_engine()
    return _async_session_factory  # type: ignore


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency yielding an async database session with automatic cleanup."""
    session_factory = get_session_factory()
    async with session_factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
