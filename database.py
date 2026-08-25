"""
Database Engine & Async Session Management (Auth N&Z)
====================================================
Configures the async SQLAlchemy engine using asyncpg for non-blocking PostgreSQL access.
Provides connection pooling, session lifecycle helpers, loop-aware engine caching, and environment resolution.
"""

from typing import AsyncGenerator, Dict, Optional
import asyncio
import os
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


_async_engines: Dict[int, AsyncEngine] = {}
_async_session_factories: Dict[int, async_sessionmaker[AsyncSession]] = {}


def get_engine(db_url: Optional[str] = None) -> AsyncEngine:
    """Get or create singleton AsyncEngine instance with event-loop awareness."""
    global _async_engines, _async_session_factories

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

    try:
        current_loop = asyncio.get_running_loop()
        loop_id = id(current_loop)
    except RuntimeError:
        current_loop = None
        loop_id = 0

    if loop_id not in _async_engines:
        engine = create_async_engine(
            get_database_url(),
            echo=False,
            pool_pre_ping=True,
            pool_size=10,
            max_overflow=20,
        )
        factory = async_sessionmaker(
            bind=engine,
            expire_on_commit=False,
            class_=AsyncSession,
        )
        _async_engines[loop_id] = engine
        _async_session_factories[loop_id] = factory

    return _async_engines[loop_id]


def get_session_factory(db_url: Optional[str] = None) -> async_sessionmaker[AsyncSession]:
    """Get or create singleton async_sessionmaker instance with event-loop awareness."""
    global _async_session_factories

    if db_url:
        engine = get_engine(db_url)
        return async_sessionmaker(
            bind=engine,
            expire_on_commit=False,
            class_=AsyncSession,
        )

    try:
        current_loop = asyncio.get_running_loop()
        loop_id = id(current_loop)
    except RuntimeError:
        current_loop = None
        loop_id = 0

    get_engine()
    return _async_session_factories[loop_id]


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency yielding an async database session with automatic cleanup."""
    session_factory = get_session_factory()
    async with session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
