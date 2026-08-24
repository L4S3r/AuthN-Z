"""
Database Engine & Async Session Management (Auth N&Z)
====================================================
Configures the async SQLAlchemy engine using asyncpg for non-blocking PostgreSQL access.
Provides connection pooling, session lifecycle helpers, and environment resolution.
"""

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


def get_database_url() -> str:
    """
    Retrieve database URL from environment variables.
    Supports DATABASE_URL or individual POSTGRES_* / PG* variables.
    Converts standard postgresql:// schemes to postgresql+asyncpg:// for async compatibility.
    """
    url = os.getenv("DATABASE_URL")
    if not url:
        user = os.getenv("POSTGRES_USER") or os.getenv("PGUSER") or "authnz_app"
        password = os.getenv("POSTGRES_PASSWORD") or os.getenv("PGPASSWORD") or ""
        host = os.getenv("POSTGRES_HOST") or os.getenv("PGHOST") or "127.0.0.1"
        port = os.getenv("POSTGRES_PORT") or os.getenv("PGPORT") or "5432"
        db_name = os.getenv("POSTGRES_DB") or os.getenv("PGDATABASE") or "authnz"

        auth_part = f"{user}:{password}" if password else user
        url = f"postgresql+asyncpg://{auth_part}@{host}:{port}/{db_name}"

    if url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
    elif url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql+asyncpg://", 1)
    return url


_async_engine: Optional[AsyncEngine] = None
_async_session_factory: Optional[async_sessionmaker[AsyncSession]] = None


def get_engine(db_url: Optional[str] = None) -> AsyncEngine:
    """Get or create singleton AsyncEngine instance."""
    global _async_engine
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

    if _async_engine is None:
        _async_engine = create_async_engine(
            get_database_url(),
            echo=False,
            pool_pre_ping=True,
            pool_size=10,
            max_overflow=20,
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

    if _async_session_factory is None:
        _async_session_factory = async_sessionmaker(
            bind=get_engine(),
            expire_on_commit=False,
            class_=AsyncSession,
        )
    return _async_session_factory


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency yielding an async database session with automatic cleanup."""
    session_factory = get_session_factory()
    async with session_factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
