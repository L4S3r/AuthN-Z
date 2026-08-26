"""
SQLAlchemy Declarative Models for PostgreSQL (Auth N&Z) - Core Identity
========================================================================
Defines the CORE identity schema shared by both BYOU (Bring-Your-Own-User)
host applications and the turnkey standalone server: the base declarative
registry, the security-fields mixin, and the two support tables that are
genuinely auth-scoped rather than workspace/task-domain (password reset
tokens, trusted devices for MFA).

Workspace/Task/Team/Notification/AuditLog models intentionally do NOT live
here anymore - see workspace_models.py. The default turnkey User model
(used only when a host hasn't supplied their own via BYOU) lives in
default_user.py, so importing this module never registers a "users" table
by itself and never collides with a host's own custom User class.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
import uuid

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    String,
    Text,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy declarative models."""
    pass


class AuthNZUserMixin:
    """
    SQLAlchemy 2.0 Mixin providing core Auth N&Z authentication, identity, and security fields.
    Host applications can inherit this mixin into their custom User model to retain their own table
    identity and add custom application fields (e.g. stripe_id, company, avatar).

    Example:
        from auth_nz.models import Base, AuthNZUserMixin

        class User(Base, AuthNZUserMixin):
            __tablename__ = "users"
            company: Mapped[str] = mapped_column(String(100))
            stripe_customer_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    IMPORTANT: import Base from this module (or from auth_nz.models) for your
    own User class rather than declaring `class Base(DeclarativeBase): pass`
    yourself. Sharing this Base's metadata/registry is what lets
    PasswordResetToken and TrustedDevice below resolve their foreign keys to
    your table, and lets a single Base.metadata.create_all() / Alembic
    target_metadata capture your whole schema in one pass.
    """
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    username: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
    )
    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
    )
    hashed_password: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default=text("true"),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    roles: Mapped[List[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default=text("'[]'::jsonb"),
    )
    # Avoid collision with Base.metadata by naming the Python attribute metadata_
    metadata_: Mapped[Dict[str, Any]] = mapped_column(
        "metadata",
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )


class PasswordResetToken(Base):
    """
    High-entropy cryptographic password reset tokens.

    FKs to "users.id" by table name - works against either the built-in
    default User (default_user.py) or a BYOU host's own User class, as long
    as that class shares this module's Base.
    """
    __tablename__ = "password_reset_tokens"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    token_hash: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        nullable=False,
        index=True,
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    used_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    ip_address: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )

    # Relationships (string-resolved: works against whichever class named
    # "User" is registered on this Base in the running process - either the
    # default turnkey User or a BYOU host's own User).
    #
    # Uses backref (not back_populates) deliberately: back_populates requires
    # the User class to explicitly declare a matching `password_reset_tokens`
    # property, which a bare BYOU host's User(Base, AuthNZUserMixin) has no
    # reason to know about. backref auto-generates that reverse attribute on
    # whichever User class is present, so a host doesn't need to add anything.
    user: Mapped["User"] = relationship("User", backref="password_reset_tokens")

    def __repr__(self) -> str:
        return f"<PasswordResetToken(id={self.id}, user_id={self.user_id}, used={self.used_at is not None})>"


class TrustedDevice(Base):
    """
    Remembered trusted devices for MFA scoping and bypass tracking.
    """
    __tablename__ = "trusted_devices"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    token_hash: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        nullable=False,
    )
    device_label: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    user_agent: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    ip_address: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    last_used_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    # Relationships. backref, not back_populates - see PasswordResetToken
    # above for why: a bare BYOU User class shouldn't need to know it's
    # expected to declare a `trusted_devices` property.
    user: Mapped["User"] = relationship("User", backref="trusted_devices")

    def __repr__(self) -> str:
        return f"<TrustedDevice(id={self.id}, user_id={self.user_id}, label='{self.device_label}')>"