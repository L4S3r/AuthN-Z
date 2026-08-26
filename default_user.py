"""
Auth N&Z - Default Turnkey User Model (default_user.py)
--------------------------------------------------------
Defines the built-in `User` class used when the turnkey standalone server
runs WITHOUT a host-supplied BYOU model (i.e. UserRepository was constructed
with user_model=None, so it falls back to this class).

This is intentionally its own module, separate from models.py. models.py
only defines Base/AuthNZUserMixin/PasswordResetToken/TrustedDevice, and a
BYOU host is expected to import from there (or from auth_nz.models) to
build their OWN User class. If the default User below lived in models.py
directly, simply importing Base/AuthNZUserMixin for a custom model would
already register a "users" table - and a host's own `class User(Base,
AuthNZUserMixin): __tablename__ = "users"` would collide with it
(SQLAlchemy: "Table 'users' is already defined for this MetaData instance").

Importing this module also imports workspace_models, since the default
User's relationships (workspace_memberships, notifications) need those
classes registered on the same Base before SQLAlchemy's mapper
configuration resolves. BYOU hosts who never import default_user never
pull in workspace_models either - that's the whole point of the split.
"""

from typing import List

from sqlalchemy.orm import Mapped, relationship

from models import Base, AuthNZUserMixin
import workspace_models  # noqa: F401 - registers Workspace/WorkspaceMember/Task/Notification on Base


class User(Base, AuthNZUserMixin):
    """
    User accounts and authentication identity credentials.
    Default turnkey model for Auth N&Z - used only when no BYOU user_model
    is configured via configure_authnz()/AuthNZ(...).
    """
    __tablename__ = "users"

    # password_reset_tokens and trusted_devices are NOT declared here -
    # PasswordResetToken/TrustedDevice's `backref` in models.py generates
    # them automatically on whichever User class is registered. Declaring
    # them here too would collide with that auto-generated property.
    #
    # workspace_memberships/notifications stay explicit with back_populates:
    # this default User only ever coexists with WorkspaceMember/Notification
    # in the turnkey server (this module unconditionally imports
    # workspace_models), so there's no BYOU-host case where the other side
    # might be missing.
    workspace_memberships: Mapped[List["WorkspaceMember"]] = relationship(
        "WorkspaceMember",
        back_populates="user",
        cascade="all, delete-orphan",
    )
    notifications: Mapped[List["Notification"]] = relationship(
        "Notification",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<User(id={self.id}, username='{self.username}', email='{self.email}')>"