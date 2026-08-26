"""
auth_nz/models.py - Public BYOU (Bring-Your-Own-User) model surface.

Import Base and AuthNZUserMixin here to attach Auth N&Z's identity/security
columns to your own SQLAlchemy model:

    from auth_nz.models import Base, AuthNZUserMixin

    class User(Base, AuthNZUserMixin):
        __tablename__ = "users"
        company_name: Mapped[str]

PasswordResetToken and TrustedDevice are also re-exported here for hosts
that want "forgot password" / "remember this device" support without
adopting the full turnkey server.

Workspace, WorkspaceMember, Task, TeamMember, Notification, and AuditLog
are intentionally NOT re-exported here - they belong to the standalone
turnkey server only (see workspace_models.py), so a BYOU host's own app
schema never gets coupled to them.
"""

from models import Base, AuthNZUserMixin, PasswordResetToken, TrustedDevice

__all__ = ["Base", "AuthNZUserMixin", "PasswordResetToken", "TrustedDevice"]