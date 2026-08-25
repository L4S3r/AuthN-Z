"""
Auth N&Z - Request & Response Schemas (api/schemas.py)
------------------------------------------------------
Pydantic v2 schemas defining validated input/output payloads across all API domain modules.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, EmailStr, Field


# =============================================================================
# Authentication & Identity Schemas
# =============================================================================
class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr = Field(..., min_length=5, max_length=100)
    password: str = Field(..., min_length=8)


class AdminCreateUserRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr = Field(..., min_length=5, max_length=100)
    password: str = Field(..., min_length=8)
    roles: List[str] = ["viewer"]
    department: Optional[str] = "General"
    clearance: Optional[int] = 1


class LoginRequest(BaseModel):
    identifier: str = Field(..., description="Username or email address")
    password: str = Field(..., description="Plaintext password")


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str = Field(..., min_length=10)
    new_password: str = Field(..., min_length=8)


class RefreshRequest(BaseModel):
    refresh_token: Optional[str] = None


class LogoutRequest(BaseModel):
    session_id: Optional[str] = None
    logout_all_devices: Optional[bool] = False


# =============================================================================
# MFA & Passkeys Schemas
# =============================================================================
class MFAVerifySetupRequest(BaseModel):
    code: str = Field(..., min_length=6, max_length=12)


class MFACompleteRequest(BaseModel):
    user_id: str
    challenge_id: str
    code: str
    remember_device: Optional[bool] = False


# =============================================================================
# WebAuthn / Passkeys Schemas
# =============================================================================
class WebAuthnRegisterVerifyRequest(BaseModel):
    client_data_json: str = Field(..., description="Base64url encoded clientDataJSON")
    attestation_object: str = Field(..., description="Base64url encoded attestationObject")
    credential_id: Optional[str] = Field(default=None, description="Base64url encoded credentialId")
    device_label: Optional[str] = Field(default="Passkey / Hardware Key", description="User device label")
    transports: Optional[List[str]] = Field(default=None, description="Optional transports list e.g. ['internal', 'hybrid', 'usb']")


class WebAuthnAuthOptionsRequest(BaseModel):
    identifier: Optional[str] = Field(default=None, description="Optional username/email for targeted passkey authentication")


class WebAuthnAuthVerifyRequest(BaseModel):
    client_data_json: str = Field(..., description="Base64url encoded clientDataJSON")
    authenticator_data: str = Field(..., description="Base64url encoded authenticatorData")
    signature: str = Field(..., description="Base64url encoded signature")
    credential_id: str = Field(..., description="Base64url encoded credential ID")
    user_handle: Optional[str] = Field(default=None, description="Base64url encoded user handle")
    identifier: Optional[str] = Field(default=None, description="Optional username/email context")


# =============================================================================
# Policy & Authorization Schemas
# =============================================================================
class PolicySimulateRequest(BaseModel):
    subject_id: Optional[str] = None
    subject: Optional[Dict[str, Any]] = None
    action: str = Field(..., description="Action to simulate: read, write, delete, etc.")
    resource_type: str = Field(..., description="Target resource type: documents, tasks, workspaces, etc.")
    resource_id: str = Field(default="sample_res_id", description="Resource unique ID")
    resource_attributes: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Attributes of the target resource")
    context: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Contextual attributes e.g. workspace_id")


# =============================================================================
# OAuth2 / Social Login Schemas
# =============================================================================
class OAuthExchangeRequest(BaseModel):
    code: str
    code_verifier: Optional[str] = None
    redirect_uri: Optional[str] = None


# =============================================================================
# Workspace & Multi-Tenancy Schemas
# =============================================================================
class WorkspaceCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    slug: Optional[str] = None
    description: Optional[str] = ""


class WorkspaceUpdateRequest(BaseModel):
    name: Optional[str] = None
    slug: Optional[str] = None
    description: Optional[str] = None


class WorkspaceInviteRequest(BaseModel):
    email: EmailStr = Field(..., min_length=5, max_length=100)
    name: Optional[str] = None
    role: Optional[str] = "viewer"
    department: Optional[str] = "General"


class WorkspaceRoleUpdateRequest(BaseModel):
    role: str = Field(..., pattern="^(admin|editor|viewer)$")


class WorkspaceAcceptInviteRequest(BaseModel):
    token: str = Field(..., min_length=10)
    password: str = Field(..., min_length=8)
    name: Optional[str] = None


class WorkspaceSwitchRequest(BaseModel):
    workspace_id: str = Field(..., min_length=3)


# =============================================================================
# Legacy Team Schemas
# =============================================================================
class TeamInviteRequest(BaseModel):
    email: EmailStr = Field(..., min_length=5, max_length=100)
    name: Optional[str] = None
    role: Optional[str] = "viewer"
    department: Optional[str] = "General"
    provision_password: Optional[str] = None


class TeamAcceptInviteRequest(BaseModel):
    token: str = Field(..., min_length=10)
    password: str = Field(..., min_length=8)
    name: Optional[str] = None


# =============================================================================
# Task Tracker App Schemas
# =============================================================================
class TaskCreateRequest(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = ""
    status: Optional[str] = "todo"
    priority: Optional[str] = "medium"
    workspace_id: Optional[str] = "ws_default"
    assignee_email: Optional[str] = None
    assignee_name: Optional[str] = None
    assignees: Optional[List[Dict[str, Any]]] = None
    tags: Optional[List[str]] = []
    due_date: Optional[str] = None


class TaskUpdateRequest(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    priority: Optional[str] = None
    workspace_id: Optional[str] = None
    assignee_email: Optional[str] = None
    assignee_name: Optional[str] = None
    assignees: Optional[List[Dict[str, Any]]] = None
    tags: Optional[List[str]] = None
    due_date: Optional[str] = None
