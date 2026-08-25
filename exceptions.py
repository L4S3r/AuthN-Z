"""
Auth N&Z - Standard Domain Exceptions & RFC 7807 Error Boundaries (exceptions.py)
---------------------------------------------------------------------------------
Provides structured domain exceptions and RFC 7807 Problem Details response handlers
to ensure consistent, machine-readable error contracts across all API endpoints.
"""

from typing import Any, Dict, Optional
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse


class AuthNZException(Exception):
    """Base exception for all Auth N&Z domain errors with RFC 7807 metadata."""

    def __init__(
        self,
        detail: str,
        status_code: int = status.HTTP_400_BAD_REQUEST,
        code: str = "BAD_REQUEST",
        title: Optional[str] = None,
        type_uri: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        extra: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(detail)
        self.detail = detail
        self.status_code = status_code
        self.code = code
        self.title = title or code.replace("_", " ").title()
        self.type_uri = type_uri or f"https://errors.authnz.dev/{code.lower().replace('_', '-')}"
        self.headers = headers or {}
        self.extra = extra or {}

    def to_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "type": self.type_uri,
            "title": self.title,
            "status": self.status_code,
            "detail": self.detail,
            "code": self.code,
        }
        if self.extra:
            payload.update(self.extra)
        return payload


class InvalidCredentialsException(AuthNZException):
    """Raised when authentication credentials (password, secret) fail verification."""

    def __init__(self, detail: str = "Invalid identifier or password.", headers: Optional[Dict[str, str]] = None):
        super().__init__(
            detail=detail,
            status_code=status.HTTP_401_UNAUTHORIZED,
            code="INVALID_CREDENTIALS",
            title="Invalid Credentials",
            headers=headers or {"WWW-Authenticate": "Bearer"},
        )


class AccountLockedException(AuthNZException):
    """Raised when an account is temporarily locked due to excessive failed attempts."""

    def __init__(self, retry_after_seconds: int = 900, detail: Optional[str] = None):
        msg = detail or f"Account is temporarily locked due to excessive failed login attempts. Try again in {retry_after_seconds // 60} minutes."
        super().__init__(
            detail=msg,
            status_code=status.HTTP_423_LOCKED,
            code="ACCOUNT_LOCKED",
            title="Account Locked",
            headers={"Retry-After": str(retry_after_seconds)},
            extra={"retry_after_seconds": retry_after_seconds},
        )


class MFARequiredException(AuthNZException):
    """Raised when secondary factor verification is required to complete authentication."""

    def __init__(self, challenge_id: str, user_id: str, detail: str = "Multi-Factor Authentication challenge required."):
        super().__init__(
            detail=detail,
            status_code=status.HTTP_403_FORBIDDEN,
            code="MFA_REQUIRED",
            title="MFA Required",
            extra={"challenge_id": challenge_id, "user_id": user_id},
        )


class TokenRevokedException(AuthNZException):
    """Raised when a presented token exists in the revocation blocklist."""

    def __init__(self, detail: str = "Token has been revoked."):
        super().__init__(
            detail=detail,
            status_code=status.HTTP_401_UNAUTHORIZED,
            code="TOKEN_REVOKED",
            title="Token Revoked",
            headers={"WWW-Authenticate": "Bearer error=\"invalid_token\", error_description=\"Token revoked\""},
        )


class TokenExpiredException(AuthNZException):
    """Raised when a presented token has expired past its lifetime."""

    def __init__(self, detail: str = "Token has expired."):
        super().__init__(
            detail=detail,
            status_code=status.HTTP_401_UNAUTHORIZED,
            code="TOKEN_EXPIRED",
            title="Token Expired",
            headers={"WWW-Authenticate": "Bearer error=\"invalid_token\", error_description=\"Token expired\""},
        )


class InvalidTokenException(AuthNZException):
    """Raised when a token signature is invalid or malformed."""

    def __init__(self, detail: str = "Invalid authentication token."):
        super().__init__(
            detail=detail,
            status_code=status.HTTP_401_UNAUTHORIZED,
            code="INVALID_TOKEN",
            title="Invalid Token",
            headers={"WWW-Authenticate": "Bearer error=\"invalid_token\""},
        )


class PermissionDeniedException(AuthNZException):
    """Raised when an authenticated principal lacks required RBAC role or ABAC permission."""

    def __init__(
        self,
        detail: str = "You do not have permission to perform this action.",
        required_permission: Optional[str] = None,
        required_role: Optional[str] = None,
    ):
        extra: Dict[str, Any] = {}
        if required_permission:
            extra["required_permission"] = required_permission
        if required_role:
            extra["required_role"] = required_role

        super().__init__(
            detail=detail,
            status_code=status.HTTP_403_FORBIDDEN,
            code="PERMISSION_DENIED",
            title="Permission Denied",
            extra=extra,
        )


class ResourceNotFoundException(AuthNZException):
    """Raised when a requested resource does not exist."""

    def __init__(self, resource_name: str = "Resource", identifier: Optional[str] = None):
        detail = f"{resource_name} not found" if not identifier else f"{resource_name} '{identifier}' not found."
        super().__init__(
            detail=detail,
            status_code=status.HTTP_404_NOT_FOUND,
            code="NOT_FOUND",
            title=f"{resource_name} Not Found",
        )


class WorkspaceNotFoundException(ResourceNotFoundException):
    """Raised when a workspace identifier does not resolve to an active workspace."""

    def __init__(self, workspace_id: Optional[str] = None):
        super().__init__(resource_name="Workspace", identifier=workspace_id)
        self.code = "WORKSPACE_NOT_FOUND"
        self.type_uri = "https://errors.authnz.dev/workspace-not-found"


class ConflictException(AuthNZException):
    """Raised when a resource already exists or state conflicts (e.g. duplicate email/slug)."""

    def __init__(self, detail: str = "Resource conflict detected.", code: str = "CONFLICT"):
        super().__init__(
            detail=detail,
            status_code=status.HTTP_409_CONFLICT,
            code=code,
            title="Resource Conflict",
        )


class RateLimitExceededException(AuthNZException):
    """Raised when an IP or user exceeds sliding window request rate limits."""

    def __init__(self, retry_after_seconds: int = 60, detail: Optional[str] = None):
        msg = detail or f"Rate limit exceeded. Please try again in {retry_after_seconds} seconds."
        super().__init__(
            detail=msg,
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            code="RATE_LIMIT_EXCEEDED",
            title="Rate Limit Exceeded",
            headers={"Retry-After": str(retry_after_seconds)},
            extra={"retry_after_seconds": retry_after_seconds},
        )


# =============================================================================
# RFC 7807 Global Exception Handlers for FastAPI
# =============================================================================

def register_exception_handlers(app: FastAPI) -> None:
    """Register uniform RFC 7807 Problem Details exception handlers on a FastAPI instance."""

    @app.exception_handler(AuthNZException)
    async def authnz_exception_handler(request: Request, exc: AuthNZException) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=exc.to_dict(),
            headers=exc.headers,
        )

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
        detail_msg = exc.detail if isinstance(exc.detail, str) else str(exc.detail)
        code = "HTTP_ERROR"
        if exc.status_code == 401:
            code = "UNAUTHORIZED"
        elif exc.status_code == 403:
            code = "FORBIDDEN"
        elif exc.status_code == 404:
            code = "NOT_FOUND"
        elif exc.status_code == 409:
            code = "CONFLICT"
        elif exc.status_code == 422:
            code = "UNPROCESSABLE_ENTITY"
        elif exc.status_code == 429:
            code = "RATE_LIMIT_EXCEEDED"

        payload = {
            "type": f"https://errors.authnz.dev/{code.lower().replace('_', '-')}",
            "title": code.replace("_", " ").title(),
            "status": exc.status_code,
            "detail": detail_msg,
            "code": code,
        }
        return JSONResponse(
            status_code=exc.status_code,
            content=payload,
            headers=exc.headers,
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        errors = []
        for err in exc.errors():
            loc = " -> ".join(str(l) for l in err.get("loc", []))
            errors.append({
                "field": loc,
                "message": err.get("msg", "Validation error"),
                "type": err.get("type", "value_error"),
            })
        payload = {
            "type": "https://errors.authnz.dev/validation-error",
            "title": "Validation Error",
            "status": status.HTTP_422_UNPROCESSABLE_ENTITY,
            "detail": "The request body or parameters failed validation schema checks.",
            "code": "VALIDATION_ERROR",
            "errors": errors,
        }
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=payload,
        )
