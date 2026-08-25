"""
Auth N&Z - Centralized Configuration Management (config.py)
-----------------------------------------------------------
Strongly-typed environment configuration and secret management powered by pydantic-settings.
Provides validated defaults, environment variable loading, and single-source-of-truth access.
"""

from typing import List, Optional
import os
import secrets
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AuthNZSettings(BaseSettings):
    """Configuration settings for Auth N&Z identity and authorization gateway."""

    # Server Environment & Debug
    ENVIRONMENT: str = Field(default="development", description="Runtime environment: production, development, or testing")
    DEBUG: bool = Field(default=False, description="Enable debug logging and detailed errors")
    ENABLE_DOCS: Optional[bool] = Field(default=None, description="Explicit flag to enable or disable /docs and /redoc")

    # Cryptography & Token Issuance
    JWT_SECRET_KEY: Optional[str] = Field(default=None, description="Secret key for signing HMAC-SHA256 JWT tokens")
    JWT_ALGORITHM: str = Field(default="HS256", description="JWT signing algorithm")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=15, description="Access token expiration lifetime in minutes")
    REFRESH_TOKEN_EXPIRE_DAYS: int = Field(default=7, description="Refresh token expiration lifetime in days")
    PASSWORD_HASH_ALGORITHM: str = Field(default="bcrypt", description="Primary password hashing algorithm: 'bcrypt' or 'argon2id'")
    BCRYPT_WORK_FACTOR: int = Field(default=12, description="Bcrypt computational work cost factor")
    ARGON2_TIME_COST: int = Field(default=3, description="Argon2id time cost parameter")
    ARGON2_MEMORY_COST: int = Field(default=65536, description="Argon2id memory cost parameter in KiB (64 MiB)")
    ARGON2_PARALLELISM: int = Field(default=4, description="Argon2id parallelism thread count")
    WEBAUTHN_ENABLED: bool = Field(default=True, description="Enable WebAuthn / FIDO2 Passkey authentication service")

    # PostgreSQL Database Backend
    DATABASE_URL: Optional[str] = Field(default=None, description="Async PostgreSQL connection URL (postgresql+asyncpg://...)")
    TEST_DATABASE_URL: Optional[str] = Field(default=None, description="Dedicated test database URL")
    POSTGRES_USER: str = Field(default="authnz_app", description="PostgreSQL database username fallback")
    POSTGRES_PASSWORD: str = Field(default="", description="PostgreSQL database password fallback")
    POSTGRES_HOST: str = Field(default="127.0.0.1", description="PostgreSQL database host fallback")
    POSTGRES_PORT: str = Field(default="5432", description="PostgreSQL database port fallback")
    POSTGRES_DB: str = Field(default="authnz", description="PostgreSQL database name fallback")
    DB_POOL_SIZE: int = Field(default=10, description="SQLAlchemy connection pool base size")
    DB_MAX_OVERFLOW: int = Field(default=20, description="SQLAlchemy connection pool max overflow")

    # Redis Persistence & Distributed Sessions
    REDIS_HOST: str = Field(default="127.0.0.1", description="Redis server hostname or IP")
    REDIS_PORT: int = Field(default=6379, description="Redis server port")
    REDIS_DB: int = Field(default=0, description="Redis database index")
    REDIS_PASSWORD: Optional[str] = Field(default=None, description="Redis password if authentication is required")
    REQUIRE_REDIS: bool = Field(default=False, description="Fail startup if Redis is unreachable (auto-enforced in production)")

    # Client Web Application & URLs
    FRONTEND_URL: str = Field(default="http://localhost:3000", description="Client web application URL for redirects and email links")
    CORS_ALLOWED_ORIGINS: List[str] = Field(
        default=[
            "https://auth-api.l4s3r.site",
            "https://tasks.l4s3r.site",
            "https://l4s3r.site",
            "https://www.l4s3r.site",
            "http://localhost:3000",
            "http://localhost:5173",
            "http://localhost:8000",
            "http://127.0.0.1:3000",
            "http://127.0.0.1:5173",
            "http://127.0.0.1:8000",
        ],
        description="Allowed CORS origin URLs",
    )

    # Social Login / OAuth2 & OIDC Providers
    GOOGLE_CLIENT_ID: Optional[str] = Field(default=None, description="Google OAuth 2.0 Client ID")
    GOOGLE_CLIENT_SECRET: Optional[str] = Field(default=None, description="Google OAuth 2.0 Client Secret")
    GITHUB_CLIENT_ID: Optional[str] = Field(default=None, description="GitHub OAuth App Client ID")
    GITHUB_CLIENT_SECRET: Optional[str] = Field(default=None, description="GitHub OAuth App Client Secret")

    # Transactional Email (SMTP)
    SMTP_HOST: Optional[str] = Field(default=None, description="SMTP server hostname")
    SMTP_PORT: int = Field(default=587, description="SMTP server port")
    SMTP_USER: Optional[str] = Field(default=None, description="SMTP server username")
    SMTP_PASSWORD: Optional[str] = Field(default=None, description="SMTP server password")
    SMTP_FROM: str = Field(default="noreply@l4s3r.site", description="Sender email address")

    # Distributed Policy & Open Policy Agent (OPA)
    OPA_ENABLED: bool = Field(default=False, description="Enable remote Open Policy Agent evaluation")
    OPA_URL: str = Field(default="http://localhost:8181/v1/data/authnz/allow", description="OPA decision endpoint URL")
    OPA_TIMEOUT_SECONDS: float = Field(default=1.0, description="Max timeout for OPA evaluation requests")
    POLICY_CACHE_TTL_SECONDS: int = Field(default=300, description="TTL in seconds for cached policy decisions in Redis")
    POLICY_FILE_PATH: str = Field(default="policies/rules.json", description="Local declarative policy file path")

    # Observability & Monitoring
    SENTRY_DSN: Optional[str] = Field(default=None, description="Sentry DSN for error and performance tracing")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    @field_validator("REDIS_HOST", mode="after")
    @classmethod
    def normalize_redis_host(cls, v: str) -> str:
        if v == "localhost":
            return "127.0.0.1"
        return v

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT.lower() == "production"

    @property
    def is_testing(self) -> bool:
        return self.ENVIRONMENT.lower() == "testing"

    @property
    def docs_enabled(self) -> bool:
        if self.ENABLE_DOCS is not None:
            return self.ENABLE_DOCS
        return not self.is_production

    def get_jwt_secret(self) -> str:
        """Retrieve configured JWT secret key or lazily generate and persist one for local development."""
        if self.JWT_SECRET_KEY:
            return self.JWT_SECRET_KEY
        
        # Check environment variable directly
        env_key = os.environ.get("JWT_SECRET_KEY")
        if env_key:
            self.JWT_SECRET_KEY = env_key
            return env_key

        # Check existing .env file
        if os.path.exists(".env"):
            with open(".env", "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("JWT_SECRET_KEY="):
                        val = line.strip().split("=", 1)[1]
                        if val and val != "replace_with_32_byte_random_hex_key":
                            self.JWT_SECRET_KEY = val
                            return val

        # Generate ephemeral or persistent secret
        new_key = secrets.token_urlsafe(32)
        self.JWT_SECRET_KEY = new_key
        try:
            with open(".env", "a", encoding="utf-8") as f:
                f.write(f"\nJWT_SECRET_KEY={new_key}\n")
        except Exception:
            pass
        return new_key

    def get_database_url(self) -> str:
        """Resolve database connection string with fallback to individual components."""
        if self.is_testing and self.TEST_DATABASE_URL:
            return self.TEST_DATABASE_URL
        if self.DATABASE_URL:
            url = self.DATABASE_URL
            if url.startswith("postgres://"):
                url = url.replace("postgres://", "postgresql+asyncpg://", 1)
            elif url.startswith("postgresql://") and not url.startswith("postgresql+asyncpg://"):
                url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
            return url

        # Fallback assembly
        user = self.POSTGRES_USER
        password = self.POSTGRES_PASSWORD
        host = self.POSTGRES_HOST
        port = self.POSTGRES_PORT
        db_name = self.POSTGRES_DB
        auth_part = f"{user}:{password}@" if password else f"{user}@"
        return f"postgresql+asyncpg://{auth_part}{host}:{port}/{db_name}"


# Singleton configuration instance
settings = AuthNZSettings()
