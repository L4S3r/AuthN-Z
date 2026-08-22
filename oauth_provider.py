"""
Auth N&Z - OAuth2 and OpenID Connect (OIDC) Provider (oauth_provider.py)
-------------------------------------------------------------------------
Provides social authentication integration for Google, GitHub, and custom
OAuth2/OIDC identity providers with PKCE and state protection.
"""

from abc import ABC, abstractmethod
import base64
import hashlib
import json
import logging
import os
import secrets
from typing import Any, Dict, Optional, Tuple
import urllib.parse

import httpx

logger = logging.getLogger("auth_nz.oauth")


# =============================================================================
# Cryptographic PKCE & State Helpers
# =============================================================================
def generate_pkce_pair() -> Tuple[str, str]:
    """Generate a high-entropy PKCE code_verifier and code_challenge (RFC 7636)."""
    # 43-128 unreserved URL-safe characters
    code_verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return code_verifier, code_challenge


def generate_oauth_state() -> str:
    """Generate a cryptographically random state parameter to prevent CSRF."""
    return secrets.token_urlsafe(32)


# =============================================================================
# Abstract OAuth2 Provider Interface
# =============================================================================
class abstractOAuth2Provider(ABC):
    @abstractmethod
    def get_authorization_url(
        self,
        redirect_uri: str,
        state: str,
        code_challenge: Optional[str] = None,
    ) -> str:
        """Construct the third-party authorization redirect URL."""
        pass

    @abstractmethod
    async def exchange_code(
        self,
        code: str,
        redirect_uri: str,
        code_verifier: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Exchange authorization code for user identity profile."""
        pass


# =============================================================================
# Google OpenID Connect (OIDC) Provider
# =============================================================================
class GoogleOAuth2Provider(abstractOAuth2Provider):
    AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
    TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
    USERINFO_ENDPOINT = "https://openidconnect.googleapis.com/v1/userinfo"

    def __init__(self, client_id: str, client_secret: str):
        self.client_id = client_id
        self.client_secret = client_secret

    def get_authorization_url(
        self,
        redirect_uri: str,
        state: str,
        code_challenge: Optional[str] = None,
    ) -> str:
        params = {
            "client_id": self.client_id,
            "response_type": "code",
            "redirect_uri": redirect_uri,
            "scope": "openid email profile",
            "state": state,
            "access_type": "offline",
            "prompt": "select_account",
        }
        if code_challenge:
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = "S256"

        return f"{self.AUTH_ENDPOINT}?{urllib.parse.urlencode(params)}"

    async def exchange_code(
        self,
        code: str,
        redirect_uri: str,
        code_verifier: Optional[str] = None,
    ) -> Dict[str, Any]:
        data = {
            "code": code,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
        }
        if code_verifier:
            data["code_verifier"] = code_verifier

        async with httpx.AsyncClient(timeout=10.0) as client:
            token_resp = await client.post(self.TOKEN_ENDPOINT, data=data)
            if token_resp.status_code != 200:
                logger.error("Google token exchange failed: %s", token_resp.text)
                raise ValueError(f"Google token exchange failed: {token_resp.text}")

            tokens = token_resp.json()
            access_token = tokens.get("access_token")

            userinfo_resp = await client.get(
                self.USERINFO_ENDPOINT,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            if userinfo_resp.status_code != 200:
                logger.error("Google userinfo request failed: %s", userinfo_resp.text)
                raise ValueError("Failed to fetch Google user profile.")

            info = userinfo_resp.json()
            return {
                "provider": "google",
                "provider_user_id": info.get("sub"),
                "email": info.get("email"),
                "email_verified": info.get("email_verified", False),
                "name": info.get("name"),
                "username": info.get("preferred_username") or (info.get("email", "").split("@")[0] if info.get("email") else None),
                "picture": info.get("picture"),
            }


# =============================================================================
# GitHub OAuth2 Provider
# =============================================================================
class GitHubOAuth2Provider(abstractOAuth2Provider):
    AUTH_ENDPOINT = "https://github.com/login/oauth/authorize"
    TOKEN_ENDPOINT = "https://github.com/login/oauth/access_token"
    USERINFO_ENDPOINT = "https://api.github.com/user"
    EMAILS_ENDPOINT = "https://api.github.com/user/emails"

    def __init__(self, client_id: str, client_secret: str):
        self.client_id = client_id
        self.client_secret = client_secret

    def get_authorization_url(
        self,
        redirect_uri: str,
        state: str,
        code_challenge: Optional[str] = None,
    ) -> str:
        params = {
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "scope": "read:user user:email",
            "state": state,
        }
        return f"{self.AUTH_ENDPOINT}?{urllib.parse.urlencode(params)}"

    async def exchange_code(
        self,
        code: str,
        redirect_uri: str,
        code_verifier: Optional[str] = None,
    ) -> Dict[str, Any]:
        data = {
            "code": code,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "redirect_uri": redirect_uri,
        }

        async with httpx.AsyncClient(timeout=10.0) as client:
            token_resp = await client.post(
                self.TOKEN_ENDPOINT,
                data=data,
                headers={"Accept": "application/json"},
            )
            if token_resp.status_code != 200:
                logger.error("GitHub token exchange failed: %s", token_resp.text)
                raise ValueError(f"GitHub token exchange failed: {token_resp.text}")

            tokens = token_resp.json()
            access_token = tokens.get("access_token")
            if not access_token:
                raise ValueError(f"GitHub did not return access_token: {tokens}")

            user_resp = await client.get(
                self.USERINFO_ENDPOINT,
                headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
            )
            if user_resp.status_code != 200:
                raise ValueError("Failed to fetch GitHub user profile.")
            user_data = user_resp.json()

            email = user_data.get("email")
            email_verified = True
            if not email:
                emails_resp = await client.get(
                    self.EMAILS_ENDPOINT,
                    headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
                )
                if emails_resp.status_code == 200:
                    emails = emails_resp.json()
                    for e in emails:
                        if e.get("primary") and e.get("verified"):
                            email = e.get("email")
                            email_verified = True
                            break

            return {
                "provider": "github",
                "provider_user_id": str(user_data.get("id")),
                "email": email,
                "email_verified": email_verified,
                "name": user_data.get("name") or user_data.get("login"),
                "username": user_data.get("login"),
                "picture": user_data.get("avatar_url"),
            }


# =============================================================================
# OAuth Manager & State Coordinator
# =============================================================================
class OAuthManager:
    """Coordinates OAuth providers, state parameters, and PKCE verifiers."""

    def __init__(self, redis_client: Optional[Any] = None):
        self.r = redis_client
        self._in_memory_states: Dict[str, Dict[str, Any]] = {}
        self.providers: Dict[str, abstractOAuth2Provider] = {}
        self._initialize_providers()

    def _initialize_providers(self) -> None:
        google_id = os.getenv("GOOGLE_CLIENT_ID")
        google_secret = os.getenv("GOOGLE_CLIENT_SECRET")
        if google_id and google_secret:
            self.providers["google"] = GoogleOAuth2Provider(google_id, google_secret)

        github_id = os.getenv("GITHUB_CLIENT_ID")
        github_secret = os.getenv("GITHUB_CLIENT_SECRET")
        if github_id and github_secret:
            self.providers["github"] = GitHubOAuth2Provider(github_id, github_secret)

    def register_provider(self, name: str, provider: abstractOAuth2Provider) -> None:
        self.providers[name.lower()] = provider

    def get_provider(self, name: str) -> Optional[abstractOAuth2Provider]:
        return self.providers.get(name.lower())

    def save_state(self, state: str, data: Dict[str, Any], ttl_seconds: int = 600) -> None:
        """Store state metadata in Redis with 10-minute TTL, fallback to memory."""
        if self.r is not None:
            try:
                self.r.set(f"oauth_state:{state}", json.dumps(data), ex=ttl_seconds)
                return
            except Exception as exc:
                logger.warning("Failed to store OAuth state in Redis (%s).", exc)
        self._in_memory_states[state] = data

    def consume_state(self, state: str) -> Optional[Dict[str, Any]]:
        """Validate and immediately delete an OAuth state to prevent replay attacks."""
        if self.r is not None:
            try:
                key = f"oauth_state:{state}"
                raw = self.r.get(key)
                if raw:
                    self.r.delete(key)
                    return json.loads(raw)
            except Exception as exc:
                logger.warning("Failed to retrieve OAuth state from Redis (%s).", exc)

        return self._in_memory_states.pop(state, None)
