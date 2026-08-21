"""
Component Role: Multi-Factor Authentication (MFA) Provider
----------------------------------------------------------
This component manages second-factor authentication challenges such as Time-based One-Time Passwords
(TOTP / RFC 6238), SMS/email OTP codes, or backup emergency recovery codes.

System Relationship:
During a multi-step login flow, after primary credentials (passwords) are verified, the Authenticator
invokes this component to issue and validate secondary challenges. It is also invoked when users enroll
in MFA, display QR codes for authenticator apps (Google Authenticator, Authy), or regenerate emergency
backup recovery codes.
"""

from abc import ABC, abstractmethod
from typing import List, Optional, Tuple
from urllib.parse import quote
import base64
import secrets
import string
import pyotp
import hashlib
import hmac

class abstractMFAProvider(ABC):
    """Abstract interface defining multi-factor authentication enrollment, challenge verification, and recovery mechanisms."""

    @abstractmethod
    def generate_secret(self, user_id: str) -> str:
        """
        Generate a cryptographically secure, base32-encoded shared secret for a user's MFA enrollment.

        Args:
            user_id: The unique identifier of the user enrolling in MFA.

        Returns:
            A base32-encoded secret string (typically 160-bit or 256-bit entropy).

        Edge Cases to Consider:
            - Cryptographic randomness source strength (using os.urandom or secrets module).
            - Protecting temporary unconfirmed enrollment secrets until the first successful verification occurs.
        """
        ...

    @abstractmethod
    def get_provisioning_uri(
        self,
        user_id: str,
        secret: str,
        account_name: str,
        issuer_name: str = "MySecureApp",
    ) -> str:
        """
        Generate an 'otpauth://totp/...' URI used to produce QR codes for authenticator applications.

        Args:
            user_id: The unique identifier of the user.
            secret: The base32-encoded shared secret.
            account_name: The user's label or email to show in the authenticator app.
            issuer_name: The name of the organization or application.

        Returns:
            A formatted URI string adhering to the Key URI Format (RFC 6238 / Google Authenticator standard).

        Edge Cases to Consider:
            - URL-encoding special characters, colons, or spaces in issuer and account names.
            - Defaulting to standard parameters (6 digits, 30-second period, SHA1/SHA256 algorithm).
        """
        ...

    @abstractmethod
    def verify_totp_code(
        self,
        secret: str,
        code: str,
        tolerance_steps: int = 1,
    ) -> bool:
        """
        Verify a time-based 6-to-8 digit OTP code against the shared secret for the current time window.

        Args:
            secret: The base32-encoded shared secret.
            code: The OTP string submitted by the user.
            tolerance_steps: Number of adjacent time windows (forward and backward) to accept to account for clock drift.

        Returns:
            True if the code is valid for the allowable time window, False otherwise.

        Edge Cases to Consider:
            - Replay attacks: preventing the same OTP code from being used twice within the same valid time window.
            - Clock drift between the client device and the authentication server.
            - Non-numeric or incorrectly formatted code inputs (stripping whitespace, hyphens).
        """
        ...

    @abstractmethod
    def generate_backup_codes(self, count: int = 8, code_length: int = 10) -> List[str]:
        """
        Generate a list of single-use emergency backup recovery codes.

        Args:
            count: Number of backup codes to generate (default is 8).
            code_length: Length/entropy of each backup code (default is 10 alphanumeric characters).

        Returns:
            A list of plaintext backup code strings to present to the user once upon setup.

        Edge Cases to Consider:
            - Excluding ambiguous characters (e.g., '0', 'O', '1', 'l', 'I') to minimize typing errors.
            - Ensuring these codes are hashed before storing in persistent databases.
        """
        ...

    @abstractmethod
    def verify_and_consume_backup_code(
        self,
        provided_code: str,
        stored_hashed_codes: List[str],
    ) -> Tuple[bool, List[str]]:
        """
        Verify a provided backup code against a list of hashed backup codes and consume it if valid.

        Args:
            provided_code: The single-use backup code submitted by the user.
            stored_hashed_codes: The list of stored hashed backup codes currently assigned to the user.

        Returns:
            A tuple of (is_valid, remaining_hashed_codes):
            - is_valid: True if matched, False otherwise.
            - remaining_hashed_codes: The updated list of hashed codes with the matched code removed.

        Edge Cases to Consider:
            - Constant-time verification against all candidate hashes to prevent timing side-channels.
            - Immediate consumption to guarantee single-use semantics.
            - Handling an empty list of stored backup codes.
        """
        ...
class MFAProvider(abstractMFAProvider):
    def generate_secret(self,user_id:str)->str:
        """Generate a cryptographically secure 160-bit base32-encoded shared secret."""
        secret = secrets.token_bytes(20)
        return base64.b32encode(secret).decode("utf-8")
    def get_provisioning_uri(
        self,
        user_id: str,
        secret: str,
        account_name: str,
        issuer_name: str = "OOB-based-auth-app",
    ) -> str:
        escaped_issuer=quote(issuer_name)
        escaped_account=quote(account_name)
        return(
            f"otpauth://totp/{escaped_issuer}:{escaped_account}?"
            f"secret={secret}&issuer={escaped_issuer}&algorithm=SHA1&digits=6&period=30"
        )
    def verify_totp_code(
        self,
        secret: str,
        code: str,
        tolerance_steps: int = 1,
    ) -> bool:
        """Verify a time-based 6-to-8 digit OTP code against the shared secret."""
        try:
            clean_code=str(code).strip().replace(" ","").replace("-","")
            return bool(pyotp.TOTP(secret).verify(clean_code,valid_window=tolerance_steps))
        except Exception:
            return False
    def generate_backup_codes(self, count: int = 8, code_length: int = 10) -> List[str]:
        characters = "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        unique_codes=set()
        while len(unique_codes)<count:
            code=''.join(secrets.choice(characters) for _ in range(code_length))
            unique_codes.add(code)
        return list(unique_codes)
    def verify_and_consume_backup_code(
        self,
        provided_code: str,
        stored_hashed_codes: List[str],
    ) -> Tuple[bool, List[str]]:
        """Verify a single-use backup code against stored hashes and remove it if valid."""
        clean_code=str(provided_code).strip()
        candidate_hash=hashlib.sha256(clean_code.encode("utf-8")).hexdigest()
        remaining_codes=list(stored_hashed_codes)
        for i,stored_hash in enumerate(stored_hashed_codes):
            if hmac.compare_digest(candidate_hash,stored_hash):
                remaining_codes.pop(i)
                return(True,remaining_codes)
        return (False,remaining_codes)


concreteMFAProvider = MFAProvider




