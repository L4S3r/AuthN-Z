"""
Auth N&Z - Dual-Engine Password Hasher (password_hasher.py)
-----------------------------------------------------------
Supports state-of-the-art Argon2id (OWASP recommended) and industry-standard Bcrypt.
Provides constant-time verification and zero-downtime automatic algorithm / work-factor migration.
"""

from abc import ABC, abstractmethod
import logging
from typing import Optional
import bcrypt

try:
    from argon2 import PasswordHasher as Argon2Hasher, Type as Argon2Type, exceptions as argon2_exceptions
    _ARGON2_AVAILABLE = True
except ImportError:
    Argon2Hasher = None
    Argon2Type = None
    argon2_exceptions = None
    _ARGON2_AVAILABLE = False

from config import settings

logger = logging.getLogger("auth_nz.password_hasher")


class abstractPasswordHasher(ABC):
    """Abstract interface defining cryptographic password hashing, verification, and upgrade operations."""

    @abstractmethod
    def hash(self, plain_password: str, algorithm: Optional[str] = None) -> str:
        """Produce a secure, salted, one-way hash from a plaintext password string."""
        pass

    @abstractmethod
    def verify(self, plain_password: str, hashed_password: str) -> bool:
        """Verify whether a plaintext password matches an existing stored password hash."""
        pass

    @abstractmethod
    def needs_rehash(self, hashed_password: str, target_algorithm: Optional[str] = None) -> bool:
        """Determine if a stored password hash was created using outdated parameters or an older algorithm."""
        pass


class PasswordHasher(abstractPasswordHasher):
    def __init__(
        self,
        default_algorithm: Optional[str] = None,
        bcrypt_rounds: Optional[int] = None,
        argon2_time_cost: Optional[int] = None,
        argon2_memory_cost: Optional[int] = None,
        argon2_parallelism: Optional[int] = None,
    ):
        self.default_algorithm = (default_algorithm or settings.PASSWORD_HASH_ALGORITHM).lower()
        self.bcrypt_rounds = bcrypt_rounds or settings.BCRYPT_WORK_FACTOR
        self.argon2_time_cost = argon2_time_cost or settings.ARGON2_TIME_COST
        self.argon2_memory_cost = argon2_memory_cost or settings.ARGON2_MEMORY_COST
        self.argon2_parallelism = argon2_parallelism or settings.ARGON2_PARALLELISM

        if _ARGON2_AVAILABLE:
            self._argon2_hasher = Argon2Hasher(
                time_cost=self.argon2_time_cost,
                memory_cost=self.argon2_memory_cost,
                parallelism=self.argon2_parallelism,
                type=Argon2Type.ID,
            )
        else:
            self._argon2_hasher = None

    def hash(self, plain_password: str, algorithm: Optional[str] = None) -> str:
        """
        Hash plaintext password using either Argon2id or Bcrypt.
        """
        if not plain_password:
            raise ValueError("Password cannot be empty")

        algo = (algorithm or self.default_algorithm).lower()

        if algo == "argon2id" or algo == "argon2":
            if not _ARGON2_AVAILABLE or self._argon2_hasher is None:
                logger.warning("Argon2 package not available, falling back to Bcrypt.")
                return self._hash_bcrypt(plain_password)
            return self._argon2_hasher.hash(plain_password)
        else:
            return self._hash_bcrypt(plain_password)

    def _hash_bcrypt(self, plain_password: str) -> str:
        password_bytes = plain_password.encode("utf-8")
        salt = bcrypt.gensalt(rounds=self.bcrypt_rounds)
        hashed = bcrypt.hashpw(password_bytes, salt)
        return hashed.decode("utf-8")

    def verify(self, plain_password: str, hashed_password: str) -> bool:
        """
        Verify plaintext against stored hash, auto-detecting Argon2id vs Bcrypt format.
        """
        if not plain_password or not hashed_password:
            return False

        # 1. Argon2 Format ($argon2id$, $argon2i$, $argon2d$)
        if hashed_password.startswith("$argon2"):
            if not _ARGON2_AVAILABLE or self._argon2_hasher is None:
                logger.error("Stored hash is Argon2 format, but argon2-cffi is not installed.")
                return False
            try:
                self._argon2_hasher.verify(hashed_password, plain_password)
                return True
            except Exception:
                return False

        # 2. Bcrypt Format ($2b$, $2a$, $2y$)
        if hashed_password.startswith(("$2b$", "$2a$", "$2y$")):
            try:
                password_bytes = plain_password.encode("utf-8")
                hashed_bytes = hashed_password.encode("utf-8")
                return bcrypt.checkpw(password_bytes, hashed_bytes)
            except (ValueError, TypeError):
                return False

        return False

    def needs_rehash(self, hashed_password: str, target_algorithm: Optional[str] = None) -> bool:
        """
        Check if stored hash needs migration to modern parameters or target algorithm.
        """
        if not hashed_password:
            return True

        target_algo = (target_algorithm or self.default_algorithm).lower()

        # If target algorithm is Argon2id
        if target_algo in ("argon2id", "argon2"):
            if not hashed_password.startswith("$argon2"):
                return True  # Bcrypt hash needs upgrade to Argon2id
            if _ARGON2_AVAILABLE and self._argon2_hasher is not None:
                try:
                    return self._argon2_hasher.check_needs_rehash(hashed_password)
                except Exception:
                    return True
            return False

        # If target algorithm is Bcrypt
        if target_algo == "bcrypt":
            if not hashed_password.startswith(("$2b$", "$2a$", "$2y$")):
                return True
            try:
                parts = hashed_password.split("$")
                if len(parts) < 4:
                    return True
                current_rounds = int(parts[2])
                return current_rounds < self.bcrypt_rounds
            except (ValueError, IndexError):
                return True

        return False


concretePasswordHasher = PasswordHasher