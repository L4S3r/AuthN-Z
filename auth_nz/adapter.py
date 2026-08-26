"""
Auth N&Z - Adapter Submodule (auth_nz.adapter)
----------------------------------------------
Re-exports adapter utilities and configuration functions.
"""

from adapter import (
    configure_authnz,
    AuthNZ,
    AuthNZAdapter,
)

__all__ = [
    "configure_authnz",
    "AuthNZ",
    "AuthNZAdapter",
]
