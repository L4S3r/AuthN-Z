"""
Auth N&Z - API v1 Router Alias (api/v1/router.py)
-------------------------------------------------
Re-exports the top-level API router for v1 compatibility.
"""

from api.router import api_router as api_v1_router
from api.router import api_router

__all__ = ["api_v1_router", "api_router"]
