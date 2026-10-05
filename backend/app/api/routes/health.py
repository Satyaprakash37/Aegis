"""Health check route."""

from typing import Any, Dict
from fastapi import APIRouter

router = APIRouter(tags=["health"])


@router.get("/health", response_model=Dict[str, Any])
async def health_check() -> Dict[str, Any]:
    """Return health status of the AEGIS service."""
    return {
        "status": "ok",
        "app": "aegis",
        "version": "1.0.0",
    }
