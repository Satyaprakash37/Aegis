"""Agent & Attack Lab API routes."""

from typing import Annotated, Any, Dict
from fastapi import APIRouter, Depends, status

from app.api.deps import require_admin
from app.models.user import User
from app.services.agent.msf_client import get_msf_status

router = APIRouter(prefix="/agent", tags=["Agent / Attack Lab"])


@router.get(
    "/msf-status",
    summary="Check Metasploit RPC Daemon Status",
    description="Admin-only diagnostic endpoint verifying connectivity to containerized msfrpcd daemon.",
    response_model=Dict[str, Any],
)
async def check_msf_status(
    admin_user: Annotated[User, Depends(require_admin)],
) -> Dict[str, Any]:
    """Retrieve Metasploit RPC daemon connection status, version, and module inventory."""
    status_data = get_msf_status()
    return status_data
