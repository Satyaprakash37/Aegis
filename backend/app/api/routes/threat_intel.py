"""Threat Intelligence API endpoints."""

from typing import Annotated, Any, Dict
from fastapi import APIRouter, Depends, HTTPException, status

from app.api.deps import require_analyst_or_admin
from app.models.user import User
from app.services.threat_intel import (
    download_kev_catalog,
    get_threat_intel,
    kev_stats,
)

router = APIRouter(prefix="/threat-intel", tags=["Threat Intelligence"])


@router.get(
    "/kev/stats",
    summary="Get CISA KEV Catalog Statistics",
    response_model=Dict[str, Any],
)
async def get_kev_catalog_stats(
    current_user: Annotated[User, Depends(require_analyst_or_admin)],
) -> Dict[str, Any]:
    """Return local cache statistics and metadata for CISA KEV catalog."""
    return {
        "status": "success",
        "data": kev_stats(),
    }


@router.post(
    "/kev/sync",
    summary="Synchronize CISA KEV Catalog",
    response_model=Dict[str, Any],
)
async def sync_kev_catalog(
    current_user: Annotated[User, Depends(require_analyst_or_admin)],
) -> Dict[str, Any]:
    """Force download and refresh of the CISA KEV catalog from official feed."""
    try:
        updated_stats = await download_kev_catalog()
        return {
            "status": "success",
            "message": "CISA KEV catalog synchronized successfully",
            "data": updated_stats,
        }
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to synchronize CISA KEV catalog: {str(exc)}",
        )


@router.get(
    "/cve/{cve_id}",
    summary="Get Comprehensive Threat Intel for a CVE",
    response_model=Dict[str, Any],
)
async def get_cve_threat_intelligence(
    cve_id: str,
    current_user: Annotated[User, Depends(require_analyst_or_admin)],
) -> Dict[str, Any]:
    """Lookup combined CISA KEV, FIRST EPSS, and public exploit reference telemetry for a CVE."""
    clean_cve = cve_id.strip().upper()
    if not clean_cve.startswith("CVE-"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid CVE ID format. Must begin with 'CVE-'",
        )

    try:
        intel = await get_threat_intel(clean_cve)
        return {
            "status": "success",
            "data": intel,
        }
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error retrieving threat intelligence for {clean_cve}: {str(exc)}",
        )
