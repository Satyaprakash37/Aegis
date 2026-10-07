"""Health check route."""

import shutil
from typing import Any, Dict
from fastapi import APIRouter, Depends
from sqlalchemy import text, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.db.session import get_db
from app.models.scan import Scan, ScanStatus

router = APIRouter(tags=["health"])


@router.get("/health", response_model=Dict[str, Any])
async def health_check(db: AsyncSession = Depends(get_db)) -> Dict[str, Any]:
    """Return health status of the AEGIS service, database, toolset, and active scan."""
    db_status = "healthy"
    try:
        await db.execute(text("SELECT 1"))
    except Exception:
        db_status = "unhealthy"

    # Query active running scan if any
    active_scan_info = None
    try:
        active_query = (
            select(Scan)
            .options(selectinload(Scan.asset))
            .where(Scan.status == ScanStatus.running)
            .order_by(Scan.started_at.desc())
            .limit(1)
        )
        active_res = await db.execute(active_query)
        running_scan = active_res.scalar_one_or_none()
        if running_scan:
            active_scan_info = {
                "id": running_scan.id,
                "target": running_scan.asset.name if running_scan.asset else f"Asset #{running_scan.asset_id}",
                "scan_type": running_scan.scan_type.value,
                "progress": running_scan.progress,
            }
    except Exception:
        pass

    tools = {
        "nmap": bool(shutil.which("nmap")),
        "nuclei": bool(shutil.which("nuclei") or shutil.which("/usr/local/bin/nuclei")),
        "subfinder": bool(shutil.which("subfinder") or shutil.which("/usr/local/bin/subfinder")),
        "testssl": bool(shutil.which("testssl.sh") or shutil.which("/usr/local/bin/testssl.sh")),
    }

    return {
        "status": "ok" if db_status == "healthy" else "degraded",
        "app": "aegis",
        "version": "1.2.0",
        "database": db_status,
        "engine": "ready",
        "tools": tools,
        "active_scan": active_scan_info,
    }
