"""Pydantic schemas for Scan entity."""

from datetime import datetime
from typing import Any, Dict, Optional
from pydantic import BaseModel, ConfigDict
from app.models.scan import ScanType, ScanStatus


class ScanBase(BaseModel):
    asset_id: int
    scan_type: ScanType = ScanType.quick
    status: ScanStatus = ScanStatus.pending


class ScanCreate(ScanBase):
    pass


class ScanRead(ScanBase):
    id: int
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    total_vulns_found: int = 0
    raw_output: Optional[Dict[str, Any]] = None

    model_config = ConfigDict(from_attributes=True)
