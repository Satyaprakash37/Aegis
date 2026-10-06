"""Pydantic schemas for Scan entity CRUD, serialization, and status tracking."""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from app.models.scan import ScanStatus, ScanType
from app.schemas.asset import VulnSeverityCounts


class ScanBase(BaseModel):
    asset_id: int
    scan_type: ScanType = ScanType.quick


class ScanCreate(ScanBase):
    pass


class ScanRead(BaseModel):
    id: int
    asset_id: int
    asset_name: Optional[str] = None
    asset_ip: Optional[str] = None
    target_type: Optional[str] = None
    resolved_ip: Optional[str] = None
    scan_type: ScanType
    status: ScanStatus
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    total_vulns_found: int = 0
    raw_output: Optional[Dict[str, Any]] = None

    model_config = ConfigDict(from_attributes=True)


class ScanDetailRead(ScanRead):
    vuln_counts: VulnSeverityCounts = Field(default_factory=VulnSeverityCounts)
    verification_breakdown: Optional[Dict[str, int]] = None


class ScanListResponse(BaseModel):
    data: List[ScanRead]
    total: int
    page: int
    page_size: int
