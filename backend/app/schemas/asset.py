"""Pydantic schemas for Asset entity CRUD and validation."""

import ipaddress
from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator
from app.models.asset import AssetType, AssetEnvironment, TargetType


class VulnSeverityCounts(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    none: int = 0


class AssetBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255, description="Name of the asset")
    ip_address: str = Field(..., min_length=1, max_length=255, description="Target IPv4 address, domain name, or URL")
    hostname: Optional[str] = Field(None, max_length=255)
    asset_type: AssetType
    environment: AssetEnvironment
    criticality: int = Field(..., ge=1, le=5, description="Criticality rating on a scale from 1 (Low) to 5 (Critical)")
    owner: str = Field(default="Unassigned", max_length=255)
    description: Optional[str] = None
    target_type: Optional[TargetType] = TargetType.ip
    resolved_ip: Optional[str] = None
    auto_created: bool = False
    is_seed: bool = False
    owner_id: Optional[int] = None


class AssetCreate(AssetBase):
    pass


class AssetUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    ip_address: Optional[str] = Field(None, min_length=1, max_length=255)
    hostname: Optional[str] = Field(None, max_length=255)
    asset_type: Optional[AssetType] = None
    environment: Optional[AssetEnvironment] = None
    criticality: Optional[int] = Field(None, ge=1, le=5)
    owner: Optional[str] = Field(None, max_length=255)
    description: Optional[str] = None
    target_type: Optional[TargetType] = None
    resolved_ip: Optional[str] = None
    auto_created: Optional[bool] = None
    is_seed: Optional[bool] = None


class AssetRead(AssetBase):
    id: int
    target_type: TargetType
    resolved_ip: Optional[str] = None
    auto_created: bool = False
    is_seed: bool = False
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AssetDetailRead(AssetRead):
    vuln_counts: VulnSeverityCounts = Field(default_factory=VulnSeverityCounts)


class AssetListResponse(BaseModel):
    data: List[AssetRead]
    total: int
    page: int
    page_size: int
