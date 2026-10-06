"""Pydantic schemas for Asset entity CRUD and validation."""

import ipaddress
from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator
from app.models.asset import AssetType, AssetEnvironment


class VulnSeverityCounts(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    none: int = 0


class AssetBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255, description="Name of the asset")
    ip_address: str = Field(..., description="Valid IPv4 address")
    hostname: Optional[str] = Field(None, max_length=255)
    asset_type: AssetType
    environment: AssetEnvironment
    criticality: int = Field(..., ge=1, le=5, description="Criticality rating on a scale from 1 (Low) to 5 (Critical)")
    owner: str = Field(default="Unassigned", max_length=255)
    description: Optional[str] = None

    @field_validator("ip_address")
    @classmethod
    def validate_ipv4_address(cls, v: str) -> str:
        trimmed = v.strip()
        try:
            ip = ipaddress.IPv4Address(trimmed)
            return str(ip)
        except ValueError:
            raise ValueError(f"'{trimmed}' is not a valid IPv4 address (e.g. 192.168.1.1)")


class AssetCreate(AssetBase):
    pass


class AssetUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    ip_address: Optional[str] = None
    hostname: Optional[str] = Field(None, max_length=255)
    asset_type: Optional[AssetType] = None
    environment: Optional[AssetEnvironment] = None
    criticality: Optional[int] = Field(None, ge=1, le=5)
    owner: Optional[str] = Field(None, max_length=255)
    description: Optional[str] = None

    @field_validator("ip_address")
    @classmethod
    def validate_ipv4_address(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        trimmed = v.strip()
        try:
            ip = ipaddress.IPv4Address(trimmed)
            return str(ip)
        except ValueError:
            raise ValueError(f"'{trimmed}' is not a valid IPv4 address (e.g. 192.168.1.1)")


class AssetRead(AssetBase):
    id: int
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
