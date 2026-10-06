"""Pydantic schemas for Asset entity."""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict
from app.models.asset import AssetType, AssetEnvironment


class AssetBase(BaseModel):
    name: str
    ip_address: str
    hostname: Optional[str] = None
    asset_type: AssetType
    environment: AssetEnvironment
    criticality: int
    owner: str
    description: Optional[str] = None


class AssetCreate(AssetBase):
    pass


class AssetRead(AssetBase):
    id: int
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)
