"""AEGIS Schemas Package.

Exports Pydantic validation schemas for data transfer and serialization.
"""

from app.schemas.user import UserBase, UserCreate, UserRead, Token, TokenPayload
from app.schemas.asset import (
    AssetBase,
    AssetCreate,
    AssetUpdate,
    AssetRead,
    AssetDetailRead,
    AssetListResponse,
    VulnSeverityCounts,
)
from app.schemas.scan import (
    ScanBase,
    ScanCreate,
    ScanRead,
    ScanDetailRead,
    ScanListResponse,
)
from app.schemas.vulnerability import (
    VulnerabilityBase,
    VulnerabilityCreate,
    VulnerabilityRead,
    VulnerabilityListResponse,
    VulnerabilityStatusUpdate,
    RiskRecalculateResponse,
)
from app.schemas.report import ReportBase, ReportCreate, ReportRead

__all__ = [
    "UserBase",
    "UserCreate",
    "UserRead",
    "Token",
    "TokenPayload",
    "AssetBase",
    "AssetCreate",
    "AssetUpdate",
    "AssetRead",
    "AssetDetailRead",
    "AssetListResponse",
    "VulnSeverityCounts",
    "ScanBase",
    "ScanCreate",
    "ScanRead",
    "ScanDetailRead",
    "ScanListResponse",
    "VulnerabilityBase",
    "VulnerabilityCreate",
    "VulnerabilityRead",
    "VulnerabilityListResponse",
    "VulnerabilityStatusUpdate",
    "RiskRecalculateResponse",
    "ReportBase",
    "ReportCreate",
    "ReportRead",
]
