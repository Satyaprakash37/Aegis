"""AEGIS Models Package.

Exports all SQLAlchemy models, declarative Base, and enumerations.
"""

from app.models.base import Base, TimestampMixin
from app.models.user import User, UserRole
from app.models.asset import Asset, AssetType, AssetEnvironment
from app.models.scan import Scan, ScanType, ScanStatus
from app.models.vulnerability import (
    Vulnerability,
    VulnerabilitySeverity,
    VulnerabilityStatus,
)
from app.models.report import Report, ReportType, ReportFormat
from app.models.chat_message import ChatMessage

__all__ = [
    "Base",
    "TimestampMixin",
    "User",
    "UserRole",
    "Asset",
    "AssetType",
    "AssetEnvironment",
    "Scan",
    "ScanType",
    "ScanStatus",
    "Vulnerability",
    "VulnerabilitySeverity",
    "VulnerabilityStatus",
    "Report",
    "ReportType",
    "ReportFormat",
    "ChatMessage",
]
