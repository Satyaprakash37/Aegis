"""Scan model definition and status tracking enums."""

import enum
from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, List, Optional
from sqlalchemy import DateTime, Enum, ForeignKey, Integer
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base

if TYPE_CHECKING:
    from app.models.asset import Asset
    from app.models.vulnerability import Vulnerability


class ScanType(str, enum.Enum):
    """Scan execution depth."""
    quick = "quick"
    full = "full"


class ScanStatus(str, enum.Enum):
    """Lifecycle status of a scan job."""
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"


class Scan(Base):
    """Nmap and enrichment scan execution record."""

    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    asset_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    scan_type: Mapped[ScanType] = mapped_column(
        Enum(ScanType, name="scan_type_enum", values_callable=lambda obj: [e.value for e in obj]),
        nullable=False,
    )
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus, name="scan_status_enum", values_callable=lambda obj: [e.value for e in obj]),
        default=ScanStatus.pending,
        nullable=False,
    )
    started_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    total_vulns_found: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )
    raw_output: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSONB,
        nullable=True,
    )

    # Relationships
    asset: Mapped["Asset"] = relationship("Asset", back_populates="scans")
    vulnerabilities: Mapped[List["Vulnerability"]] = relationship(
        "Vulnerability",
        back_populates="scan",
        cascade="all, delete-orphan",
    )
