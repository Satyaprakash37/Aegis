"""Asset model definition and categorization enums."""

import enum
from typing import TYPE_CHECKING, List, Optional
from sqlalchemy import Enum, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin

if TYPE_CHECKING:
    from app.models.scan import Scan
    from app.models.vulnerability import Vulnerability


class AssetType(str, enum.Enum):
    """Network asset classifications."""
    server = "server"
    web = "web"
    db = "db"
    network = "network"


class AssetEnvironment(str, enum.Enum):
    """Operational deployment environments."""
    production = "production"
    staging = "staging"
    dev = "dev"


class TargetType(str, enum.Enum):
    """Asset target specification type."""
    ip = "ip"
    domain = "domain"


class Asset(Base, TimestampMixin):
    """Network asset entity registered for vulnerability tracking."""

    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    ip_address: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    target_type: Mapped[TargetType] = mapped_column(
        Enum(TargetType, name="target_type_enum", values_callable=lambda obj: [e.value for e in obj]),
        nullable=False,
        default=TargetType.ip,
        server_default="ip",
    )
    resolved_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    asset_type: Mapped[AssetType] = mapped_column(
        Enum(AssetType, name="asset_type_enum", values_callable=lambda obj: [e.value for e in obj]),
        nullable=False,
    )
    environment: Mapped[AssetEnvironment] = mapped_column(
        Enum(AssetEnvironment, name="asset_environment_enum", values_callable=lambda obj: [e.value for e in obj]),
        nullable=False,
    )
    criticality: Mapped[int] = mapped_column(Integer, nullable=False)  # Scale 1-5
    owner: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    scans: Mapped[List["Scan"]] = relationship(
        "Scan",
        back_populates="asset",
        cascade="all, delete-orphan",
    )
    vulnerabilities: Mapped[List["Vulnerability"]] = relationship(
        "Vulnerability",
        back_populates="asset",
        cascade="all, delete-orphan",
    )
