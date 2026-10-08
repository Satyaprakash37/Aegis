"""User model definition and RBAC role enumeration."""

import enum
from datetime import datetime
from typing import TYPE_CHECKING, List
from sqlalchemy import Boolean, DateTime, Enum, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base

if TYPE_CHECKING:
    from app.models.asset import Asset
    from app.models.report import Report
    from app.models.scan import Scan


class UserRole(str, enum.Enum):
    """User roles for role-based access control."""
    admin = "admin"
    analyst = "analyst"
    viewer = "viewer"


class User(Base):
    """User account entity."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[UserRole] = mapped_column(
        Enum(UserRole, name="user_role_enum", values_callable=lambda obj: [e.value for e in obj]),
        default=UserRole.analyst,
        nullable=False,
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    # Relationships
    assets: Mapped[List["Asset"]] = relationship(
        "Asset",
        back_populates="owner_user",
        foreign_keys="Asset.owner_id",
    )
    scans: Mapped[List["Scan"]] = relationship(
        "Scan",
        back_populates="creator_user",
        foreign_keys="Scan.created_by",
    )
    reports: Mapped[List["Report"]] = relationship(
        "Report",
        back_populates="user",
        cascade="all, delete-orphan",
    )
