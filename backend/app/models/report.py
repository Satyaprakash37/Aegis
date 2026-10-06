"""Report model definition and type/format enums."""

import enum
from datetime import datetime
from typing import TYPE_CHECKING
from sqlalchemy import DateTime, Enum, ForeignKey, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base

if TYPE_CHECKING:
    from app.models.user import User


class ReportType(str, enum.Enum):
    """Supported report generation templates."""
    executive = "executive"
    detailed = "detailed"
    compliance = "compliance"


class ReportFormat(str, enum.Enum):
    """Generated document export formats."""
    pdf = "pdf"
    excel = "excel"


class Report(Base):
    """Generated security report audit record."""

    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    report_type: Mapped[ReportType] = mapped_column(
        Enum(ReportType, name="report_type_enum", values_callable=lambda obj: [e.value for e in obj]),
        nullable=False,
    )
    format: Mapped[ReportFormat] = mapped_column(
        Enum(ReportFormat, name="report_format_enum", values_callable=lambda obj: [e.value for e in obj]),
        nullable=False,
    )
    generated_by: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    file_path: Mapped[str] = mapped_column(String(512), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    # Relationships
    user: Mapped["User"] = relationship("User", back_populates="reports")
