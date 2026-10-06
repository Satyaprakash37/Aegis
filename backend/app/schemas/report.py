"""Pydantic schemas for Report entity and generation workflows."""

from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, ConfigDict, field_validator
from app.models.report import ReportType, ReportFormat


class ReportBase(BaseModel):
    report_type: ReportType
    format: ReportFormat


class ReportCreate(ReportBase):
    pass


class ReportGenerateRequest(BaseModel):
    report_type: ReportType
    format: ReportFormat

    @field_validator("format")
    @classmethod
    def validate_type_format_combination(cls, v: ReportFormat, info) -> ReportFormat:
        report_type = info.data.get("report_type")
        if report_type in [ReportType.executive, ReportType.detailed] and v != ReportFormat.pdf:
            raise ValueError("Executive and Detailed reports must be generated in PDF format.")
        if report_type == ReportType.compliance and v != ReportFormat.excel:
            raise ValueError("Compliance reports must be generated in Excel format.")
        return v


class ReportRead(ReportBase):
    id: int
    generated_by: int
    generated_by_name: Optional[str] = None
    file_path: str
    filename: Optional[str] = None
    file_size_bytes: Optional[int] = 0
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ReportListResponse(BaseModel):
    data: List[ReportRead]
    total: int
