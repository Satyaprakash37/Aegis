"""Pydantic schemas for Report entity."""

from datetime import datetime
from pydantic import BaseModel, ConfigDict
from app.models.report import ReportType, ReportFormat


class ReportBase(BaseModel):
    report_type: ReportType
    format: ReportFormat


class ReportCreate(ReportBase):
    pass


class ReportRead(ReportBase):
    id: int
    generated_by: int
    file_path: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
