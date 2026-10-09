"""Pydantic schemas for operator action audit logs."""

from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field


class OperatorActionBase(BaseModel):
    tool: str = Field(..., min_length=1, max_length=50, description="Tool or method name used (e.g. nmap, manual, curl)")
    command_or_action: str = Field(..., min_length=1, max_length=5000, description="Exact command or testing action performed")
    result_summary: str = Field(..., min_length=1, max_length=5000, description="Summary notes or findings outcome")
    evidence: Optional[str] = Field(None, max_length=20000, description="Raw output or captured response evidence")
    linked_cves: Optional[List[str]] = Field(default_factory=list, description="Target CVE identifiers associated with this action")


class OperatorActionCreate(OperatorActionBase):
    asset_id: int = Field(..., description="Target asset identifier")


class OperatorActionRead(OperatorActionBase):
    id: int
    asset_id: int
    user_id: Optional[int] = None
    user_email: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class OperatorActionListResponse(BaseModel):
    data: List[OperatorActionRead]
    total: int
    page: int
    page_size: int
