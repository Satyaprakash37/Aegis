"""Notification schemas for AEGIS SecOps event stream."""

from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel


class NotificationItem(BaseModel):
    id: str
    type: str  # "scan_completed", "critical_vuln", "verified_vuln"
    title: str
    detail: str
    target: Optional[str] = None
    timestamp: datetime
    is_critical: bool = False
    link: str


class NotificationListResponse(BaseModel):
    data: List[NotificationItem]
    total: int
    critical_count_24h: int
