"""Pydantic schemas for AI Operations Copilot."""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ChatRequest(BaseModel):
    asset_id: int = Field(..., description="Target asset ID for context")
    message: str = Field(..., min_length=1, max_length=4000, description="Operator user prompt")


class ToolInvocation(BaseModel):
    tool: str
    args: Dict[str, Any] = Field(default_factory=dict)
    summary: Optional[str] = None


class ChatResponse(BaseModel):
    reply: str
    tools_used: List[Dict[str, Any]] = Field(default_factory=list)
    saved: bool = True


class ChatMessageOut(BaseModel):
    id: int
    asset_id: int
    user_id: int
    role: str
    content: str
    tools_used: Optional[List[Dict[str, Any]]] = None
    created_at: datetime

    class Config:
        from_attributes = True


class SuggestionsResponse(BaseModel):
    asset_id: int
    suggestions: List[str]
