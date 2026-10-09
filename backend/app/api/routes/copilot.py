"""API routes for AEGIS AI Operations Copilot."""

import asyncio
import logging
from typing import Annotated, Any, Dict, List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import delete, desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_analyst_or_admin
from app.core.config import settings
from app.db.session import get_db
from app.models.asset import Asset
from app.models.chat_message import ChatMessage
from app.models.user import User
from app.schemas.copilot import ChatMessageOut, ChatRequest, ChatResponse, SuggestionsResponse
from app.services.copilot.engine import CopilotEngine

logger = logging.getLogger("aegis.copilot.routes")

router = APIRouter(prefix="/copilot", tags=["AI Operations Copilot"])


@router.post(
    "/chat",
    response_model=ChatResponse,
    summary="Chat with AEGIS Operations Copilot",
    description="Conversational analyst guidance with function calling tool integration.",
)
async def chat_with_copilot(
    req: ChatRequest,
    current_user: Annotated[User, Depends(require_analyst_or_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ChatResponse:
    """Send a user message to Copilot and receive defensive guidance with tool telemetry."""
    # 1. Verify GEMINI_API_KEY configuration
    if not settings.GEMINI_API_KEY or not settings.GEMINI_API_KEY.strip():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Copilot not configured - set GEMINI_API_KEY",
        )

    # 2. Verify target asset exists
    asset_res = await db.execute(select(Asset).where(Asset.id == req.asset_id))
    asset = asset_res.scalar_one_or_none()
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset #{req.asset_id} not found in inventory.",
        )

    # 3. Persist operator's user message
    user_msg = ChatMessage(
        asset_id=req.asset_id,
        user_id=current_user.id,
        role="user",
        content=req.message.strip(),
    )
    db.add(user_msg)
    await db.commit()

    # 4. Fetch recent conversation history
    history_res = await db.execute(
        select(ChatMessage)
        .where(ChatMessage.asset_id == req.asset_id)
        .order_by(ChatMessage.created_at.asc())
        .limit(50)
    )
    history_records = history_res.scalars().all()

    # 5. Execute Copilot engine with 60s timeout
    engine = CopilotEngine(db)
    try:
        copilot_output = await asyncio.wait_for(
            engine.run_chat(
                asset_id=req.asset_id,
                message=req.message.strip(),
                history_records=history_records,
            ),
            timeout=60.0,
        )
    except asyncio.TimeoutError:
        logger.error("Copilot execution timed out for asset %d", req.asset_id)
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="Copilot analysis timed out after 60 seconds.",
        )
    except Exception as e:
        logger.exception("Error in Copilot chat execution: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Copilot reasoning failure: {str(e)}",
        )

    # 6. Persist Copilot assistant response
    assistant_msg = ChatMessage(
        asset_id=req.asset_id,
        user_id=current_user.id,
        role="assistant",
        content=copilot_output.get("reply", "Analysis complete."),
        tools_used=copilot_output.get("tools_used", []),
    )
    db.add(assistant_msg)
    await db.commit()

    return ChatResponse(
        reply=copilot_output.get("reply", ""),
        tools_used=copilot_output.get("tools_used", []),
        saved=True,
    )


@router.get(
    "/history/{asset_id}",
    response_model=List[ChatMessageOut],
    summary="Get Copilot conversation history",
    description="Retrieve the last 50 chat messages for a specific asset context.",
)
async def get_chat_history(
    asset_id: int,
    current_user: Annotated[User, Depends(require_analyst_or_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> List[ChatMessageOut]:
    """Fetch conversation history for an asset."""
    stmt = (
        select(ChatMessage)
        .where(ChatMessage.asset_id == asset_id)
        .order_by(ChatMessage.created_at.asc())
        .limit(50)
    )
    res = await db.execute(stmt)
    messages = res.scalars().all()
    return messages


@router.delete(
    "/history/{asset_id}",
    summary="Clear Copilot conversation history",
    description="Erase all conversation history for an asset to start a fresh thread.",
)
async def clear_chat_history(
    asset_id: int,
    current_user: Annotated[User, Depends(require_analyst_or_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> Dict[str, Any]:
    """Delete all messages for an asset."""
    stmt = delete(ChatMessage).where(ChatMessage.asset_id == asset_id)
    await db.execute(stmt)
    await db.commit()
    return {"status": "cleared", "asset_id": asset_id}


@router.get(
    "/suggestions/{asset_id}",
    response_model=SuggestionsResponse,
    summary="Get suggested questions for an asset",
    description="Returns 5 data-driven suggested analyst prompts.",
)
async def get_suggested_questions(
    asset_id: int,
    current_user: Annotated[User, Depends(require_analyst_or_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> SuggestionsResponse:
    """Return 5 standard suggested questions for the target asset."""
    suggestions = [
        "What are the most critical findings on this target?",
        "Which vulnerabilities are actively exploited right now?",
        "What should the operator assess first and why?",
        "Summarize the attack surface of this target",
        "Which findings have public exploits documented?",
    ]
    return SuggestionsResponse(asset_id=asset_id, suggestions=suggestions)
