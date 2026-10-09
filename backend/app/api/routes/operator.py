"""API routes for Operator Action audit logs."""

import logging
from typing import Annotated, Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from app.api.deps import require_admin, require_analyst_or_admin
from app.db.session import get_db
from app.models.asset import Asset
from app.models.operator_action import OperatorAction
from app.models.user import User
from app.schemas.operator import (
    OperatorActionCreate,
    OperatorActionListResponse,
    OperatorActionRead,
)

logger = logging.getLogger("aegis.operator.routes")

router = APIRouter(prefix="/operator-actions", tags=["Operator Actions"])


@router.post(
    "",
    response_model=OperatorActionRead,
    status_code=status.HTTP_201_CREATED,
    summary="Record operator testing action",
    description="Logs a manual command, automated tool run, or verification step against an asset.",
)
async def create_operator_action(
    action_in: OperatorActionCreate,
    current_user: Annotated[User, Depends(require_analyst_or_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> OperatorActionRead:
    """Record an operator action into the immutable audit trail."""
    # 1. Verify target asset exists
    asset_res = await db.execute(select(Asset).where(Asset.id == action_in.asset_id))
    asset = asset_res.scalar_one_or_none()
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset #{action_in.asset_id} not found in inventory.",
        )

    # 2. Sanitize and persist operator action
    action = OperatorAction(
        asset_id=action_in.asset_id,
        user_id=current_user.id,
        tool=action_in.tool.strip(),
        command_or_action=action_in.command_or_action.strip(),
        result_summary=action_in.result_summary.strip(),
        evidence=action_in.evidence.strip() if action_in.evidence else None,
        linked_cves=action_in.linked_cves or [],
    )
    db.add(action)
    await db.commit()
    await db.refresh(action)

    logger.info(
        "Operator action #%d recorded by %s against asset #%d (Tool: %s)",
        action.id,
        current_user.email,
        action.asset_id,
        action.tool,
    )

    return OperatorActionRead(
        id=action.id,
        asset_id=action.asset_id,
        user_id=action.user_id,
        user_email=current_user.email,
        tool=action.tool,
        command_or_action=action.command_or_action,
        result_summary=action.result_summary,
        evidence=action.evidence,
        linked_cves=action.linked_cves or [],
        created_at=action.created_at,
    )


@router.get(
    "/{asset_id}",
    response_model=OperatorActionListResponse,
    summary="List operator actions for asset",
    description="Retrieve paginated audit log of operator actions for a target asset (latest first).",
)
async def list_operator_actions(
    asset_id: int,
    current_user: Annotated[User, Depends(require_analyst_or_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=100, description="Page size"),
) -> OperatorActionListResponse:
    """Fetch chronological operator actions for a specific target asset."""
    # 1. Total count
    count_stmt = select(func.count(OperatorAction.id)).where(OperatorAction.asset_id == asset_id)
    total = (await db.execute(count_stmt)).scalar_one()

    # 2. Query paginated records with user details
    stmt = (
        select(OperatorAction, User.email)
        .outerjoin(User, OperatorAction.user_id == User.id)
        .where(OperatorAction.asset_id == asset_id)
        .order_by(desc(OperatorAction.created_at))
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    res = await db.execute(stmt)
    rows = res.all()

    actions_out = []
    for action, user_email in rows:
        actions_out.append(
            OperatorActionRead(
                id=action.id,
                asset_id=action.asset_id,
                user_id=action.user_id,
                user_email=user_email,
                tool=action.tool,
                command_or_action=action.command_or_action,
                result_summary=action.result_summary,
                evidence=action.evidence,
                linked_cves=action.linked_cves or [],
                created_at=action.created_at,
            )
        )

    return OperatorActionListResponse(
        data=actions_out,
        total=total,
        page=page,
        page_size=page_size,
    )


@router.delete(
    "/{id}",
    summary="Delete operator action entry",
    description="Administrator-only endpoint to remove an erroneous action log entry.",
)
async def delete_operator_action(
    id: int,
    current_user: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> Dict[str, Any]:
    """Delete an operator action audit entry. Requires administrator privileges."""
    stmt = select(OperatorAction).where(OperatorAction.id == id)
    action = (await db.execute(stmt)).scalar_one_or_none()
    if not action:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Operator action #{id} not found.",
        )

    await db.delete(action)
    await db.commit()

    logger.warning("Operator action #%d deleted by admin %s", id, current_user.email)
    return {
        "status": "success",
        "message": f"Operator action #{id} removed successfully.",
        "id": id,
    }
