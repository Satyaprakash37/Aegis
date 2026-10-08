"""Report management and generation API endpoints."""

import os
from typing import Annotated, List
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.db.session import get_db
from app.api.deps import get_current_user, require_analyst_or_admin
from app.models.user import User
from app.models.report import Report, ReportType, ReportFormat
from app.schemas.report import (
    ReportGenerateRequest,
    ReportRead,
    ReportListResponse,
)
from app.services.reports.generator import generate_report

router = APIRouter(prefix="/reports", tags=["Reports"])


@router.post(
    "/generate",
    response_model=ReportRead,
    status_code=status.HTTP_201_CREATED,
    summary="Generate security audit report (PDF / Excel)",
)
async def create_report(
    payload: ReportGenerateRequest,
    current_user: Annotated[User, Depends(require_analyst_or_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Generate executive, detailed, or compliance reports.

    - Executive: High-level PDF for leadership.
    - Detailed: Comprehensive technical PDF for SecOps engineers.
    - Compliance: Multi-sheet Excel workbook for auditors.
    """
    # Strict validation of type and format pairing
    if payload.report_type in [ReportType.executive, ReportType.detailed] and payload.format != ReportFormat.pdf:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Report type '{payload.report_type.value}' must be exported as PDF format.",
        )
    if payload.report_type == ReportType.compliance and payload.format != ReportFormat.excel:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Compliance reports must be exported as Excel (.xlsx) format.",
        )

    try:
        file_path, filename, file_size = await generate_report(
            report_type=payload.report_type,
            format=payload.format,
            user=current_user,
            db=db,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate report: {str(e)}",
        )

    # Persist report audit record
    report = Report(
        report_type=payload.report_type,
        format=payload.format,
        generated_by=current_user.id,
        file_path=file_path,
    )
    db.add(report)
    await db.commit()
    await db.refresh(report)

    return ReportRead(
        id=report.id,
        report_type=report.report_type,
        format=report.format,
        generated_by=report.generated_by,
        generated_by_name=current_user.full_name,
        file_path=report.file_path,
        filename=filename,
        file_size_bytes=file_size,
        created_at=report.created_at,
    )


@router.get(
    "",
    response_model=ReportListResponse,
    summary="List all generated audit reports",
)
async def list_reports(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """List historical reports with file availability and generation metadata."""
    stmt = (
        select(Report)
        .options(selectinload(Report.user))
        .where(Report.generated_by == current_user.id)
        .order_by(Report.created_at.desc())
    )
    result = await db.execute(stmt)
    reports = result.scalars().all()

    data = []
    for r in reports:
        file_exists = os.path.exists(r.file_path)
        file_size = os.path.getsize(r.file_path) if file_exists else 0
        data.append(
            ReportRead(
                id=r.id,
                report_type=r.report_type,
                format=r.format,
                generated_by=r.generated_by,
                generated_by_name=r.user.full_name if r.user else "System",
                file_path=r.file_path,
                filename=os.path.basename(r.file_path),
                file_size_bytes=file_size,
                created_at=r.created_at,
            )
        )

    return ReportListResponse(data=data, total=len(data))


@router.get(
    "/{report_id}/download",
    summary="Download generated report file",
)
async def download_report(
    report_id: int,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Stream report file with clean attachment content-disposition."""
    stmt = select(Report).where(Report.id == report_id, Report.generated_by == current_user.id)
    result = await db.execute(stmt)
    report = result.scalar_one_or_none()

    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report #{report_id} not found.",
        )

    if not os.path.exists(report.file_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report file on disk was not found for report #{report_id}.",
        )

    date_str = report.created_at.strftime("%Y-%m-%d")
    ext = "pdf" if report.format == ReportFormat.pdf else "xlsx"
    download_filename = f"aegis_{report.report_type.value}_{date_str}.{ext}"

    if report.format == ReportFormat.pdf:
        media_type = "application/pdf"
    else:
        media_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

    return FileResponse(
        path=report.file_path,
        media_type=media_type,
        filename=download_filename,
    )
