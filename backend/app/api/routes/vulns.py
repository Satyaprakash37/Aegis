"""Vulnerability findings management and query routes."""

from typing import Annotated, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import get_current_user
from app.db.session import get_db
from app.models.user import User
from app.models.vulnerability import Vulnerability, VulnerabilitySeverity, VulnerabilityStatus
from app.schemas.vulnerability import VulnerabilityListResponse, VulnerabilityRead

router = APIRouter(prefix="/vulns", tags=["Vulnerabilities"])


@router.get("", response_model=VulnerabilityListResponse)
async def list_vulnerabilities(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    severity: Optional[VulnerabilitySeverity] = Query(None, description="Filter by severity"),
    status_filter: Optional[VulnerabilityStatus] = Query(None, alias="status", description="Filter by status"),
    asset_id: Optional[int] = Query(None, description="Filter by asset ID"),
    scan_id: Optional[int] = Query(None, description="Filter by scan ID"),
    search: Optional[str] = Query(None, description="Search by CVE ID, title, or service"),
) -> VulnerabilityListResponse:
    """List detected vulnerabilities with filtering by severity, status, asset, and search."""
    query = (
        select(Vulnerability)
        .options(selectinload(Vulnerability.asset))
        .order_by(Vulnerability.cvss_score.desc(), Vulnerability.id.desc())
    )
    count_query = select(func.count(Vulnerability.id))

    if severity:
        query = query.where(Vulnerability.severity == severity)
        count_query = count_query.where(Vulnerability.severity == severity)

    if status_filter:
        query = query.where(Vulnerability.status == status_filter)
        count_query = count_query.where(Vulnerability.status == status_filter)

    if asset_id:
        query = query.where(Vulnerability.asset_id == asset_id)
        count_query = count_query.where(Vulnerability.asset_id == asset_id)

    if scan_id:
        query = query.where(Vulnerability.scan_id == scan_id)
        count_query = count_query.where(Vulnerability.scan_id == scan_id)

    if search:
        search_filter = or_(
            Vulnerability.cve_id.ilike(f"%{search}%"),
            Vulnerability.title.ilike(f"%{search}%"),
            Vulnerability.service.ilike(f"%{search}%"),
        )
        query = query.where(search_filter)
        count_query = count_query.where(search_filter)

    total = (await db.execute(count_query)).scalar_one()
    offset = (page - 1) * page_size
    query = query.offset(offset).limit(page_size)

    results = (await db.execute(query)).scalars().all()

    items = [
        VulnerabilityRead(
            id=v.id,
            scan_id=v.scan_id,
            asset_id=v.asset_id,
            asset_name=v.asset.name if v.asset else f"Asset #{v.asset_id}",
            asset_ip=v.asset.ip_address if v.asset else None,
            cve_id=v.cve_id,
            title=v.title,
            description=v.description,
            cvss_score=v.cvss_score,
            severity=v.severity,
            port=v.port,
            service=v.service,
            service_version=v.service_version,
            risk_score=v.risk_score,
            epss_score=v.epss_score,
            status=v.status,
            remediation=v.remediation,
            first_seen_at=v.first_seen_at,
            last_seen_at=v.last_seen_at,
        )
        for v in results
    ]

    return VulnerabilityListResponse(
        data=items,
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{id}", response_model=VulnerabilityRead)
async def get_vulnerability(
    id: int,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> VulnerabilityRead:
    """Retrieve full details of a specific vulnerability finding."""
    query = (
        select(Vulnerability)
        .options(selectinload(Vulnerability.asset))
        .where(Vulnerability.id == id)
    )
    vuln = (await db.execute(query)).scalar_one_or_none()

    if not vuln:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vulnerability with ID {id} not found",
        )

    return VulnerabilityRead(
        id=vuln.id,
        scan_id=vuln.scan_id,
        asset_id=vuln.asset_id,
        asset_name=vuln.asset.name if vuln.asset else f"Asset #{vuln.asset_id}",
        asset_ip=vuln.asset.ip_address if vuln.asset else None,
        cve_id=vuln.cve_id,
        title=vuln.title,
        description=vuln.description,
        cvss_score=vuln.cvss_score,
        severity=vuln.severity,
        port=vuln.port,
        service=vuln.service,
        service_version=vuln.service_version,
        risk_score=vuln.risk_score,
        epss_score=vuln.epss_score,
        status=vuln.status,
        remediation=vuln.remediation,
        first_seen_at=vuln.first_seen_at,
        last_seen_at=vuln.last_seen_at,
    )
