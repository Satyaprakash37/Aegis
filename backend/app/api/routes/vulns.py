"""Vulnerability findings management, status tracking, and risk calculation routes."""

from typing import Annotated, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import asc, desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import get_current_user, require_admin, require_analyst_or_admin
from app.db.session import get_db
from app.models.asset import Asset
from app.models.user import User
from app.models.vulnerability import (
    VerificationType,
    Vulnerability,
    VulnerabilitySeverity,
    VulnerabilityStatus,
)
from app.schemas.vulnerability import (
    RiskRecalculateResponse,
    VulnerabilityListResponse,
    VulnerabilityRead,
    VulnerabilityStatusUpdate,
)
from app.services.risk.engine import calculate_risk_score, get_risk_tier
from app.services.risk.danger_engine import evaluate_vulnerability_danger

router = APIRouter(prefix="/vulns", tags=["Vulnerabilities"])


def _map_vuln_to_read(v: Vulnerability) -> VulnerabilityRead:
    """Helper to convert ORM model to Pydantic schema."""
    return VulnerabilityRead(
        id=v.id,
        scan_id=v.scan_id,
        asset_id=v.asset_id,
        asset_name=v.asset.name if v.asset else f"Asset #{v.asset_id}",
        asset_ip=v.asset.ip_address if v.asset else None,
        asset_criticality=v.asset.criticality if v.asset else 3,
        risk_tier=get_risk_tier(v.risk_score),
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
        verification=v.verification,
        evidence=v.evidence,
        danger_score=v.danger_score,
        exploitability=v.exploitability,
        impact=v.impact,
        public_exploit=v.public_exploit,
        first_seen_at=v.first_seen_at,
        last_seen_at=v.last_seen_at,
    )


@router.post("/recalculate-risk", response_model=RiskRecalculateResponse)
async def recalculate_all_risk_scores(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_admin)],
) -> RiskRecalculateResponse:
    """Recalculate contextual risk scores and danger metrics for ALL vulnerabilities.

    Admin only endpoint.
    """
    query = select(Vulnerability).options(selectinload(Vulnerability.asset))
    result = await db.execute(query)
    vulns = result.scalars().all()

    updated_count = 0
    for v in vulns:
        crit = v.asset.criticality if v.asset else 3
        v.risk_score = calculate_risk_score(v.cvss_score, crit)

        # Also recalculate danger metrics
        danger_meta = evaluate_vulnerability_danger(
            cve_id=v.cve_id,
            cvss_score=v.cvss_score,
            verification=v.verification.value if hasattr(v.verification, "value") else str(v.verification),
            title=v.title,
            description=v.description,
        )
        v.danger_score = danger_meta["danger_score"]
        v.exploitability = danger_meta["exploitability"]
        v.impact = danger_meta["impact"]
        v.public_exploit = danger_meta["public_exploit"]

        updated_count += 1

    await db.commit()
    return RiskRecalculateResponse(
        updated_count=updated_count,
        message=f"Successfully recomputed contextual risk scores and danger metrics for {updated_count} vulnerabilities.",
    )


@router.get("", response_model=VulnerabilityListResponse)
async def list_vulnerabilities(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    severity: Optional[VulnerabilitySeverity] = Query(None, description="Filter by severity"),
    status_filter: Optional[VulnerabilityStatus] = Query(None, alias="status", description="Filter by status"),
    verification: Optional[VerificationType] = Query(None, description="Filter by verification type"),
    min_danger: Optional[float] = Query(None, ge=0.0, le=10.0, description="Filter by minimum danger score"),
    asset_id: Optional[int] = Query(None, description="Filter by asset ID"),
    scan_id: Optional[int] = Query(None, description="Filter by scan ID"),
    search: Optional[str] = Query(None, description="Search by CVE ID, title, or service"),
    sort_by: Optional[str] = Query("cvss_score", description="Sort by: cvss_score, risk_score, danger_score, first_seen_at"),
    order: Optional[str] = Query("desc", description="Sort direction: asc or desc"),
) -> VulnerabilityListResponse:
    """List detected vulnerabilities with filtering and sortable columns."""
    query = (
        select(Vulnerability)
        .join(Asset, Vulnerability.asset_id == Asset.id)
        .options(selectinload(Vulnerability.asset))
        .where(Asset.owner_id == current_user.id)
    )
    count_query = (
        select(func.count(Vulnerability.id))
        .join(Asset, Vulnerability.asset_id == Asset.id)
        .where(Asset.owner_id == current_user.id)
    )

    if severity:
        query = query.where(Vulnerability.severity == severity)
        count_query = count_query.where(Vulnerability.severity == severity)

    if status_filter:
        query = query.where(Vulnerability.status == status_filter)
        count_query = count_query.where(Vulnerability.status == status_filter)

    if verification:
        query = query.where(Vulnerability.verification == verification)
        count_query = count_query.where(Vulnerability.verification == verification)

    if min_danger is not None:
        query = query.where(Vulnerability.danger_score >= min_danger)
        count_query = count_query.where(Vulnerability.danger_score >= min_danger)

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

    # Sortable columns
    sort_column_map = {
        "cvss_score": Vulnerability.cvss_score,
        "risk_score": Vulnerability.risk_score,
        "danger_score": Vulnerability.danger_score,
        "first_seen_at": Vulnerability.first_seen_at,
        "id": Vulnerability.id,
    }
    col = sort_column_map.get(sort_by, Vulnerability.cvss_score)
    order_func = desc if order and order.lower() == "desc" else asc
    query = query.order_by(order_func(col), Vulnerability.id.desc())

    total = (await db.execute(count_query)).scalar_one()
    offset = (page - 1) * page_size
    query = query.offset(offset).limit(page_size)

    results = (await db.execute(query)).scalars().all()

    items = [_map_vuln_to_read(v) for v in results]

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
        .join(Asset, Vulnerability.asset_id == Asset.id)
        .options(selectinload(Vulnerability.asset))
        .where(Vulnerability.id == id, Asset.owner_id == current_user.id)
    )
    vuln = (await db.execute(query)).scalar_one_or_none()

    if not vuln:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vulnerability with ID {id} not found",
        )

    return _map_vuln_to_read(vuln)


@router.patch("/{id}/status", response_model=VulnerabilityRead)
async def update_vulnerability_status(
    id: int,
    status_in: VulnerabilityStatusUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_analyst_or_admin)],
) -> VulnerabilityRead:
    """Update lifecycle status of a vulnerability finding (open, in_progress, mitigated, false_positive)."""
    query = (
        select(Vulnerability)
        .join(Asset, Vulnerability.asset_id == Asset.id)
        .options(selectinload(Vulnerability.asset))
        .where(Vulnerability.id == id, Asset.owner_id == current_user.id)
    )
    vuln = (await db.execute(query)).scalar_one_or_none()

    if not vuln:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vulnerability with ID {id} not found",
        )

    vuln.status = status_in.status
    await db.commit()
    await db.refresh(vuln)

    return _map_vuln_to_read(vuln)
