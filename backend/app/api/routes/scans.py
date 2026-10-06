"""Scan management and execution routes."""

from datetime import datetime, timezone
import logging
from typing import Annotated, List, Optional
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import get_current_user, require_analyst_or_admin
from app.db.session import get_db
from app.models.asset import Asset
from app.models.scan import Scan, ScanStatus, ScanType
from app.models.user import User
from app.models.vulnerability import Vulnerability, VulnerabilitySeverity
from app.schemas.asset import VulnSeverityCounts
from app.schemas.scan import ScanCreate, ScanDetailRead, ScanListResponse, ScanRead
from app.schemas.vulnerability import VulnerabilityRead
from app.services.scanner.pipeline import execute_scan_pipeline

logger = logging.getLogger("aegis.scans")

router = APIRouter(prefix="/scans", tags=["Scans"])


@router.post("", response_model=ScanRead, status_code=status.HTTP_201_CREATED)
async def create_scan(
    scan_in: ScanCreate,
    background_tasks: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_analyst_or_admin)],
) -> ScanRead:
    """Trigger a new vulnerability scan in the background. Requires analyst or admin role."""
    # Verify asset existence
    asset_query = await db.execute(select(Asset).where(Asset.id == scan_in.asset_id))
    asset = asset_query.scalar_one_or_none()
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset with ID {scan_in.asset_id} not found",
        )

    # Initialize pending scan record
    new_scan = Scan(
        asset_id=asset.id,
        scan_type=scan_in.scan_type,
        status=ScanStatus.pending,
        started_at=datetime.now(timezone.utc),
        total_vulns_found=0,
        raw_output=None,
    )
    db.add(new_scan)
    await db.commit()
    await db.refresh(new_scan)

    # Launch scanning and enrichment pipeline in background
    background_tasks.add_task(execute_scan_pipeline, new_scan.id)

    return ScanRead(
        id=new_scan.id,
        asset_id=new_scan.asset_id,
        asset_name=asset.name,
        asset_ip=asset.ip_address,
        scan_type=new_scan.scan_type,
        status=ScanStatus.running,  # Return running status immediately to client
        started_at=new_scan.started_at,
        completed_at=None,
        total_vulns_found=0,
        raw_output=None,
    )


@router.get("", response_model=ScanListResponse)
async def list_scans(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(10, ge=1, le=100, description="Items per page"),
    asset_id: Optional[int] = Query(None, description="Filter by asset ID"),
    status_filter: Optional[ScanStatus] = Query(None, alias="status", description="Filter by status"),
) -> ScanListResponse:
    """List historical and active scans with pagination and asset metadata."""
    query = select(Scan).options(selectinload(Scan.asset)).order_by(Scan.id.desc())
    count_query = select(func.count(Scan.id))

    if asset_id:
        query = query.where(Scan.asset_id == asset_id)
        count_query = count_query.where(Scan.asset_id == asset_id)

    if status_filter:
        query = query.where(Scan.status == status_filter)
        count_query = count_query.where(Scan.status == status_filter)

    total = (await db.execute(count_query)).scalar_one()
    offset = (page - 1) * page_size
    query = query.offset(offset).limit(page_size)

    results = (await db.execute(query)).scalars().all()

    items: List[ScanRead] = []
    for s in results:
        items.append(
            ScanRead(
                id=s.id,
                asset_id=s.asset_id,
                asset_name=s.asset.name if s.asset else f"Asset #{s.asset_id}",
                asset_ip=s.asset.ip_address if s.asset else None,
                scan_type=s.scan_type,
                status=s.status,
                started_at=s.started_at,
                completed_at=s.completed_at,
                total_vulns_found=s.total_vulns_found,
                raw_output=s.raw_output,
            )
        )

    return ScanListResponse(
        data=items,
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{id}", response_model=ScanDetailRead)
async def get_scan(
    id: int,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> ScanDetailRead:
    """Retrieve full details of a specific scan including vulnerability severity breakdown."""
    query = select(Scan).options(selectinload(Scan.asset)).where(Scan.id == id)
    scan = (await db.execute(query)).scalar_one_or_none()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID {id} not found",
        )

    # Compute vulnerability counts by severity for this scan
    counts_query = (
        select(Vulnerability.severity, func.count(Vulnerability.id))
        .where(Vulnerability.scan_id == id)
        .group_by(Vulnerability.severity)
    )
    counts_result = await db.execute(counts_query)
    raw_counts = dict(counts_result.all())

    vuln_counts = VulnSeverityCounts(
        critical=raw_counts.get(VulnerabilitySeverity.critical, 0),
        high=raw_counts.get(VulnerabilitySeverity.high, 0),
        medium=raw_counts.get(VulnerabilitySeverity.medium, 0),
        low=raw_counts.get(VulnerabilitySeverity.low, 0),
        none=raw_counts.get(VulnerabilitySeverity.none, 0),
    )

    # Compute verification counts
    from app.models.vulnerability import VerificationType
    v_counts_query = (
        select(Vulnerability.verification, func.count(Vulnerability.id))
        .where(Vulnerability.scan_id == id)
        .group_by(Vulnerability.verification)
    )
    v_counts_result = await db.execute(v_counts_query)
    raw_v_counts = dict(v_counts_result.all())
    verification_breakdown = {
        "version_match": raw_v_counts.get(VerificationType.version_match, 0),
        "nse_verified": raw_v_counts.get(VerificationType.nse_verified, 0),
        "nuclei_verified": raw_v_counts.get(VerificationType.nuclei_verified, 0),
    }

    return ScanDetailRead(
        id=scan.id,
        asset_id=scan.asset_id,
        asset_name=scan.asset.name if scan.asset else f"Asset #{scan.asset_id}",
        asset_ip=scan.asset.ip_address if scan.asset else None,
        scan_type=scan.scan_type,
        status=scan.status,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        total_vulns_found=scan.total_vulns_found,
        raw_output=scan.raw_output,
        vuln_counts=vuln_counts,
        verification_breakdown=verification_breakdown,
    )


@router.get("/{id}/vulnerabilities", response_model=List[VulnerabilityRead])
async def get_scan_vulnerabilities(
    id: int,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> List[VulnerabilityRead]:
    """Retrieve all vulnerability findings associated with a specific scan."""
    # Verify scan exists
    scan_query = select(Scan).options(selectinload(Scan.asset)).where(Scan.id == id)
    scan = (await db.execute(scan_query)).scalar_one_or_none()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID {id} not found",
        )

    vulns_query = (
        select(Vulnerability)
        .options(selectinload(Vulnerability.asset))
        .where(Vulnerability.scan_id == id)
        .order_by(Vulnerability.cvss_score.desc())
    )
    vulns = (await db.execute(vulns_query)).scalars().all()

    items: List[VulnerabilityRead] = []
    for v in vulns:
        items.append(
            VulnerabilityRead(
                id=v.id,
                scan_id=v.scan_id,
                asset_id=v.asset_id,
                asset_name=v.asset.name if v.asset else None,
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
                verification=v.verification,
                evidence=v.evidence,
                danger_score=v.danger_score,
                exploitability=v.exploitability,
                impact=v.impact,
                public_exploit=v.public_exploit,
                first_seen_at=v.first_seen_at,
                last_seen_at=v.last_seen_at,
            )
        )

    return items
