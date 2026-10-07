"""Scan management and execution routes."""

from datetime import datetime, timedelta, timezone
import logging
from typing import Annotated, List, Optional
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import get_current_user, require_analyst_or_admin
from app.db.session import get_db
from app.models.asset import Asset, AssetEnvironment, AssetType, TargetType
from app.models.scan import Scan, ScanStatus, ScanType
from app.models.user import User
from app.models.vulnerability import Vulnerability, VulnerabilitySeverity
from app.schemas.asset import VulnSeverityCounts
from app.schemas.scan import (
    DirectScanCreate,
    DirectScanResponse,
    ScanCreate,
    ScanDetailRead,
    ScanListResponse,
    ScanRead,
)
from app.schemas.vulnerability import VulnerabilityRead
from app.services.scanner.pipeline import execute_scan_pipeline
from app.services.scanner.target_resolver import resolve_target

logger = logging.getLogger("aegis.scans")

router = APIRouter(prefix="/scans", tags=["Scans"])


@router.post("/direct", response_model=DirectScanResponse, status_code=status.HTTP_201_CREATED)
async def create_direct_scan(
    scan_in: DirectScanCreate,
    background_tasks: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_analyst_or_admin)],
) -> DirectScanResponse:
    """Directly scan any IP address, domain name, or URL without pre-registering an asset."""
    # 1. Run resolve_target on input
    resolution = resolve_target(scan_in.target)
    if resolution["type"] == "invalid":
        # Check if input matches an existing registered asset as fallback
        cleaned_input = (
            scan_in.target.strip()
            .lower()
            .replace("http://", "")
            .replace("https://", "")
            .rstrip("/")
        )
        fallback_query = await db.execute(
            select(Asset).where(
                or_(
                    Asset.name == cleaned_input,
                    Asset.ip_address == cleaned_input,
                    Asset.resolved_ip == cleaned_input,
                )
            )
        )
        fallback_asset = fallback_query.scalar_one_or_none()
        if fallback_asset:
            logger.info(
                f"Target resolution fallback: found existing asset #{fallback_asset.id} for '{scan_in.target}'."
            )
            resolution = {
                "type": "domain" if fallback_asset.target_type == TargetType.domain else "ip",
                "ip": fallback_asset.resolved_ip or fallback_asset.ip_address,
                "hostname": fallback_asset.hostname or fallback_asset.name,
                "target": fallback_asset.ip_address,
                "original": scan_in.target,
                "error": None,
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=resolution["error"],
            )

    cleaned_target = resolution["target"]
    resolved_ip = resolution["ip"] if resolution["type"] == "domain" else None
    effective_ip = resolution["ip"]
    target_type = TargetType.domain if resolution["type"] == "domain" else TargetType.ip
    hostname = resolution.get("hostname")

    # 2. Search existing assets (match ip_address OR resolved_ip)
    search_conditions = [
        Asset.ip_address == cleaned_target,
        Asset.resolved_ip == cleaned_target,
    ]
    if resolved_ip:
        search_conditions.extend([
            Asset.ip_address == resolved_ip,
            Asset.resolved_ip == resolved_ip,
        ])
    elif effective_ip:
        search_conditions.append(Asset.resolved_ip == effective_ip)

    existing_query = await db.execute(select(Asset).where(or_(*search_conditions)))
    asset = existing_query.scalar_one_or_none()

    auto_created = False
    if not asset:
        # 3. No match found -> auto-create asset silently
        asset = Asset(
            name=cleaned_target,
            ip_address=cleaned_target,
            target_type=target_type,
            resolved_ip=resolved_ip,
            hostname=hostname,
            asset_type=AssetType.server,
            environment=AssetEnvironment.production,
            criticality=3,
            owner="Auto-Discovered",
            description=f"Auto-registered target created via direct scan on {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}.",
            auto_created=True,
            is_seed=False,
        )
        db.add(asset)
        await db.commit()
        await db.refresh(asset)
        auto_created = True

    # 4. Prevent duplicate concurrent scans on the same target asset
    active_scan_query = await db.execute(
        select(Scan).where(
            Scan.asset_id == asset.id,
            Scan.status.in_([ScanStatus.pending, ScanStatus.running]),
        )
    )
    active_scan = active_scan_query.scalar_one_or_none()
    if active_scan:
        now_utc = datetime.now(timezone.utc)
        scan_age = (now_utc - active_scan.started_at) if active_scan.started_at else timedelta(hours=2)
        if scan_age > timedelta(hours=1):
            logger.warning(
                "Auto-recovering stale active scan #%d on asset #%d (age: %s)",
                active_scan.id, asset.id, scan_age
            )
            active_scan.status = ScanStatus.failed
            active_scan.completed_at = now_utc
            active_scan.raw_output = {
                "error": "Scan execution timed out or was interrupted by a previous restart.",
                "error_type": "ScanTimeoutError",
                "error_hint": "New scan was launched to supersede the stalled execution.",
                "failure_stage": "timeout",
            }
            await db.commit()
        else:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"A scan (Scan #{active_scan.id}, {active_scan.scan_type.value}) is already active on '{asset.name}'. Please allow it to finish before starting a new scan.",
            )

    # 5. Initialize scan
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

    # 6. Launch scan pipeline in background
    background_tasks.add_task(execute_scan_pipeline, new_scan.id)

    return DirectScanResponse(
        scan_id=new_scan.id,
        asset_id=asset.id,
        asset_name=asset.name,
        target=asset.ip_address,
        target_type=asset.target_type.value if hasattr(asset.target_type, "value") else str(asset.target_type),
        resolved_ip=asset.resolved_ip,
        scan_type=new_scan.scan_type,
        status=ScanStatus.running,
        auto_created=auto_created,
        message=f"Direct scan #{new_scan.id} initiated on '{cleaned_target}'.",
    )


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

    # Prevent duplicate concurrent scans on the same target asset
    active_scan_query = await db.execute(
        select(Scan).where(
            Scan.asset_id == asset.id,
            Scan.status.in_([ScanStatus.pending, ScanStatus.running]),
        )
    )
    active_scan = active_scan_query.scalar_one_or_none()
    if active_scan:
        now_utc = datetime.now(timezone.utc)
        scan_age = (now_utc - active_scan.started_at) if active_scan.started_at else timedelta(hours=2)
        if scan_age > timedelta(hours=1):
            logger.warning(
                "Auto-recovering stale active scan #%d on asset #%d (age: %s)",
                active_scan.id, asset.id, scan_age
            )
            active_scan.status = ScanStatus.failed
            active_scan.completed_at = now_utc
            active_scan.raw_output = {
                "error": "Scan execution timed out or was interrupted by a previous restart.",
                "error_type": "ScanTimeoutError",
                "error_hint": "New scan was launched to supersede the stalled execution.",
                "failure_stage": "timeout",
            }
            await db.commit()
        else:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"A scan (Scan #{active_scan.id}, {active_scan.scan_type.value}) is already active on '{asset.name}'. Please allow it to finish before starting a new scan.",
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
        target_type=asset.target_type.value if hasattr(asset.target_type, 'value') else str(asset.target_type),
        resolved_ip=asset.resolved_ip,
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
                target_type=s.asset.target_type.value if (s.asset and hasattr(s.asset.target_type, 'value')) else (str(s.asset.target_type) if s.asset else None),
                resolved_ip=s.asset.resolved_ip if s.asset else None,
                scan_type=s.scan_type,
                status=s.status,
                started_at=s.started_at,
                completed_at=s.completed_at,
                total_vulns_found=s.total_vulns_found,
                raw_output=s.raw_output,
                progress=s.progress,
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
        "ssl_verified": raw_v_counts.get(VerificationType.ssl_verified, 0),
    }

    return ScanDetailRead(
        id=scan.id,
        asset_id=scan.asset_id,
        asset_name=scan.asset.name if scan.asset else f"Asset #{scan.asset_id}",
        asset_ip=scan.asset.ip_address if scan.asset else None,
        target_type=scan.asset.target_type.value if (scan.asset and hasattr(scan.asset.target_type, 'value')) else (str(scan.asset.target_type) if scan.asset else None),
        resolved_ip=scan.asset.resolved_ip if scan.asset else None,
        scan_type=scan.scan_type,
        status=scan.status,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        total_vulns_found=scan.total_vulns_found,
        raw_output=scan.raw_output,
        progress=scan.progress,
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
