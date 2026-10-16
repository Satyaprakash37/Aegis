"""Executive dashboard analytics and metrics reporting endpoints."""

from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import case, func, select, literal_column, text, or_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import get_current_user
from app.db.session import get_db
from app.models.asset import Asset
from app.models.scan import Scan, ScanStatus
from app.models.user import User
from app.models.vulnerability import (
    VerificationType,
    Vulnerability,
    VulnerabilitySeverity,
    VulnerabilityStatus,
)
from app.services.risk.engine import get_risk_tier

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


async def _verify_asset_ownership(db: AsyncSession, asset_id: int, user_id: int) -> Asset:
    """Verify that the target asset exists and is owned by the current user."""
    asset = (
        await db.execute(
            select(Asset).where(Asset.id == asset_id, Asset.owner_id == user_id)
        )
    ).scalar_one_or_none()
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset #{asset_id} not found or unauthorized",
        )
    return asset


@router.get("/summary")
async def get_dashboard_summary(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    asset_id: Optional[int] = Query(None, description="Scope summary to a specific asset"),
) -> Dict[str, Any]:
    """Retrieve top-level operational cybersecurity KPI metrics, optionally scoped to a single asset."""
    thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)

    selected_asset_data = None
    latest_scan_data = None

    if asset_id is not None:
        asset = await _verify_asset_ownership(db, asset_id, current_user.id)
        total_assets = 1

        selected_asset_data = {
            "id": asset.id,
            "name": asset.name,
            "ip_address": asset.ip_address,
            "target_type": asset.target_type.value if hasattr(asset.target_type, "value") else str(asset.target_type),
            "criticality": asset.criticality,
        }

        # Asset-scoped vulnerability queries
        total_vulns = (
            await db.execute(
                select(func.count(Vulnerability.id)).where(Vulnerability.asset_id == asset_id)
            )
        ).scalar_one()

        open_vulns = (
            await db.execute(
                select(func.count(Vulnerability.id)).where(
                    Vulnerability.asset_id == asset_id,
                    Vulnerability.status == VulnerabilityStatus.open,
                )
            )
        ).scalar_one()

        mitigated_vulns = (
            await db.execute(
                select(func.count(Vulnerability.id)).where(
                    Vulnerability.asset_id == asset_id,
                    Vulnerability.status == VulnerabilityStatus.mitigated,
                )
            )
        ).scalar_one()

        crit_high_count = (
            await db.execute(
                select(func.count(Vulnerability.id)).where(
                    Vulnerability.asset_id == asset_id,
                    Vulnerability.status.in_([VulnerabilityStatus.open, VulnerabilityStatus.in_progress]),
                    Vulnerability.severity.in_([VulnerabilitySeverity.critical, VulnerabilitySeverity.high]),
                )
            )
        ).scalar_one()

        verified_dangerous_count = (
            await db.execute(
                select(func.count(Vulnerability.id)).where(
                    Vulnerability.asset_id == asset_id,
                    Vulnerability.danger_score > 6.0,
                    Vulnerability.verification.in_([
                        VerificationType.nse_verified,
                        VerificationType.nuclei_verified,
                        VerificationType.ssl_verified,
                    ]),
                    Vulnerability.status.in_([VulnerabilityStatus.open, VulnerabilityStatus.in_progress]),
                )
            )
        ).scalar_one()

        scans_30d = (
            await db.execute(
                select(func.count(Scan.id)).where(
                    Scan.asset_id == asset_id,
                    Scan.created_by == current_user.id,
                    Scan.started_at >= thirty_days_ago,
                )
            )
        ).scalar_one()

        # Query latest scan for this specific asset
        latest_scan_query = (
            select(Scan)
            .where(Scan.asset_id == asset_id, Scan.created_by == current_user.id)
            .order_by(Scan.started_at.desc().nullslast(), Scan.id.desc())
            .limit(1)
        )
        latest_scan = (await db.execute(latest_scan_query)).scalar_one_or_none()
        if latest_scan:
            latest_scan_data = {
                "id": latest_scan.id,
                "status": latest_scan.status.value,
                "scan_type": latest_scan.scan_type.value if hasattr(latest_scan.scan_type, "value") else str(latest_scan.scan_type),
                "started_at": latest_scan.started_at.isoformat() if latest_scan.started_at else None,
                "completed_at": latest_scan.completed_at.isoformat() if latest_scan.completed_at else None,
                "total_vulns_found": latest_scan.total_vulns_found,
                "scan_findings_count": latest_scan.total_vulns_found,
            }

        return {
            "status": "success",
            "data": {
                "scope": "asset",
                "total_assets": total_assets,
                "total_vulnerabilities": total_vulns,
                "open_vulns": open_vulns,
                "mitigated_vulns": mitigated_vulns,
                "critical_high_count": crit_high_count,
                "verified_dangerous_count": verified_dangerous_count,
                "scans_run_30d": scans_30d,
                "selected_asset": selected_asset_data,
                "latest_scan": latest_scan_data,
            },
        }

    # Account-wide metrics (All Assets)
    total_assets = (
        await db.execute(
            select(func.count(Asset.id)).where(
                or_(Asset.owner_id == current_user.id, Asset.is_seed == True)
            )
        )
    ).scalar_one()

    total_vulns = (
        await db.execute(
            select(func.count(Vulnerability.id))
            .join(Asset, Vulnerability.asset_id == Asset.id)
            .where(Asset.owner_id == current_user.id)
        )
    ).scalar_one()

    open_vulns = (
        await db.execute(
            select(func.count(Vulnerability.id))
            .join(Asset, Vulnerability.asset_id == Asset.id)
            .where(
                Asset.owner_id == current_user.id,
                Vulnerability.status == VulnerabilityStatus.open,
            )
        )
    ).scalar_one()

    mitigated_vulns = (
        await db.execute(
            select(func.count(Vulnerability.id))
            .join(Asset, Vulnerability.asset_id == Asset.id)
            .where(
                Asset.owner_id == current_user.id,
                Vulnerability.status == VulnerabilityStatus.mitigated,
            )
        )
    ).scalar_one()

    crit_high_count = (
        await db.execute(
            select(func.count(Vulnerability.id))
            .join(Asset, Vulnerability.asset_id == Asset.id)
            .where(
                Asset.owner_id == current_user.id,
                Vulnerability.status.in_([VulnerabilityStatus.open, VulnerabilityStatus.in_progress]),
                Vulnerability.severity.in_([VulnerabilitySeverity.critical, VulnerabilitySeverity.high]),
            )
        )
    ).scalar_one()

    verified_dangerous_count = (
        await db.execute(
            select(func.count(Vulnerability.id))
            .join(Asset, Vulnerability.asset_id == Asset.id)
            .where(
                Asset.owner_id == current_user.id,
                Vulnerability.danger_score > 6.0,
                Vulnerability.verification.in_([
                    VerificationType.nse_verified,
                    VerificationType.nuclei_verified,
                    VerificationType.ssl_verified,
                ]),
                Vulnerability.status.in_([VulnerabilityStatus.open, VulnerabilityStatus.in_progress]),
            )
        )
    ).scalar_one()

    scans_30d = (
        await db.execute(
            select(func.count(Scan.id)).where(
                Scan.created_by == current_user.id,
                Scan.started_at >= thirty_days_ago,
            )
        )
    ).scalar_one()

    # Query latest scan account-wide
    latest_scan_query = (
        select(Scan)
        .where(Scan.created_by == current_user.id)
        .order_by(Scan.started_at.desc().nullslast(), Scan.id.desc())
        .limit(1)
    )
    latest_scan = (await db.execute(latest_scan_query)).scalar_one_or_none()
    if latest_scan:
        latest_scan_data = {
            "id": latest_scan.id,
            "asset_id": latest_scan.asset_id,
            "status": latest_scan.status.value,
            "scan_type": latest_scan.scan_type.value if hasattr(latest_scan.scan_type, "value") else str(latest_scan.scan_type),
            "started_at": latest_scan.started_at.isoformat() if latest_scan.started_at else None,
            "completed_at": latest_scan.completed_at.isoformat() if latest_scan.completed_at else None,
            "total_vulns_found": latest_scan.total_vulns_found,
            "scan_findings_count": latest_scan.total_vulns_found,
        }

    return {
        "status": "success",
        "data": {
            "scope": "all",
            "total_assets": total_assets,
            "total_vulnerabilities": total_vulns,
            "open_vulns": open_vulns,
            "mitigated_vulns": mitigated_vulns,
            "critical_high_count": crit_high_count,
            "verified_dangerous_count": verified_dangerous_count,
            "scans_run_30d": scans_30d,
            "selected_asset": None,
            "latest_scan": latest_scan_data,
        },
    }


@router.get("/severity-distribution")
async def get_severity_distribution(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    asset_id: Optional[int] = Query(None, description="Scope severity distribution to a specific asset"),
) -> Dict[str, Any]:
    """Retrieve vulnerability breakdown by CVSS severity classification, optionally scoped to an asset."""
    if asset_id is not None:
        await _verify_asset_ownership(db, asset_id, current_user.id)
        counts_query = (
            select(Vulnerability.severity, func.count(Vulnerability.id))
            .where(Vulnerability.asset_id == asset_id)
            .group_by(Vulnerability.severity)
        )
    else:
        counts_query = (
            select(Vulnerability.severity, func.count(Vulnerability.id))
            .join(Asset, Vulnerability.asset_id == Asset.id)
            .where(Asset.owner_id == current_user.id)
            .group_by(Vulnerability.severity)
        )

    result = await db.execute(counts_query)
    raw_dict = dict(result.all())

    palette = {
        VulnerabilitySeverity.critical: {"name": "Critical", "color": "#ef4444"},
        VulnerabilitySeverity.high: {"name": "High", "color": "#f97316"},
        VulnerabilitySeverity.medium: {"name": "Medium", "color": "#eab308"},
        VulnerabilitySeverity.low: {"name": "Low", "color": "#3b82f6"},
        VulnerabilitySeverity.none: {"name": "None", "color": "#64748b"},
    }

    distribution = []
    for sev, meta in palette.items():
        count = raw_dict.get(sev, 0)
        distribution.append({
            "severity": sev.value,
            "name": meta["name"],
            "count": count,
            "color": meta["color"],
        })

    return {
        "status": "success",
        "data": distribution,
    }


@router.get("/trend")
async def get_vulnerability_trend(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    asset_id: Optional[int] = Query(None, description="Scope discovery trend to a specific asset"),
) -> Dict[str, Any]:
    """Retrieve 30-day timeline trend showing newly discovered vulnerabilities per day, optionally scoped."""
    start_date = datetime.now(timezone.utc) - timedelta(days=29)

    if asset_id is not None:
        await _verify_asset_ownership(db, asset_id, current_user.id)
        asset_vulns_count_query = select(func.count(Vulnerability.id)).where(Vulnerability.asset_id == asset_id)
        total_vulns = (await db.execute(asset_vulns_count_query)).scalar_one()

        if total_vulns == 0:
            return {
                "status": "success",
                "data": [],
            }

        day_col = func.date_trunc(literal_column("'day'"), Vulnerability.first_seen_at).label("day")
        query = (
            select(
                day_col,
                func.count(Vulnerability.id).label("count"),
            )
            .where(
                Vulnerability.asset_id == asset_id,
                Vulnerability.first_seen_at >= start_date,
            )
            .group_by(day_col)
            .order_by(day_col)
        )
    else:
        user_vulns_count_query = (
            select(func.count(Vulnerability.id))
            .join(Asset, Vulnerability.asset_id == Asset.id)
            .where(Asset.owner_id == current_user.id)
        )
        total_user_vulns = (await db.execute(user_vulns_count_query)).scalar_one()

        if total_user_vulns == 0:
            return {
                "status": "success",
                "data": [],
            }

        day_col = func.date_trunc(literal_column("'day'"), Vulnerability.first_seen_at).label("day")
        query = (
            select(
                day_col,
                func.count(Vulnerability.id).label("count"),
            )
            .join(Asset, Vulnerability.asset_id == Asset.id)
            .where(
                Asset.owner_id == current_user.id,
                Vulnerability.first_seen_at >= start_date,
            )
            .group_by(day_col)
            .order_by(day_col)
        )

    records = (await db.execute(query)).all()
    counts_by_date = {
        r.day.strftime("%Y-%m-%d") if hasattr(r.day, "strftime") else str(r.day)[:10]: r.count
        for r in records
    }

    if sum(counts_by_date.values()) == 0:
        return {
            "status": "success",
            "data": [],
        }

    trend_series = []
    for i in range(30):
        current_day = start_date + timedelta(days=i)
        day_key = current_day.strftime("%Y-%m-%d")
        display_label = current_day.strftime("%b %d")
        c = counts_by_date.get(day_key, 0)
        trend_series.append({
            "date": day_key,
            "label": display_label,
            "discovered": c,
            "count": c,
        })

    return {
        "status": "success",
        "data": trend_series,
    }


@router.get("/top-risky-assets")
async def get_top_risky_assets(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    asset_id: Optional[int] = Query(None, description="Filter risky assets report to a specific asset"),
) -> Dict[str, Any]:
    """Retrieve riskiest network assets ranked by number of open critical and high vulnerabilities."""
    query = (
        select(
            Asset.id,
            Asset.name,
            Asset.ip_address,
            Asset.criticality,
            func.count(
                case(
                    (
                        (Vulnerability.severity == VulnerabilitySeverity.critical)
                        & (Vulnerability.status.in_([VulnerabilityStatus.open, VulnerabilityStatus.in_progress])),
                        1,
                    ),
                    else_=None,
                )
            ).label("critical_count"),
            func.count(
                case(
                    (
                        (Vulnerability.severity == VulnerabilitySeverity.high)
                        & (Vulnerability.status.in_([VulnerabilityStatus.open, VulnerabilityStatus.in_progress])),
                        1,
                    ),
                    else_=None,
                )
            ).label("high_count"),
            func.count(Vulnerability.id).label("total_vulns"),
        )
        .join(Vulnerability, Vulnerability.asset_id == Asset.id, isouter=True)
        .where(Asset.owner_id == current_user.id)
    )

    if asset_id is not None:
        await _verify_asset_ownership(db, asset_id, current_user.id)
        query = query.where(Asset.id == asset_id)

    query = (
        query.group_by(Asset.id, Asset.name, Asset.ip_address, Asset.criticality)
        .order_by(
            (
                func.count(
                    case(
                        (
                            (Vulnerability.severity == VulnerabilitySeverity.critical)
                            & (Vulnerability.status.in_([VulnerabilityStatus.open, VulnerabilityStatus.in_progress])),
                            1,
                        ),
                        else_=None,
                    )
                ) * 2
                + func.count(
                    case(
                        (
                            (Vulnerability.severity == VulnerabilitySeverity.high)
                            & (Vulnerability.status.in_([VulnerabilityStatus.open, VulnerabilityStatus.in_progress])),
                            1,
                        ),
                        else_=None,
                    )
                )
            ).desc()
        )
        .limit(5)
    )

    records = (await db.execute(query)).all()
    results = []
    for r in records:
        crit_count = int(r.critical_count or 0)
        hi_count = int(r.high_count or 0)
        results.append({
            "asset_id": r.id,
            "name": r.name,
            "ip_address": r.ip_address,
            "criticality": r.criticality,
            "critical_count": crit_count,
            "high_count": hi_count,
            "total_open_critical_high": crit_count + hi_count,
            "total_vulns": int(r.total_vulns or 0),
        })

    return {
        "status": "success",
        "data": results,
    }


@router.get("/top-dangerous-vulns")
async def get_top_dangerous_vulnerabilities(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    asset_id: Optional[int] = Query(None, description="Scope dangerous vulnerabilities to a specific asset"),
) -> Dict[str, Any]:
    """Retrieve top 5 most dangerous active vulnerabilities, optionally scoped to an asset."""
    query = (
        select(Vulnerability)
        .join(Asset, Vulnerability.asset_id == Asset.id)
        .options(selectinload(Vulnerability.asset))
        .where(
            Asset.owner_id == current_user.id,
            Vulnerability.status.in_([VulnerabilityStatus.open, VulnerabilityStatus.in_progress]),
            Vulnerability.danger_score.isnot(None),
        )
    )

    if asset_id is not None:
        await _verify_asset_ownership(db, asset_id, current_user.id)
        query = query.where(Vulnerability.asset_id == asset_id)

    query = query.order_by(Vulnerability.danger_score.desc(), Vulnerability.id.desc()).limit(5)

    results = (await db.execute(query)).scalars().all()
    items = [
        {
            "id": v.id,
            "cve_id": v.cve_id,
            "title": v.title,
            "danger_score": v.danger_score,
            "cvss_score": v.cvss_score,
            "severity": v.severity.value,
            "verification": v.verification.value,
            "public_exploit": v.public_exploit,
            "exploitability": v.exploitability,
            "impact": v.impact,
            "asset_name": v.asset.name if v.asset else f"Asset #{v.asset_id}",
            "asset_ip": v.asset.ip_address if v.asset else None,
            "service": v.service,
            "port": v.port,
        }
        for v in results
    ]
    return {
        "status": "success",
        "data": items,
    }


@router.get("/recent-vulns")
async def get_recent_vulnerabilities(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    asset_id: Optional[int] = Query(None, description="Scope recent discoveries to a specific asset"),
) -> Dict[str, Any]:
    """Retrieve the latest 8 vulnerability discoveries, optionally scoped to an asset."""
    query = (
        select(Vulnerability)
        .join(Asset, Vulnerability.asset_id == Asset.id)
        .options(selectinload(Vulnerability.asset))
        .where(Asset.owner_id == current_user.id)
    )

    if asset_id is not None:
        await _verify_asset_ownership(db, asset_id, current_user.id)
        query = query.where(Vulnerability.asset_id == asset_id)

    query = query.order_by(Vulnerability.first_seen_at.desc(), Vulnerability.id.desc()).limit(8)

    results = (await db.execute(query)).scalars().all()

    items = [
        {
            "id": v.id,
            "cve_id": v.cve_id,
            "title": v.title,
            "severity": v.severity.value,
            "cvss_score": v.cvss_score,
            "risk_score": v.risk_score,
            "danger_score": v.danger_score,
            "verification": v.verification.value,
            "public_exploit": v.public_exploit,
            "risk_tier": get_risk_tier(v.risk_score),
            "asset_name": v.asset.name if v.asset else f"Asset #{v.asset_id}",
            "asset_ip": v.asset.ip_address if v.asset else None,
            "service": v.service,
            "port": v.port,
            "status": v.status.value,
            "first_seen_at": v.first_seen_at.isoformat() if v.first_seen_at else None,
        }
        for v in results
    ]

    return {
        "status": "success",
        "data": items,
    }
