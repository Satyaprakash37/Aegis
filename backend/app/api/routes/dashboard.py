"""Executive dashboard analytics and metrics reporting endpoints."""

from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, Dict, List
from fastapi import APIRouter, Depends
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import get_current_user
from app.db.session import get_db
from app.models.asset import Asset
from app.models.scan import Scan
from app.models.user import User
from app.models.vulnerability import Vulnerability, VulnerabilitySeverity, VulnerabilityStatus
from app.services.risk.engine import get_risk_tier

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/summary")
async def get_dashboard_summary(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> Dict[str, Any]:
    """Retrieve top-level operational cybersecurity KPI metrics."""
    thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)

    # Asset count
    total_assets = (await db.execute(select(func.count(Asset.id)))).scalar_one()

    # Total vulns
    total_vulns = (await db.execute(select(func.count(Vulnerability.id)))).scalar_one()

    # Open vulns
    open_vulns = (
        await db.execute(
            select(func.count(Vulnerability.id)).where(
                Vulnerability.status == VulnerabilityStatus.open
            )
        )
    ).scalar_one()

    # Mitigated vulns
    mitigated_vulns = (
        await db.execute(
            select(func.count(Vulnerability.id)).where(
                Vulnerability.status == VulnerabilityStatus.mitigated
            )
        )
    ).scalar_one()

    # Critical + High open count
    crit_high_count = (
        await db.execute(
            select(func.count(Vulnerability.id)).where(
                Vulnerability.status.in_([VulnerabilityStatus.open, VulnerabilityStatus.in_progress]),
                Vulnerability.severity.in_([VulnerabilitySeverity.critical, VulnerabilitySeverity.high]),
            )
        )
    ).scalar_one()

    # Scans run in last 30 days
    scans_30d = (
        await db.execute(
            select(func.count(Scan.id)).where(Scan.started_at >= thirty_days_ago)
        )
    ).scalar_one()

    return {
        "status": "success",
        "data": {
            "total_assets": total_assets,
            "total_vulnerabilities": total_vulns,
            "open_vulns": open_vulns,
            "mitigated_vulns": mitigated_vulns,
            "critical_high_count": crit_high_count,
            "scans_run_30d": scans_30d,
        },
    }


@router.get("/severity-distribution")
async def get_severity_distribution(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> Dict[str, Any]:
    """Retrieve vulnerability breakdown by CVSS severity classification for donut charts."""
    counts_query = (
        select(Vulnerability.severity, func.count(Vulnerability.id))
        .group_by(Vulnerability.severity)
    )
    result = await db.execute(counts_query)
    raw_dict = dict(result.all())

    # Pre-defined colors and ordered categories
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
) -> Dict[str, Any]:
    """Retrieve vulnerability discovery velocity over the past 30 days."""
    today = datetime.now(timezone.utc).date()
    days_data: Dict[str, Dict[str, Any]] = {}

    for i in range(29, -1, -1):
        day = today - timedelta(days=i)
        day_str = day.strftime("%Y-%m-%d")
        display_label = day.strftime("%b %d")
        days_data[day_str] = {
            "date": display_label,
            "full_date": day_str,
            "discovered": 0,
            "open": 0,
            "mitigated": 0,
        }

    # Query discovery timeline
    start_date = datetime.now(timezone.utc) - timedelta(days=30)
    query = (
        select(
            func.date(Vulnerability.first_seen_at).label("day"),
            func.count(Vulnerability.id).label("count"),
            func.sum(
                case((Vulnerability.status == VulnerabilityStatus.mitigated, 1), else_=0)
            ).label("mitigated_count"),
        )
        .where(Vulnerability.first_seen_at >= start_date)
        .group_by(func.date(Vulnerability.first_seen_at))
    )

    records = (await db.execute(query)).all()
    for row in records:
        day_key = str(row.day)
        if day_key in days_data:
            days_data[day_key]["discovered"] = int(row.count)
            days_data[day_key]["mitigated"] = int(row.mitigated_count or 0)
            days_data[day_key]["open"] = int(row.count - (row.mitigated_count or 0))

    return {
        "status": "success",
        "data": list(days_data.values()),
    }


@router.get("/top-risky-assets")
async def get_top_risky_assets(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> Dict[str, Any]:
    """Retrieve top 5 critical infrastructure nodes by open critical/high vulnerability volume."""
    query = (
        select(
            Asset.id,
            Asset.name,
            Asset.ip_address,
            Asset.criticality,
            func.count(Vulnerability.id).label("total_vulns"),
            func.sum(
                case((Vulnerability.severity == VulnerabilitySeverity.critical, 1), else_=0)
            ).label("critical_count"),
            func.sum(
                case((Vulnerability.severity == VulnerabilitySeverity.high, 1), else_=0)
            ).label("high_count"),
        )
        .join(Vulnerability, Vulnerability.asset_id == Asset.id)
        .where(Vulnerability.status.in_([VulnerabilityStatus.open, VulnerabilityStatus.in_progress]))
        .group_by(Asset.id, Asset.name, Asset.ip_address, Asset.criticality)
        .order_by(
            func.sum(
                case(
                    (Vulnerability.severity == VulnerabilitySeverity.critical, 3),
                    (Vulnerability.severity == VulnerabilitySeverity.high, 2),
                    else_=1,
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

    # If no assets with open vulns, return empty list cleanly
    return {
        "status": "success",
        "data": results,
    }


@router.get("/recent-vulns")
async def get_recent_vulnerabilities(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> Dict[str, Any]:
    """Retrieve the latest 8 vulnerability discoveries for live activity monitoring."""
    query = (
        select(Vulnerability)
        .options(selectinload(Vulnerability.asset))
        .order_by(Vulnerability.first_seen_at.desc(), Vulnerability.id.desc())
        .limit(8)
    )
    results = (await db.execute(query)).scalars().all()

    items = [
        {
            "id": v.id,
            "cve_id": v.cve_id,
            "title": v.title,
            "severity": v.severity.value,
            "cvss_score": v.cvss_score,
            "risk_score": v.risk_score,
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
