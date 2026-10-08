"""Notification events route for AEGIS Topbar alerts and event feed."""

from datetime import datetime, timedelta, timezone
from typing import Annotated, List
from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import get_current_user
from app.db.session import get_db
from app.models.asset import Asset
from app.models.scan import Scan, ScanStatus
from app.models.user import User
from app.models.vulnerability import VerificationType, Vulnerability, VulnerabilitySeverity
from app.schemas.notification import NotificationItem, NotificationListResponse

router = APIRouter(prefix="/notifications", tags=["notifications"])


@router.get("", response_model=NotificationListResponse)
async def get_notifications(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> NotificationListResponse:
    """Retrieve top 20 latest platform security events (scans, critical CVEs, verified findings)."""
    items: List[NotificationItem] = []
    now_utc = datetime.now(timezone.utc)
    one_day_ago = now_utc - timedelta(hours=24)

    # 1. Fetch recent completed scans (up to 10)
    scans_stmt = (
        select(Scan)
        .options(selectinload(Scan.asset))
        .where(
            Scan.created_by == current_user.id,
            Scan.status == ScanStatus.completed,
        )
        .order_by(Scan.completed_at.desc())
        .limit(10)
    )
    scans_res = await db.execute(scans_stmt)
    recent_scans = scans_res.scalars().all()

    for s in recent_scans:
        # Check if scan discovered critical vulns
        crit_count_stmt = select(func.count(Vulnerability.id)).where(
            Vulnerability.scan_id == s.id,
            Vulnerability.severity == VulnerabilitySeverity.critical,
        )
        crit_count = (await db.execute(crit_count_stmt)).scalar() or 0

        target_name = s.asset.name if s.asset else f"Asset #{s.asset_id}"
        event_time = s.completed_at or s.started_at or now_utc
        items.append(
            NotificationItem(
                id=f"scan-{s.id}",
                type="scan_completed",
                title=f"{s.scan_type.value.capitalize()} scan completed on {target_name}",
                detail=f"{s.total_vulns_found} finding(s) detected ({crit_count} critical)",
                target=target_name,
                timestamp=event_time,
                is_critical=crit_count > 0,
                link=f"/vulns?scan_id={s.id}" if s.total_vulns_found > 0 else "/scans",
            )
        )

    # 2. Fetch recent critical vulnerabilities (up to 10)
    crit_vulns_stmt = (
        select(Vulnerability)
        .join(Asset, Vulnerability.asset_id == Asset.id)
        .options(selectinload(Vulnerability.asset))
        .where(
            Asset.owner_id == current_user.id,
            Vulnerability.severity == VulnerabilitySeverity.critical,
        )
        .order_by(Vulnerability.first_seen_at.desc())
        .limit(10)
    )
    crit_vulns = (await db.execute(crit_vulns_stmt)).scalars().all()

    for v in crit_vulns:
        target_name = v.asset.name if v.asset else "Host"
        items.append(
            NotificationItem(
                id=f"vuln-crit-{v.id}",
                type="critical_vuln",
                title=f"Critical Exposure: {v.cve_id}",
                detail=f"{v.title[:75]} on {target_name}:{v.port or 0}",
                target=target_name,
                timestamp=v.first_seen_at or now_utc,
                is_critical=True,
                link=f"/vulns?search={v.cve_id}",
            )
        )

    # 3. Fetch recent actively verified vulnerabilities (up to 5)
    ver_vulns_stmt = (
        select(Vulnerability)
        .join(Asset, Vulnerability.asset_id == Asset.id)
        .options(selectinload(Vulnerability.asset))
        .where(
            Asset.owner_id == current_user.id,
            Vulnerability.verification.in_([
                VerificationType.nuclei_verified,
                VerificationType.nse_verified,
                VerificationType.ssl_verified,
            ]),
        )
        .order_by(Vulnerability.first_seen_at.desc())
        .limit(5)
    )
    ver_vulns = (await db.execute(ver_vulns_stmt)).scalars().all()

    for v in ver_vulns:
        target_name = v.asset.name if v.asset else "Host"
        v_name = v.verification.value.replace("_", " ").title()
        items.append(
            NotificationItem(
                id=f"vuln-ver-{v.id}",
                type="verified_vuln",
                title=f"Verified Exploit ({v_name}): {v.cve_id}",
                detail=f"Proof of concept captured on {target_name}:{v.port or 0}",
                target=target_name,
                timestamp=v.first_seen_at or now_utc,
                is_critical=v.severity in (VulnerabilitySeverity.critical, VulnerabilitySeverity.high),
                link=f"/vulns?search={v.cve_id}",
            )
        )

    # Deduplicate by event ID & sort by timestamp descending
    deduped_items = {}
    for item in items:
        if item.id not in deduped_items:
            deduped_items[item.id] = item

    sorted_items = sorted(deduped_items.values(), key=lambda x: x.timestamp, reverse=True)[:20]

    # Calculate unseen critical count in the last 24h
    crit_24h_count = sum(
        1 for it in sorted_items if it.is_critical and it.timestamp >= one_day_ago
    )

    return NotificationListResponse(
        data=sorted_items,
        total=len(sorted_items),
        critical_count_24h=crit_24h_count,
    )
