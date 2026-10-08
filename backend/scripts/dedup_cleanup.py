"""Deduplication script for existing database vulnerabilities.

Merges duplicate findings grouped by (asset_id, cve_id, port).
Treats NULL ports as a single group.
Preserves highest verification rank, mitigated/in_progress status, and non-empty evidence.
"""

import asyncio
import logging
from sqlalchemy import select, func, delete
from app.db.session import AsyncSessionLocal
from app.models.vulnerability import (
    Vulnerability,
    VulnerabilityStatus,
    VerificationType,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("aegis.dedup")

VERIFICATION_HIERARCHY = {
    VerificationType.nuclei_verified: 4,
    VerificationType.ssl_verified: 3,
    VerificationType.nse_verified: 2,
    VerificationType.version_match: 1,
}

STATUS_HIERARCHY = {
    VulnerabilityStatus.mitigated: 3,
    VulnerabilityStatus.in_progress: 2,
    VulnerabilityStatus.open: 1,
    VulnerabilityStatus.false_positive: 0,
}


async def run_deduplication():
    async with AsyncSessionLocal() as session:
        logger.info("[DEDUP] Starting vulnerability deduplication scan...")

        # 1. Find all duplicate groups
        subq = (
            select(
                Vulnerability.asset_id,
                Vulnerability.cve_id,
                Vulnerability.port,
                func.count(Vulnerability.id).label("cnt"),
            )
            .group_by(
                Vulnerability.asset_id,
                Vulnerability.cve_id,
                Vulnerability.port,
            )
            .having(func.count(Vulnerability.id) > 1)
        )
        dup_groups = (await session.execute(subq)).all()

        if not dup_groups:
            logger.info("[DEDUP] No duplicate vulnerabilities found. Database is clean!")
            return

        logger.info(f"[DEDUP] Found {len(dup_groups)} duplicate group(s) to process.")
        total_deleted = 0

        for row in dup_groups:
            asset_id = row.asset_id
            cve_id = row.cve_id
            port = row.port

            port_filter = (
                Vulnerability.port.is_(None)
                if port is None
                else Vulnerability.port == port
            )

            vuln_stmt = (
                select(Vulnerability)
                .where(
                    Vulnerability.asset_id == asset_id,
                    Vulnerability.cve_id == cve_id,
                    port_filter,
                )
                .order_by(Vulnerability.id.asc())
            )
            records = (await session.execute(vuln_stmt)).scalars().all()
            if len(records) <= 1:
                continue

            logger.info(
                f"[DEDUP] Processing group: Asset {asset_id}, {cve_id}, Port {port if port is not None else 'None'} ({len(records)} records: {[r.id for r in records]})"
            )

            # Sort records to choose best keeper:
            # 1. Verification rank (higher is better)
            # 2. Status rank (mitigated/in_progress preferred)
            # 3. updated_at or id (most recent)
            sorted_records = sorted(
                records,
                key=lambda v: (
                    VERIFICATION_HIERARCHY.get(v.verification, 1),
                    STATUS_HIERARCHY.get(v.status, 1),
                    v.last_seen_at or v.first_seen_at,
                    v.id,
                ),
                reverse=True,
            )

            keeper = sorted_records[0]
            to_delete = sorted_records[1:]

            # Merge evidence and attributes from all records
            all_evidence = [r.evidence for r in records if r.evidence]
            if all_evidence:
                keeper.evidence = "\n---\n".join(dict.fromkeys(all_evidence))

            # Preserve highest verification rank across group
            best_verif = max(records, key=lambda v: VERIFICATION_HIERARCHY.get(v.verification, 1)).verification
            keeper.verification = best_verif

            # Preserve status: if any was mitigated, keep mitigated. If in_progress, keep in_progress
            if any(r.status == VulnerabilityStatus.mitigated for r in records):
                keeper.status = VulnerabilityStatus.mitigated
            elif any(r.status == VulnerabilityStatus.in_progress for r in records):
                keeper.status = VulnerabilityStatus.in_progress
            elif any(r.status == VulnerabilityStatus.false_positive for r in records):
                keeper.status = VulnerabilityStatus.false_positive

            # Retain non-null danger/exploit metrics
            for r in records:
                if r.danger_score and not keeper.danger_score:
                    keeper.danger_score = r.danger_score
                if r.exploitability and not keeper.exploitability:
                    keeper.exploitability = r.exploitability
                if r.impact and not keeper.impact:
                    keeper.impact = r.impact
                if r.public_exploit:
                    keeper.public_exploit = True

            session.add(keeper)

            # Delete the remaining duplicates
            delete_ids = [r.id for r in to_delete]
            await session.execute(
                delete(Vulnerability).where(Vulnerability.id.in_(delete_ids))
            )
            total_deleted += len(delete_ids)

            logger.info(
                f"[DEDUP] Kept ID {keeper.id} (verif={keeper.verification.value}, status={keeper.status.value}), deleted IDs {delete_ids}"
            )

        await session.commit()
        logger.info(f"[DEDUP] Deduplication complete. Deleted {total_deleted} redundant duplicate rows.")


if __name__ == "__main__":
    asyncio.run(run_deduplication())
