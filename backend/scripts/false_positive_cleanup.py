"""False positive re-classification script for pre-Phase 8.6 legacy version_match findings.

Scans all version_match findings and uses is_cve_applicable / domain heuristics
to mark legacy false positives as status="false_positive".
Specifically addresses:
- Ancient OpenSSH CVEs (CVE-1999-0661, CVE-2000-0525) on modern servers
- Trend Micro smtpscan.dll (CVE-2001-1573) on generic mail ports
- RemoteEditor (CVE-2004-2248) on generic mail submission ports
"""

import asyncio
import logging
from sqlalchemy import select
from app.db.session import AsyncSessionLocal
from app.models.vulnerability import (
    Vulnerability,
    VulnerabilityStatus,
    VerificationType,
)
from app.services.enricher.nvd_client import is_cve_applicable, normalize_service_identity

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("aegis.fp_cleanup")

# Explicit known false-positive CVE signatures that were erroneously matched against generic ports
KNOWN_FP_CVES = {
    "CVE-2001-1573",  # Trend Micro InterScan VirusWall smtpscan.dll on port 465
    "CVE-2004-2248",  # RemoteEditor on port 587 submission
    "CVE-1999-0661",  # Trojan horse distribution from 1999 on modern OpenSSH
    "CVE-2000-0525",  # OpenSSH UseLogin flaw from 2000 on modern OpenSSH
}


async def run_false_positive_cleanup():
    async with AsyncSessionLocal() as session:
        logger.info("[FP CLEANUP] Starting false positive audit on legacy version_match findings...")

        stmt = (
            select(Vulnerability)
            .where(
                Vulnerability.verification == VerificationType.version_match,
                Vulnerability.status == VulnerabilityStatus.open,
            )
            .order_by(Vulnerability.id.asc())
        )
        vulns = (await session.execute(stmt)).scalars().all()
        logger.info(f"[FP CLEANUP] Inspecting {len(vulns)} open version_match findings...")

        reclassified_count = 0

        for v in vulns:
            is_fp = False
            reason = ""

            # 1. Direct match on known erroneous CVEs
            if v.cve_id in KNOWN_FP_CVES:
                is_fp = True
                reason = f"Known pre-8.6 false positive signature ({v.cve_id})"

            # 2. Re-run is_cve_applicable
            if not is_fp:
                norm_prod, norm_ver = normalize_service_identity(
                    product=v.service,
                    service=v.service,
                    version=v.service_version,
                )
                applicable = is_cve_applicable(
                    cve_id=v.cve_id,
                    description=v.description,
                    product=norm_prod or (v.service or ""),
                    version=norm_ver or (v.service_version or ""),
                )
                if not applicable:
                    is_fp = True
                    reason = f"is_cve_applicable rejected match for {norm_prod} {norm_ver}"

            if is_fp:
                logger.info(
                    f"[FP CLEANUP] Reclassifying Vuln ID {v.id} ({v.cve_id}) on Asset {v.asset_id}: {reason}"
                )
                v.status = VulnerabilityStatus.false_positive
                session.add(v)
                reclassified_count += 1

        await session.commit()
        logger.info(
            f"[FP CLEANUP] Audit complete. Reclassified {reclassified_count} vulnerabilities to 'false_positive'."
        )


if __name__ == "__main__":
    asyncio.run(run_false_positive_cleanup())
