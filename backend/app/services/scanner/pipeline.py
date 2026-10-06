"""Scan Execution Pipeline.

Coordinates the Nmap port scanning engine, NVD API enrichment,
vulnerability deduplication, and database persistence.
"""

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional
from sqlalchemy import func, select
from sqlalchemy.orm import selectinload

from app.db.session import AsyncSessionLocal
from app.models.asset import Asset
from app.models.scan import Scan, ScanStatus
from app.models.vulnerability import Vulnerability, VulnerabilitySeverity, VulnerabilityStatus
from app.services.enricher.nvd_client import nvd_client
from app.services.scanner.nmap_runner import ScanExecutionError, run_nmap_scan

logger = logging.getLogger("aegis.pipeline")


async def execute_scan_pipeline(scan_id: int) -> None:
    """Execute scan and enrichment asynchronously in the background."""
    async with AsyncSessionLocal() as db:
        # Load scan and target asset
        scan_query = select(Scan).options(selectinload(Scan.asset)).where(Scan.id == scan_id)
        result = await db.execute(scan_query)
        scan: Optional[Scan] = result.scalar_one_or_none()

        if not scan:
            logger.error(f"Scan ID {scan_id} not found in database. Aborting pipeline.")
            return

        asset: Optional[Asset] = scan.asset
        if not asset:
            logger.error(f"Asset for Scan ID {scan_id} not found. Aborting pipeline.")
            scan.status = ScanStatus.failed
            scan.completed_at = datetime.now(timezone.utc)
            scan.raw_output = {"error": "Target asset does not exist"}
            await db.commit()
            return

        try:
            # Transition scan status to running
            logger.info(f"Initiating pipeline for Scan #{scan.id} on asset {asset.name} ({asset.ip_address})")
            scan.status = ScanStatus.running
            scan.started_at = datetime.now(timezone.utc)
            await db.commit()

            # Execute Nmap scan in worker thread
            ports: List[Dict[str, Any]] = await run_nmap_scan(
                ip_address=asset.ip_address,
                scan_type=scan.scan_type.value,
            )

            # Persist raw port scan telemetry
            scan.raw_output = {
                "target_ip": asset.ip_address,
                "target_hostname": asset.hostname,
                "scan_type": scan.scan_type.value,
                "ports_discovered": len(ports),
                "ports": ports,
            }
            await db.commit()

            # If no open ports were identified, complete scan cleanly
            if not ports:
                logger.info(f"Scan #{scan.id} finished: no open ports found on {asset.ip_address}")
                scan.status = ScanStatus.completed
                scan.completed_at = datetime.now(timezone.utc)
                scan.total_vulns_found = 0
                await db.commit()
                return

            # Enrich discovered open ports with NVD CVE telemetry
            total_vulns = 0

            for port_info in ports:
                product = port_info.get("product")
                service = port_info.get("service")
                version = port_info.get("version")
                port_num = port_info.get("port")
                cpe = port_info.get("cpe")

                # Skip enrichment if port has no identifiable service info
                if not product and not service:
                    continue

                cve_records = await nvd_client.enrich_service(
                    product=product,
                    service=service,
                    version=version,
                    cpe=cpe,
                )

                for cve in cve_records:
                    cve_id = cve["cve_id"]
                    cvss_score = cve["cvss_score"]
                    severity_str = cve["severity"].lower()

                    try:
                        severity_enum = VulnerabilitySeverity(severity_str)
                    except ValueError:
                        severity_enum = VulnerabilitySeverity.none

                    # Deduplication check: check if (asset_id, cve_id, port) already recorded
                    dup_query = select(Vulnerability).where(
                        Vulnerability.asset_id == asset.id,
                        Vulnerability.cve_id == cve_id,
                        Vulnerability.port == port_num,
                    )
                    dup_result = await db.execute(dup_query)
                    existing_vuln: Optional[Vulnerability] = dup_result.scalar_one_or_none()

                    now_utc = datetime.now(timezone.utc)

                    if existing_vuln:
                        # If finding exists and is not marked as mitigated, refresh last_seen_at
                        if existing_vuln.status != VulnerabilityStatus.mitigated:
                            existing_vuln.last_seen_at = now_utc
                            existing_vuln.scan_id = scan.id
                            await db.commit()
                            total_vulns += 1
                    else:
                        title = f"{cve_id}: {cve['description'][:80]}..." if cve.get("description") else cve_id

                        # TODO: Phase 5 will refine risk_score with asset criticality weighting:
                        # risk_score = round((cvss_score * 0.6) + (((criticality / 5) * 10) * 0.4), 2)
                        risk_score = float(cvss_score)

                        new_vuln = Vulnerability(
                            scan_id=scan.id,
                            asset_id=asset.id,
                            cve_id=cve_id,
                            title=title[:255],
                            description=cve.get("description", "No vulnerability description available."),
                            cvss_score=cvss_score,
                            severity=severity_enum,
                            port=port_num,
                            service=service or product,
                            service_version=version,
                            risk_score=risk_score,
                            epss_score=None,
                            status=VulnerabilityStatus.open,
                            remediation="Review vendor security advisories and update to the latest patched software version.",
                            first_seen_at=now_utc,
                            last_seen_at=now_utc,
                        )
                        db.add(new_vuln)
                        await db.commit()
                        total_vulns += 1

            # Mark scan completed successfully
            scan.status = ScanStatus.completed
            scan.completed_at = datetime.now(timezone.utc)
            scan.total_vulns_found = total_vulns
            await db.commit()
            logger.info(f"Scan #{scan.id} completed successfully. Identified {total_vulns} vulnerability finding(s).")

        except ScanExecutionError as see:
            logger.warning(f"Scan #{scan.id} execution failed: {see}")
            scan.status = ScanStatus.failed
            scan.completed_at = datetime.now(timezone.utc)
            scan.raw_output = {"error": str(see)}
            await db.commit()

        except Exception as exc:
            logger.error(f"Unexpected pipeline exception on Scan #{scan.id}: {exc}", exc_info=True)
            scan.status = ScanStatus.failed
            scan.completed_at = datetime.now(timezone.utc)
            scan.raw_output = {"error": f"Pipeline failure: {str(exc)}"}
            await db.commit()
