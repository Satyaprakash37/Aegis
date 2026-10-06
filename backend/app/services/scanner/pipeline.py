"""Scan Execution Pipeline.

Coordinates the Nmap port scanning engine, NSE vulnerability scripts, Nuclei active
verification, NVD API enrichment, danger assessment, deduplication, and database persistence.
"""

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional
from sqlalchemy import func, select
from sqlalchemy.orm import selectinload

from app.db.session import AsyncSessionLocal
from app.models.asset import Asset, AssetType, TargetType
from app.models.scan import Scan, ScanStatus, ScanType
from app.models.vulnerability import (
    Vulnerability,
    VulnerabilitySeverity,
    VulnerabilityStatus,
    VerificationType,
)
from app.services.enricher.nvd_client import nvd_client
from app.services.risk.engine import calculate_risk_score
from app.services.risk.danger_engine import evaluate_vulnerability_danger
from app.services.scanner.nmap_runner import ScanExecutionError, run_nmap_scan
from app.services.scanner.deep_scanner import run_deep_scan

logger = logging.getLogger("aegis.pipeline")


async def execute_scan_pipeline(scan_id: int) -> None:
    """Execute scan, active verification, and enrichment asynchronously."""
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
            # Determine actual network target (resolved IP for domain targets)
            scan_target = (
                asset.resolved_ip
                if (asset.target_type == TargetType.domain and asset.resolved_ip)
                else asset.ip_address
            )

            logger.info(
                f"Initiating pipeline for Scan #{scan.id} (type: {scan.scan_type.value}) "
                f"on {asset.name} (target: {asset.ip_address}, scanning: {scan_target})"
            )
            scan.status = ScanStatus.running
            scan.started_at = datetime.now(timezone.utc)
            await db.commit()

            is_deep = scan.scan_type == ScanType.deep or scan.scan_type.value == "deep"
            active_verified_findings: List[Dict[str, Any]] = []

            if is_deep:
                # Execute three-stage deep scan against resolved IP
                ports, active_verified_findings = await run_deep_scan(scan_target)
            else:
                # Execute standard Nmap port scan (quick or full) against resolved IP
                ports = await run_nmap_scan(
                    ip_address=scan_target,
                    scan_type=scan.scan_type.value,
                )

            # Record initial raw output
            stage_names = (
                [
                    "Stage 1: Nmap Service Discovery (top 500 ports)",
                    "Stage 2: Nmap NSE Script Active Scanning",
                    "Stage 3: Nuclei Dynamic Active Verification",
                ]
                if is_deep
                else [f"Nmap Port & Service Fingerprinting ({scan.scan_type.value})"]
            )

            scan.raw_output = {
                "target": asset.ip_address,
                "target_type": asset.target_type.value if hasattr(asset.target_type, "value") else str(asset.target_type),
                "target_ip": scan_target,
                "resolved_ip": asset.resolved_ip,
                "target_hostname": asset.hostname,
                "scan_type": scan.scan_type.value,
                "ports_discovered": len(ports),
                "ports": ports,
                "stages": stage_names,
                "active_verified_count": len(active_verified_findings),
            }
            await db.commit()

            total_vulns = 0
            verification_counts = {
                "version_match": 0,
                "nse_verified": 0,
                "nuclei_verified": 0,
            }

            now_utc = datetime.now(timezone.utc)

            # 1. Process actively verified findings first (highest confidence)
            for v_finding in active_verified_findings:
                cve_id = v_finding["cve_id"]
                port_num = v_finding.get("port")
                v_type = v_finding.get("verification", VerificationType.nse_verified.value)
                cvss_score = float(v_finding.get("cvss_score", 7.5))
                evidence = v_finding.get("evidence", "")
                title = v_finding.get("title", cve_id)
                description = v_finding.get("description", title)
                severity_enum = v_finding.get("severity", VulnerabilitySeverity.high)

                # Check for existing vulnerability to deduplicate / upgrade
                dup_query = select(Vulnerability).where(
                    Vulnerability.asset_id == asset.id,
                    Vulnerability.cve_id == cve_id,
                    Vulnerability.port == port_num,
                )
                dup_result = await db.execute(dup_query)
                existing_vuln: Optional[Vulnerability] = dup_result.scalar_one_or_none()

                danger_meta = evaluate_vulnerability_danger(
                    cve_id=cve_id,
                    cvss_score=cvss_score,
                    verification=v_type,
                    title=title,
                    description=description,
                )

                risk_score = calculate_risk_score(cvss_score, asset.criticality)

                if existing_vuln:
                    # Upgrade verification level and update evidence/danger
                    existing_vuln.verification = VerificationType(v_type)
                    existing_vuln.evidence = evidence
                    existing_vuln.danger_score = danger_meta["danger_score"]
                    existing_vuln.exploitability = danger_meta["exploitability"]
                    existing_vuln.impact = danger_meta["impact"]
                    existing_vuln.public_exploit = danger_meta["public_exploit"]
                    existing_vuln.risk_score = risk_score
                    existing_vuln.last_seen_at = now_utc
                    existing_vuln.scan_id = scan.id
                    if existing_vuln.status == VulnerabilityStatus.mitigated:
                        existing_vuln.status = VulnerabilityStatus.open
                else:
                    new_vuln = Vulnerability(
                        scan_id=scan.id,
                        asset_id=asset.id,
                        cve_id=cve_id,
                        title=title[:255],
                        description=description,
                        cvss_score=cvss_score,
                        severity=severity_enum,
                        port=port_num,
                        service=None,
                        service_version=None,
                        risk_score=risk_score,
                        epss_score=None,
                        status=VulnerabilityStatus.open,
                        remediation="Apply official security patch or mitigation playbook immediately.",
                        verification=VerificationType(v_type),
                        evidence=evidence,
                        danger_score=danger_meta["danger_score"],
                        exploitability=danger_meta["exploitability"],
                        impact=danger_meta["impact"],
                        public_exploit=danger_meta["public_exploit"],
                        first_seen_at=now_utc,
                        last_seen_at=now_utc,
                    )
                    db.add(new_vuln)

                await db.commit()
                total_vulns += 1
                verification_counts[v_type] = verification_counts.get(v_type, 0) + 1

            # 2. Enrich discovered open ports with NVD CVE telemetry (version match)
            for port_info in ports:
                product = port_info.get("product")
                service = port_info.get("service")
                version = port_info.get("version")
                port_num = port_info.get("port")
                cpe = port_info.get("cpe")

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

                    # Deduplication check
                    dup_query = select(Vulnerability).where(
                        Vulnerability.asset_id == asset.id,
                        Vulnerability.cve_id == cve_id,
                        Vulnerability.port == port_num,
                    )
                    dup_result = await db.execute(dup_query)
                    existing_vuln = dup_result.scalar_one_or_none()

                    danger_meta = evaluate_vulnerability_danger(
                        cve_id=cve_id,
                        cvss_score=cvss_score,
                        verification=VerificationType.version_match.value,
                        title=cve_id,
                        description=cve.get("description", ""),
                    )

                    risk_score = calculate_risk_score(cvss_score, asset.criticality)

                    if existing_vuln:
                        # If existing finding was version match, update danger fields
                        if existing_vuln.verification == VerificationType.version_match:
                            existing_vuln.danger_score = danger_meta["danger_score"]
                            existing_vuln.exploitability = danger_meta["exploitability"]
                            existing_vuln.impact = danger_meta["impact"]
                            existing_vuln.public_exploit = danger_meta["public_exploit"]
                        existing_vuln.last_seen_at = now_utc
                        existing_vuln.scan_id = scan.id
                        await db.commit()
                        total_vulns += 1
                        verification_counts[existing_vuln.verification.value] = (
                            verification_counts.get(existing_vuln.verification.value, 0) + 1
                        )
                    else:
                        title = f"{cve_id}: {cve['description'][:80]}..." if cve.get("description") else cve_id
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
                            verification=VerificationType.version_match,
                            evidence=None,
                            danger_score=danger_meta["danger_score"],
                            exploitability=danger_meta["exploitability"],
                            impact=danger_meta["impact"],
                            public_exploit=danger_meta["public_exploit"],
                            first_seen_at=now_utc,
                            last_seen_at=now_utc,
                        )
                        db.add(new_vuln)
                        await db.commit()
                        total_vulns += 1
                        verification_counts["version_match"] += 1

            # 3. Smart Asset Type Detection for auto_created assets
            if getattr(asset, "auto_created", False):
                discovered_port_numbers = {p.get("port") for p in ports if p.get("port")}
                for vf in active_verified_findings:
                    if vf.get("port"):
                        discovered_port_numbers.add(vf.get("port"))

                discovered_services = {
                    (p.get("service") or "").lower() for p in ports if p.get("service")
                }

                WEB_PORTS = {80, 443, 8080, 8443, 3000, 3001, 8000, 8081, 5000, 9000}
                DB_PORTS = {5432, 3306, 1433, 1521, 27017, 6379, 5433, 33060}

                is_web = any(p in WEB_PORTS for p in discovered_port_numbers) or any(
                    s in ("http", "https", "http-proxy", "web", "apache", "nginx", "node")
                    for s in discovered_services
                )
                is_db = any(p in DB_PORTS for p in discovered_port_numbers) or any(
                    s in ("postgresql", "postgres", "mysql", "mssql", "oracle", "mongodb", "redis")
                    for s in discovered_services
                )

                if is_web:
                    asset.asset_type = AssetType.web
                    logger.info(f"Smart Detection: Auto-created asset #{asset.id} ('{asset.name}') updated to type 'web'")
                elif is_db:
                    asset.asset_type = AssetType.db
                    logger.info(f"Smart Detection: Auto-created asset #{asset.id} ('{asset.name}') updated to type 'db'")

            # Update final scan record with breakdown
            raw_out = scan.raw_output or {}
            raw_out["verification_breakdown"] = verification_counts
            scan.raw_output = raw_out
            scan.status = ScanStatus.completed
            scan.completed_at = datetime.now(timezone.utc)
            scan.total_vulns_found = total_vulns
            await db.commit()

            logger.info(
                f"Scan #{scan.id} completed successfully. Identified {total_vulns} finding(s) "
                f"(Breakdown: {verification_counts})."
            )

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
