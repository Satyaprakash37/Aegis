"""Scan Execution Pipeline.

Coordinates the Nmap port scanning engine, NSE vulnerability scripts, Nuclei active
verification, NVD API enrichment, danger assessment, deduplication, and database persistence.
"""

import asyncio
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
from app.services.scanner.vulnerability_upsert import upsert_vulnerability

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

            progress_lock = asyncio.Lock()

            async def update_progress(
                current_stage: str,
                stage_number: int,
                stages_total: int,
                detail: str,
                hosts_processed: int = 0,
                hosts_total: int = 0,
            ):
                async with progress_lock:
                    try:
                        scan.progress = {
                            "current_stage": current_stage,
                            "stage_number": stage_number,
                            "stages_total": stages_total,
                            "detail": detail,
                            "hosts_processed": hosts_processed,
                            "hosts_total": hosts_total,
                            "updated_at": datetime.now(timezone.utc).isoformat(),
                        }
                        await db.commit()
                    except Exception as pe:
                        logger.warning(f"Error persisting scan progress update: {pe}")

            is_deep = scan.scan_type == ScanType.deep or scan.scan_type.value == "deep"
            stage_names = (
                [
                    "Stage 1: Subdomain Discovery",
                    "Stage 2: Live Web Probing & Tech Stack Detection",
                    "Stage 3: Smart Port & NSE Vulnerability Scanning",
                    "Stage 4: Expanded Nuclei Active Web Exploitation",
                    "Stage 5: SSL/TLS Cryptographic Audit",
                    "Stage 6: Technology Version Vulnerability Analysis",
                    "Stage 7: Aggregation & Threat Prioritization",
                ]
                if is_deep
                else [f"Nmap Port & Service Fingerprinting ({scan.scan_type.value})", "NVD Threat Intelligence Enrichment"]
            )
            active_verified_findings: List[Dict[str, Any]] = []
            recon_data: Optional[Dict[str, Any]] = None

            if is_deep:
                # Execute 7-stage reconnaissance and active verification engine
                ports, active_verified_findings, recon_data = await run_deep_scan(
                    target=scan_target,
                    target_type=asset.target_type.value if hasattr(asset.target_type, "value") else str(asset.target_type),
                    target_hostname=asset.hostname or (asset.ip_address if asset.target_type == TargetType.domain else None),
                    resolved_ip=asset.resolved_ip,
                    progress_callback=update_progress,
                )
            else:
                stages_total = 2
                await update_progress(
                    current_stage="port_scanning",
                    stage_number=1,
                    stages_total=stages_total,
                    detail=f"Scanning ports ({scan.scan_type.value})...",
                )
                # Execute standard Nmap port scan (quick or full) against resolved IP
                ports = await run_nmap_scan(
                    ip_address=scan_target,
                    scan_type=scan.scan_type.value,
                )
                await update_progress(
                    current_stage="nvd_enrichment",
                    stage_number=2,
                    stages_total=stages_total,
                    detail="Correlating NVD CVE threat intelligence...",
                )

            # Record initial raw output

            scan_raw = {
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
            if recon_data:
                scan_raw["recon"] = recon_data
            scan.raw_output = scan_raw
            await db.commit()

            total_vulns = 0
            verification_counts = {
                "version_match": 0,
                "nse_verified": 0,
                "nuclei_verified": 0,
                "ssl_verified": 0,
            }

            now_utc = datetime.now(timezone.utc)

            # 1. Process actively verified findings first (highest confidence)
            for v_finding in active_verified_findings:
                cve_id = v_finding["cve_id"]
                port_num = v_finding.get("port")
                v_type_str = v_finding.get("verification", VerificationType.nse_verified.value)
                try:
                    ver_enum = VerificationType(v_type_str)
                except ValueError:
                    ver_enum = VerificationType.nse_verified
                cvss_score = float(v_finding.get("cvss_score", 7.5))
                evidence = v_finding.get("evidence", "")
                title = v_finding.get("title", cve_id)
                description = v_finding.get("description", title)
                severity_enum = v_finding.get("severity", VulnerabilitySeverity.high)

                danger_meta = evaluate_vulnerability_danger(
                    cve_id=cve_id,
                    cvss_score=cvss_score,
                    verification=ver_enum.value,
                    title=title,
                    description=description,
                )

                vuln_obj, _ = await upsert_vulnerability(
                    db=db,
                    asset_id=asset.id,
                    cve_id=cve_id,
                    title=title,
                    description=description,
                    cvss_score=cvss_score,
                    severity=severity_enum,
                    port=port_num,
                    service=v_finding.get("service"),
                    verification=ver_enum,
                    evidence=evidence,
                    danger_meta=danger_meta,
                    scan_id=scan.id,
                    remediation=v_finding.get("remediation") or "Apply official security patch or mitigation playbook immediately.",
                    asset_criticality=asset.criticality,
                )

                await db.commit()
                total_vulns += 1
                ver_val = vuln_obj.verification.value if hasattr(vuln_obj.verification, "value") else str(vuln_obj.verification)
                verification_counts[ver_val] = verification_counts.get(ver_val, 0) + 1

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

                    danger_meta = evaluate_vulnerability_danger(
                        cve_id=cve_id,
                        cvss_score=cvss_score,
                        verification=VerificationType.version_match.value,
                        title=cve_id,
                        description=cve.get("description", ""),
                    )

                    title = f"{cve_id}: {cve['description'][:80]}..." if cve.get("description") else cve_id
                    vuln_obj, _ = await upsert_vulnerability(
                        db=db,
                        asset_id=asset.id,
                        cve_id=cve_id,
                        title=title,
                        description=cve.get("description", "No vulnerability description available."),
                        cvss_score=cvss_score,
                        severity=severity_enum,
                        port=port_num,
                        service=service or product,
                        service_version=version,
                        verification=VerificationType.version_match,
                        danger_meta=danger_meta,
                        scan_id=scan.id,
                        remediation="Review vendor security advisories and update to the latest patched software version.",
                        asset_criticality=asset.criticality,
                    )

                    await db.commit()
                    total_vulns += 1
                    ver_val = vuln_obj.verification.value if hasattr(vuln_obj.verification, "value") else str(vuln_obj.verification)
                    verification_counts[ver_val] = verification_counts.get(ver_val, 0) + 1

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

            # Update final scan record with breakdown and recon data
            raw_out = scan.raw_output or {}
            raw_out["verification_breakdown"] = verification_counts
            if recon_data:
                raw_out["recon"] = recon_data
            scan.raw_output = raw_out
            scan.status = ScanStatus.completed
            scan.completed_at = datetime.now(timezone.utc)
            scan.total_vulns_found = total_vulns

            final_stages = 7 if is_deep else 2
            await update_progress(
                current_stage="completed",
                stage_number=final_stages,
                stages_total=final_stages,
                detail=f"Scan completed: {total_vulns} finding(s) identified",
            )
            await db.commit()

            logger.info(
                f"Scan #{scan.id} completed successfully. Identified {total_vulns} finding(s) "
                f"(Breakdown: {verification_counts})."
            )

        except ScanExecutionError as see:
            logger.warning(f"Scan #{scan.id} execution failed: {see}")
            scan.status = ScanStatus.failed
            scan.completed_at = datetime.now(timezone.utc)
            
            err_msg = str(see)
            err_lower = err_msg.lower()
            if "offline" in err_lower or "unreachable" in err_lower:
                hint = "Host unreachable — verify target is online, network route is available, and firewall allows incoming TCP/UDP traffic."
            elif "dns" in err_lower or "resolve" in err_lower:
                hint = "DNS resolution failed — verify the domain is registered and resolvable via public DNS servers (8.8.8.8, 1.1.1.1)."
            elif "timeout" in err_lower:
                hint = "Scan timed out before receiving responses — the target may be rate-limiting probes or dropping connections."
            else:
                hint = "Scanner tool error — inspect technical details and container execution logs."

            current_stg = scan.progress.get("current_stage") if (scan.progress and isinstance(scan.progress, dict)) else "port_scanning"

            scan.raw_output = {
                "error": err_msg,
                "error_type": "ScanExecutionError",
                "error_hint": hint,
                "target": asset.ip_address,
                "target_ip": scan_target,
                "failure_stage": current_stg,
                "stages": stage_names,
            }
            scan.progress = {
                "current_stage": "failed",
                "stage_number": 0,
                "stages_total": 7 if is_deep else 2,
                "detail": f"Scan failed: {err_msg}",
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
            await db.commit()

        except Exception as exc:
            import traceback
            tb = traceback.format_exc()
            logger.error(f"Unexpected pipeline exception on Scan #{scan.id}: {exc}", exc_info=True)
            scan.status = ScanStatus.failed
            scan.completed_at = datetime.now(timezone.utc)

            err_msg = str(exc)
            current_stg = scan.progress.get("current_stage") if (scan.progress and isinstance(scan.progress, dict)) else "pipeline_execution"

            scan.raw_output = {
                "error": f"Pipeline failure: {err_msg}",
                "error_type": type(exc).__name__,
                "error_hint": "An unexpected pipeline exception occurred during execution. Inspect the technical detail below or container logs.",
                "traceback_summary": tb[-600:] if tb else None,
                "target": asset.ip_address,
                "target_ip": scan_target,
                "failure_stage": current_stg,
                "stages": stage_names,
            }
            scan.progress = {
                "current_stage": "failed",
                "stage_number": 0,
                "stages_total": 7 if is_deep else 2,
                "detail": f"Pipeline error: {err_msg}",
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
            await db.commit()
