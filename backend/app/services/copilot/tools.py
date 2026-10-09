"""Read-only platform tools for AEGIS Operations Copilot.

Provides 8 data-access tools:
1. get_asset_context(asset_id)
2. get_scan_results(asset_id, limit)
3. research_cve(cve_id)
4. check_kev(cve_id)
5. get_epss(cve_id)
6. find_public_exploit_refs(cve_id)
7. get_top_vulnerabilities(asset_id, count)
8. suggest_next_steps(asset_id)
"""

import logging
from typing import Any, Dict, List, Optional
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset import Asset
from app.models.scan import Scan, ScanStatus
from app.models.vulnerability import Vulnerability, VulnerabilityStatus
from app.services.threat_intel.kev import check_kev as service_check_kev
from app.services.threat_intel.epss import get_epss as service_get_epss
from app.services.threat_intel.exploit_refs import ExploitReferenceService

logger = logging.getLogger("aegis.copilot.tools")


class CopilotToolbox:
    """Read-only data access tools for Copilot defensive analysis."""

    def __init__(self, db: AsyncSession):
        self.db = db
        self.exploit_service = ExploitReferenceService()

    async def get_asset_context(self, asset_id: int) -> Dict[str, Any]:
        """Retrieve target asset profile and vulnerability statistics.
        
        Args:
            asset_id: Integer identifier of the target asset.
        """
        stmt = select(Asset).where(Asset.id == asset_id)
        result = await self.db.execute(stmt)
        asset = result.scalar_one_or_none()
        if not asset:
            return {"error": f"Asset {asset_id} not found."}

        # Query vulnerability aggregates
        vuln_stmt = select(Vulnerability).where(Vulnerability.asset_id == asset_id)
        vuln_res = await self.db.execute(vuln_stmt)
        vulns = vuln_res.scalars().all()

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "none": 0}
        threat_counts = {"ACTIVE-THREAT": 0, "ELEVATED": 0, "MODERATE": 0, "LOW": 0}
        kev_count = 0
        open_count = 0
        max_risk = 0.0

        for v in vulns:
            sev_key = (v.severity.value if hasattr(v.severity, "value") else str(v.severity)).lower()
            if sev_key in severity_counts:
                severity_counts[sev_key] += 1
            
            tl = (v.threat_level or "LOW").upper()
            if tl in threat_counts:
                threat_counts[tl] += 1
            else:
                threat_counts["LOW"] += 1

            if v.in_kev:
                kev_count += 1
            if v.status == VulnerabilityStatus.open:
                open_count += 1
            if v.risk_score and v.risk_score > max_risk:
                max_risk = float(v.risk_score)

        return {
            "asset_id": asset.id,
            "name": asset.name,
            "ip_address": asset.ip_address,
            "resolved_ip": asset.resolved_ip,
            "target_type": asset.target_type,
            "asset_type": asset.asset_type.value if hasattr(asset.asset_type, "value") else str(asset.asset_type),
            "environment": asset.environment.value if hasattr(asset.environment, "value") else str(asset.environment),
            "criticality": asset.criticality,
            "is_lab": getattr(asset, "is_lab", False),
            "total_vulnerabilities": len(vulns),
            "open_vulnerabilities": open_count,
            "severity_breakdown": severity_counts,
            "threat_level_breakdown": threat_counts,
            "kev_count": kev_count,
            "highest_risk_score": round(max_risk, 2),
        }

    async def get_scan_results(self, asset_id: int, limit: int = 5) -> Dict[str, Any]:
        """Fetch historical audit and vulnerability scan records for an asset.
        
        Args:
            asset_id: Target asset ID.
            limit: Maximum scan records to return (default 5).
        """
        stmt = (
            select(Scan)
            .where(Scan.asset_id == asset_id)
            .order_by(desc(Scan.started_at))
            .limit(limit)
        )
        result = await self.db.execute(stmt)
        scans = result.scalars().all()

        scan_items = []
        for s in scans:
            # count findings
            v_stmt = select(func.count(Vulnerability.id)).where(Vulnerability.scan_id == s.id)
            v_res = await self.db.execute(v_stmt)
            count = v_res.scalar() or 0

            scan_items.append({
                "scan_id": s.id,
                "scan_type": s.scan_type.value if hasattr(s.scan_type, "value") else str(s.scan_type),
                "status": s.status.value if hasattr(s.status, "value") else str(s.status),
                "started_at": s.started_at.isoformat() if s.started_at else None,
                "completed_at": s.completed_at.isoformat() if s.completed_at else None,
                "findings_count": count,
            })

        return {
            "asset_id": asset_id,
            "scans_count": len(scan_items),
            "scans": scan_items,
        }

    async def research_cve(self, cve_id: str) -> Dict[str, Any]:
        """Research a specific CVE identifier across NVD and AEGIS database telemetry.
        
        Args:
            cve_id: Standard CVE identifier (e.g. CVE-2021-44228).
        """
        clean_cve = (cve_id or "").strip().upper()
        stmt = select(Vulnerability).where(Vulnerability.cve_id == clean_cve).limit(5)
        res = await self.db.execute(stmt)
        db_vulns = res.scalars().all()

        title = "No database record"
        description = "No description available in local database."
        cvss_score = None
        severity = "none"
        threat_level = "LOW"
        in_kev = False
        epss_score = None
        affected = []

        if db_vulns:
            v0 = db_vulns[0]
            title = v0.title or title
            description = v0.description or description
            cvss_score = v0.cvss_score
            severity = v0.severity.value if hasattr(v0.severity, "value") else str(v0.severity)
            threat_level = v0.threat_level or "LOW"
            in_kev = bool(v0.in_kev)
            epss_score = v0.epss_score

            for v in db_vulns:
                affected.append({
                    "vuln_id": v.id,
                    "asset_id": v.asset_id,
                    "port": v.port,
                    "service": v.service or "unknown",
                    "status": v.status.value if hasattr(v.status, "value") else str(v.status),
                })

        # Augment with live KEV/EPSS if missing
        kev_info = service_check_kev(clean_cve)
        if kev_info.get("in_kev"):
            in_kev = True

        epss_info = await service_get_epss(clean_cve)

        return {
            "cve_id": clean_cve,
            "title": title,
            "description": description,
            "cvss_score": cvss_score,
            "severity": severity,
            "threat_level": threat_level,
            "in_kev": in_kev,
            "epss_score": epss_info.get("epss_score", epss_score),
            "epss_interpretation": epss_info.get("interpretation", "Unknown"),
            "affected_instances_count": len(affected),
            "instances": affected,
        }

    async def check_kev(self, cve_id: str) -> Dict[str, Any]:
        """Check if a CVE is actively tracked in the CISA Known Exploited Vulnerabilities catalog.
        
        Args:
            cve_id: CVE identifier (e.g. CVE-2022-26134).
        """
        clean_cve = (cve_id or "").strip().upper()
        res = service_check_kev(clean_cve)
        entry = res.get("entry") or {}
        return {
            "cve_id": clean_cve,
            "in_kev": res.get("in_kev", False),
            "vulnerability_name": entry.get("vulnerabilityName"),
            "date_added": entry.get("dateAdded"),
            "due_date": entry.get("dueDate"),
            "known_ransomware_campaign_use": entry.get("knownRansomwareCampaignUse"),
            "required_action": entry.get("requiredAction"),
        }

    async def get_epss(self, cve_id: str) -> Dict[str, Any]:
        """Retrieve FIRST EPSS exploitation probability score and percentile for a CVE.
        
        Args:
            cve_id: CVE identifier.
        """
        clean_cve = (cve_id or "").strip().upper()
        res = await service_get_epss(clean_cve)
        return {
            "cve_id": clean_cve,
            "epss_score": res.get("epss_score", 0.0),
            "percentile": res.get("percentile", 0.0),
            "interpretation": res.get("interpretation", "Unknown"),
        }

    async def find_public_exploit_refs(self, cve_id: str) -> Dict[str, Any]:
        """Retrieve documented public exploit references and PoC code links for a CVE.
        
        Args:
            cve_id: CVE identifier.
        """
        clean_cve = (cve_id or "").strip().upper()
        # Look in DB first
        stmt = select(Vulnerability).where(Vulnerability.cve_id == clean_cve).limit(1)
        res = await self.db.execute(stmt)
        v = res.scalar_one_or_none()

        if v and v.exploit_refs:
            refs = v.exploit_refs if isinstance(v.exploit_refs, list) else []
            has_exploit = any(r.get("type") in ["exploit-db", "metasploit-module", "github-poc"] for r in refs)
            return {
                "cve_id": clean_cve,
                "public_exploit_available": has_exploit,
                "references_count": len(refs),
                "references": refs,
            }

        live_res = await self.exploit_service.find_public_exploit_refs(clean_cve, fetch_nvd=False)
        return live_res

    async def get_top_vulnerabilities(self, asset_id: int, count: int = 10) -> Dict[str, Any]:
        """Fetch highest priority vulnerabilities for an asset ordered by risk score and threat level.
        
        Args:
            asset_id: Target asset ID.
            count: Number of vulnerabilities to retrieve (default 10).
        """
        stmt = (
            select(Vulnerability)
            .where(Vulnerability.asset_id == asset_id)
            .order_by(
                desc(Vulnerability.risk_score).nullslast(),
                desc(Vulnerability.cvss_score).nullslast(),
            )
            .limit(count)
        )
        result = await self.db.execute(stmt)
        vulns = result.scalars().all()

        items = []
        for v in vulns:
            items.append({
                "id": v.id,
                "cve_id": v.cve_id,
                "title": v.title,
                "severity": v.severity.value if hasattr(v.severity, "value") else str(v.severity),
                "threat_level": v.threat_level or "LOW",
                "in_kev": bool(v.in_kev),
                "epss_score": v.epss_score,
                "risk_score": float(v.risk_score) if v.risk_score else None,
                "cvss_score": float(v.cvss_score) if v.cvss_score else None,
                "port": v.port,
                "service_name": v.service or "unknown",
                "status": v.status.value if hasattr(v.status, "value") else str(v.status),
            })

        return {
            "asset_id": asset_id,
            "returned_count": len(items),
            "vulnerabilities": items,
        }

    async def suggest_next_steps(self, asset_id: int) -> Dict[str, Any]:
        """Generate a prioritized, defensive assessment and remediation checklist for an asset.
        
        Args:
            asset_id: Target asset ID.
        """
        # Fetch asset
        stmt = select(Asset).where(Asset.id == asset_id)
        res = await self.db.execute(stmt)
        asset = res.scalar_one_or_none()
        if not asset:
            return {"error": f"Asset {asset_id} not found."}

        # Fetch vulns
        vuln_stmt = (
            select(Vulnerability)
            .where(Vulnerability.asset_id == asset_id)
            .order_by(
                desc(Vulnerability.in_kev),
                desc(Vulnerability.risk_score).nullslast(),
            )
        )
        vuln_res = await self.db.execute(vuln_stmt)
        vulns = vuln_res.scalars().all()

        priorities = []
        priority_idx = 1

        # 1. KEV items
        kev_items = [v for v in vulns if v.in_kev and v.status == VulnerabilityStatus.open]
        for k in kev_items[:3]:
            priorities.append({
                "priority": priority_idx,
                "phase": "Immediate Patching (Active Exploit)",
                "cve_id": k.cve_id,
                "action": f"Apply vendor patch or emergency mitigation for {k.title or k.cve_id} on port {k.port} ({k.service or 'http'}).",
                "rationale": f"Listed in CISA Known Exploited Vulnerabilities catalog (EPSS: {round(k.epss_score*100, 1) if k.epss_score else 'N/A'}%). Actively weaponized in the wild.",
            })
            priority_idx += 1

        # 2. High EPSS / ACTIVE-THREAT non-KEV
        elevated_items = [
            v for v in vulns
            if not v.in_kev and v.threat_level in ["ACTIVE-THREAT", "ELEVATED"] and v.status == VulnerabilityStatus.open
        ]
        for e in elevated_items[:2]:
            priorities.append({
                "priority": priority_idx,
                "phase": "High Probability Defense",
                "cve_id": e.cve_id,
                "action": f"Restrict network access to port {e.port} and verify software patch availability for {e.title or e.cve_id}.",
                "rationale": f"Categorized as {e.threat_level} with elevated threat telemetry and public exploit references.",
            })
            priority_idx += 1

        # 3. Critical/High Risk findings
        other_critical = [
            v for v in vulns
            if v not in kev_items and v not in elevated_items
            and (v.severity.value if hasattr(v.severity, "value") else str(v.severity)) in ["critical", "high"]
            and v.status == VulnerabilityStatus.open
        ]
        for c in other_critical[:2]:
            priorities.append({
                "priority": priority_idx,
                "phase": "System Hardening & Configuration",
                "cve_id": c.cve_id,
                "action": f"Evaluate exploitability and schedule maintenance window to patch {c.cve_id} (Risk: {c.risk_score}).",
                "rationale": f"High severity finding (CVSS {c.cvss_score}) exposed on target perimeter.",
            })
            priority_idx += 1

        if not priorities:
            priorities.append({
                "priority": 1,
                "phase": "Routine Maintenance",
                "cve_id": None,
                "action": f"No open critical or actively exploited vulnerabilities identified on {asset.name}.",
                "rationale": "Target infrastructure demonstrates clean posture or low-severity residual findings.",
            })

        return {
            "asset_id": asset_id,
            "asset_name": asset.name,
            "target_ip": asset.ip_address,
            "total_open_findings": len([v for v in vulns if v.status == VulnerabilityStatus.open]),
            "prioritized_checklist": priorities,
        }
