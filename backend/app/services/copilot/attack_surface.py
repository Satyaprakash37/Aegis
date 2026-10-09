"""AEGIS Attack Surface Intelligence Service.

Generates structured defensive attack surface profiling, exposed service mapping,
and verified attack path correlation narratives for target assets.
"""

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.asset import Asset
from app.models.scan import Scan, ScanStatus
from app.models.vulnerability import Vulnerability, VulnerabilitySeverity

logger = logging.getLogger("aegis.copilot.attack_surface")

ATTACK_SURFACE_SYSTEM_PROMPT = """You are AEGIS Copilot - a senior defensive security architect performing attack surface profiling and defensive vulnerability correlation analysis.
You analyze an asset's exposed perimeter, service posture, and vulnerabilities to produce high-fidelity, structured JSON risk assessments.

CRITICAL RULES:
1. Every CVE ID in 'findings_refs' and attack path chains MUST strictly be one of the provided Verified Asset CVE IDs. NEVER hallucinate or invent CVE identifiers.
2. Mark all attack path narratives as potential analytical risk chains (e.g., 'Potential initial access...'), NOT confirmed active breaches.
3. Return ONLY valid, raw JSON matching the required schema. No markdown backticks, no commentary outside JSON.

Required Schema:
{
  "executive_summary": "2-3 paragraph plain-language assessment of this target's security posture and risk exposure.",
  "attack_surface_map": {
    "entry_points": [
      {
        "type": "web|network|service|physical",
        "detail": "Description of entry point",
        "port_if_any": 80,
        "risk_level": "critical|high|medium|low"
      }
    ],
    "exposed_services": [
      {
        "service": "Service name",
        "port": 80,
        "version": "Version string or Unknown",
        "known_issues_count": 3
      }
    ],
    "trust_boundaries": "Description of network/context boundaries visible from telemetry"
  },
  "attack_paths": [
    {
      "title": "Descriptive chain title",
      "chain": [
        "Step 1 - Potential initial vector",
        "Step 2 - Potential pivoting or exploitation step",
        "Step 3 - Potential impact"
      ],
      "likelihood": "high|medium|low",
      "impact": "Affected systems or confidentiality/integrity consequences",
      "findings_refs": ["CVE-XXXX-YYYY"]
    }
  ],
  "prioritized_concerns": [
    {
      "rank": 1,
      "concern": "High-priority concern title",
      "why_now": "KEV/EPSS/Risk justification",
      "recommended_action": "Actionable defensive remediation"
    }
  ]
}
"""


async def generate_attack_surface_report(asset_id: int, db: AsyncSession) -> Dict[str, Any]:
    """Generate or regenerate the comprehensive Attack Surface Intelligence Report.
    
    Persists the structured report into Asset.attack_surface_report and updates
    Asset.report_generated_at.
    """
    # 1. Fetch Target Asset
    stmt = select(Asset).where(Asset.id == asset_id)
    res = await db.execute(stmt)
    asset = res.scalar_one_or_none()
    if not asset:
        raise ValueError(f"Asset with ID {asset_id} does not exist.")

    # 2. Fetch all vulnerabilities for this asset
    vuln_stmt = (
        select(Vulnerability)
        .where(Vulnerability.asset_id == asset_id)
        .order_by(
            Vulnerability.in_kev.desc(),
            Vulnerability.cvss_score.desc(),
            Vulnerability.epss_score.desc().nullslast(),
        )
    )
    vuln_res = await db.execute(vuln_stmt)
    vulns: List[Vulnerability] = vuln_res.scalars().all()

    # 3. Fetch recent scan metadata
    scan_stmt = (
        select(Scan)
        .where(Scan.asset_id == asset_id)
        .order_by(desc(Scan.id))
        .limit(3)
    )
    scan_res = await db.execute(scan_stmt)
    recent_scans: List[Scan] = scan_res.scalars().all()

    # 4. Handle Empty State Gracefully (Asset with NO findings)
    if not vulns:
        report = _build_clean_empty_report(asset, recent_scans)
        asset.attack_surface_report = report
        asset.report_generated_at = datetime.now(timezone.utc)
        await db.commit()
        await db.refresh(asset)
        return report

    # 5. Extract telemetry context & build allowed CVE pool
    allowed_cves = list({v.cve_id for v in vulns if v.cve_id})
    vuln_summaries = []
    service_map: Dict[str, Dict[str, Any]] = {}

    for v in vulns:
        port = v.port or 80
        srv = v.service or ("http" if port in (80, 443, 3000, 8000, 8080) else "service")
        ver = v.service_version or "Detected"
        srv_key = f"{srv}:{port}"

        if srv_key not in service_map:
            service_map[srv_key] = {
                "service": srv,
                "port": port,
                "version": ver,
                "known_issues_count": 0,
            }
        service_map[srv_key]["known_issues_count"] += 1

        vuln_summaries.append({
            "cve_id": v.cve_id,
            "title": v.title,
            "severity": v.severity.value if hasattr(v.severity, "value") else str(v.severity),
            "cvss_score": v.cvss_score,
            "threat_level": v.threat_level or "MODERATE",
            "in_kev": bool(v.in_kev),
            "epss_score": v.epss_score,
            "port": port,
            "service": srv,
            "remediation": v.remediation,
        })

    # 6. Attempt Gemini AI Generation if configured
    report = None
    api_key = (settings.GEMINI_API_KEY or "").strip()
    is_live_gemini = (
        api_key.startswith("AIza")
        and not api_key.startswith("mock")
        and not api_key.startswith("test")
    )

    if is_live_gemini:
        try:
            report = await _generate_with_gemini(asset, vuln_summaries, service_map, allowed_cves)
        except Exception as e:
            logger.warning("Gemini AI attack surface generation failed: %s. Falling back to defensive engine.", e)
            report = None

    # 7. Fallback to Deterministic Defensive Architect Engine if no AI report
    if not report:
        report = _build_deterministic_report(asset, vuln_summaries, service_map, allowed_cves)

    # 8. Sanitize & Verify: Guarantee all findings_refs strictly exist in allowed_cves
    report = _sanitize_and_verify_report(report, allowed_cves, vuln_summaries, service_map, asset)

    # 9. Store and persist report in asset
    asset.attack_surface_report = report
    asset.report_generated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(asset)

    logger.info("Generated attack surface intelligence report for asset #%s (%s)", asset.id, asset.name)
    return report


def _build_clean_empty_report(asset: Asset, recent_scans: List[Scan]) -> Dict[str, Any]:
    """Produce a structured empty-state intelligence report when no findings are detected."""
    env_str = asset.environment.value if hasattr(asset.environment, "value") else str(asset.environment)
    target_type_str = asset.target_type.value if hasattr(asset.target_type, "value") else str(asset.target_type)
    
    scans_note = f"{len(recent_scans)} completed audit scan(s)" if recent_scans else "no completed scans recorded"

    exec_summary = (
        f"Defensive attack surface assessment for target **{asset.name}** (`{asset.ip_address}`) indicates an intact "
        f"perimeter posture with **zero identified security vulnerabilities** currently cataloged in platform telemetry.\n\n"
        f"The asset is registered as a `{target_type_str}` in the `{env_str}` environment (Criticality: {asset.criticality}/5). "
        f"Historical monitoring reflects {scans_note}. Because no open service exposures or software vulnerabilities "
        f"are active, potential attack chains cannot be established from existing data.\n\n"
        f"Defenders should maintain proactive monitoring and schedule deep credentialed scans to ensure comprehensive coverage."
    )

    entry_points = [
        {
            "type": "network",
            "detail": f"Direct host reachability for {asset.ip_address} on {target_type_str} layer.",
            "port_if_any": None,
            "risk_level": "low",
        }
    ]

    return {
        "executive_summary": exec_summary,
        "attack_surface_map": {
            "entry_points": entry_points,
            "exposed_services": [],
            "trust_boundaries": f"Host perimeter boundary within {env_str} environment; no external services or unauthenticated endpoints cataloged.",
        },
        "attack_paths": [],
        "prioritized_concerns": [
            {
                "rank": 1,
                "concern": "Baseline Telemetry Verification",
                "why_now": "Zero vulnerabilities are cataloged for this target; baseline scanning depth should be re-validated.",
                "recommended_action": "Initiate an active deep scan to establish an authoritative software and service inventory.",
            }
        ],
    }


def _build_deterministic_report(
    asset: Asset,
    vuln_summaries: List[Dict[str, Any]],
    service_map: Dict[str, Dict[str, Any]],
    allowed_cves: List[str],
) -> Dict[str, Any]:
    """High-fidelity defensive architect analytical engine with strictly verified CVE correlation."""
    env_str = asset.environment.value if hasattr(asset.environment, "value") else str(asset.environment)
    total_vulns = len(vuln_summaries)
    kev_vulns = [v for v in vuln_summaries if v.get("in_kev")]
    critical_vulns = [v for v in vuln_summaries if v.get("severity") in ("critical", "high")]

    # 1. Executive Summary
    p1 = (
        f"Defensive attack surface analysis of **{asset.name}** (`{asset.ip_address}`) reveals an exposed operational profile "
        f"comprising **{total_vulns} cataloged vulnerabilities** across {len(service_map)} exposed network service(s). "
        f"The asset is classified as a `{env_str}` resource with criticality rating **{asset.criticality}/5**"
        f"{' (Isolated Attack Lab Target)' if asset.is_lab else ''}."
    )

    if kev_vulns:
        kev_cves_str = ", ".join(f"`{k['cve_id']}`" for k in kev_vulns[:3])
        p2 = (
            f"Of paramount concern is the presence of **{len(kev_vulns)} actively weaponized vulnerability** "
            f"listed in the **CISA Known Exploited Vulnerabilities (KEV)** catalog ({kev_cves_str}). "
            f"The leading threat vector exhibits an EPSS score of {round((kev_vulns[0].get('epss_score') or 0.0) * 100, 1)}%, "
            f"indicating substantiated threat actor exploitation activity in the wild."
        )
    elif critical_vulns:
        top_cve = critical_vulns[0]["cve_id"]
        p2 = (
            f"The asset presents **{len(critical_vulns)} elevated-severity security finding(s)**, headed by `{top_cve}` "
            f"(CVSS {critical_vulns[0]['cvss_score']}). While unlisted in active KEV catalogs, these findings provide viable "
            f"vectors for remote access, authorization circumvention, or denial-of-service."
        )
    else:
        p2 = (
            f"Observed weaknesses are primarily medium-to-low risk configuration issues or deprecated component versions. "
            f"No critical remote code execution vectors were verified, but existing flaws provide initial reconnaissance footholds."
        )

    p3 = (
        f"Defensive segmentation must focus on isolating exposed entry points on ports "
        f"{', '.join(str(s['port']) for s in service_map.values()) or '80'}. Prioritized remediation of active threat CVEs "
        f"is strongly recommended to disrupt correlated multi-stage exploit paths."
    )
    executive_summary = f"{p1}\n\n{p2}\n\n{p3}"

    # 2. Attack Surface Map
    entry_points = []
    for srv_key, srv_data in service_map.items():
        port = srv_data["port"]
        srv_name = srv_data["service"]
        
        # Determine risk level based on max severity on this port
        port_vulns = [v for v in vuln_summaries if v.get("port") == port]
        has_kev = any(v.get("in_kev") for v in port_vulns)
        has_crit = any(v.get("severity") in ("critical", "high") for v in port_vulns)

        if has_kev or has_crit:
            risk_level = "critical" if has_kev else "high"
        elif any(v.get("severity") == "medium" for v in port_vulns):
            risk_level = "medium"
        else:
            risk_level = "low"

        entry_type = "web" if port in (80, 443, 3000, 8000, 8080) or "http" in srv_name.lower() else "service"
        entry_points.append({
            "type": entry_type,
            "detail": f"{srv_name.upper()} endpoint exposed on TCP port {port} ({srv_data['version']}).",
            "port_if_any": port,
            "risk_level": risk_level,
        })

    exposed_services = list(service_map.values())

    if asset.is_lab:
        trust_boundaries = (
            f"Target resides on isolated lab network segment ({asset.ip_address}). Boundary filtering isolates production "
            f"assets, but unauthenticated HTTP ingress on port {exposed_services[0]['port'] if exposed_services else 80} "
            f"allows direct ingress from adjacent lab containers."
        )
    else:
        trust_boundaries = (
            f"Target host located at {asset.ip_address} within {env_str} perimeter. External traffic routes directly to "
            f"exposed listener endpoints without intermediate web application firewall inspection."
        )

    # 3. Attack Paths (Correlated Chains referencing ONLY verified CVEs)
    attack_paths = []

    # Path 1: Primary exploit chain (KEV / High Severity lead)
    primary_cve = kev_vulns[0] if kev_vulns else (critical_vulns[0] if critical_vulns else vuln_summaries[0])
    secondary_cve = None
    for v in vuln_summaries:
        if v["cve_id"] != primary_cve["cve_id"] and v["severity"] in ("high", "medium", "critical"):
            secondary_cve = v
            break

    if secondary_cve:
        # 2-step or 3-step chain
        chain_steps = [
            f"Step 1: Potential perimeter ingress and reconnaissance targeting {primary_cve['service']} on port {primary_cve['port']}.",
            f"Step 2: Potential exploitation of {primary_cve['cve_id']} ({primary_cve['title'][:80]}) to bypass controls or execute unprivileged routines.",
            f"Step 3: Potential secondary pivoting or privilege escalation via {secondary_cve['cve_id']} ({secondary_cve['title'][:80]}), compromising target services.",
        ]
        path_cves = [primary_cve["cve_id"], secondary_cve["cve_id"]]
    else:
        chain_steps = [
            f"Step 1: Potential network probe of exposed port {primary_cve['port']} ({primary_cve['service']}).",
            f"Step 2: Potential weaponization of {primary_cve['cve_id']} ({primary_cve['title'][:90]}) against vulnerable component.",
            f"Step 3: Potential unauthorized service disruption, configuration compromise, or execution under service privileges.",
        ]
        path_cves = [primary_cve["cve_id"]]

    path_likelihood = "high" if primary_cve.get("in_kev") or (primary_cve.get("epss_score") or 0) > 0.3 else "medium"
    attack_paths.append({
        "title": f"Potential Multi-Stage Exploitation via {primary_cve['service'].upper()} Endpoint",
        "chain": chain_steps,
        "likelihood": path_likelihood,
        "impact": "Potential compromise of exposed application tier, unprivileged process hijacking, or sensitive configuration exposure.",
        "findings_refs": path_cves,
    })

    # Path 2: Web Application / Lateral Foothold if more CVEs exist
    remaining_cves = [v for v in vuln_summaries if v["cve_id"] not in path_cves]
    if remaining_cves:
        web_pivot = remaining_cves[0]
        attack_paths.append({
            "title": f"Potential Service Impairment and Session Integrity Attack",
            "chain": [
                f"Step 1: Unauthenticated request dispatch to exposed {web_pivot['service']} endpoint on port {web_pivot['port']}.",
                f"Step 2: Potential trigger of {web_pivot['cve_id']} ({web_pivot['title'][:80]}), destabilizing validation logic or session boundaries.",
                f"Step 3: Potential persistent unauthorized state tampering or lateral service disruption.",
            ],
            "likelihood": "medium" if web_pivot.get("cvss_score", 0) >= 7.0 else "low",
            "impact": "Potential security boundary degradation, unauthorized request forgery, or service unavailability.",
            "findings_refs": [web_pivot["cve_id"]],
        })

    # 4. Prioritized Concerns (Ranked list)
    prioritized_concerns = []
    rank = 1
    for v in (kev_vulns + [x for x in critical_vulns if x not in kev_vulns] + vuln_summaries)[:4]:
        if any(p["concern"].startswith(v["cve_id"]) for p in prioritized_concerns):
            continue
        
        if v.get("in_kev"):
            why_now = f"Confirmed entry in CISA KEV catalog with active real-world weaponization (EPSS: {round((v.get('epss_score') or 0)*100, 1)}%)."
        elif v.get("cvss_score", 0) >= 7.0:
            why_now = f"High severity CVSS rating of {v['cvss_score']} on exposed network port {v['port']}."
        else:
            why_now = f"Elevated exposure score in operational {env_str} environment."

        action = v.get("remediation") or f"Upgrade {v['service']} or apply vendor security patches for {v['cve_id']} immediately."
        prioritized_concerns.append({
            "rank": rank,
            "concern": f"{v['cve_id']}: {v['title'][:65]}",
            "why_now": why_now,
            "recommended_action": action,
        })
        rank += 1

    return {
        "executive_summary": executive_summary,
        "attack_surface_map": {
            "entry_points": entry_points,
            "exposed_services": exposed_services,
            "trust_boundaries": trust_boundaries,
        },
        "attack_paths": attack_paths,
        "prioritized_concerns": prioritized_concerns,
    }


async def _generate_with_gemini(
    asset: Asset,
    vuln_summaries: List[Dict[str, Any]],
    service_map: Dict[str, Dict[str, Any]],
    allowed_cves: List[str],
) -> Optional[Dict[str, Any]]:
    """Invoke Gemini LLM with structured defensive prompt and strict JSON schema."""
    import asyncio
    import google.generativeai as genai

    genai.configure(api_key=settings.GEMINI_API_KEY.strip())
    model = genai.GenerativeModel(
        model_name="gemini-1.5-flash",
        system_instruction=ATTACK_SURFACE_SYSTEM_PROMPT,
    )

    user_prompt = (
        f"Analyze target asset '{asset.name}' (IP: {asset.ip_address}, Type: {asset.target_type}, Criticality: {asset.criticality}/5, Lab: {asset.is_lab}).\n"
        f"Verified Asset CVE IDs (You MUST ONLY reference these): {json.dumps(allowed_cves)}\n\n"
        f"Exposed Services: {json.dumps(list(service_map.values()))}\n\n"
        f"Asset Vulnerability Telemetry: {json.dumps(vuln_summaries[:15])}\n\n"
        f"Generate the comprehensive Attack Surface Intelligence Report strictly following the JSON schema."
    )

    response = await asyncio.wait_for(
        asyncio.to_thread(model.generate_content, user_prompt),
        timeout=25.0,
    )

    text = response.text.strip() if hasattr(response, "text") and response.text else ""
    if not text:
        return None

    # Strip code fences if returned
    if text.startswith("```json"):
        text = text[7:]
    if text.startswith("```"):
        text = text[3:]
    if text.endswith("```"):
        text = text[:-3]
    text = text.strip()

    parsed = json.loads(text)
    return parsed


def _sanitize_and_verify_report(
    report: Dict[str, Any],
    allowed_cves: List[str],
    vuln_summaries: List[Dict[str, Any]],
    service_map: Dict[str, Dict[str, Any]],
    asset: Asset,
) -> Dict[str, Any]:
    """Strictly verify that every findings_refs entry is in allowed_cves and structure is complete."""
    allowed_set = set(allowed_cves)

    # 1. Verify and sanitize attack_paths
    paths = report.get("attack_paths", [])
    sanitized_paths = []
    for p in paths:
        raw_refs = p.get("findings_refs", [])
        verified_refs = [ref for ref in raw_refs if ref in allowed_set]

        # If LLM omitted or invented refs, fall back to valid top CVEs
        if not verified_refs and allowed_cves:
            verified_refs = [allowed_cves[0]]

        sanitized_paths.append({
            "title": p.get("title", "Potential Attack Vector Chain"),
            "chain": p.get("chain", ["Step 1: Network probe", "Step 2: Potential vulnerability trigger"]),
            "likelihood": p.get("likelihood", "medium"),
            "impact": p.get("impact", "Potential service exposure"),
            "findings_refs": verified_refs,
        })

    report["attack_paths"] = sanitized_paths

    # 2. Ensure attack_surface_map format
    asm = report.get("attack_surface_map", {})
    if "entry_points" not in asm:
        asm["entry_points"] = []
    if "exposed_services" not in asm:
        asm["exposed_services"] = list(service_map.values())
    if "trust_boundaries" not in asm:
        asm["trust_boundaries"] = f"Network boundary for {asset.ip_address}."
    report["attack_surface_map"] = asm

    # 3. Ensure executive_summary and prioritized_concerns
    if "executive_summary" not in report or not report["executive_summary"]:
        report["executive_summary"] = f"Executive security posture summary for target {asset.name}."
    if "prioritized_concerns" not in report:
        report["prioritized_concerns"] = []

    return report
