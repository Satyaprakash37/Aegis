"""Deep Vulnerability Scanner with Active Verification.

Implements the three-stage deep scan pipeline:
- Stage 1: Port and Service Discovery (Nmap top 500 ports)
- Stage 2: Nmap NSE Script Scanning (active vulnerability verification)
- Stage 3: Nuclei Dynamic Active Verification (web & protocol template checks)
"""

import asyncio
import json
import logging
import os
import re
import shutil
import subprocess
import time
from typing import Any, Dict, List, Optional, Set, Tuple
import nmap

from app.models.vulnerability import VulnerabilitySeverity, VerificationType
from app.services.scanner.nmap_runner import ScanExecutionError

logger = logging.getLogger("aegis.scanner.deep")

# Mapping of known NSE scripts to CVEs and titles
NSE_SCRIPT_CVE_MAP: Dict[str, Dict[str, Any]] = {
    "smb-vuln-ms17-010": {
        "cve_id": "CVE-2017-0144",
        "title": "EternalBlue SMBv1 Remote Code Execution",
        "cvss_score": 8.1,
        "severity": VulnerabilitySeverity.high,
        "description": "Remote code execution flaw in Microsoft SMBv1 protocol actively verified by NSE script.",
    },
    "ssl-heartbleed": {
        "cve_id": "CVE-2014-0160",
        "title": "Heartbleed OpenSSL TLS Information Disclosure",
        "cvss_score": 7.5,
        "severity": VulnerabilitySeverity.high,
        "description": "OpenSSL TLS heartbeat extension memory leakage flaw actively verified by NSE probe.",
    },
    "http-vuln-cve2021-44228": {
        "cve_id": "CVE-2021-44228",
        "title": "Log4Shell Apache Log4j2 JNDI Remote Code Execution",
        "cvss_score": 10.0,
        "severity": VulnerabilitySeverity.critical,
        "description": "Apache Log4j2 JNDI injection vulnerability actively verified via HTTP probe.",
    },
    "rdp-vuln-ms12-020": {
        "cve_id": "CVE-2012-0002",
        "title": "MS12-020 Windows Remote Desktop RCE / DoS",
        "cvss_score": 9.3,
        "severity": VulnerabilitySeverity.critical,
        "description": "Remote Desktop Protocol vulnerability actively verified by NSE script.",
    },
    "http-shellshock": {
        "cve_id": "CVE-2014-6271",
        "title": "Shellshock GNU Bash Environment Variable Injection RCE",
        "cvss_score": 9.8,
        "severity": VulnerabilitySeverity.critical,
        "description": "GNU Bash trailing function definition vulnerability actively confirmed.",
    },
    "ssl-ccs-injection": {
        "cve_id": "CVE-2014-0224",
        "title": "OpenSSL ChangeCipherSpec Man-in-the-Middle Injection",
        "cvss_score": 7.4,
        "severity": VulnerabilitySeverity.high,
        "description": "OpenSSL Early CCS handshake flaw actively verified by TLS handshake probe.",
    },
    "ftp-vsftpd-backdoor": {
        "cve_id": "CVE-2011-2523",
        "title": "vsftpd 2.3.4 Smiley Face Backdoor Command Execution",
        "cvss_score": 10.0,
        "severity": VulnerabilitySeverity.critical,
        "description": "Compromised vsftpd source archive backdoor triggered on port 6200.",
    },
}


def _run_stage1_ports(ip_address: str) -> List[Dict[str, Any]]:
    """Stage 1: Nmap Service Discovery (top 500 ports, -T4, -sV)."""
    logger.info(f"[STAGE 1] Running service discovery on {ip_address} (top 500 ports)")
    try:
        nm = nmap.PortScanner()
        args = "-sV --top-ports 500 -T4"
        nm.scan(hosts=ip_address, arguments=args)
    except Exception as e:
        logger.error(f"[STAGE 1] Nmap error on {ip_address}: {e}")
        raise ScanExecutionError(f"Stage 1 Nmap service scan failed: {e}")

    all_hosts = nm.all_hosts()
    if not all_hosts:
        raise ScanExecutionError(f"Target host {ip_address} is unreachable or offline")

    host_key = ip_address if ip_address in all_hosts else all_hosts[0]
    if nm[host_key].state() == "down":
        raise ScanExecutionError(f"Target host {ip_address} is down")

    open_ports = []
    for proto in nm[host_key].all_protocols():
        pdict = nm[host_key][proto]
        for port in sorted(pdict.keys()):
            pinfo = pdict[port]
            if pinfo.get("state") == "open":
                open_ports.append({
                    "port": int(port),
                    "protocol": proto,
                    "service": pinfo.get("name", "") or "",
                    "version": pinfo.get("version", "") or "",
                    "product": pinfo.get("product", "") or "",
                    "extrainfo": pinfo.get("extrainfo", "") or "",
                    "cpe": pinfo.get("cpe", "") or "",
                })
    logger.info(f"[STAGE 1] Discovery finished: {len(open_ports)} open port(s) on {ip_address}")
    return open_ports


def _run_stage2_nse(ip_address: str, open_ports: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Stage 2: Nmap NSE Vulnerability Scripts."""
    logger.info(f"[STAGE 2] Running active NSE vulnerability scripts on {ip_address}")
    if not open_ports:
        return []

    port_list = ",".join(str(p["port"]) for p in open_ports)
    args = f"-sV -p {port_list} --script vuln -T4 --script-timeout 30s"
    
    findings: List[Dict[str, Any]] = []
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=ip_address, arguments=args)
        host_key = ip_address if ip_address in nm.all_hosts() else (nm.all_hosts()[0] if nm.all_hosts() else None)
        if not host_key:
            return findings

        # Check hostscripts
        host_scripts = nm[host_key].get("hostscript", [])
        for script in host_scripts:
            s_name = script.get("id", "")
            s_output = script.get("output", "")
            _parse_nse_script_output(s_name, s_output, None, ip_address, findings)

        # Check port scripts
        for proto in nm[host_key].all_protocols():
            for port, pdata in nm[host_key][proto].items():
                p_scripts = pdata.get("script", {})
                for s_name, s_output in p_scripts.items():
                    _parse_nse_script_output(s_name, s_output, int(port), ip_address, findings)

    except Exception as e:
        logger.warning(f"[STAGE 2] NSE scan encountered non-fatal error: {e}")

    logger.info(f"[STAGE 2] NSE scripts verified {len(findings)} vulnerability finding(s)")
    return findings


def _parse_nse_script_output(
    script_name: str,
    output: str,
    port: Optional[int],
    ip_address: str,
    findings: List[Dict[str, Any]],
) -> None:
    """Evaluate if NSE script output indicates a positive vulnerability."""
    out_lower = output.lower()
    is_vuln = any(kw in out_lower for kw in ["vulnerable", "state: vulnerable", "infection confirmed", "exploit successful"])
    
    if not is_vuln and script_name not in NSE_SCRIPT_CVE_MAP:
        return

    # Check known mapping
    if script_name in NSE_SCRIPT_CVE_MAP and ("vulnerable" in out_lower or is_vuln):
        mapping = NSE_SCRIPT_CVE_MAP[script_name]
        findings.append({
            "cve_id": mapping["cve_id"],
            "title": mapping["title"],
            "description": mapping["description"],
            "cvss_score": mapping["cvss_score"],
            "severity": mapping["severity"],
            "port": port,
            "verification": VerificationType.nse_verified.value,
            "evidence": f"NSE Script: {script_name}\nTarget Port: {port or 'Host'}\nScript Output:\n{output}",
            "source": f"nse:{script_name}",
        })
        return

    # If generic vuln script output matches CVE-YYYY-NNNN and says VULNERABLE
    cve_matches = re.findall(r"CVE-\d{4}-\d{4,7}", output, re.IGNORECASE)
    if is_vuln and cve_matches:
        for cve in set(cve_matches):
            cve_clean = cve.upper()
            findings.append({
                "cve_id": cve_clean,
                "title": f"{cve_clean}: Verified via Nmap NSE script {script_name}",
                "description": f"NSE script '{script_name}' detected active vulnerability on {ip_address}:{port or 'host'}.",
                "cvss_score": 7.5,
                "severity": VulnerabilitySeverity.high,
                "port": port,
                "verification": VerificationType.nse_verified.value,
                "evidence": f"NSE Script: {script_name}\nTarget Port: {port or 'Host'}\nScript Output:\n{output}",
                "source": f"nse:{script_name}",
            })


def _run_stage3_nuclei(ip_address: str, open_ports: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Stage 3: Nuclei Active Dynamic Scanning with Real-Time Streaming."""
    logger.info(f"[STAGE 3] Running Nuclei active template verification against {ip_address}")
    
    nuclei_bin = shutil.which("nuclei") or "/usr/local/bin/nuclei"
    if not os.path.exists(nuclei_bin):
        logger.warning(f"[STAGE 3] Nuclei binary not found at '{nuclei_bin}'. Skipping Stage 3.")
        return []

    templates_dir = os.environ.get("NUCLEI_TEMPLATES_DIR", "/nuclei-templates")

    # Build targets prioritizing web ports discovered in Stage 1
    targets = []
    web_ports = set()
    for p in open_ports:
        port_num = p["port"]
        service = p.get("service", "").lower()
        if port_num in (80, 443, 3000, 3001, 8000, 8080, 8443, 9000, 5000, 8081) or "http" in service or "web" in service or "ppp" in service:
            scheme = "https" if port_num in (443, 8443) or "ssl" in service else "http"
            targets.append(f"{scheme}://{ip_address}:{port_num}")
            web_ports.add(port_num)

    if not targets:
        targets.append(ip_address)

    findings: List[Dict[str, Any]] = []

    for target in targets:
        cmd = [
            nuclei_bin,
            "-t", templates_dir,
            "-target", target,
            "-silent",
            "-jsonl",
            "-timeout", "10",
            "-max-host-error", "30",
        ]

        logger.info(f"[STAGE 3] Invoking nuclei: {' '.join(cmd)}")
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            start_time = time.time()
            max_wait_seconds = 75

            while time.time() - start_time < max_wait_seconds:
                line = proc.stdout.readline()
                if line:
                    line = line.strip()
                    if line.startswith("{"):
                        try:
                            record = json.loads(line)
                            parsed = _parse_nuclei_record(record, target, open_ports)
                            if parsed:
                                findings.append(parsed)
                                logger.info(f"[STAGE 3] Nuclei actively verified: {parsed['title']} ({parsed['cve_id']})")
                        except json.JSONDecodeError:
                            continue
                elif proc.poll() is not None:
                    break
                else:
                    time.sleep(0.1)

            if proc.poll() is None:
                proc.terminate()
        except Exception as e:
            logger.error(f"[STAGE 3] Nuclei execution error on {target}: {e}")

    logger.info(f"[STAGE 3] Nuclei verified {len(findings)} active finding(s)")
    return findings


def _parse_nuclei_record(
    record: Dict[str, Any],
    target: str,
    open_ports: List[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    """Convert raw Nuclei JSON match record to AEGIS vulnerability schema."""
    template_id = record.get("template-id", "unknown")
    info = record.get("info", {})
    name = info.get("name", template_id)
    description = info.get("description", name)
    severity_str = info.get("severity", "medium").lower()

    # Classification & CVE
    classification = info.get("classification", {}) or {}
    cve_field = classification.get("cve-id")
    cve_id = None
    if isinstance(cve_field, list) and cve_field:
        cve_id = str(cve_field[0]).upper()
    elif isinstance(cve_field, str) and cve_field:
        cve_id = cve_field.upper()
    else:
        # Check template-id for CVE
        cve_match = re.search(r"cve-\d{4}-\d{4,7}", template_id, re.IGNORECASE)
        if cve_match:
            cve_id = cve_match.group(0).upper()
        else:
            cve_id = f"CVE-ACTIVE-{template_id.upper().replace('-', '_')}"

    # Severity mapping
    severity_map = {
        "critical": VulnerabilitySeverity.critical,
        "high": VulnerabilitySeverity.high,
        "medium": VulnerabilitySeverity.medium,
        "low": VulnerabilitySeverity.low,
        "info": VulnerabilitySeverity.low,
    }
    severity_enum = severity_map.get(severity_str, VulnerabilitySeverity.medium)

    # CVSS Score
    cvss_val = classification.get("cvss-score")
    if cvss_val is not None:
        try:
            cvss_score = float(cvss_val)
        except (ValueError, TypeError):
            cvss_score = 6.0
    else:
        default_cvss = {
            VulnerabilitySeverity.critical: 9.5,
            VulnerabilitySeverity.high: 8.0,
            VulnerabilitySeverity.medium: 5.5,
            VulnerabilitySeverity.low: 3.5,
        }
        cvss_score = default_cvss.get(severity_enum, 5.0)

    # Port extraction
    matched_at = record.get("matched-at", target)
    port = None
    port_match = re.search(r":(\d+)", matched_at)
    if port_match:
        port = int(port_match.group(1))
    elif open_ports:
        port = open_ports[0].get("port")

    curl_command = record.get("curl-command", "")
    extracted_results = record.get("extracted-results", [])
    matcher_name = record.get("matcher-name", "")

    evidence_parts = [
        f"Matched At: {matched_at}",
        f"Template ID: {template_id}",
    ]
    if matcher_name:
        evidence_parts.append(f"Matcher Name: {matcher_name}")
    if curl_command:
        evidence_parts.append(f"Reproducer Command:\n{curl_command}")
    if extracted_results:
        evidence_parts.append(f"Extracted Results: {extracted_results}")

    evidence = "\n".join(evidence_parts)

    return {
        "cve_id": cve_id,
        "title": name[:255],
        "description": description or f"Actively verified finding by Nuclei template {template_id}",
        "cvss_score": cvss_score,
        "severity": severity_enum,
        "port": port,
        "verification": VerificationType.nuclei_verified.value,
        "evidence": evidence,
        "source": f"nuclei:{template_id}",
    }


async def run_deep_scan(ip_address: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Execute all three deep scan stages asynchronously."""
    logger.info(f"Starting Phase 8 Deep Scan with Active Verification against {ip_address}")

    # STAGE 1: Port and Service Discovery
    open_ports = await asyncio.to_thread(_run_stage1_ports, ip_address)

    if not open_ports:
        return [], []

    # STAGE 2: Nmap NSE Script Scanning
    nse_findings = await asyncio.to_thread(_run_stage2_nse, ip_address, open_ports)

    # STAGE 3: Nuclei Active Dynamic Verification
    nuclei_findings = await asyncio.to_thread(_run_stage3_nuclei, ip_address, open_ports)

    all_verified = nse_findings + nuclei_findings
    logger.info(
        f"Deep Scan completed for {ip_address}: {len(open_ports)} ports, "
        f"{len(nse_findings)} NSE findings, {len(nuclei_findings)} Nuclei findings"
    )
    return open_ports, all_verified
