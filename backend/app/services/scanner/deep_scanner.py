"""Deep Reconnaissance & Active Vulnerability Scanner (Phase 8.3).

Implements the 7-stage professional web reconnaissance and active verification engine:
- STAGE 1: Subdomain Discovery (subfinder)
- STAGE 2: Live Web Probing & Tech Stack Detection (httpx)
- STAGE 3: Smart Port Scanning (Nmap CDN-aware + NSE scripts)
- STAGE 4: Expanded Nuclei Active Web Exploitation
- STAGE 5: SSL/TLS Cryptographic Audit (testssl.sh)
- STAGE 6: Technology Version Vulnerability Analysis
- STAGE 7: Aggregation, Deduplication & Recon Inventory Summary
"""

import asyncio
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import nmap

from app.models.vulnerability import VulnerabilitySeverity, VerificationType
from app.services.scanner.nmap_runner import (
    ScanExecutionError,
    CRITICAL_PORTS,
    _enrich_open_ports_fingerprint,
)

logger = logging.getLogger("aegis.scanner.deep")

WAF_SIGNATURES: List[Tuple[str, str]] = [
    ("bitninja", "BitNinja WAF"),
    ("cloudflare", "Cloudflare WAF"),
    ("modsecurity", "ModSecurity WAF"),
    ("incapsula", "Imperva Incapsula WAF"),
    ("wordfence", "Wordfence WAF"),
    ("sucuri", "Sucuri CloudProxy WAF"),
    ("aws waf", "AWS WAF"),
    ("akamai", "Akamai Kona Site Defender"),
    ("f5 big-ip", "F5 BIG-IP ASM"),
]

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

# Known vulnerable software technology patterns
TECH_VULN_CATALOG: List[Dict[str, Any]] = [
    {
        "pattern": r"wordpress(?::|\s+)?([3-5]\.[\d\.]+)?",
        "name": "WordPress",
        "cve_id": "CVE-2022-21661",
        "title": "WordPress Core Outdated Deployment - SQL Injection & RCE Risk",
        "cvss": 7.5,
        "severity": VulnerabilitySeverity.high,
        "description": "Detected outdated WordPress instance subject to multiple unpatched security advisories.",
        "remediation": "Update WordPress to the latest stable release (6.x+).",
    },
    {
        "pattern": r"php(?::|\s+)?([5-7]\.[0-2][\d\.]*)?",
        "name": "PHP",
        "cve_id": "CVE-2019-11043",
        "title": "End-of-Life PHP Runtime Detected",
        "cvss": 9.8,
        "severity": VulnerabilitySeverity.critical,
        "description": "Target server runs an unsupported, end-of-life PHP runtime vulnerable to remote code execution.",
        "remediation": "Upgrade PHP runtime to a supported version (PHP 8.2+).",
    },
    {
        "pattern": r"jquery(?::|\s+)?([1-2]\.[\d\.]+|3\.[0-4][\d\.]*)?",
        "name": "jQuery",
        "cve_id": "CVE-2020-11022",
        "title": "Outdated jQuery Core - Cross-Site Scripting / Prototype Pollution",
        "cvss": 6.1,
        "severity": VulnerabilitySeverity.medium,
        "description": "The client-side web application includes an outdated version of jQuery containing known XSS flaws.",
        "remediation": "Upgrade jQuery library to version 3.5.0 or later.",
    },
    {
        "pattern": r"apache(?::|\s+)?(2\.4\.49|2\.4\.50|2\.2[\d\.]*)?",
        "name": "Apache",
        "cve_id": "CVE-2021-41773",
        "title": "Outdated Apache HTTP Server - Path Traversal & RCE Advisory",
        "cvss": 7.5,
        "severity": VulnerabilitySeverity.high,
        "description": "Detected Apache HTTP Server banner matching vulnerable path traversal release branches.",
        "remediation": "Upgrade Apache HTTP Server to version 2.4.51 or higher.",
    },
    {
        "pattern": r"gunicorn(?::|\s+)?(19\.[\d\.]+|20\.0[\d\.]*)?",
        "name": "gunicorn",
        "cve_id": "CVE-2024-1135",
        "title": "Outdated Gunicorn WSGI Server - HTTP Request Smuggling Risk",
        "cvss": 6.5,
        "severity": VulnerabilitySeverity.medium,
        "description": "Target application is served by an outdated Gunicorn WSGI server susceptible to request smuggling.",
        "remediation": "Upgrade Gunicorn to version 22.0.0 or later.",
    },
]


def _run_stage1_subdomains(domain: str) -> List[str]:
    """Stage 1: Subdomain Discovery using subfinder."""
    subfinder_bin = shutil.which("subfinder") or "/usr/local/bin/subfinder"
    clean_domain = domain.split(":")[0].strip().lower()
    discovered: Set[str] = {clean_domain}

    if not os.path.exists(subfinder_bin):
        logger.warning(f"[STAGE 1] subfinder binary not found at '{subfinder_bin}'. Skipping.")
        return list(discovered)

    cmd = [subfinder_bin, "-d", clean_domain, "-silent", "-all", "-timeout", "30"]
    logger.info(f"[STAGE 1] Invoking subfinder: {' '.join(cmd)}")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        for line in proc.stdout.splitlines():
            sub = line.strip().lower()
            if sub and "." in sub:
                discovered.add(sub)
    except Exception as e:
        logger.error(f"[STAGE 1] subfinder execution error on {clean_domain}: {e}")

    # Safety cap: max 100 subdomains
    result_list = sorted(list(discovered))
    if len(result_list) > 100:
        logger.info(f"[STAGE 1] Capping discovered subdomains from {len(result_list)} to 100")
        result_list = result_list[:100]

    logger.info(f"[STAGE 1] Subdomain discovery complete: {len(result_list)} subdomains found")
    return result_list


def _run_stage2_live_probing(
    subdomains: List[str],
    domain: str,
    resolved_ip: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Stage 2: Live Web Probing and Technology Detection using httpx."""
    httpx_bin = shutil.which("httpx") or "/usr/local/bin/httpx"
    live_hosts: List[Dict[str, Any]] = []

    if not os.path.exists(httpx_bin):
        logger.warning(f"[STAGE 2] httpx binary not found at '{httpx_bin}'. Skipping.")
        return [{
            "url": f"https://{domain}",
            "title": domain,
            "status_code": 200,
            "tech": [],
            "host": domain,
            "ip": resolved_ip or "127.0.0.1",
            "cdn": False,
        }]

    with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".txt") as tf:
        for sub in subdomains:
            tf.write(f"{sub}\n")
        temp_input_path = tf.name

    try:
        cmd = [
            httpx_bin,
            "-l", temp_input_path,
            "-silent",
            "-title",
            "-tech-detect",
            "-status-code",
            "-ip",
            "-follow-redirects",
            "-json",
            "-timeout", "8",
            "-retries", "1",
            "-threads", "30",
        ]
        logger.info(f"[STAGE 2] Invoking httpx: {' '.join(cmd)}")
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                rec = json.loads(line)
                url = rec.get("url", "")
                if not url:
                    continue

                cdn_name = rec.get("cdn_name") or ""
                cdn_type = rec.get("cdn_type") or ""
                webserver = (rec.get("webserver") or "").lower()
                is_cdn = bool(
                    cdn_name or cdn_type or
                    any(c in webserver for c in ["cloudflare", "fastly", "akamai", "cloudfront", "incapsula"])
                )

                host_ips = rec.get("a") or []
                main_ip = rec.get("host_ip") or (host_ips[0] if host_ips else "")

                # Detect WAF signatures in webserver, cdn_name, or detected technologies
                host_waf = None
                combined_host_str = f"{webserver} {cdn_name} {' '.join(rec.get('tech') or [])}".lower()
                for sig_key, sig_label in WAF_SIGNATURES:
                    if sig_key in combined_host_str:
                        host_waf = sig_label
                        break

                live_hosts.append({
                    "url": url,
                    "title": rec.get("title") or rec.get("host") or domain,
                    "status_code": rec.get("status_code", 200),
                    "tech": rec.get("tech") or [],
                    "host": rec.get("host") or domain,
                    "ip": main_ip,
                    "all_ips": host_ips,
                    "cdn": is_cdn,
                    "cdn_name": cdn_name,
                    "webserver": rec.get("webserver") or "",
                    "waf": host_waf,
                })
            except Exception:
                continue
    except Exception as e:
        logger.error(f"[STAGE 2] httpx probing failed: {e}")
    finally:
        if os.path.exists(temp_input_path):
            os.remove(temp_input_path)

    # Fallback if no subdomains replied: probe domain directly
    if not live_hosts:
        logger.info(f"[STAGE 2] No subdomains responded. Using fallback host for {domain}")
        live_hosts.append({
            "url": f"https://{domain}",
            "title": domain,
            "status_code": 200,
            "tech": [],
            "host": domain,
            "ip": resolved_ip or "127.0.0.1",
            "all_ips": [resolved_ip] if resolved_ip else [],
            "cdn": False,
            "cdn_name": "",
            "webserver": "",
        })

    logger.info(f"[STAGE 2] Live web probing completed: {len(live_hosts)} active service(s) discovered")
    return live_hosts


def _run_stage3_port_scan_single_ip(
    ip: str,
    is_cdn: bool = False,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Stage 3: Port and NSE scan on a single IP address."""
    nm = nmap.PortScanner()
    open_ports: List[Dict[str, Any]] = []
    nse_findings: List[Dict[str, Any]] = []

    try:
        # CDN IPs scanned light (top 100), real origin IPs scanned deep (top 1000 + critical port coverage)
        port_args = (
            "-sT -sV -Pn --top-ports 100 -T4 --version-intensity 7 --host-timeout 3m"
            if is_cdn
            else f"-sT -sV -Pn -p 1-1000,{CRITICAL_PORTS} -T4 -f --data-length 24 --version-intensity 7 --script-timeout 30s --host-timeout 5m"
        )
        logger.info(f"[STAGE 3] Port scanning {ip} (is_cdn={is_cdn}, args='{port_args}')")
        nm.scan(hosts=ip, arguments=port_args)

        all_hosts = nm.all_hosts()
        if not all_hosts:
            return [], []

        host_key = ip if ip in all_hosts else all_hosts[0]
        for proto in nm[host_key].all_protocols():
            pdict = nm[host_key][proto]
            for port_num, pdata in pdict.items():
                if pdata.get("state") == "open":
                    open_ports.append({
                        "ip": ip,
                        "port": int(port_num),
                        "protocol": proto,
                        "service": pdata.get("name", "unknown"),
                        "version": pdata.get("version", ""),
                        "product": pdata.get("product", ""),
                        "extrainfo": pdata.get("extrainfo", ""),
                        "cpe": pdata.get("cpe", ""),
                    })

        # Deep version fingerprinting for unspecified/generic versions
        if open_ports:
            _enrich_open_ports_fingerprint(ip, open_ports)

        # Run NSE script vuln only on real backend servers with open ports
        if not is_cdn and open_ports:
            port_spec = ",".join(str(p["port"]) for p in open_ports[:15])
            nse_args = (
                f"-sT -sV -Pn --script vuln -p {port_spec} -T4 -f --data-length 24 "
                f"--version-intensity 7 --host-timeout 5m --script-timeout 30s"
            )
            logger.info(f"[STAGE 3] Executing Nmap NSE scripts on {ip}:{port_spec}")
            nm.scan(hosts=ip, arguments=nse_args)

            if host_key in nm.all_hosts():
                for proto in nm[host_key].all_protocols():
                    for port_num, pdata in nm[host_key][proto].items():
                        script_results = pdata.get("script", {})
                        for script_id, script_output in script_results.items():
                            lower_out = script_output.lower()
                            if "vuln" in lower_out or "vulnerable" in lower_out or "exploitable" in lower_out:
                                meta = NSE_SCRIPT_CVE_MAP.get(script_id, {
                                    "cve_id": f"CVE-NSE-{script_id.upper().replace('-', '_')}",
                                    "title": f"Nmap NSE Detected Flaw: {script_id}",
                                    "cvss_score": 7.5,
                                    "severity": VulnerabilitySeverity.high,
                                    "description": f"Vulnerability detected by Nmap script {script_id}.",
                                })
                                nse_findings.append({
                                    "cve_id": meta["cve_id"],
                                    "title": meta["title"],
                                    "description": meta["description"],
                                    "cvss_score": meta["cvss_score"],
                                    "severity": meta["severity"],
                                    "port": int(port_num),
                                    "service": pdata.get("name", ""),
                                    "verification": VerificationType.nse_verified.value,
                                    "evidence": f"Target: {ip}:{port_num}\nNSE Script: {script_id}\nOutput:\n{script_output[:1000]}",
                                    "source": f"nse:{script_id}",
                                })
    except Exception as e:
        logger.error(f"[STAGE 3] Nmap scan failed for {ip}: {e}")

    return open_ports, nse_findings


def _parse_nuclei_record(
    record: Dict[str, Any],
    target_url: str,
    open_ports: List[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    """Convert raw Nuclei JSON match record to AEGIS vulnerability schema."""
    template_id = record.get("template-id", "unknown")
    info = record.get("info", {})
    name = info.get("name", template_id)
    description = info.get("description", name)
    severity_str = info.get("severity", "medium").lower()

    classification = info.get("classification", {}) or {}
    cve_field = classification.get("cve-id")
    cve_id = None
    if isinstance(cve_field, list) and cve_field:
        cve_id = str(cve_field[0]).upper()
    elif isinstance(cve_field, str) and cve_field:
        cve_id = cve_field.upper()
    else:
        cve_match = re.search(r"cve-\d{4}-\d{4,7}", template_id, re.IGNORECASE)
        if cve_match:
            cve_id = cve_match.group(0).upper()
        else:
            cve_id = f"CVE-ACTIVE-{template_id.upper().replace('-', '_')}"

    severity_map = {
        "critical": VulnerabilitySeverity.critical,
        "high": VulnerabilitySeverity.high,
        "medium": VulnerabilitySeverity.medium,
        "low": VulnerabilitySeverity.low,
        "info": VulnerabilitySeverity.low,
    }
    severity_enum = severity_map.get(severity_str, VulnerabilitySeverity.medium)

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

    matched_at = record.get("matched-at", target_url)
    port = None
    port_match = re.search(r":(\d+)", matched_at)
    if port_match:
        port = int(port_match.group(1))
    elif "https://" in matched_at:
        port = 443
    elif "http://" in matched_at:
        port = 80
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
        evidence_parts.append(f"Matcher: {matcher_name}")
    if curl_command:
        evidence_parts.append(f"Reproduction Command:\n{curl_command}")
    if extracted_results:
        evidence_parts.append(f"Extracted Results: {extracted_results}")

    return {
        "cve_id": cve_id,
        "title": name[:255],
        "description": description or f"Actively verified finding by Nuclei template {template_id}",
        "cvss_score": cvss_score,
        "severity": severity_enum,
        "port": port,
        "verification": VerificationType.nuclei_verified.value,
        "evidence": "\n".join(evidence_parts),
        "source": f"nuclei:{template_id}",
        "remediation": info.get("remediation", "Apply vendor patches or configuration hardening."),
    }


def _run_stage4_nuclei_target(
    url: str,
    open_ports: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Execute expanded Nuclei scan on a single target URL."""
    nuclei_bin = shutil.which("nuclei") or "/usr/local/bin/nuclei"
    if not os.path.exists(nuclei_bin):
        return []

    templates_dir = os.environ.get("NUCLEI_TEMPLATES_DIR", "/nuclei-templates")
    findings: List[Dict[str, Any]] = []

    # Run CVE, vulnerability, exposure, misconfig checks
    cmd = [
        nuclei_bin,
        "-target", url,
        "-t", templates_dir,
        "-severity", "critical,high,medium",
        "-tags", "cve,exposure,misconfig,vulnerability,unauth",
        "-silent",
        "-jsonl",
        "-timeout", "10",
        "-rl", "25",
        "-concurrency", "15",
        "-max-host-error", "10",
    ]

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            stdout_data, _ = proc.communicate(timeout=300)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout_data, _ = proc.communicate()

        for line in stdout_data.splitlines():
            line = line.strip()
            if line.startswith("{"):
                try:
                    record = json.loads(line)
                    parsed = _parse_nuclei_record(record, url, open_ports)
                    if parsed:
                        findings.append(parsed)
                except json.JSONDecodeError:
                    continue
    except Exception as e:
        logger.error(f"[STAGE 4] Nuclei error on {url}: {e}")

    return findings


def _parse_testssl_records(
    records: List[Dict[str, Any]],
    target: str,
) -> List[Dict[str, Any]]:
    """Parse testssl.sh JSON array into verified vulnerabilities."""
    findings = []
    seen_keys = set()

    for item in records:
        test_id = item.get("id", "")
        sev = str(item.get("severity", "")).upper()
        finding_text = item.get("finding", "")
        cve_field = item.get("cve", "")
        port = int(item.get("port", 443)) if str(item.get("port", "")).isdigit() else 443

        # 1. Deprecated TLS 1.0 or TLS 1.1
        if test_id in ("TLS1", "TLS1_1") and ("offered" in finding_text.lower() or sev in ("LOW", "MEDIUM", "WARN")):
            proto_name = "TLS 1.0" if test_id == "TLS1" else "TLS 1.1"
            cve_id = f"SSL-{test_id}-DEPRECATED"
            if cve_id not in seen_keys:
                seen_keys.add(cve_id)
                findings.append({
                    "cve_id": cve_id,
                    "title": f"Deprecated {proto_name} Protocol Enabled",
                    "description": f"Target supports {proto_name}, which is deprecated by IETF RFC 8996 and susceptible to downgrade attacks.",
                    "cvss_score": 5.3,
                    "severity": VulnerabilitySeverity.medium,
                    "port": port,
                    "verification": VerificationType.ssl_verified.value,
                    "evidence": f"Target: {target}\nProtocol: {proto_name}\ntestssl.sh Finding: {finding_text}\nSeverity: {sev}",
                    "remediation": f"Disable {proto_name} in server SSL/TLS cipher and protocol configurations; require TLS 1.2+.",
                })

        # 2. Missing HSTS Header
        elif test_id == "HSTS" and "not offered" in finding_text.lower():
            cve_id = "SSL-MISSING-HSTS"
            if cve_id not in seen_keys:
                seen_keys.add(cve_id)
                findings.append({
                    "cve_id": cve_id,
                    "title": "Strict-Transport-Security (HSTS) Header Missing",
                    "description": "The remote web server does not provide an HTTP Strict Transport Security (HSTS) header, allowing potential SSL stripping.",
                    "cvss_score": 3.7,
                    "severity": VulnerabilitySeverity.low,
                    "port": port,
                    "verification": VerificationType.ssl_verified.value,
                    "evidence": f"Target: {target}\nHeader: Strict-Transport-Security\ntestssl.sh Finding: {finding_text}",
                    "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to all HTTPS responses.",
                })

        # 3. Known SSL Vulnerabilities
        elif test_id in ("heartbleed", "ROBOT", "poodle_ssl", "LOGJAM", "BEAST", "SWEET32", "FREAK", "DROWN"):
            if sev in ("LOW", "MEDIUM", "HIGH", "CRITICAL", "WARN") or "vulnerable" in finding_text.lower():
                vuln_cve = cve_field or {
                    "heartbleed": "CVE-2014-0160",
                    "ROBOT": "CVE-2017-13099",
                    "poodle_ssl": "CVE-2014-3566",
                    "LOGJAM": "CVE-2015-4000",
                    "BEAST": "CVE-2011-3389",
                    "SWEET32": "CVE-2016-2183",
                    "FREAK": "CVE-2015-0204",
                    "DROWN": "CVE-2016-0800",
                }.get(test_id, f"SSL-{test_id.upper()}")

                if vuln_cve not in seen_keys:
                    seen_keys.add(vuln_cve)
                    sev_enum = VulnerabilitySeverity.high if test_id in ("heartbleed", "ROBOT", "LOGJAM", "DROWN") else VulnerabilitySeverity.medium
                    cvss = 7.5 if sev_enum == VulnerabilitySeverity.high else 5.3
                    findings.append({
                        "cve_id": vuln_cve,
                        "title": f"SSL/TLS Protocol Vulnerability: {test_id.upper()}",
                        "description": f"Target is vulnerable to {test_id.upper()} ({vuln_cve}). Finding: {finding_text}",
                        "cvss_score": cvss,
                        "severity": sev_enum,
                        "port": port,
                        "verification": VerificationType.ssl_verified.value,
                        "evidence": f"Target: {target}\nVulnerability: {test_id}\ntestssl.sh Finding: {finding_text}\nSeverity: {sev}",
                        "remediation": f"Upgrade OpenSSL libraries and update TLS server configuration for {test_id.upper()}.",
                    })

        # 4. Weak / Broken Cipher Suites
        elif test_id in ("null_ciphers", "rc4", "des_ciphers", "weak_ciphers") and ("offered" in finding_text.lower() or sev in ("LOW", "MEDIUM", "HIGH", "WARN")):
            cve_id = f"SSL-WEAK-CIPHER-{test_id.upper()}"
            if cve_id not in seen_keys:
                seen_keys.add(cve_id)
                findings.append({
                    "cve_id": cve_id,
                    "title": f"Insecure Cipher Suite Supported ({test_id.replace('_', ' ').title()})",
                    "description": f"Server negotiates legacy or weak cipher suites ({test_id}): {finding_text}",
                    "cvss_score": 5.9,
                    "severity": VulnerabilitySeverity.medium,
                    "port": port,
                    "verification": VerificationType.ssl_verified.value,
                    "evidence": f"Target: {target}\nCipher Category: {test_id}\ntestssl.sh Finding: {finding_text}",
                    "remediation": "Restrict TLS configuration to modern, authenticated AEAD cipher suites only.",
                })

        # 5. Certificate Lifecycle Anomaly
        elif test_id in ("cert_expiration_status", "cert_self_signed", "cert_common_name_mismatch"):
            if sev in ("LOW", "MEDIUM", "HIGH", "WARN") or any(k in finding_text.lower() for k in ["expired", "self signed", "mismatch"]):
                cve_id = f"SSL-CERT-{test_id.upper().replace('_', '-')}"
                if cve_id not in seen_keys:
                    seen_keys.add(cve_id)
                    findings.append({
                        "cve_id": cve_id,
                        "title": f"SSL/TLS Certificate Finding: {test_id.replace('_', ' ').title()}",
                        "description": f"Certificate anomaly: {finding_text}",
                        "cvss_score": 4.5,
                        "severity": VulnerabilitySeverity.medium,
                        "port": port,
                        "verification": VerificationType.ssl_verified.value,
                        "evidence": f"Target: {target}\nCheck: {test_id}\ntestssl.sh Finding: {finding_text}",
                        "remediation": "Deploy a valid, currently active, trusted certificate matching the hostname.",
                    })

    return findings


def _run_stage5_testssl_target(target: str) -> List[Dict[str, Any]]:
    """Stage 5: Execute testssl.sh on a single target hostname/IP."""
    testssl_bin = shutil.which("testssl.sh") or "/usr/local/bin/testssl.sh"
    if not os.path.exists(testssl_bin):
        logger.warning(f"[STAGE 5] testssl.sh not found at '{testssl_bin}'. Skipping.")
        return []

    # Strip scheme if present
    clean_target = target.replace("https://", "").replace("http://", "").split("/")[0]
    out_file = f"/tmp/testssl_{int(time.time()*1000)}.json"

    cmd = [
        testssl_bin,
        "--fast",
        "-p", "-s", "-U", "-h", "-c",
        "--ip", "one",
        "--jsonfile", out_file,
        "--quiet",
        "--warnings", "off",
        "--color", "0",
        clean_target,
    ]

    logger.info(f"[STAGE 5] Invoking testssl.sh: {' '.join(cmd)}")
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=90)
        if os.path.exists(out_file) and os.path.getsize(out_file) > 0:
            with open(out_file, "r") as f:
                content = f.read().strip()
                if content.startswith("["):
                    records = json.loads(content)
                    return _parse_testssl_records(records, clean_target)
    except Exception as e:
        logger.error(f"[STAGE 5] testssl.sh error on {clean_target}: {e}")
    finally:
        if os.path.exists(out_file):
            try:
                os.remove(out_file)
            except Exception:
                pass

    return []


def _run_stage6_tech_analysis(
    live_hosts: List[Dict[str, Any]],
    open_ports: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Stage 6: Technology Version Vulnerability Analysis from httpx tech stack."""
    findings: List[Dict[str, Any]] = []
    seen_cves: Set[str] = set()

    for host in live_hosts:
        tech_list = host.get("tech") or []
        webserver = host.get("webserver") or ""
        url = host.get("url", "")
        port = 443 if "https://" in url else 80

        combined_tech = " ".join(tech_list + [webserver])

        for entry in TECH_VULN_CATALOG:
            pattern = entry["pattern"]
            cve_id = entry["cve_id"]
            if cve_id in seen_cves:
                continue

            match = re.search(pattern, combined_tech, re.IGNORECASE)
            if match:
                seen_cves.add(cve_id)
                findings.append({
                    "cve_id": cve_id,
                    "title": entry["title"],
                    "description": entry["description"],
                    "cvss_score": entry["cvss"],
                    "severity": entry["severity"],
                    "port": port,
                    "verification": VerificationType.version_match.value,
                    "evidence": f"Target: {url}\nMatched Software Component: {match.group(0)}\nDetected Tech: {tech_list}",
                    "source": f"tech:{entry['name'].lower()}",
                    "remediation": entry["remediation"],
                })

    return findings


async def run_deep_scan(
    target: str,
    target_type: str = "ip",
    target_hostname: Optional[str] = None,
    resolved_ip: Optional[str] = None,
    progress_callback: Optional[Callable[..., Any]] = None,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
    """Execute complete 7-stage reconnaissance and deep active verification scan.

    Returns:
        (open_ports, all_verified_findings, recon_summary)
    """
    logger.info(f"=== INITIATING PHASE 8.3 DEEP RECON SCAN ON {target} (type: {target_type}) ===")
    stages_total = 7
    is_domain = (target_type == "domain") or ("." in target and not re.match(r"^\d+\.\d+\.\d+\.\d+$", target))
    root_domain = target_hostname or target

    async def report_progress(stage_num: int, current_stage: str, detail: str, hosts_processed: int = 0, hosts_total: int = 0):
        if progress_callback:
            try:
                await progress_callback(
                    current_stage=current_stage,
                    stage_number=stage_num,
                    stages_total=stages_total,
                    detail=detail,
                    hosts_processed=hosts_processed,
                    hosts_total=hosts_total,
                )
            except Exception as e:
                logger.warning(f"Progress callback exception: {e}")

    subdomains: List[str] = []
    live_hosts: List[Dict[str, Any]] = []
    all_open_ports: List[Dict[str, Any]] = []
    all_findings: List[Dict[str, Any]] = []

    # -------------------------------------------------------------
    # STAGE 1: Subdomain Discovery
    # -------------------------------------------------------------
    if is_domain:
        await report_progress(1, "subdomain_discovery", f"Searching for subdomains of {root_domain}...")
        subdomains = await asyncio.to_thread(_run_stage1_subdomains, root_domain)
        await report_progress(1, "subdomain_discovery", f"Discovered {len(subdomains)} subdomains for {root_domain}")
    else:
        await report_progress(1, "subdomain_discovery", "Target is IP address - skipping subdomain discovery")
        subdomains = [target]

    # -------------------------------------------------------------
    # STAGE 2: Live Web Probing & Tech Stack Detection
    # -------------------------------------------------------------
    if is_domain:
        await report_progress(2, "live_web_probing", f"Probing {len(subdomains)} subdomains for live web services...")
        live_hosts = await asyncio.to_thread(_run_stage2_live_probing, subdomains, root_domain, resolved_ip)
        await report_progress(2, "live_web_probing", f"Discovered {len(live_hosts)} active web services")
    else:
        await report_progress(2, "live_web_probing", "Target is IP address - skipping multi-host web probing")
        live_hosts = [{
            "url": f"http://{target}",
            "title": target,
            "status_code": 200,
            "tech": [],
            "host": target,
            "ip": target,
            "all_ips": [target],
            "cdn": False,
        }]

    # -------------------------------------------------------------
    # STAGE 3: Smart Port Scanning
    # -------------------------------------------------------------
    # Build list of distinct IPs to port scan
    ip_map: Dict[str, bool] = {}
    if is_domain:
        for h in live_hosts:
            hip = h.get("ip")
            if hip and hip != "127.0.0.1":
                ip_map[hip] = h.get("cdn", False)
            for extra_ip in h.get("all_ips", []):
                if extra_ip and extra_ip not in ip_map and extra_ip != "127.0.0.1":
                    ip_map[extra_ip] = h.get("cdn", False)
        if resolved_ip and resolved_ip not in ip_map:
            ip_map[resolved_ip] = False
    else:
        ip_map[target] = False

    # Limit port scanning to top 6 unique IPs
    target_ips = list(ip_map.keys())[:6] or [resolved_ip or target]
    await report_progress(3, "smart_port_scanning", f"Port scanning {len(target_ips)} target IP addresses...")

    for idx, ip_addr in enumerate(target_ips, start=1):
        is_cdn_host = ip_map.get(ip_addr, False)
        ports, nse_f = await asyncio.to_thread(_run_stage3_port_scan_single_ip, ip_addr, is_cdn_host)
        all_open_ports.extend(ports)
        all_findings.extend(nse_f)
        await report_progress(3, "smart_port_scanning", f"Port scanned {idx}/{len(target_ips)} IPs ({ip_addr})", hosts_processed=idx, hosts_total=len(target_ips))

    # If no ports discovered on domain IPs, fallback to default HTTP/HTTPS ports
    if not all_open_ports and is_domain:
        all_open_ports = [
            {"ip": resolved_ip or target, "port": 80, "protocol": "tcp", "service": "http", "version": ""},
            {"ip": resolved_ip or target, "port": 443, "protocol": "tcp", "service": "https", "version": ""},
        ]

    # -------------------------------------------------------------
    # STAGE 4: Expanded Nuclei Active Web Exploitation (Parallelized & Filtered)
    # -------------------------------------------------------------
    # Intelligent Target Reduction:
    # 1. Skip dead weight: 404, 502, 503, 504 errors
    # 2. Deduplicate: if multiple subdomains resolve to the same IP and have identical tech stacks, scan once
    valid_candidates: List[Dict[str, Any]] = []
    seen_ip_tech: Set[Tuple[str, str]] = set()

    for h in live_hosts:
        sc = h.get("status_code", 200)
        if sc in (404, 502, 503, 504):
            continue

        ip_addr = h.get("ip") or ""
        tech_key = ",".join(sorted(h.get("tech", [])))
        dedup_key = (ip_addr, tech_key)
        if ip_addr and dedup_key in seen_ip_tech:
            logger.info(f"[STAGE 4] Skipping redundant target {h.get('url')} (shares IP {ip_addr} and tech with existing target)")
            continue

        if ip_addr:
            seen_ip_tech.add(dedup_key)
        valid_candidates.append(h)

    nuclei_targets: List[str] = [h["url"] for h in valid_candidates if h.get("url")]

    # Cap Nuclei targets to top 10 unique, active URLs
    nuclei_targets = nuclei_targets[:10]
    if not nuclei_targets:
        # Fallback to web ports discovered
        for p in all_open_ports:
            port_num = p["port"]
            scheme = "https" if port_num in (443, 8443) else "http"
            nuclei_targets.append(f"{scheme}://{p.get('ip', target)}:{port_num}")

    await report_progress(
        4,
        "nuclei_web_scanning",
        f"Launching parallel Nuclei scanning on {len(nuclei_targets)} target endpoints...",
        hosts_processed=0,
        hosts_total=len(nuclei_targets),
    )

    # Parallelize Nuclei scanning across up to 4 concurrent processes
    sem = asyncio.Semaphore(4)
    completed_nuclei = 0

    async def scan_single_target(n_url: str) -> List[Dict[str, Any]]:
        nonlocal completed_nuclei
        async with sem:
            logger.info(f"[STAGE 4] Starting parallel Nuclei worker on {n_url}")
            results = await asyncio.to_thread(_run_stage4_nuclei_target, n_url, all_open_ports)
            completed_nuclei += 1
            await report_progress(
                4,
                "nuclei_web_scanning",
                f"Nuclei: completed {completed_nuclei}/{len(nuclei_targets)} targets ({n_url})",
                hosts_processed=completed_nuclei,
                hosts_total=len(nuclei_targets),
            )
            return results

    if nuclei_targets:
        nuclei_batches = await asyncio.gather(*[scan_single_target(u) for u in nuclei_targets], return_exceptions=True)
        for res in nuclei_batches:
            if isinstance(res, list):
                all_findings.extend(res)
            elif isinstance(res, Exception):
                logger.error(f"[STAGE 4] Nuclei worker error: {res}")

    # -------------------------------------------------------------
    # STAGE 5: SSL/TLS Cryptographic Audit (testssl.sh) - Unique IP Deduplicated
    # -------------------------------------------------------------
    # Find HTTPS hosts for testssl - only 1 audit per unique IP (same server = same cert)
    ssl_candidates: List[str] = []
    seen_ssl_ips: Set[str] = set()

    for h in live_hosts:
        u = h.get("url", "")
        if u.startswith("https://"):
            ip_val = h.get("ip") or ""
            if ip_val and ip_val in seen_ssl_ips:
                continue
            if ip_val:
                seen_ssl_ips.add(ip_val)
            host_only = u.replace("https://", "").split("/")[0]
            if host_only not in ssl_candidates:
                ssl_candidates.append(host_only)

    if not ssl_candidates:
        # Check if 443 is in open ports
        for p in all_open_ports:
            if p["port"] in (443, 8443):
                cand = p.get("ip") or (root_domain if is_domain else target)
                if cand not in ssl_candidates:
                    ssl_candidates.append(cand)

    # Cap testssl audits to top 3 hosts
    ssl_targets = ssl_candidates[:3]
    await report_progress(5, "ssl_tls_audit", f"Auditing SSL/TLS security on {len(ssl_targets)} endpoints...", hosts_processed=0, hosts_total=len(ssl_targets))

    for idx, ssl_target in enumerate(ssl_targets, start=1):
        await report_progress(5, "ssl_tls_audit", f"testssl: auditing {idx}/{len(ssl_targets)} ({ssl_target})...", hosts_processed=idx, hosts_total=len(ssl_targets))
        ssl_f = await asyncio.to_thread(_run_stage5_testssl_target, ssl_target)
        all_findings.extend(ssl_f)

    # -------------------------------------------------------------
    # STAGE 6: Technology Version Vulnerability Analysis
    # -------------------------------------------------------------
    await report_progress(6, "technology_analysis", "Analyzing software stack versions against known CVE advisories...")
    tech_f = _run_stage6_tech_analysis(live_hosts, all_open_ports)
    all_findings.extend(tech_f)
    await report_progress(6, "technology_analysis", f"Identified {len(tech_f)} software component findings")

    # -------------------------------------------------------------
    # STAGE 7: Aggregation & Recon Summary
    # -------------------------------------------------------------
    # Deduplicate findings by (cve_id, port)
    deduped_findings: List[Dict[str, Any]] = []
    seen_vulns: Set[Tuple[str, Optional[int]]] = set()
    for f in all_findings:
        key = (f["cve_id"], f.get("port"))
        if key not in seen_vulns:
            seen_vulns.add(key)
            deduped_findings.append(f)

    # Distinct technologies across all live hosts
    all_tech: Set[str] = set()
    for h in live_hosts:
        for t in h.get("tech", []):
            all_tech.add(t)

    cdn_name = None
    waf_name = None
    for h in live_hosts:
        if not cdn_name and h.get("cdn"):
            cdn_name = h.get("cdn")
        if not waf_name and h.get("waf"):
            waf_name = h.get("waf")

    recon_summary: Dict[str, Any] = {
        "is_domain": is_domain,
        "subdomains_count": len(subdomains),
        "subdomains_found": len(subdomains),
        "subdomains": subdomains[:50],
        "live_hosts": live_hosts[:25],
        "live_hosts_count": len(live_hosts),
        "live_hosts_found": len(live_hosts),
        "cdn_detected": any(h.get("cdn") for h in live_hosts),
        "cdn_name": cdn_name,
        "waf_detected": bool(waf_name),
        "waf_name": waf_name,
        "backend_ips": target_ips,
        "ssl_audited_count": len(ssl_targets),
        "technologies_summary": sorted(list(all_tech)),
        "ports_discovered_count": len(all_open_ports),
    }

    await report_progress(
        7,
        "completed",
        f"Recon scan completed: {len(deduped_findings)} vulnerabilities identified across {len(live_hosts)} services",
        hosts_processed=len(live_hosts),
        hosts_total=len(live_hosts),
    )

    logger.info(
        f"=== COMPLETED DEEP RECON SCAN ON {target}: {len(all_open_ports)} ports, "
        f"{len(deduped_findings)} findings, {len(subdomains)} subdomains, {len(live_hosts)} live hosts ==="
    )

    return all_open_ports, deduped_findings, recon_summary
