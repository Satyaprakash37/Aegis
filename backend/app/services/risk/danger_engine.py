"""Danger Assessment Engine for AEGIS.

Computes exploitability, real-world business impact, and composite danger scores
for actively verified and version-matched vulnerabilities.
"""

from typing import Any, Dict, Optional, Tuple


KNOWN_EXPLOITS_DB: Dict[str, Dict[str, Any]] = {
    "CVE-2017-0144": {
        "has_metasploit": True,
        "has_public_exploit": True,
        "exploit_complexity": "low",
        "attack_vector": "network",
        "name": "EternalBlue SMBv1 Remote Code Execution",
    },
    "CVE-2014-6271": {
        "has_metasploit": True,
        "has_public_exploit": True,
        "exploit_complexity": "low",
        "attack_vector": "network",
        "name": "Shellshock Bash Environment Variable RCE",
    },
    "CVE-2019-0708": {
        "has_metasploit": True,
        "has_public_exploit": True,
        "exploit_complexity": "low",
        "attack_vector": "network",
        "name": "BlueKeep Windows RDP Pre-Auth RCE",
    },
    "CVE-2021-44228": {
        "has_metasploit": True,
        "has_public_exploit": True,
        "exploit_complexity": "low",
        "attack_vector": "network",
        "name": "Log4Shell Apache Log4j2 JNDI RCE",
    },
    "CVE-2012-0002": {
        "has_metasploit": True,
        "has_public_exploit": True,
        "exploit_complexity": "low",
        "attack_vector": "network",
        "name": "MS12-020 Windows Remote Desktop RCE",
    },
    "CVE-2014-0160": {
        "has_metasploit": True,
        "has_public_exploit": True,
        "exploit_complexity": "low",
        "attack_vector": "network",
        "name": "Heartbleed OpenSSL TLS Heartbeat Memory Disclosure",
    },
    "CVE-2020-1472": {
        "has_metasploit": True,
        "has_public_exploit": True,
        "exploit_complexity": "low",
        "attack_vector": "network",
        "name": "Zerologon Netlogon Cryptographic Flaw",
    },
    "CVE-2021-26855": {
        "has_metasploit": True,
        "has_public_exploit": True,
        "exploit_complexity": "low",
        "attack_vector": "network",
        "name": "ProxyLogon Microsoft Exchange SSRF/RCE",
    },
    "CVE-2023-4966": {
        "has_metasploit": True,
        "has_public_exploit": True,
        "exploit_complexity": "low",
        "attack_vector": "network",
        "name": "Citrix Bleed NetScaler Memory Leak Session Hijack",
    },
    "CVE-2022-22965": {
        "has_metasploit": True,
        "has_public_exploit": True,
        "exploit_complexity": "low",
        "attack_vector": "network",
        "name": "Spring4Shell Spring Framework DataBinder RCE",
    },
    "CVE-2023-34362": {
        "has_metasploit": True,
        "has_public_exploit": True,
        "exploit_complexity": "low",
        "attack_vector": "network",
        "name": "MOVEit Transfer SQL Injection & Remote Execution",
    },
    "CVE-2021-3156": {
        "has_metasploit": False,
        "has_public_exploit": True,
        "exploit_complexity": "medium",
        "attack_vector": "local",
        "name": "Baron Samedit Sudo Heap Buffer Overflow",
    },
    "CVE-2022-30190": {
        "has_metasploit": True,
        "has_public_exploit": True,
        "exploit_complexity": "low",
        "attack_vector": "network",
        "name": "Follina Microsoft Support Diagnostic Tool RCE",
    },
    "CVE-2023-23397": {
        "has_metasploit": False,
        "has_public_exploit": True,
        "exploit_complexity": "low",
        "attack_vector": "network",
        "name": "Outlook NTLM Credential Theft Privilege Escalation",
    },
    "CVE-2021-4034": {
        "has_metasploit": False,
        "has_public_exploit": True,
        "exploit_complexity": "low",
        "attack_vector": "local",
        "name": "PwnKit Polkit pkexec Privilege Escalation",
    },
    "CVE-2022-26134": {
        "has_metasploit": True,
        "has_public_exploit": True,
        "exploit_complexity": "low",
        "attack_vector": "network",
        "name": "Confluence Server OGNL Injection Remote Code Execution",
    },
    "CVE-2021-21972": {
        "has_metasploit": True,
        "has_public_exploit": True,
        "exploit_complexity": "low",
        "attack_vector": "network",
        "name": "VMware vCenter Server Unauthorized File Upload RCE",
    },
    "CVE-2011-2523": {
        "has_metasploit": True,
        "has_public_exploit": True,
        "exploit_complexity": "low",
        "attack_vector": "network",
        "name": "vsftpd 2.3.4 Backdoor Command Execution",
    },
    "CVE-2014-0224": {
        "has_metasploit": False,
        "has_public_exploit": True,
        "exploit_complexity": "medium",
        "attack_vector": "network",
        "name": "OpenSSL ChangeCipherSpec MiTM Injection",
    },
}


def assess_exploitability(
    cve_id: str,
    verification: str,
    title: str = "",
    description: str = "",
) -> Tuple[str, bool, float]:
    """Determine exploitability narrative, public exploit existence, and exploit ease score."""
    cve_norm = cve_id.strip().upper()
    exploit_meta = KNOWN_EXPLOITS_DB.get(cve_norm)

    has_public = False
    has_meta = False
    complexity = "medium"

    if exploit_meta:
        has_public = exploit_meta.get("has_public_exploit", False)
        has_meta = exploit_meta.get("has_metasploit", False)
        complexity = exploit_meta.get("exploit_complexity", "medium")

    # If verification was done dynamically by Nuclei or NSE
    is_actively_verified = verification in ("nuclei_verified", "nse_verified")

    # Determine ease metric
    if has_public and complexity == "low":
        exploit_ease = 10.0
    elif has_public:
        exploit_ease = 7.0
    elif is_actively_verified:
        exploit_ease = 5.0
    else:
        exploit_ease = 3.0

    # Narrative explanation
    if has_meta and has_public:
        narrative = (
            f"Weaponized exploit available in Metasploit Framework and public repositories. "
            f"Attack vector is network-accessible with {complexity} complexity."
        )
    elif has_public:
        narrative = (
            f"Functional public exploit code (PoC) is publicly available on GitHub/Exploit-DB. "
            f"Allows reliable reproduction with {complexity} complexity."
        )
    elif verification == "nuclei_verified":
        narrative = (
            "Confirmed via active Nuclei dynamic check. Targeted HTTP/TCP request elicited "
            "positive signature match without relying on static version banners."
        )
    elif verification == "nse_verified":
        narrative = (
            "Confirmed via active Nmap NSE vulnerability script execution. Target service "
            "responded with vulnerable protocol behavior."
        )
    else:
        narrative = (
            "Inferred from service banner and version matching against CVE database. "
            "No active exploit verification attempted."
        )

    return narrative, has_public, exploit_ease


def assess_impact(title: str = "", description: str = "") -> Tuple[str, float]:
    """Map vulnerability description to real-world business impact and severity score."""
    combined = f"{title} {description}".lower()

    if any(k in combined for k in ["remote code execution", " rce", "command injection", "code execution"]):
        return "Full system compromise - attacker gets complete control", 10.0
    if any(k in combined for k in ["authentication bypass", "auth bypass", "privilege escalation", "takeover"]):
        return "Unauthorized access - full application control", 10.0
    if any(k in combined for k in ["sql injection", "sqli"]):
        return "Database breach - data theft/manipulation possible", 8.0
    if any(k in combined for k in ["ssrf", "server-side request forgery"]):
        return "Internal network access - pivot point for attacker", 8.0
    if any(k in combined for k in ["local file inclusion", "path traversal", "directory traversal", "file disclosure"]):
        return "Sensitive file disclosure - credentials exposure", 6.0
    if any(k in combined for k in ["cross-site scripting", " xss"]):
        return "Session hijacking - credential theft from users", 6.0
    if any(k in combined for k in ["information disclosure", "info disclosure", "memory disclosure", "information leak", "leak"]):
        return "Information leakage - recon aid for attacker", 4.0
    if any(k in combined for k in ["denial of service", " dos", "crash"]):
        return "Service availability impact - downtime", 3.0

    return "Security posture degradation - potential unauthorized manipulation", 5.0


def calculate_danger_score(
    cvss_score: float,
    exploit_ease: float,
    impact_severity: float,
) -> float:
    """Calculate composite danger score: (cvss * 0.4) + (exploit_ease * 0.35) + (impact_severity * 0.25)."""
    score = (cvss_score * 0.4) + (exploit_ease * 0.35) + (impact_severity * 0.25)
    clamped = max(0.0, min(10.0, score))
    return round(clamped, 2)


def evaluate_vulnerability_danger(
    cve_id: str,
    cvss_score: float,
    verification: str,
    title: str = "",
    description: str = "",
) -> Dict[str, Any]:
    """Full danger assessment calculation returning all danger metadata."""
    exploitability, public_exploit, exploit_ease = assess_exploitability(
        cve_id=cve_id,
        verification=verification,
        title=title,
        description=description,
    )

    impact, impact_severity = assess_impact(title=title, description=description)

    danger_score = calculate_danger_score(
        cvss_score=cvss_score,
        exploit_ease=exploit_ease,
        impact_severity=impact_severity,
    )

    return {
        "danger_score": danger_score,
        "exploitability": exploitability,
        "impact": impact,
        "public_exploit": public_exploit,
    }
