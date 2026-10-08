"""Database seed data script for AEGIS platform.

Creates realistic demo infrastructure assets, real-world CVE vulnerability findings,
and historical scan records. Safe and idempotent to execute multiple times.
"""

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List

from sqlalchemy import select
from app.db.session import AsyncSessionLocal
from app.models.user import User, UserRole
from app.models.asset import Asset, AssetType, AssetEnvironment
from app.models.scan import Scan, ScanType, ScanStatus
from app.models.vulnerability import (
    Vulnerability,
    VulnerabilitySeverity,
    VulnerabilityStatus,
    VerificationType,
)
from app.core.security import hash_password
from app.services.risk.engine import calculate_risk_score
from app.services.risk.danger_engine import evaluate_vulnerability_danger
from app.services.scanner.vulnerability_upsert import upsert_vulnerability

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("aegis.seed")


async def seed_database():
    """Populate database with rich demonstration telemetry."""
    async with AsyncSessionLocal() as session:
        logger.info("[AEGIS SEED] Checking existing database state...")

        # 1. Ensure Default Admin User Exists
        user_stmt = select(User).where(User.email == "admin@aegis.internal")
        admin_user = (await session.execute(user_stmt)).scalar_one_or_none()

        if not admin_user:
            logger.info("[AEGIS SEED] Creating default admin operator user...")
            admin_user = User(
                email="admin@aegis.internal",
                password_hash=hash_password("SuperSecretPassword123"),
                full_name="Admin Operator",
                role=UserRole.admin,
                is_active=True,
            )
            session.add(admin_user)
            await session.commit()
            await session.refresh(admin_user)
            logger.info("[AEGIS SEED] Created admin user: admin@aegis.internal")
        else:
            logger.info("[AEGIS SEED] Admin user exists: %s", admin_user.email)

        # 2. Check Idempotency for Demo Assets
        check_stmt = select(Asset).where(Asset.name == "web-server-01")
        existing_demo = (await session.execute(check_stmt)).scalar_one_or_none()
        if existing_demo:
            logger.info("[AEGIS SEED] Demo seed data is already present. Skipping insertion (idempotent).")
            return

        now = datetime.now(timezone.utc)

        # 3. Create 8-10 Realistic Demo Assets
        logger.info("[AEGIS SEED] Provisioning demo assets...")
        assets_spec = [
            {
                "name": "web-server-01",
                "ip_address": "10.0.1.10",
                "hostname": "web-01.internal.aegis",
                "asset_type": AssetType.web,
                "environment": AssetEnvironment.production,
                "criticality": 4,
                "owner": "Web Operations",
                "description": "Primary customer-facing reverse proxy and web frontend cluster node",
            },
            {
                "name": "db-cluster-primary",
                "ip_address": "10.0.2.15",
                "hostname": "pg-primary.internal.aegis",
                "asset_type": AssetType.db,
                "environment": AssetEnvironment.production,
                "criticality": 5,
                "owner": "Data Platform Team",
                "description": "Main PostgreSQL enterprise database cluster master instance",
            },
            {
                "name": "api-gateway",
                "ip_address": "10.0.1.20",
                "hostname": "gateway.internal.aegis",
                "asset_type": AssetType.web,
                "environment": AssetEnvironment.production,
                "criticality": 5,
                "owner": "Platform Engineering",
                "description": "Edge API routing layer, rate-limiting, and OAuth2 security gateway",
            },
            {
                "name": "fileserver-nas",
                "ip_address": "10.0.3.50",
                "hostname": "storage-nas.internal.aegis",
                "asset_type": AssetType.server,
                "environment": AssetEnvironment.staging,
                "criticality": 3,
                "owner": "Infrastructure",
                "description": "Centralized storage server hosting internal project artifacts and logs",
            },
            {
                "name": "mail-relay-edge",
                "ip_address": "10.0.3.25",
                "hostname": "smtp-edge.internal.aegis",
                "asset_type": AssetType.network,
                "environment": AssetEnvironment.production,
                "criticality": 3,
                "owner": "IT Security",
                "description": "Inbound/outbound SMTP gateway and anti-spam filtering MTA",
            },
            {
                "name": "legacy-app-host",
                "ip_address": "10.0.4.100",
                "hostname": "legacy-vm.internal.aegis",
                "asset_type": AssetType.server,
                "environment": AssetEnvironment.dev,
                "criticality": 2,
                "owner": "Legacy Engineering",
                "description": "Legacy monolithic service test bed hosting unpatched runtime dependencies",
            },
            {
                "name": "vpn-endpoint-perimeter",
                "ip_address": "10.0.5.1",
                "hostname": "vpn-gw.internal.aegis",
                "asset_type": AssetType.network,
                "environment": AssetEnvironment.production,
                "criticality": 4,
                "owner": "SecOps Core",
                "description": "Corporate perimeter remote-access VPN gateway (Citrix/IPSec)",
            },
            {
                "name": "backup-server-vault",
                "ip_address": "10.0.6.12",
                "hostname": "backup-vault.internal.aegis",
                "asset_type": AssetType.server,
                "environment": AssetEnvironment.production,
                "criticality": 4,
                "owner": "Backup Admin",
                "description": "Hardened immutable storage vault for automated off-site disaster backups",
            },
            {
                # Live OWASP Juice Shop vulnerable target container for live active verification deep scanning
                "name": "owasp-juice-shop",
                "ip_address": "172.20.0.5",
                "hostname": "vulnerable-target",
                "asset_type": AssetType.web,
                "environment": AssetEnvironment.dev,
                "criticality": 3,
                "owner": "Security Engineering",
                "description": "OWASP Juice Shop intentional vulnerable target for live deep vulnerability scanning and verification testing.",
            },
        ]

        created_assets: Dict[str, Asset] = {}
        for a_spec in assets_spec:
            # Check if an asset with this IP already exists
            existing_ip = (await session.execute(select(Asset).where(Asset.ip_address == a_spec["ip_address"]))).scalar_one_or_none()
            if existing_ip:
                created_assets[a_spec["name"]] = existing_ip
            else:
                asset = Asset(**a_spec, is_seed=True, owner_id=None)
                session.add(asset)
                await session.flush()
                created_assets[a_spec["name"]] = asset

        logger.info("[AEGIS SEED] Created/linked %d assets.", len(created_assets))

        # 4. Create Historical Scans
        logger.info("[AEGIS SEED] Provisioning historical scan runs...")
        scans_spec = [
            {
                "asset_id": created_assets["web-server-01"].id,
                "scan_type": ScanType.quick,
                "status": ScanStatus.completed,
                "started_at": now - timedelta(days=26, hours=4),
                "completed_at": now - timedelta(days=26, hours=3, minutes=58),
                "total_vulns_found": 3,
                "raw_output": {"summary": "Nmap completed with 3 open ports"},
            },
            {
                "asset_id": created_assets["db-cluster-primary"].id,
                "scan_type": ScanType.full,
                "status": ScanStatus.completed,
                "started_at": now - timedelta(days=21, hours=2),
                "completed_at": now - timedelta(days=21, hours=1, minutes=45),
                "total_vulns_found": 3,
                "raw_output": {"summary": "Nmap deep scan identified database exposure"},
            },
            {
                "asset_id": created_assets["api-gateway"].id,
                "scan_type": ScanType.quick,
                "status": ScanStatus.completed,
                "started_at": now - timedelta(days=14, hours=6),
                "completed_at": now - timedelta(days=14, hours=5, minutes=58),
                "total_vulns_found": 4,
                "raw_output": {"summary": "Discovered Log4Shell and Spring framework exposure"},
            },
            {
                "asset_id": created_assets["vpn-endpoint-perimeter"].id,
                "scan_type": ScanType.quick,
                "status": ScanStatus.completed,
                "started_at": now - timedelta(days=7, hours=1),
                "completed_at": now - timedelta(days=7, hours=0, minutes=57),
                "total_vulns_found": 2,
                "raw_output": {"summary": "Perimeter gateway audit completed"},
            },
            {
                "asset_id": created_assets["legacy-app-host"].id,
                "scan_type": ScanType.full,
                "status": ScanStatus.completed,
                "started_at": now - timedelta(days=2, hours=3),
                "completed_at": now - timedelta(days=2, hours=2, minutes=40),
                "total_vulns_found": 4,
                "raw_output": {"summary": "Full port range sweep on legacy staging VM"},
            },
        ]

        created_scans: List[Scan] = []
        for s_spec in scans_spec:
            scan = Scan(**s_spec, created_by=admin_user.id)
            session.add(scan)
            await session.flush()
            created_scans.append(scan)

        logger.info("[AEGIS SEED] Provisioned %d scan history records.", len(created_scans))

        # 5. Create 16 Real-World Vulnerability Findings across Scans & Assets
        logger.info("[AEGIS SEED] Ingesting realistic CVE vulnerability telemetry...")
        vulns_spec = [
            # 1. Log4Shell on API Gateway
            {
                "asset": created_assets["api-gateway"],
                "scan_id": created_scans[2].id,
                "cve_id": "CVE-2021-44228",
                "title": "Apache Log4j2 JNDI Remote Code Execution (Log4Shell)",
                "description": "Apache Log4j2 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers.",
                "cvss_score": 10.0,
                "severity": VulnerabilitySeverity.critical,
                "port": 8080,
                "service": "http-proxy",
                "service_version": "Apache Tomcat 9.0.45",
                "status": VulnerabilityStatus.open,
                "days_ago": 28,
                "remediation": "Upgrade Apache Log4j to version 2.17.1 or higher. Set log4j2.formatMsgNoLookups=true as emergency mitigation.",
            },
            # 2. Citrix Bleed on VPN Gateway
            {
                "asset": created_assets["vpn-endpoint-perimeter"],
                "scan_id": created_scans[3].id,
                "cve_id": "CVE-2023-4966",
                "title": "Citrix NetScaler ADC/Gateway Sensitive Memory Information Disclosure (Citrix Bleed)",
                "description": "Sensitive information disclosure in NetScaler ADC and NetScaler Gateway allows unauthenticated attackers to extract session tokens and memory contents via crafted HTTP requests, bypassing MFA.",
                "cvss_score": 9.4,
                "severity": VulnerabilitySeverity.critical,
                "port": 443,
                "service": "https",
                "service_version": "Citrix Gateway 13.1",
                "status": VulnerabilityStatus.in_progress,
                "days_ago": 25,
                "remediation": "Apply vendor hotfix NetScaler ADC 13.1-49.13 and terminate all active user sessions.",
            },
            # 3. Spring4Shell on API Gateway
            {
                "asset": created_assets["api-gateway"],
                "scan_id": created_scans[2].id,
                "cve_id": "CVE-2022-22965",
                "title": "Spring Framework RCE via Data Binding on JDK 9+ (Spring4Shell)",
                "description": "A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution via class loader data binding exploitation when packaged as a traditional WAR.",
                "cvss_score": 9.8,
                "severity": VulnerabilitySeverity.critical,
                "port": 8443,
                "service": "https-alt",
                "service_version": "Spring Boot 2.6.5",
                "status": VulnerabilityStatus.open,
                "days_ago": 23,
                "remediation": "Upgrade Spring Framework to versions 5.3.18 or 5.2.20 and upgrade Spring Boot to 2.6.6+.",
            },
            # 4. Heartbleed on Web Server 01
            {
                "asset": created_assets["web-server-01"],
                "scan_id": created_scans[0].id,
                "cve_id": "CVE-2014-0160",
                "title": "OpenSSL TLS Heartbeat Extension Information Disclosure (Heartbleed)",
                "description": "The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, allowing remote attackers to obtain sensitive information from process memory.",
                "cvss_score": 7.5,
                "severity": VulnerabilitySeverity.high,
                "port": 443,
                "service": "https",
                "service_version": "OpenSSL 1.0.1f",
                "status": VulnerabilityStatus.mitigated,
                "days_ago": 22,
                "remediation": "Upgrade OpenSSL package to version 1.0.1g or later and regenerate all private SSL keys.",
            },
            # 5. BlueKeep on Legacy VM
            {
                "asset": created_assets["legacy-app-host"],
                "scan_id": created_scans[4].id,
                "cve_id": "CVE-2019-0708",
                "title": "Microsoft Remote Desktop Services Remote Code Execution (BlueKeep)",
                "description": "A remote code execution vulnerability exists in Remote Desktop Services formerly known as Terminal Services when an unauthenticated attacker connects to the target system using RDP and sends specially crafted requests.",
                "cvss_score": 9.8,
                "severity": VulnerabilitySeverity.critical,
                "port": 3389,
                "service": "ms-wbt-server",
                "service_version": "Windows RDP 7.1",
                "status": VulnerabilityStatus.open,
                "days_ago": 19,
                "remediation": "Apply Microsoft Security Update KB4499175 and enable Network Level Authentication (NLA).",
            },
            # 6. PrintNightmare on Legacy VM
            {
                "asset": created_assets["legacy-app-host"],
                "scan_id": created_scans[4].id,
                "cve_id": "CVE-2021-34527",
                "title": "Windows Print Spooler Remote Code Execution Vulnerability (PrintNightmare)",
                "description": "A remote code execution vulnerability exists when the Windows Print Spooler service improperly performs privileged file operations, enabling an attacker to run arbitrary code with SYSTEM privileges.",
                "cvss_score": 8.8,
                "severity": VulnerabilitySeverity.high,
                "port": 445,
                "service": "microsoft-ds",
                "service_version": "SMBv2 Windows Server 2016",
                "status": VulnerabilityStatus.in_progress,
                "days_ago": 17,
                "remediation": "Install Microsoft Cumulative Update KB5004945 or disable the Print Spooler service where not required.",
            },
            # 7. Zerologon on Fileserver NAS
            {
                "asset": created_assets["fileserver-nas"],
                "scan_id": created_scans[0].id,
                "cve_id": "CVE-2020-1472",
                "title": "Netlogon Elevation of Privilege Vulnerability (Zerologon)",
                "description": "An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure channel connection to a domain controller using the Netlogon Remote Protocol (MS-NRPC).",
                "cvss_score": 10.0,
                "severity": VulnerabilitySeverity.critical,
                "port": 135,
                "service": "epmap",
                "service_version": "Microsoft Windows RPC",
                "status": VulnerabilityStatus.open,
                "days_ago": 15,
                "remediation": "Enforce secure RPC communication with Netlogon by applying Windows Server Patch KB4565349.",
            },
            # 8. EternalBlue on Legacy VM
            {
                "asset": created_assets["legacy-app-host"],
                "scan_id": created_scans[4].id,
                "cve_id": "CVE-2017-0144",
                "title": "Windows SMBv1 Server Remote Code Execution (EternalBlue)",
                "description": "A remote code execution vulnerability exists in Microsoft Server Message Block 1.0 (SMBv1) protocol when it improperly handles specially crafted packets.",
                "cvss_score": 8.1,
                "severity": VulnerabilitySeverity.high,
                "port": 445,
                "service": "microsoft-ds",
                "service_version": "SMBv1",
                "status": VulnerabilityStatus.open,
                "days_ago": 13,
                "remediation": "Disable the obsolete SMBv1 protocol entirely and apply MS17-010 security bulletin.",
            },
            # 9. ProxyLogon on Mail Relay
            {
                "asset": created_assets["mail-relay-edge"],
                "scan_id": created_scans[0].id,
                "cve_id": "CVE-2021-26855",
                "title": "Microsoft Exchange Server Server-Side Request Forgery (ProxyLogon)",
                "description": "A Server-Side Request Forgery (SSRF) vulnerability in Microsoft Exchange Server allows remote attackers to bypass authentication and execute arbitrary commands by chaining with backend CVEs.",
                "cvss_score": 9.8,
                "severity": VulnerabilitySeverity.critical,
                "port": 25,
                "service": "smtp",
                "service_version": "Microsoft ESMTP 15.1",
                "status": VulnerabilityStatus.open,
                "days_ago": 11,
                "remediation": "Install official Microsoft Security Updates for Exchange Server 2013/2016/2019 (March 2021).",
            },
            # 10. MOVEit Transfer SQLi on Backup Vault
            {
                "asset": created_assets["backup-server-vault"],
                "scan_id": created_scans[3].id,
                "cve_id": "CVE-2023-34362",
                "title": "Progress MOVEit Transfer SQL Injection Remote Code Execution",
                "description": "A SQL injection vulnerability in the MOVEit Transfer web application allows an unauthenticated attacker to gain access to the database and potentially execute arbitrary code on the underlying operating system.",
                "cvss_score": 9.8,
                "severity": VulnerabilitySeverity.critical,
                "port": 443,
                "service": "https",
                "service_version": "MOVEit Transfer 2023.0",
                "status": VulnerabilityStatus.open,
                "days_ago": 9,
                "remediation": "Apply the Progress Software June 2023 security patch immediately and rotate all database credentials.",
            },
            # 11. Baron Samedit on Database Cluster
            {
                "asset": created_assets["db-cluster-primary"],
                "scan_id": created_scans[1].id,
                "cve_id": "CVE-2021-3156",
                "title": "Sudo Heap-Based Buffer Overflow Privilege Escalation (Baron Samedit)",
                "description": "A heap-based buffer overflow in Sudo before 1.9.5p2 allows any local unprivileged user to gain root privileges through the command-line argument escaping logic.",
                "cvss_score": 7.8,
                "severity": VulnerabilitySeverity.high,
                "port": 22,
                "service": "ssh",
                "service_version": "OpenSSH 8.2p1 Ubuntu",
                "status": VulnerabilityStatus.mitigated,
                "days_ago": 8,
                "remediation": "Update the sudo package to version 1.9.5p2 or higher via apt/yum.",
            },
            # 12. Follina on Legacy VM
            {
                "asset": created_assets["legacy-app-host"],
                "scan_id": created_scans[4].id,
                "cve_id": "CVE-2022-30190",
                "title": "Microsoft Windows Support Diagnostic Tool (MSDT) Remote Code Execution (Follina)",
                "description": "A remote code execution vulnerability exists when MSDT is called using the URL protocol from an application such as Microsoft Word. An attacker who successfully exploits this vulnerability can run arbitrary code with the caller privileges.",
                "cvss_score": 7.8,
                "severity": VulnerabilitySeverity.high,
                "port": 80,
                "service": "http",
                "service_version": "IIS 8.5",
                "status": VulnerabilityStatus.in_progress,
                "days_ago": 6,
                "remediation": "Apply Microsoft Security Update KB5014699 or disable the MSDT URL Protocol in the Windows registry.",
            },
            # 13. Outlook NTLM Leak on Mail Relay
            {
                "asset": created_assets["mail-relay-edge"],
                "scan_id": created_scans[0].id,
                "cve_id": "CVE-2023-23397",
                "title": "Microsoft Outlook Elevation of Privilege Net-NTLMv2 Hash Leak",
                "description": "Microsoft Outlook elevation of privilege vulnerability where an adversary sends a specially crafted reminder note triggering automatic Net-NTLMv2 authentication to an attacker-controlled SMB server.",
                "cvss_score": 9.8,
                "severity": VulnerabilitySeverity.critical,
                "port": 587,
                "service": "submission",
                "service_version": "Postfix ESMTP",
                "status": VulnerabilityStatus.open,
                "days_ago": 5,
                "remediation": "Block outbound SMB traffic (TCP port 445) at network boundary and deploy Microsoft March 2023 updates.",
            },
            # 14. PwnKit on Database Cluster
            {
                "asset": created_assets["db-cluster-primary"],
                "scan_id": created_scans[1].id,
                "cve_id": "CVE-2021-4034",
                "title": "Polkit pkexec Memory Corruption Local Privilege Escalation (PwnKit)",
                "description": "A local privilege escalation vulnerability in Polkit's pkexec component allows an unprivileged local attacker to gain full root privileges by taking advantage of an out-of-bounds write.",
                "cvss_score": 7.8,
                "severity": VulnerabilitySeverity.high,
                "port": 5432,
                "service": "postgresql",
                "service_version": "PostgreSQL 14.1",
                "status": VulnerabilityStatus.in_progress,
                "days_ago": 4,
                "remediation": "Update policykit-1 package or strip SUID permission from pkexec: chmod 0755 /usr/bin/pkexec.",
            },
            # 15. Atlassian Confluence OGNL Injection on Web Server 01
            {
                "asset": created_assets["web-server-01"],
                "scan_id": created_scans[0].id,
                "cve_id": "CVE-2022-26134",
                "title": "Atlassian Confluence Server OGNL Injection Remote Code Execution",
                "description": "An OGNL injection vulnerability in Atlassian Confluence Server and Data Center allows an unauthenticated attacker to execute arbitrary code on the target server via malicious HTTP GET query strings.",
                "cvss_score": 9.8,
                "severity": VulnerabilitySeverity.critical,
                "port": 8090,
                "service": "http-confluence",
                "service_version": "Confluence 7.18.0",
                "status": VulnerabilityStatus.open,
                "days_ago": 2,
                "remediation": "Upgrade Confluence Server to version 7.18.1, 7.17.4, or 7.16.5 immediately.",
            },
            # 16. VMware vCenter RCE on Fileserver NAS
            {
                "asset": created_assets["fileserver-nas"],
                "scan_id": created_scans[0].id,
                "cve_id": "CVE-2021-21972",
                "title": "VMware vCenter Server Remote Code Execution in vSphere Client",
                "description": "The vSphere Client (HTML5) contains a remote code execution vulnerability in a vCenter Server plugin. An unauthorized actor with network access to port 443 may execute arbitrary commands on the underlying host.",
                "cvss_score": 9.8,
                "severity": VulnerabilitySeverity.critical,
                "port": 443,
                "service": "https",
                "service_version": "VMware vCenter 7.0",
                "status": VulnerabilityStatus.open,
                "days_ago": 1,
                "remediation": "Apply VMware security patch VMSA-2021-0002 or disable the vROps plugin in compatibility config.",
            },
            # 19. Deprecated TLS 1.0 (SSL Audit Finding)
            {
                "asset": created_assets["vpn-endpoint-perimeter"],
                "scan_id": created_scans[0].id,
                "cve_id": "SSL-TLS1-DEPRECATED",
                "title": "Deprecated TLS 1.0 Protocol Enabled",
                "description": "Target supports TLS 1.0, which is deprecated by IETF RFC 8996 and susceptible to cryptographic downgrade attacks.",
                "cvss_score": 5.3,
                "severity": VulnerabilitySeverity.medium,
                "port": 443,
                "service": "https",
                "service_version": "OpenSSL 1.0.1f",
                "status": VulnerabilityStatus.open,
                "days_ago": 2,
                "remediation": "Disable TLS 1.0 and TLS 1.1 in perimeter gateway cipher settings; require TLS 1.2 or TLS 1.3.",
            },
            # 20. Missing HSTS Header (SSL Audit Finding)
            {
                "asset": created_assets["web-server-prod"],
                "scan_id": created_scans[0].id,
                "cve_id": "SSL-MISSING-HSTS",
                "title": "Strict-Transport-Security (HSTS) Header Missing",
                "description": "The remote HTTPS service does not transmit an HTTP Strict Transport Security (HSTS) response header, leaving users vulnerable to SSL stripping attacks.",
                "cvss_score": 3.7,
                "severity": VulnerabilitySeverity.low,
                "port": 443,
                "service": "https",
                "service_version": "nginx/1.18.0",
                "status": VulnerabilityStatus.open,
                "days_ago": 4,
                "remediation": "Configure 'Strict-Transport-Security: max-age=31536000; includeSubDomains' in nginx/Apache SSL config.",
            },
        ]

        for v_item in vulns_spec:
            target_asset: Asset = v_item["asset"]
            risk_val = calculate_risk_score(v_item["cvss_score"], target_asset.criticality)
            first_seen = now - timedelta(days=v_item["days_ago"], hours=5, minutes=12)

            # Determine verification type
            if v_item["cve_id"].startswith("SSL-"):
                ver_type = VerificationType.ssl_verified
                evidence_text = f"testssl.sh cryptographic audit confirmed flaw on {target_asset.ip_address}:{v_item['port']}. Handshake cipher negotiation validated."
            elif v_item["cve_id"] in ("CVE-2017-0144", "CVE-2014-0160", "CVE-2021-44228"):
                ver_type = VerificationType.nse_verified
                evidence_text = f"Nmap NSE script verification confirmed on port {v_item['port']}. Host returned vulnerable payload response signature."
            else:
                ver_type = VerificationType.version_match
                evidence_text = None

            danger_meta = evaluate_vulnerability_danger(
                cve_id=v_item["cve_id"],
                cvss_score=v_item["cvss_score"],
                verification=ver_type.value,
                title=v_item["title"],
                description=v_item["description"],
            )

            await upsert_vulnerability(
                session=session,
                asset_id=target_asset.id,
                scan_id=v_item["scan_id"],
                cve_id=v_item["cve_id"],
                title=v_item["title"],
                description=v_item["description"],
                cvss_score=v_item["cvss_score"],
                severity=v_item["severity"],
                port=v_item["port"],
                service=v_item["service"],
                service_version=v_item["service_version"],
                remediation=v_item["remediation"],
                verification=ver_type,
                evidence=evidence_text,
                danger_score=danger_meta["danger_score"],
                exploitability=danger_meta["exploitability"],
                impact=danger_meta["impact"],
                public_exploit=danger_meta["public_exploit"],
                status=v_item["status"],
            )

        # Backfill any existing vulnerabilities in DB that lack danger metrics
        all_existing = (await session.execute(select(Vulnerability))).scalars().all()
        for ev in all_existing:
            if ev.danger_score is None:
                d_meta = evaluate_vulnerability_danger(
                    cve_id=ev.cve_id,
                    cvss_score=ev.cvss_score,
                    verification=ev.verification.value if hasattr(ev.verification, "value") else str(ev.verification),
                    title=ev.title,
                    description=ev.description,
                )
                ev.danger_score = d_meta["danger_score"]
                ev.exploitability = d_meta["exploitability"]
                ev.impact = d_meta["impact"]
                ev.public_exploit = d_meta["public_exploit"]

        await session.commit()
        logger.info("[AEGIS SEED] Database seeding completed successfully!")
        logger.info(
            "[AEGIS SEED] Summary: %d Assets, %d Historical Scans, %d Real CVE Vulnerabilities created.",
            len(created_assets),
            len(created_scans),
            len(vulns_spec),
        )


if __name__ == "__main__":
    asyncio.run(seed_database())
