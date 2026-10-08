"""NVD API 2.0 Client and CVE Enrichment Service.

Queries the National Vulnerability Database for identified service versions
with rate limiting, retries, and CVSS severity extraction.
"""

import asyncio
import logging
import time
from typing import Any, Dict, List, Optional, Set, Tuple
import httpx

from app.core.config import settings

logger = logging.getLogger("aegis.enricher")

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def score_to_severity(score: float) -> str:
    """Map CVSS base score to standard severity enum value."""
    if score >= 9.0:
        return "critical"
    elif score >= 7.0:
        return "high"
    elif score >= 4.0:
        return "medium"
    elif score > 0.0:
        return "low"
    return "none"


class NVDRateLimiter:
    """Sliding-window client-side rate limiter for NVD API 2.0 compliance."""

    def __init__(self, max_requests: int = 5, window_seconds: float = 30.0):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.timestamps: List[float] = []
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Throttle execution if limit within window is reached."""
        async with self._lock:
            now = time.monotonic()
            # Evict timestamps older than sliding window
            self.timestamps = [t for t in self.timestamps if now - t < self.window_seconds]

            if len(self.timestamps) >= self.max_requests:
                sleep_time = self.window_seconds - (now - self.timestamps[0]) + 0.1
                if sleep_time > 0:
                    logger.info(f"NVD rate limiter throttling request for {sleep_time:.2f}s...")
                    await asyncio.sleep(sleep_time)
                # Re-clean window after awaiting
                now = time.monotonic()
                self.timestamps = [t for t in self.timestamps if now - t < self.window_seconds]

            self.timestamps.append(time.monotonic())


# Determine rate limit configuration: 50 req/30s with API key, 5 req/30s without key
max_reqs = 50 if bool(settings.NVD_API_KEY) else 5
rate_limiter = NVDRateLimiter(max_requests=max_reqs, window_seconds=30.0)


# Canonical product normalization table to ensure accurate NVD queries
PRODUCT_NORMALIZATION: Dict[str, str] = {
    "apache": "Apache HTTP Server",
    "apache httpd": "Apache HTTP Server",
    "httpd": "Apache HTTP Server",
    "apache http server": "Apache HTTP Server",
    "nginx": "nginx",
    "openssh": "OpenSSH",
    "mysql": "MySQL",
    "mariadb": "MariaDB",
    "postgresql": "PostgreSQL",
    "postgres": "PostgreSQL",
    "pure-ftpd": "Pure-FTPd",
    "pureftpd": "Pure-FTPd",
    "vsftpd": "vsftpd",
    "proftpd": "ProFTPD",
    "redis": "Redis",
    "mongodb": "MongoDB",
    "cloudflare": "Cloudflare",
    "cloudflare http proxy": "Cloudflare",
    "openssl": "OpenSSL",
    "litespeed": "LiteSpeed Web Server",
    "litespeed httpd": "LiteSpeed Web Server",
    "powerdns": "PowerDNS Authoritative Server",
    "powerdns authoritative server": "PowerDNS Authoritative Server",
    "dovecot": "Dovecot",
    "dovecot pop3d": "Dovecot",
    "dovecot imapd": "Dovecot",
    "node.js": "Node.js",
    "nodejs": "Node.js",
}

# Generic service names that must NEVER be queried in NVD without a concrete product or version
GENERIC_SERVICE_BLACKLIST: Set[str] = {
    "submission",
    "smtps",
    "smtp",
    "domain",
    "http",
    "https",
    "ftp",
    "imap",
    "imaps",
    "pop3",
    "pop3s",
    "unknown",
    "tcpwrapped",
    "ssl",
    "echo",
    "discard",
    "time",
    "ssh",
}

# Approximate release years for major software branches to guard against ancient CVEs
SOFTWARE_GENERATION_YEARS: Dict[str, Dict[str, int]] = {
    "MariaDB": {
        "10.6": 2021,
        "10.5": 2020,
        "10.4": 2019,
        "10.3": 2018,
        "10.2": 2017,
        "10.1": 2015,
        "10.0": 2014,
    },
    "MySQL": {
        "8.0": 2018,
        "8.4": 2024,
        "5.7": 2015,
    },
    "Apache HTTP Server": {
        "2.4": 2012,
    },
    "PowerDNS Authoritative Server": {
        "5.1": 2024,
        "4.8": 2023,
        "4.7": 2022,
    },
    "Pure-FTPd": {
        "1.0": 2010,
    },
    "OpenSSH": {
        "9.": 2022,
        "8.": 2019,
        "7.": 2015,
        "6.6": 2014,
        "6.": 2012,
        "5.": 2008,
    },
    "nginx": {
        "1.31": 2025,
        "1.26": 2024,
        "1.24": 2023,
        "1.22": 2022,
        "1.20": 2021,
    },
}


def normalize_service_identity(
    product: Optional[str] = None,
    service: Optional[str] = None,
    version: Optional[str] = None,
    cpe: Optional[str] = None,
) -> Tuple[str, str]:
    """Parse, clean, and normalize detected product and version.
    
    Handles compatibility prefixes (e.g. MariaDB '5.5.5-10.6.28'),
    PostgreSQL suffixes ('PostgreSQL DB 9.6.0 or later'), and distro tags.
    """
    import re

    raw_prod = (product or "").strip()
    raw_serv = (service or "").strip()
    raw_ver = (version or "").strip()
    raw_cpe = (cpe or "").strip().lower()

    # 1. MariaDB compatibility prefix detection ('5.5.5-10.6.28' -> product=MariaDB, version=10.6.28)
    is_mariadb = False
    if "mariadb" in raw_prod.lower() or "mariadb" in raw_serv.lower() or "mariadb" in raw_cpe or "mariadb" in raw_ver.lower():
        is_mariadb = True

    if raw_ver.startswith("5.5.5-"):
        is_mariadb = True
        raw_ver = re.sub(r"^5\.5\.5-", "", raw_ver)

    if is_mariadb:
        raw_prod = "MariaDB"
        # Strip trailing tags like '-MariaDB', '~deb11', '-log', etc.
        raw_ver = re.sub(r"[-~](mariadb|debian|ubuntu|log).*", "", raw_ver, flags=re.IGNORECASE)

    # 2. PostgreSQL normalization ('PostgreSQL DB 9.6.0 or later' -> product=PostgreSQL, version=9.6.0)
    if "postgres" in raw_prod.lower() or "postgres" in raw_serv.lower() or "postgres" in raw_cpe:
        raw_prod = "PostgreSQL"

    # 3. Strip database and daemon suffixes from product name
    clean_prod = re.sub(r"\s+(DB|database|server|daemon|httpd|pop3d|imapd)$", "", raw_prod, flags=re.IGNORECASE).strip()
    clean_prod = PRODUCT_NORMALIZATION.get(clean_prod.lower(), clean_prod)

    # If product is still empty, check normalized service
    if not clean_prod and raw_serv:
        normalized_from_serv = PRODUCT_NORMALIZATION.get(raw_serv.lower(), "")
        if normalized_from_serv and raw_serv.lower() not in GENERIC_SERVICE_BLACKLIST:
            clean_prod = normalized_from_serv

    # 4. Clean version string
    ver_cleaned = re.sub(r"\s*(or\s+later|or\s+newer|\+|~.*|-ubuntu.*|-debian.*)\s*", "", raw_ver, flags=re.IGNORECASE).strip()
    v_match = re.search(r"^\d+(\.\d+)*", ver_cleaned)
    clean_ver = v_match.group(0) if v_match else ver_cleaned

    return clean_prod, clean_ver


def is_cve_applicable(
    cve_id: str,
    description: str,
    product: str,
    version: str,
) -> bool:
    """Verify if a candidate CVE legitimately applies to the detected product and version.
    
    Filters out cross-product confusion (e.g. Oracle MySQL CVEs applied to MariaDB)
    and enforces the Minimum Version Guard (temporal filter).
    """
    import re

    # Extract publication year from CVE ID (CVE-YYYY-NNNN)
    cve_year = 0
    year_match = re.search(r"CVE-(\d{4})-", cve_id)
    if year_match:
        cve_year = int(year_match.group(1))

    desc_lower = description.lower()
    prod_lower = product.lower()

    # Rule A: MariaDB vs MySQL segregation
    if "mariadb" in prod_lower:
        # If the CVE description explicitly targets Oracle MySQL and makes no mention of MariaDB, skip
        if "oracle mysql" in desc_lower or "mysql server" in desc_lower or "mysql before" in desc_lower or "mysql through" in desc_lower or "mysql <= " in desc_lower:
            if "mariadb" not in desc_lower:
                logger.info(f"Filtering false positive {cve_id}: Oracle MySQL CVE does not apply to MariaDB ({product} {version})")
                return False

        # If detected version is MariaDB 10.x, CVEs from 2013 or earlier cannot apply
        if version.startswith("10.") and cve_year > 0 and cve_year < 2014:
            logger.info(f"Filtering false positive {cve_id}: pre-dates MariaDB 10.x release ({cve_year} < 2014)")
            return False

        # For MariaDB 10.6, CVEs prior to 2018 are impossible matches
        if version.startswith("10.6") and cve_year > 0 and cve_year < 2018:
            logger.info(f"Filtering false positive {cve_id}: pre-dates MariaDB 10.6 branch ({cve_year} < 2018)")
            return False

    # Rule B: MySQL major generation temporal guard
    if prod_lower == "mysql" and version.startswith("8."):
        if cve_year > 0 and cve_year < 2018:
            logger.info(f"Filtering false positive {cve_id}: pre-dates MySQL 8.x ({cve_year} < 2018)")
            return False

    # Rule C: PowerDNS Authoritative Server temporal guard
    if "powerdns" in prod_lower and (version.startswith("5.") or version.startswith("4.")):
        if cve_year > 0 and cve_year < 2018:
            logger.info(f"Filtering false positive {cve_id}: ancient PowerDNS 2.x/3.x flaw ({cve_year})")
            return False

    # Rule D: General Minimum Version Guard (5+ years older than known branch release)
    branch_years = SOFTWARE_GENERATION_YEARS.get(product, {})
    if not branch_years:
        for p_name, p_dict in SOFTWARE_GENERATION_YEARS.items():
            if p_name.lower() == prod_lower:
                branch_years = p_dict
                break

    for branch_prefix, release_year in branch_years.items():
        if version.startswith(branch_prefix):
            if cve_year > 0 and cve_year < (release_year - 4):
                logger.info(f"Temporal guard triggered for {cve_id} on {product} {version} ({cve_year} is >4 yrs older than {release_year})")
                return False
            break

    # Rule D2: OpenSSH specific ancient CVE protection
    if "openssh" in prod_lower or "ssh" in prod_lower:
        if cve_id in ("CVE-1999-0661", "CVE-2000-0525"):
            logger.info(f"Filtering false positive {cve_id}: obsolete OpenSSH CVE on modern host ({product} {version})")
            return False
        if any(version.startswith(v) for v in ("6.", "7.", "8.", "9.")) and cve_year > 0 and cve_year < 2012:
            logger.info(f"Filtering false positive {cve_id}: pre-dates OpenSSH 6.x+ ({cve_year} < 2012)")
            return False

    # Rule D3: Mail/Submission false positives (VirusWall, RemoteEditor)
    if ("smtpscan" in desc_lower or "viruswall" in desc_lower) and "viruswall" not in prod_lower:
        logger.info(f"Filtering false positive {cve_id}: VirusWall CVE applied to non-VirusWall service ({product})")
        return False
    if ("remoteeditor" in desc_lower or "remote editor" in desc_lower) and "remoteeditor" not in prod_lower:
        logger.info(f"Filtering false positive {cve_id}: RemoteEditor CVE applied to non-RemoteEditor service ({product})")
        return False

    # Rule E: Version Upper Bound Check in CVE text
    # e.g., "before 5.7.12", "through 5.6.30", "earlier than 2.4.50"
    if version:
        try:
            detected_parts = [int(p) for p in version.split(".") if p.isdigit()]
            if detected_parts:
                detected_major = detected_parts[0]
                # Look for upper bounds like "5.5.x", "through 5.7"
                upper_bounds = re.findall(r"(?:before|through|earlier than|prior to|up to|<|<=)\s+(\d+)\.(\d+)(?:\.(\d+))?", desc_lower)
                for b in upper_bounds:
                    bound_major = int(b[0])
                    # If upper bound major is strictly less than detected major (e.g. bound is 5.x and detected is 10.x or 8.x)
                    if bound_major < detected_major:
                        logger.info(f"Version upper bound filter: {cve_id} specifies max version {b[0]}.{b[1]}, detected is {version}")
                        return False
        except Exception:
            pass

    return True


class NVDClient:
    """Asynchronous client interacting with the NVD REST API 2.0."""

    def __init__(self) -> None:
        self.headers: Dict[str, str] = {
            "User-Agent": "AEGIS-Vulnerability-Management-Platform/1.0",
            "Accept": "application/json",
        }
        if settings.NVD_API_KEY:
            self.headers["apiKey"] = settings.NVD_API_KEY

    def _parse_cve_item(
        self,
        item: Dict[str, Any],
        product: str = "",
        version: str = "",
    ) -> Optional[Dict[str, Any]]:
        """Extract CVE ID, English summary, and CVSS v3.1 metrics from an NVD record."""
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            return None

        # Extract English description
        descriptions = cve.get("descriptions", [])
        desc = ""
        for d in descriptions:
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        if not desc and descriptions:
            desc = descriptions[0].get("value", "")

        # Check precision filters
        if product and not is_cve_applicable(cve_id, desc, product, version):
            return None

        # Extract CVSS metrics (preference: v3.1 -> v3.0 -> v2.0)
        metrics = cve.get("metrics", {})
        cvss_score = 0.0
        severity = "none"

        if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
            data = metrics["cvssMetricV31"][0].get("cvssData", {})
            cvss_score = float(data.get("baseScore", 0.0))
            raw_sev = str(data.get("baseSeverity", "")).lower()
            severity = raw_sev if raw_sev in ["critical", "high", "medium", "low", "none"] else score_to_severity(cvss_score)
        elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
            data = metrics["cvssMetricV30"][0].get("cvssData", {})
            cvss_score = float(data.get("baseScore", 0.0))
            raw_sev = str(data.get("baseSeverity", "")).lower()
            severity = raw_sev if raw_sev in ["critical", "high", "medium", "low", "none"] else score_to_severity(cvss_score)
        elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
            v2_item = metrics["cvssMetricV2"][0]
            data = v2_item.get("cvssData", {})
            cvss_score = float(data.get("baseScore", 0.0))
            raw_sev = str(v2_item.get("baseSeverity", "")).lower()
            severity = raw_sev if raw_sev in ["critical", "high", "medium", "low", "none"] else score_to_severity(cvss_score)
        else:
            severity = score_to_severity(cvss_score)

        return {
            "cve_id": cve_id,
            "description": desc,
            "cvss_score": round(cvss_score, 1),
            "severity": severity,
        }

    async def _query_nvd(
        self,
        client: httpx.AsyncClient,
        keyword: str,
        product: str = "",
        version: str = "",
    ) -> List[Dict[str, Any]]:
        """Execute a single throttled request to NVD API with retry."""
        params: Dict[str, Any] = {
            "resultsPerPage": 5,
            "keywordSearch": keyword,
        }
        await rate_limiter.acquire()
        for attempt in range(2):
            try:
                logger.info(f"Querying NVD API for '{keyword}' (attempt {attempt + 1}/2)...")
                response = await client.get(
                    NVD_API_URL,
                    params=params,
                    headers=self.headers,
                )
                if response.status_code == 200:
                    payload = response.json()
                    vulnerabilities = payload.get("vulnerabilities", [])
                    results: List[Dict[str, Any]] = []
                    for v in vulnerabilities:
                        parsed = self._parse_cve_item(v, product=product, version=version)
                        if parsed:
                            results.append(parsed)
                    logger.info(f"NVD returned {len(results)} verified candidate(s) for '{keyword}' after precision filtering")
                    return results
                elif response.status_code == 404:
                    return []
                elif response.status_code in [403, 429, 503]:
                    logger.warning(f"NVD API returned HTTP {response.status_code}. Throttling before retry.")
                    if attempt == 0:
                        await asyncio.sleep(2.0)
                        continue
                    return []
                else:
                    return []
            except httpx.RequestError as exc:
                logger.warning(f"NVD request exception on '{keyword}' (attempt {attempt + 1}/2): {exc}")
                if attempt == 0:
                    await asyncio.sleep(1.5)
                    continue
                return []
            except Exception as exc:
                logger.error(f"Unexpected error querying NVD for '{keyword}': {exc}")
                return []
        return []

    async def enrich_service(
        self,
        product: Optional[str] = None,
        service: Optional[str] = None,
        version: Optional[str] = None,
        cpe: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Query NVD 2.0 for known CVE vulnerabilities with precision normalization and guards."""
        clean_prod, clean_ver = normalize_service_identity(
            product=product,
            service=service,
            version=version,
            cpe=cpe,
        )

        clean_serv = (service or "").strip().lower()

        # Guard: If no product and no version, and service is generic (e.g. submission, smtp, domain), SKIP
        if not clean_prod and not clean_ver:
            if not clean_serv or clean_serv in GENERIC_SERVICE_BLACKLIST:
                logger.debug(f"Skipping generic/empty service '{clean_serv}' from NVD false positive generation")
                return []

        # If clean_prod is empty but clean_serv is specific and not blacklisted
        if not clean_prod and clean_serv and clean_serv not in GENERIC_SERVICE_BLACKLIST:
            clean_prod = PRODUCT_NORMALIZATION.get(clean_serv, clean_serv)

        # Construct high-confidence search keywords
        keywords_to_try: List[str] = []
        if clean_prod and clean_ver:
            keywords_to_try.append(f"{clean_prod} {clean_ver}")
            # Only add bare product if version is short or specific product
            if clean_prod not in ["LiteSpeed Web Server", "Dovecot", "PowerDNS Authoritative Server"]:
                keywords_to_try.append(clean_prod)
        elif clean_prod:
            keywords_to_try.append(clean_prod)

        if not keywords_to_try:
            return []

        async with httpx.AsyncClient(timeout=15.0) as client:
            for kw in keywords_to_try:
                findings = await self._query_nvd(client, kw, product=clean_prod, version=clean_ver)
                if findings:
                    return findings

        return []


nvd_client = NVDClient()

