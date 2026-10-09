# AEGIS - Industry-Grade Vulnerability Management Platform
## System Architecture & Technical Specifications

---

## 1. Project Vision
AEGIS is an enterprise-ready continuous vulnerability management platform. Organizations can register network assets, trigger automated scans using Nmap, enrich findings with live CVE telemetry via the NVD API 2.0, prioritize vulnerabilities using a contextual risk engine, track remediation lifecycle, and generate executive/compliance reports. Designed with a dark security operations center (SOC) aesthetic, clean data architecture, and production-grade patterns.

---

## 2. Technology Stack

### Backend
- **Framework:** FastAPI (Python 3.11)
- **Database & ORM:** PostgreSQL 16, async SQLAlchemy 2.0
- **Migrations:** Alembic
- **Authentication & Security:** JWT (JSON Web Tokens), Passlib / bcrypt password hashing
- **Data Validation:** Pydantic v2
- **Scanner Engine:** `python-nmap` asynchronous/threaded execution wrapper
- **Enrichment:** National Vulnerability Database (NVD) REST API 2.0 (CPE/CVE lookups)

### Frontend
- **Core:** React 18, Vite, JavaScript / React Router DOM v6
- **Styling:** Tailwind CSS (Enterprise Dark SOC theme)
- **Visualization:** Recharts (donut charts, trend lines, bar charts)
- **HTTP Client:** Axios (interceptor pattern for JWT bearer authentication)
- **Icons & UI:** Lucide React

### Infrastructure & DevOps
- **Containerization:** Docker & Docker Compose (`postgres`, `backend`, `frontend`)
- **Version Control:** Git & GitHub (commit format: `feat:`, `fix:`, `chore:`)

---

## 3. Database Schema

### `users`
- `id` (PK, UUID / Integer)
- `email` (String, Unique, Indexed)
- `password_hash` (String)
- `full_name` (String)
- `role` (Enum: `admin`, `analyst`, `viewer`)
- `is_active` (Boolean, default `True`)
- `created_at` (Timestamp with timezone)

### `assets`
- `id` (PK, UUID / Integer)
- `name` (String)
- `ip_address` (String(255), Indexed, Non-unique - target IP address or domain name; scoped by `owner_id`)
- `target_type` (Enum: `ip`, `domain`, default `ip`)
- `resolved_ip` (String(45), Nullable - auto-resolved IPv4 for domain targets)
- `hostname` (String, Nullable)
- `asset_type` (Enum: `server`, `web`, `db`, `network`)
- `environment` (Enum: `production`, `staging`, `dev`)
- `criticality` (Integer, 1 to 5)
- `owner` (String)
- `owner_id` (FK -> `users.id`, Nullable, Indexed - per-user asset ownership isolation)
- `is_seed` (Boolean, default `False` - shared system demo targets visible across tenants)
- `auto_created` (Boolean, default `False` - flag for direct scan auto-registered targets)
- `description` (Text, Nullable)
- `created_at` (Timestamp with timezone)
- `updated_at` (Timestamp with timezone)

### `scans`
- `id` (PK, UUID / Integer)
- `asset_id` (FK -> `assets.id`)
- `scan_type` (Enum: `quick`, `full`, `deep`)
- `status` (Enum: `pending`, `running`, `completed`, `failed`)
- `started_at` (Timestamp with timezone, Nullable)
- `completed_at` (Timestamp with timezone, Nullable)
- `total_vulns_found` (Integer, default 0)
- `raw_output` (JSONB)
- `progress` (JSONB, Nullable - live progress tracking `current_stage`, `stage_number`, `stages_total`, `detail`, `hosts_processed`, `hosts_total`, `updated_at`)
- `created_by` (FK -> `users.id`, Nullable, Indexed - initiator user identity for multi-tenant isolation)

### `vulnerabilities`
- `id` (PK, UUID / Integer)
- `scan_id` (FK -> `scans.id`)
- `asset_id` (FK -> `assets.id`)
- `cve_id` (String, Indexed)
- `title` (String)
- `description` (Text)
- `cvss_score` (Float)
- `severity` (Enum: `critical`, `high`, `medium`, `low`, `none`)
- `port` (Integer, Nullable)
- `service` (String, Nullable)
- `service_version` (String, Nullable)
- `risk_score` (Float)
- `epss_score` (Float, Nullable)
- `status` (Enum: `open`, `in_progress`, `mitigated`, `false_positive`)
- `remediation` (Text, Nullable)
- `first_seen_at` (Timestamp with timezone)
- `last_seen_at` (Timestamp with timezone)
- `verification` (Enum: `version_match`, `nse_verified`, `nuclei_verified`, `ssl_verified`, default `version_match`)
- `evidence` (Text, Nullable - raw HTTP/NSE payload proof)
- `danger_score` (Float, Nullable - composite 0-10 metric)
- `exploitability` (Text, Nullable - ease and method of exploitation narrative)
- `impact` (Text, Nullable - blast radius and consequence narrative)
- `public_exploit` (Boolean, default `False` - known public exploit weaponization)

### `reports`
- `id` (PK, UUID / Integer)
- `report_type` (Enum: `executive`, `detailed`, `compliance`)
- `format` (Enum: `pdf`, `excel`)
- `generated_by` (FK -> `users.id`)
- `file_path` (String)
- `created_at` (Timestamp with timezone)

---

## 4. Prioritization & Threat Assessment Engines

### A. Contextual Risk Engine
Prioritizes CVEs within the organization's business context:
$$\text{criticality\_weight} = \left(\frac{\text{criticality}}{5}\right) \times 10$$
$$\text{risk\_score} = \text{round}\left((\text{cvss\_score} \times 0.6) + (\text{criticality\_weight} \times 0.4), 2\right)$$

### B. Danger Assessment Engine (Phase 8)
Assesses weaponization and real-world hazard beyond static version claims:
$$\text{danger\_score} = \text{round}\left((\text{cvss\_score} \times 0.40) + (\text{exploit\_ease} \times 0.35) + (\text{impact\_severity} \times 0.25), 2\right)$$
- **Exploit Ease (0-10):** Measured by public weaponization, Metasploit integration, active remote execution vs local interaction.
- **Impact Severity (0-10):** RCE/root access (10.0), SQLi/Auth Bypass (8.0-9.0), Info Leak (4.0-6.0), DoS (3.0-5.0).
- **Public Exploit:** Flagged with 🔥 when active PoC or weaponized module is identified.

### C. Severity Auto-Mapping from CVSS
- **Critical:** CVSS $\ge 9.0$
- **High:** $7.0 \le \text{CVSS} \le 8.9$
- **Medium:** $4.0 \le \text{CVSS} \le 6.9$
- **Low:** $0.1 \le \text{CVSS} \le 3.9$
- **None:** $\text{CVSS} = 0.0$

### D. Target Resolution & DNS Discovery Engine (Phase 8.1)
Normalizes, validates, and automatically resolves diverse network target specifications:
- **URL/Scheme Cleaning:** Strips protocols (`http://`, `https://`), userinfo, URL paths, query parameters, fragment identifiers, and port designations (e.g. `https://example.com:8080/path` $\rightarrow$ `example.com`).
- **Target Type Discrimination:** Distinguishes attempted IPv4 addresses (all numeric dot-segments) from RFC-compliant hostnames/domains.
- **Dynamic DNS Resolution:** Leverages `socket.getaddrinfo` to resolve domain targets to live IPv4 addresses, populating `resolved_ip` while preserving original domain branding.
- **Cross-Target Conflict Detection:** Detects duplicates bidirectionally across `ip_address` and `resolved_ip` (prevents registering domain targets whose resolved IP is already monitored, and vice versa).
- **Scanner Execution Target:** Scanner engine directs Nmap and Nuclei probes to the resolved IP while attributing findings to the parent domain identity.

### E. Direct Target Scanning & Auto-Discovery (Phase 8.2)
Streamlines operator workflow by removing asset registration preconditions:
- **Instant Target Scanning (`POST /api/scans/direct`):** Operator provides arbitrary IPv4 address, domain name, or URL. Input undergoes real-time DNS resolution and validation.
- **Deduplication & Asset Reuse:** System inspects existing inventory across `ip_address` and `resolved_ip`. If target already exists, the scan attaches immediately to the existing asset record without duplicating entries.
- **Silent Asset Auto-Creation:** Unregistered targets automatically instantiate a monitored asset record flagged with `auto_created = True`, baseline `criticality = 3`, and owner `"Auto-Discovered"`.
- **Smart Asset Type Inference:** Post-scan inspection dynamically infers asset classification:
  - If open ports/services include web infrastructure (`80`, `443`, `3000`, `8080`, `8443`, etc.), `asset_type` updates to `web`.
  - If open ports/services include database engines (`5432`, `3306`, `27017`, `6379`, etc.), `asset_type` updates to `db`.
  - Default falls back to `server`.
- **Demo Data Lifecycle Management:** Distinguishes demonstration seeds (`is_seed = True`) from operator-scanned targets. Endpoint `DELETE /api/assets/seed` cleanly removes demo fixtures and cascading findings while preserving all operator-scanned targets.

---

## 5. Deep Active Verification & Web Reconnaissance Architecture

### A. Active Verification Engine (Phase 8)
Deep scanning moves beyond probabilistic banner matching to active, evidence-backed proof of exploitability using a multi-engine pipeline:
- **Nmap NSE Scripts:** Actively probe open ports for known exploits (`vuln` category). Sets `verification = nse_verified`.
- **Nuclei v3 Engine:** Dynamic HTTP/API vulnerability and misconfiguration templates. Sets `verification = nuclei_verified`.
- **Deduplication & Risk Pipeline:** In-place upgrades (`version_match` $\rightarrow$ verified), Danger score and contextual risk scoring.

### B. Real-World Web Reconnaissance Engine & Live Progress (Phase 8.3)
Professional external scanning must unmask virtual hosts and backend services obscured behind CDNs and reverse proxies. The 7-stage reconnaissance engine executes sequentially:

```
[Domain / IP Target]
       │
       ▼
 Stage 1: Subdomain Discovery (Domain Targets)
   • Subfinder v2 passive reconnaissance (enumerates up to 100 subdomains)
   • Falls back to apex host if 0 subdomains found; skips if target is IPv4
       │
       ▼
 Stage 2: Live Web Probing & Tech Stack Detection
   • ProjectDiscovery httpx v1 probes HTTP/HTTPS across all subdomains
   • Extracts status codes, page titles, CDN edge detection, and software technologies
       │
       ▼
 Stage 3: Smart Port & NSE Scanning
   • CDN-aware scanning: CDN-proxied IPs scanned light (-top-ports 100)
   • True origin backend IPs scanned deep (-top-ports 500 + NSE vuln scripts)
       │
       ▼
 Stage 4: Expanded Nuclei Active Web Exploitation
   • Scans live web endpoints across discovered services
   • Uses pinned Nuclei v3 with cve, exposure, misconfig, vulnerability tags
       │
       ▼
 Stage 5: SSL/TLS Cryptographic Audit
   • testssl.sh evaluates cipher suites, deprecated protocols (TLS 1.0/1.1),
     missing HSTS, Heartbleed, ROBOT, POODLE, and certificate anomalies
   • Sets verification = ssl_verified with cryptographic handshake evidence
       │
       ▼
 Stage 6: Technology Version Vulnerability Analysis
   • Correlates detected software versions (WordPress, PHP, Apache, nginx)
   • Generates targeted advisories for out-of-date runtime stacks
       │
       ▼
 Stage 7: Aggregation & Threat Prioritization
   • Deduplicates findings across subdomains and ports
   • Commits raw_output.recon dossier (subdomains, live hosts, CDN status)
```

### C. Live Progress Reporting Architecture
- `scans.progress` JSONB column updated asynchronously in real-time during pipeline execution.
- Tracks `current_stage`, `stage_number`, `stages_total`, `detail`, `hosts_processed`, `hosts_total`, and `updated_at`.
- Frontend displays an active pulsing progress banner with dynamic percentage bar, stage name, elapsed timer, and host counter.
- Scan Execution Dossier modal provides the full **Reconnaissance Summary** section (subdomain badges, live hosts table, detected tech stack pills, and CDN edge warnings).

---

## 6. Legacy 3-Stage Pipeline Overview (Phase 8 Reference)

```
[Target Asset IP]
       │
       ▼
 Stage 1: Fast Service Discovery
   • Nmap -sV -T4 --top-ports 500
   • Rapid port & service fingerprinting
       │
       ▼
 Stage 2: Nmap NSE Script Engine
   • nmap -sV --script vuln -p <discovered_ports>
   • Actively tests MS17-010, Heartbleed, Log4Shell, etc.
   • Sets verification = nse_verified, captures raw output evidence
       │
       ▼
 Stage 3: Nuclei Dynamic Testing
   • ProjectDiscovery Nuclei v3 execution
   • Streaming JSONL output against open web/API ports (-t /nuclei-templates)
   • Sets verification = nuclei_verified, extracts HTTP matched-at & proof
       │
       ▼
 Deduplication & Risk Pipeline
   • In-place upgrades: (asset_id, cve_id, port) upgraded from version_match to verified
   • Contextual risk & Danger scores computed automatically
```

---

## 5. Backend API Endpoints

- `/api/auth`
  - `POST /register`: Account registration
  - `POST /login`: OAuth2/JWT password flow
  - `GET /me`: Current authenticated user info
- `/api/assets`
  - `GET /`: List assets (pagination, search, filter by criticality/environment)
  - `POST /`: Create asset
  - `DELETE /seed`: Delete all seed demo assets and cascading findings (admin only)
  - `GET /{id}`: Asset details
  - `PUT /{id}`: Update asset
  - `DELETE /{id}`: Delete asset
- `/api/scans`
  - `POST /direct`: Trigger direct scan on any IP, domain, or URL (auto-creates or reuses asset)
  - `POST /`: Trigger scan on existing registered asset (quick/full/deep)
  - `GET /`: List scan history
  - `GET /{id}`: Scan execution status and raw output
- `/api/vulns`
  - `GET /`: List vulnerabilities (filter by severity, status, asset)
  - `GET /{id}`: Vulnerability detail drawer
  - `PATCH /{id}/status`: Update remediation status (`open`, `in_progress`, `mitigated`, `false_positive`)
  - `GET /stats`: Vulnerability statistics
- `/api/reports`
  - `POST /generate`: Trigger report generation (`pdf`, `excel`)
  - `GET /`: List generated reports
  - `GET /{id}/download`: Download report file
- `/api/dashboard`
  - `GET /stats`: Aggregated metrics (severity distribution, trends over time, top risky assets, open vs mitigated)

---

## 6. Frontend Pages & Layout

1. **Login / Register:** Dark cybersecurity theme, form validation, token storage.
2. **Dashboard:** High-level overview with key metric cards (Total Vulns, Critical Count, Assets, Open Vulns), Severity Donut Chart, Vulnerability Trends Over Time, Top Risky Assets Bar Chart, and Recent Vulnerabilities table.
3. **Assets:** Inventory table with search/filter, Add/Edit/Delete modals, criticality indicator badges, and active vulnerability counters.
4. **Vulnerabilities:** Filterable and sortable findings table, severity color badges, flyout detail drawer with CVE details, CVSS/risk breakdown, remediation recommendations, and status management.
5. **Scans:** Scan initiation form (select asset + scan type), real-time progress indicators, and historical scan table.
6. **Reports:** Report builder (executive, technical, compliance), format picker (PDF/Excel), and file download repository.

---

## 7. Development & Coding Standards

- **Response Format:** Uniform standard across all endpoints:
  ```json
  {
    "data": ...,
    "message": "...",
    "status": "success" | "error"
  }
  ```
- **Type Annotations & Validation:** Full Python type hints, Pydantic v2 schemas for all request/response models.
- **Naming Conventions:** `snake_case` in Python; `camelCase` in JavaScript.
- **Error Handling:** Global exception handler returning standardized JSON errors and proper HTTP status codes.
- **Security & Config:** Configuration via `.env`, template in `.env.example`, credentials excluded from Git.
- **Git Protocol:** Clean atomic commits using conventional prefixes (`feat:`, `fix:`, `chore:`).

---

## 8. Phase Roadmap

- **Phase 0:** Repo structure, Docker setup (`postgres`, `backend`, `frontend`), health check endpoints, frontend layout shell with sidebar.
- **Phase 1:** SQLAlchemy async models, Alembic setup, initial migrations.
- **Phase 2:** Authentication system (JWT, password hashing, user registration/login, route guards).
- **Phase 3:** Asset CRUD API + Assets frontend management page.
- **Phase 4:** Nmap scanner service + NVD API 2.0 enrichment service + background execution.
- **Phase 5:** Contextual Risk Engine + Vulnerabilities management page + Dashboard charts.
- **Phase 6:** Report generation engine (PDF/Excel) + Reports UI.
- **Phase 7:** Platform polish, database seeding script, comprehensive documentation & testing.
- **Phase 8:** Deep Active Vulnerability Scanning + Active Verification Engine (Nmap NSE + Nuclei v3) + Threat Danger Assessment Engine.
- **Phase 8.1:** Domain & URL Target Support with Automatic DNS Resolution, Bidirectional Conflict Detection, and Visual 🌐/🖥️ Indicators.
- **Phase 8.2:** Direct Target Scanning (No Asset Pre-Registration Required), Automatic Asset Deduplication & Reuse, Smart Asset Type Detection, and Demo Data Lifecycle Teardown.
- **Phase 8.3:** Real-World Web Reconnaissance Engine + Subdomain Discovery (subfinder) + Live Web Probing (httpx) + SSL/TLS Cryptographic Audit (testssl.sh) + Live Scan Progress Reporting + Scan Details Reconnaissance Dossier.
- **Phase 8.4:** Performance Optimization & Bugfix Release:
  - Aggressive Scan Execution Speedups:
    - Nuclei parallelization with `asyncio.Semaphore(4)` and thread pool offloading (`-rl 50`, `-concurrency 25`, `-timeout 10`, 300s process cap).
    - Subfinder passive OSINT timeout reduced to 30-60s max.
    - Httpx web probe timeout capped at 120s with 30 concurrent threads and `-timeout 8`.
    - testssl.sh accelerated via `--fast` flag, deduplicated across unique target IPs, 90s process cap.
    - Intelligent target pruning: automatically skips dead / 404 / 50x endpoints and deduplicates subdomains sharing identical IP + technology stack.
    - Juice Shop IP benchmark: 32.86s (down from 4-8 mins); Domain benchmark: 7.9 mins (down from 30-45+ mins).
  - Security Notifications Stream:
    - Backend `GET /api/notifications` endpoint returning recent 20 security events (completed scans, verified exploits, critical CVEs).
    - Interactive topbar dropdown panel with unread badge counter, `localStorage` persistence, relative time markers, and outside click / Escape dismiss.
  - Core Engine Telemetry & System Diagnostics:
    - Enhanced `GET /health` with database status, container toolchain binary verification (`nmap`, `nuclei`, `subfinder`, `testssl`), and active scan telemetry.
    - Live status strip in Topbar pulsing during active scans and opening System Diagnostics modal on demand.

- **Phase 8.5:** Full QA & Stability Release: Autonomous Bug Hunting, Scan Failure Transparency & Engine Hardening:
  - **Quick Scan Failure on External Domains (Root Cause & Fix)**:
    - *Root Cause*: Backend container runs as unprivileged user `appuser`. Without root capabilities, Nmap default ping uses TCP SYN/ACK discovery packets to ports 80/443. External firewalled targets (e.g. `cutn.ac.in`) drop discovery probes, prompting Nmap to assume "Host seems down" and terminate in 2.17s without scanning ports.
    - *Fix*: Standardized unprivileged TCP connect scanning (`-sT`) with ping suppression (`-Pn`), service version detection (`-sV`), and top 100 ports scan profile (`-sT -sV -Pn --top-ports 100 -T4 --host-timeout 3m`). Added exponential backoff retry logic (2 attempts) to handle transient network packet loss.
    - *Verification*: Quick scan on `cutn.ac.in` completes reliably in ~26s, discovering open web ports (80/443 Apache) and generating 10 NVD vulnerability correlations.
  - **Scan Failure Transparency & Diagnostic Dossier**:
    - Backend persists comprehensive error telemetry in `scan.raw_output`: `error`, `error_type`, `error_hint`, `failure_stage`, `target`, `target_ip`, and sanitized tracebacks.
    - Automatic actionable recommendation generation based on failure mode (unreachable host, DNS resolution error, network timeout).
    - Frontend Scans page table: failed scan rows render a high-visibility red `Failure Reason` action button with `AlertTriangle` icon.
    - Scan Execution Dossier modal displays an executive `Scan Execution Failure` alert banner detailing the exact abort stage, primary error message, exception type, actionable operator guidance, and timing metadata.
  - **Dead IP / Unreachable Target Detection**:
    - Scanner distinguishes active filtered targets from non-existent hosts (e.g., TEST-NET-2 IP `203.0.113.99`). If zero open ports and no protocols respond (`reason: no-response`), immediately raises `ScanExecutionError` with tailored guidance.
  - **Scan Collision & Concurrency Protection**:
    - `POST /api/scans` and `POST /api/scans/direct` validate active scans against target asset; returns HTTP 409 Conflict if a scan is already running/pending on that asset.
  - **Frontend State Stability & Memory Leak Prevention**:
    - Resolved React state dependency cycle in `Scans.jsx` where closing the Dossier triggered `fetchScans` recreation, resetting `selectedScan`. Decoupled using `useRef` for `selectedScanIdRef` and unified `handleCloseModal`.
    - Added Escape key listeners, backdrop dismissal, and `data-testid` handles for modal controls.
  - **Full Platform QA Suite**:
    - Automated Playwright end-to-end audit covering Auth (`/login`), Assets (`/assets`), Scans (`/scans`), Vulnerabilities (`/vulns`), Reports (`/reports`), and 404 handler (`/404`) with 0 console errors detected.

- **Infrastructure & Scan Launch Path Hardening**:
  - **Docker Compose Container Lifecycle**: Standardized `restart: unless-stopped` on all 4 containers (`postgres`, `backend`, `frontend`, `juice-shop`). Prevented standalone container naming collisions.
  - **DNS Resolution Engine**: Configured upstream public DNS resolvers (`8.8.8.8`, `1.1.1.1`) in `docker-compose.yml` to prevent Docker internal resolver `127.0.0.11` from returning `SERVFAIL` on external domain lookups and NVD NIST API queries.
  - **Dual-Layer DNS Fallback**: `target_resolver.py` augmented with secondary subprocess resolution on `gaierror`, plus database fallback to existing asset records.
  - **Stuck Scan Startup Recovery**: Application `lifespan` automatically identifies and marks lingering/stalled scans from prior server terminations as failed with actionable hints.
  - **Active Scan Staleness Pruning**: Scan launch routes auto-recover active scans older than 1 hour, preventing indefinite HTTP 409 lockout.

- **Phase 8.6: Scanner Intelligence, Firewall Evasion & Deep Service Fingerprinting**:
  - **Issue 1: Version Parsing Intelligence & False Positive Elimination**:
    - *MariaDB / MySQL Segregation*: Detects MySQL protocol `5.5.5-` compatibility prefix on MariaDB instances; extracts true release version (e.g. `10.6.28`) and canonical product `MariaDB`. Filters out ancient Oracle MySQL 5.5 CVEs (e.g. `CVE-2016-3615`) from being attributed to modern MariaDB.
    - *Temporal Guard (Minimum Version Guard)*: Prevents historical CVEs published $>4$ years prior to a software major branch launch from matching (e.g. 2001/2004/2012 CVEs blocked on MariaDB 10.6 and PowerDNS 5.1).
    - *Generic Service Blacklist*: Prevents bare keyword queries against NVD on generic port services without concrete versions (`submission`, `smtps`, `domain`, `http`), eliminating 2002-era Sendmail/Mutt/WebSight false positives.
    - *Version Upper-Bound Validation*: Regex-checks CVE advisory vulnerability text bounds (`before X.Y`, `<= X.Y`) against detected major versions.
  - **Issue 2: Firewall Evasion & Deep Fingerprinting Engine**:
    - *Smart Host Discovery*: Strict `-Pn` across all scanning pipelines. Added `--disable-arp-ping` to eliminate false positive local-network dropouts.
    - *TCP ACK Scan (`-sA`) Reachability Fallback*: If initial connect scans encounter 0 open ports, executes an ACK scan fallback to differentiate stateful firewall drops from live hosts returning TCP RSTs.
    - *Evasion Packet Shaping*: Integrated `-f` (fragmentation), `--data-length 24` (packet padding), and `-T2` stealth timing on retry attempts for full and deep scans.
    - *Targeted Socket Handshake Probing*: Custom socket protocol parsers for unspecified/generic service banners:
      - Port 3306: Parses MySQL/MariaDB `Protocol::HandshakeV10` greeting packet without credentials.
      - Port 21: Extracts FTP `220` daemon greeting banners (`Pure-FTPd`, `vsftpd`, `ProFTPD`).
      - Port 80/443: Direct socket HTTP `HEAD` / `Server` header grab + fallback to `httpx` tech detection.
    - *Anti-WAF Tuning*: Tuned Nuclei to `-rl 25` and `-concurrency 15`; parses WAF signatures (`BitNinja`, `Cloudflare`, `ModSecurity`, `Incapsula`) into reconnaissance telemetry.
  - **Issue 3: Port Coverage Expansion**:
    - Expanded Deep Recon port scanning from top 500 ports to top 1000 ports plus critical infrastructure port list (`21,22,23,25,53,80,110,111,135,139,143,443,445,465,587,993,995,1433,1521,2049,3306,3389,5432,5900,6379,8080,8443,8888,9090,27017,61616`).

- **Phase 8.7: Multi-Tenancy Data Isolation, Data Integrity Cleanup & UI Theme Refresh**:
  - **Workstream A: Per-User Multi-Tenant Data Isolation**:
    - *Database Schema Migration (`006_phase8_7_multi_tenancy.py`)*:
      - Added `owner_id` (FK to `users.id`, nullable for seed assets) to `assets` table.
      - Dropped unique constraint on `assets.ip_address` and created non-unique index `ix_assets_ip_address` to allow distinct owners to scan shared targets (e.g. `172.20.0.5` or demo targets) without collision.
      - Added `created_by` (FK to `users.id`) to `scans` table.
      - Backfilled all existing legacy assets and scans to the primary administrative user (`admin@aegis.internal`, ID 1).
    - *API Layer Scoping*:
      - `assets.py`: List filters by `(Asset.owner_id == current_user.id) | (Asset.is_seed == True)`. Target registration assigns `owner_id = current_user.id`. Duplicate target checks are scoped strictly per owner. Detail, update, and delete enforce ownership and return 404 for unowned assets.
      - `scans.py`: Direct scan launch searches and auto-creates assets strictly scoped to `owner_id = current_user.id`. Scans assign `created_by = current_user.id`. Scans list, detail, and scan vulnerability endpoints filter by `Scan.created_by == current_user.id`.
      - `vulns.py`: Joins `Asset` on `Vulnerability.asset_id == Asset.id` and scopes by `Asset.owner_id == current_user.id`. Detail, verification status update, and mitigation status update strictly verify asset ownership.
      - `dashboard.py`: Summary metrics, severity breakdown, 7-day scan activity trends, top risky assets, dangerous vulnerabilities, and recent vulnerabilities scoped by `current_user.id`.
      - `notifications.py`: Scans scoped by `Scan.created_by == current_user.id`, vulnerabilities joined and scoped by `Asset.owner_id == current_user.id`.
      - `reports.py`: Scoped by `Report.generated_by == current_user.id`.
    - *Seed vs. User Assets*: Seed assets (`is_seed=True`) are shared demo reference points visible to all users. When a non-admin user scans a seed asset or direct IP, the platform isolates their scan and vulnerability findings to their own tenant context.
  - **Workstream B: Deduplication & Legacy False Positive Elimination**:
    - *Unified Vulnerability Upsert Service (`vulnerability_upsert.py`)*:
      - Centralized vulnerability deduplication across all scanner pipelines (`pipeline.py`, `deep_scanner.py`, `seed.py`).
      - Identifies matches on `(asset_id, cve_id, port)`. Upgrades verification rank monotonically (`nuclei_verified` > `ssl_verified` > `nse_verified` > `version_match`). Merges raw proof and evidence, recalculates contextual risk scores dynamically, and preserves user-assigned mitigation status.
    - *Database Deduplication Cleanup Script (`dedup_cleanup.py`)*:
      - Merged all existing historical duplicate vulnerabilities on identical `(asset_id, cve_id, port)`, pruning 8 duplicate records and keeping highest verification rank records.
    - *OpenSSH Temporal Guards & False Positive Reclassification (`false_positive_cleanup.py`)*:
      - Augmented `nvd_client.py` with OpenSSH branch temporal launch barriers (`9.x: 2022`, `8.x: 2019`, `7.x: 2015`, `6.6: 2014`, `6.x: 2012`, `5.x: 2008`) and generic mail/submission false positive guards (`CVE-2001-1573`, `CVE-2004-2248`, `CVE-1999-0661`, `CVE-2000-0525`).
      - Audited and updated 39 legacy false positives in the database to `status="false_positive"`.
  - **Workstream C: UI Polish, Theme Refresh & Navigation**:
    - *Deep Navy Theme Refresh*: Redesigned visual design system to deep navy palette (`#0b1220` base, `#0a0f1c` dark sidebar, `#111a2e` card elevations, with subtle `border-white/5` borders) across Tailwind config, styles, sidebar, topbar, cards, login, and registration.
    - *Reports Page Navigation*: Added prominent Back navigation button on `/reports` page allowing quick return to dashboard or previous views.
    - *Zero-State Handling*: First-time / new tenants see clean, empty states with zero console errors or broken counters.
- **Phase 8.9: Comprehensive Security Hardening Audit & Defense-in-Depth Release**:
  - **Authentication & Credential Hardening**:
    - *Password Complexity Policy*: Enforced minimum 12 characters (max 128) with required uppercase, lowercase, numeric, and special character combinations. Rejects common guessable dictionary patterns (`password`, `qwerty`, `admin123`, `123456`) and username substrings.
    - *Email Sanitization & Normalization*: Lowercase and whitespace normalized with RFC compliance via `EmailStr`. Blocklist enforced across ~20 disposable mail domains (`tempmail`, `10minutemail`, `guerrillamail`, `mailinator`, etc.).
    - *Registration Anti-Enumeration*: Returns generic failure response on duplicate email attempts without confirming account existence. Added Confirm Password validation in UI.
    - *Cryptographic Hashing & JWT Integrity*: Explicitly configured bcrypt cost factor to 12 (`bcrypt__rounds=12`). JWT signed with 256-bit+ secure secret with minimal payload `{"sub": user_id, "exp": timestamp}`. Lifespan startup asserts `SECRET_KEY` length $\ge 32$ characters and rejects default development secrets.
  - **Injection & Input Validation Defenses**:
    - *Dynamic Sort Column Whitelist*: Strict validation of `sort_by` and `order` query parameters on `/api/assets` and `/api/vulns`, rejecting arbitrary column expressions or SQL fragments with `HTTP 422 Unprocessable Entity`.
    - *Command Injection Target Defenses*: Target validation rejects shell metacharacters (`;`, `&`, `|`, `` ` ``, `$`, `\n`, `\r`, `<`, `>`, `\`, quotes) before any subprocess invocation. Subprocesses strictly invoke list-based arguments (never `shell=True`).
    - *SSRF & Cloud Metadata Protection*: Explicitly prohibits targeting AWS/GCP cloud metadata IP `169.254.169.254` or hostnames (`metadata.google.internal`), with configurable `ENABLE_SSRF_PROTECTION`.
    - *Mass Assignment Protection*: Stripped sensitive columns (`is_seed`, `auto_created`, `role`, `owner_id`) from client-writable Pydantic schemas. Enforced string bounds across all schemas.
  - **API Rate Limiting, Middleware & Traffic Shaping**:
    - *Rate Limiting*: Tightened authentication limits to 10 req/min for login and 5 req/hour for registration with 15-minute brute-force lockout after 5 consecutive failures.
    - *Request Body Size Limit*: Middleware rejects payloads exceeding 1MB with `HTTP 413 Payload Too Large`.
    - *Enhanced Security Headers*: Injected `Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `X-XSS-Protection: 1; mode=block`, `Referrer-Policy: strict-origin-when-cross-origin`, and `Permissions-Policy`.
    - *Report Path Traversal Protection*: Download routes canonicalize paths using `os.path.realpath()` and verify containment strictly within `/app/reports`, returning `HTTP 404` for invalid or traversing paths.
    - *Sanitized Exception Handling*: Generic 500 error responses returned to clients with zero tracebacks leaked.
    - *Hardened Nginx Frontend*: Configured `server_tokens off;` and `autoindex off;` with security response headers.

- **Phase 8.10: Subdomain Discovery Reliability & Multi-Method Redundancy**:
  - **Problem Solved**:
    - Subfinder passive sources intermittently hang or fail when external OSINT APIs (`api.sub.md`, `scanmalware.com`, etc.) throttle, Cloudflare 523, or time out. A static subprocess timeout killed subfinder prematurely, collapsing discovered subdomains to 1 (apex domain) and bypassing internal origin servers (`115.241.211.x`) behind CDNs.
    - Public `crt.sh` servers frequently encounter `HTTP 502 Bad Gateway` and rate limits under heavy traffic.
  - **Redundant Multi-Method Architecture**:
    - *Method 1 (Subfinder Optimized)*: Invoked with `-all`, internal time budget `-max-time 1` (capped to 60s within subfinder), `-timeout 15`, and subprocess timeout of 90s with retry logic. Supports dynamic `/home/appuser/.config/subfinder/provider-config.yaml` generation when `SUBFINDER_VIRUSTOTAL_KEY` or `SUBFINDER_SECURITYTRAILS_KEY` environment variables are provided.
    - *Method 2 (Certificate Transparency + Secondary Passive Fallback)*: Queries `crt.sh` JSON API with automatic retry after 5s delay. If `crt.sh` fails (e.g. 502 Bad Gateway), immediately falls back to `HackerTarget` hostsearch API (`https://api.hackertarget.com/hostsearch/?q=<domain>`), extracting 30-50+ passive subdomains in <2s.
    - *Method 3 (Active DNS Infrastructure Brute-Force)*: High-speed concurrent DNS resolution (`socket.gethostbyname`) via `ThreadPoolExecutor(max_workers=10)` across 23 enterprise prefixes (`www`, `mail`, `webmail`, `ftp`, `smtp`, `ns1`, `ns2`, `vpn`, `api`, `dev`, `test`, `staging`, `portal`, `erp`, `crm`, `admin`, `cpanel`, `webdisk`, `autodiscover`, `autoconfig`, `campusone`, `admission`, `moodle`, `app`), guaranteeing discovery of critical enterprise origin hosts even with 100% passive source outages.
    - *Deduplicated Union*: Merges all three sources into a deduplicated set, ensuring apex domain presence and safe capping to 100 subdomains.
    - *Telemetry Breakdown & Transparency*: Emits real-time discovery breakdown (`subfinder: X, crt.sh: Y, brute: Z → total N`) displayed in the scan dossier reconnaissance badge. Automatically triggers a discovery notice banner if $\le 1$ subdomain is found.
    - *Privilege-Aware Firewall Evasion*: Fixed Nmap `-f` (packet fragmentation) flag by detecting non-root user execution (`os.geteuid() == 0`), ensuring origin servers (`115.241.211.x`) are deeply port-scanned without `fragscan requires root privileges` fatal errors.

- **Phase 8.11: Virtual Host Resolution & Origin Infrastructure Configuration Auditing**:
  - **Concept & Problem**:
    - When target applications are fronted by reverse proxies or CDNs (Cloudflare, Fastly, Akamai, CloudFront), traditional vulnerability scans hit edge IP caching or WAF blocks (e.g. Cloudflare Ray 104.21.x / 172.67.x) and never reach backend application servers.
    - Security posture auditing for authorized infrastructure requires discovering backend origin IPs and conducting non-destructive virtual host routing directly against origins to inspect true exposure, cipher suites, and misconfigurations.
  - **Backend Pipeline (`deep_scanner.py`)**:
    - *CDN Edge Identification (`_is_cdn_ip`)*: Validates target apex and subdomain IPs against known CDN IP blocks (Cloudflare, CloudFront, Akamai, Fastly).
    - *Origin Resolution & Discovery (`_resolve_and_verify_origin_infrastructure`)*:
      - Sibling subnet inference: Analyzes discovered live subdomains to extract real organization infrastructure ranges (e.g. `/24` subnets like `115.241.211.0/24`).
      - Local Docker network inference: Automatically scans sandbox subnets (`172.20.0.0/24`) during development/testing.
      - Virtual host verification: Employs `httpx -u https://<origin_ip> -header "Host: <domain>" -status-code -title -tech-detect -tls-verify false` to verify web endpoints responding to the virtual host domain. Matching HTTP status and title confirms origin mapping.
    - *Origin Configuration Auditing*:
      - Prioritized Port Scanning (Stage 3): Origin hosts are flagged with `is_cdn = False`, prioritizing deep port scanning and Nmap NSE vulnerability audits.
      - Origin Nuclei Scanning (Stage 4): Nuclei scans target the verified origin directly with `-header "Host: <domain>"`, capturing origin-level CVEs and misconfigurations.
      - Origin SSL/Cipher Auditing (Stage 5): Inspects origin TLS configuration and CN certificates directly.
      - Evidence Tagging: All findings discovered via direct origin routing are tagged with `[ORIGIN CONFIG AUDIT] via virtual host routing to <origin_ip> (Host: <host_header>)`.
  - **Schema & API Updates**:
    - `VulnerabilityBase`: Added `is_origin_direct: bool = False`.
    - `vulns.py`: Automatically computes `is_origin_direct` based on `[ORIGIN CONFIG AUDIT]` evidence tags.
  - **Frontend UI & Dossier Visuals**:
    - `Scans.jsx`: Dossier modal renders **Origin Infrastructure Map (VHost Routing & WAF Bypass)** table displaying Virtual Host Domain, Edge Proxy, Discovered Origin IP, Direct Response status code and title, and `CONFIRMED ✓` confidence chip.
    - `Badge.jsx` & `Vulnerabilities.jsx`: Renders amber `Origin-Direct` badge chip alongside verification status in the findings table and detail modal drawer.
  - **End-to-End Verification**:
    - Phase A Local Sandbox: Verified with `aegis-juice-shop` (`172.20.0.2:3000`) fronted by `aegis-proxy` (`172.20.0.6:8088`), successfully mapping origin with title `"OWASP Juice Shop"`.
    - Phase B Authorized Target: Verified against `cutm.ac.in` behind Cloudflare edge `172.67.158.164`, mapping 5 confirmed origins across `115.241.211.x` (`.179`, `.182`, `.183`, `.185`, `.178`).
    - Automated Playwright suite verified rendering and evidence transparency with 0 console errors.

- **Phase M0: AEGIS v2.0 Attack Lab Infrastructure & Safety Foundations**:
  - **Scope & Objectives**:
    - Build the containerized attack lab environment and safety foundations for AEGIS v2.0 without exploit execution or autonomous agents.
    - Provide an isolated target network (`aegis-lab-net`) where known vulnerable containers can be audited and safely tested.
  - **Isolated Lab Network (`aegis-lab-net`)**:
    - Dedicated Docker bridge network (`aegis-lab-net`) hosting vulnerable targets: `lab-wordpress` (WordPress 5.4 / PHP 7.2 Apache), `lab-mysql` (MySQL 5.7), and `lab-dvwa` (Damn Vulnerable Web Application).
    - `vulnerable-target` (`aegis-juice-shop`) joins both `default` and `aegis-lab-net`.
    - Targets do NOT publish ports to the host system, isolating them from external network ingress.
    - Dual-homed management services (`backend` and `metasploit`) join both `default` and `aegis-lab-net` to control scans and RPC communication.
  - **Containerized Metasploit RPC Daemon (`msfrpcd`)**:
    - Official image `metasploitframework/metasploit-framework` running `msfrpcd -P <MSF_RPC_PASSWORD> -S -a 0.0.0.0 -p 55553 -n -f` on port 55553.
    - Client bridge (`backend/app/services/agent/msf_client.py`) using `pymetasploit3` with instant telemetry extraction (`client.core.stats` returning 7,119+ module inventory in 0.01s).
    - Admin diagnostic API endpoint: `GET /api/agent/msf-status`.
  - **Database & Asset Classification**:
    - Added `is_lab: bool` column to `assets` table via Alembic migration `007_phase_m0_lab_infrastructure.py`.
    - Added `lab` value to `asset_environment_enum`.
    - Seed script `scripts/seed_lab.py` registers `lab-wordpress`, `lab-dvwa`, and marks `aegis-juice-shop` as lab targets (`is_lab=True`, `criticality=3`, `environment="lab"`).
    - Single-label Docker container hostnames (`lab-wordpress`, `lab-dvwa`) are recognized and resolved by `target_resolver.py`.
  - **Frontend Lab Awareness**:
    - Assets Page: Renders purple `🧪 LAB` badge alongside lab assets.
    - Vulnerabilities Drawer: Displays `🧪 Attack simulation available` banner and disabled placeholder button (`coming in v2.0`) for findings linked to lab assets.
  - **Safety Boundaries**:
    - Exploit execution capabilities are strictly bounded to lab targets (`is_lab=True`). Non-lab assets cannot be targeted with simulation payloads.

---

## 9. Operating Rules

- Never implement future phases early; only execute the phase explicitly requested.
- Verify every phase thoroughly with integration testing / browser verification before declaring completion.
- Ensure Docker container builds and services run cleanly.
- Maintain transparent communication and clarify ambiguities proactively.

