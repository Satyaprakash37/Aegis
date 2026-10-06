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
- `ip_address` (String(255), Unique, Indexed - target IP address or domain name)
- `target_type` (Enum: `ip`, `domain`, default `ip`)
- `resolved_ip` (String(45), Nullable - auto-resolved IPv4 for domain targets)
- `hostname` (String, Nullable)
- `asset_type` (Enum: `server`, `web`, `db`, `network`)
- `environment` (Enum: `production`, `staging`, `dev`)
- `criticality` (Integer, 1 to 5)
- `owner` (String)
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
- `verification` (Enum: `version_match`, `nse_verified`, `nuclei_verified`, default `version_match`)
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

## 5. Deep Active Verification Architecture (Phase 8)

Deep scanning moves beyond probabilistic banner matching to active, evidence-backed proof of exploitability using a 3-stage pipeline:

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

---

## 9. Operating Rules

- Never implement future phases early; only execute the phase explicitly requested.
- Verify every phase thoroughly with integration testing / browser verification before declaring completion.
- Ensure Docker container builds and services run cleanly.
- Maintain transparent communication and clarify ambiguities proactively.
