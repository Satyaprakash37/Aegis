# AEGIS - Vulnerability Management Platform

AEGIS is an enterprise-grade Continuous Vulnerability Management Platform designed to discover, track, enrich, prioritize, and remediate security vulnerabilities across organizational network infrastructure.

---

## Architecture Overview

- **Backend:** FastAPI (Python 3.11), SQLAlchemy 2.0 (asyncpg), PostgreSQL 16
- **Frontend:** React 18, Vite, Tailwind CSS (Dark SOC Theme), Recharts, Axios
- **Scanner Engine (Phase 4):** Nmap asynchronous network scanner
- **Threat Intelligence (Phase 4):** National Vulnerability Database (NVD API 2.0)
- **Prioritization (Phase 5):** Contextual composite risk scoring engine
- **Infrastructure:** Multi-stage Docker & Docker Compose

Refer to [ARCHITECTURE.md](ARCHITECTURE.md) for full architectural specifications and schema definitions.

---

## Repository Structure

```
aegis/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   └── routes/
│   │   │       └── health.py
│   │   ├── core/
│   │   │   └── config.py
│   │   ├── db/
│   │   │   └── session.py
│   │   └── main.py
│   ├── requirements.txt
│   ├── Dockerfile
│   └── .env.example
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── Sidebar.jsx
│   │   │   └── Topbar.jsx
│   │   ├── App.jsx
│   │   ├── main.jsx
│   │   └── index.css
│   ├── nginx.conf
│   ├── package.json
│   ├── tailwind.config.js
│   ├── vite.config.js
│   └── Dockerfile
├── docker-compose.yml
├── .gitignore
├── .env.example
├── ARCHITECTURE.md
└── README.md
```

---

## Quick Start (Docker Compose)

### 1. Clone & Configure Environment
```bash
cp .env.example .env
```

### 2. Start Services
```bash
docker compose up --build -d
```

### 3. Service Verification
- **Frontend Dashboard:** [http://localhost:3000](http://localhost:3000)
- **Backend API Docs (Swagger):** [http://localhost:8000/docs](http://localhost:8000/docs)
- **Health Check Endpoint:** [http://localhost:8000/health](http://localhost:8000/health)

---

## Core Features

- **Continuous Asset Inventory:** Complete IP and infrastructure management with criticality rankings (1-5), environment mapping, and real-time vulnerability aggregation.
- **Nmap Port Scanner:** Multi-threaded asynchronous port and service version scanner (Quick 100 ports & Full 1000 ports) running securely inside Docker.
- **NVD API 2.0 Threat Enrichment:** Automated CVE lookup by detected product, service, and version with CVSS v3.1 scoring.
- **Contextual Risk Prioritization:** Industry-standard composite scoring:
  $$\text{risk\_score} = \text{round}((\text{cvss\_score} \times 0.6) + (\text{criticality\_weight} \times 0.4), 2)$$
- **Cybersecurity Command Center:** Real-time SOC dashboard featuring live severity donut chart, 30-day vulnerability velocity area chart, top risky infrastructure nodes, and recent threat discoveries.
- **Report Generation Engine (Phase 6):**
  - **Executive Risk Briefing (PDF):** C-suite summary with risk posture statement, key metrics, top 10 riskiest findings, and prioritized strategic recommendations.
  - **Detailed Technical Audit (PDF):** Engineering dossier with full asset inventory, scan history, and all vulnerability dossiers grouped by target host.
  - **Compliance Audit Matrix (Excel):** Multi-sheet audit spreadsheet with auto-filters, frozen headers, severity color-coded cells, and SLA breakdown for regulatory compliance.

---

## Project Status

- [x] **Phase 0:** Project Foundation & Docker Multi-Service Setup
- [x] **Phase 1:** SQLAlchemy Models & Alembic Migrations
- [x] **Phase 2:** Authentication & RBAC (JWT Bearer)
- [x] **Phase 3:** Network Asset Inventory CRUD
- [x] **Phase 4:** Nmap Engine & NVD CVE Enrichment
- [x] **Phase 5:** Contextual Risk Engine & Interactive Analytics
- [x] **Phase 6:** PDF / Excel Compliance Report Generation
- [ ] **Phase 7:** Seeding, Security Hardening & Platform Release
