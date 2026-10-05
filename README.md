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

## Project Status

- [x] **Phase 0:** Project Foundation & Docker Multi-Service Setup
- [ ] **Phase 1:** SQLAlchemy Models & Alembic Migrations
- [ ] **Phase 2:** Authentication & RBAC (JWT Bearer)
- [ ] **Phase 3:** Network Asset Inventory CRUD
- [ ] **Phase 4:** Nmap Engine & NVD CVE Enrichment
- [ ] **Phase 5:** Contextual Risk Engine & Interactive Analytics
- [ ] **Phase 6:** PDF / Excel Compliance Report Generation
- [ ] **Phase 7:** Seeding, Security Hardening & Platform Release
