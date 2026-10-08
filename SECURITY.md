# AEGIS Security Policy & Hardening Documentation

## 1. Overview
AEGIS is an enterprise continuous vulnerability management platform designed for security operations centers (SOC). Because AEGIS interacts with active network scanning tools and sensitive infrastructure vulnerability findings, it adheres to rigorous defense-in-depth security standards.

---

## 2. OWASP Top 10 (2021) Mapping

| OWASP Category | Threat Description | AEGIS Security Control Implementation | Verification |
| :--- | :--- | :--- | :--- |
| **A01: Broken Access Control** | Unauthorized access to assets, scans, or findings belonging to another tenant / user (IDOR, mass assignment). | • Strict per-user data isolation via `owner_id` on assets and `created_by` on scans.<br>• IDOR prevention: All asset, scan, report, and vulnerability CRUD endpoints verify object ownership (`404 Not Found` returned on unowned resources).<br>• Mass assignment defense: Pydantic schemas explicitly strip sensitive internal columns (`is_seed`, `auto_created`, `role`, `owner_id`). | Test Case 5: User B cannot access, modify, or delete User A assets (HTTP 404). |
| **A02: Cryptographic Failures** | Compromised credentials, weak JWT tokens, or exposed secrets in transit. | • Bcrypt password hashing with explicit cost factor $\ge 12$ (`bcrypt__rounds=12`).<br>• JWT tokens signed using HS256 with strong 256-bit+ random secret keys.<br>• Lifespan validation enforces minimum 32-character `SECRET_KEY` and refuses to boot with insecure development defaults.<br>• Minimal JWT payload: Contains strictly `{"sub": user_id, "exp": timestamp}` (no email, role, or PII). | Startup assertion check; secret key rotation guidance. |
| **A03: Injection** | SQL injection on dynamic parameters; command injection on scanning targets. | • 100% SQLAlchemy 2.0 ORM query parameterization; zero raw SQL queries.<br>• Dynamic sorting whitelist validation: `sort_by` and `order` strictly checked against field whitelists, rejecting unknown strings with `HTTP 422`.<br>• Command injection defense: Target strings checked with `DANGEROUS_SHELL_CHARS` regex (`[;\`$|&><\n\r\t{}()\\\"']`), rejecting metacharacters before any subprocess execution.<br>• Subprocesses invoked strictly using argument arrays (never `shell=True`). | Test Case 1 (`sort_by` SQLi -> 422); Test Case 2 (Command injection targets -> 422). |
| **A04: Insecure Design** | Unrestricted resource exhaustion, brute-force credential stuffing, cloud metadata SSRF. | • Rate limiting: Login capped at 10 requests/min per IP; Registration capped at 5 requests/hour per IP.<br>• Account lockout: In-memory tracker triggers 15-minute temporary lock after 5 consecutive failed login attempts.<br>• Maximum concurrent scan quota: Capped at 5 active scans per user to prevent worker starvation.<br>• SSRF & Cloud Metadata blocking: Prohibits scanning `169.254.169.254`, `metadata.google.internal`, and configurable loopbacks. | Test Case 2 (Metadata blocked); Test Case 7 (Login rate limit -> 429). |
| **A05: Security Misconfiguration** | Missing security headers, permissive CORS, stack traces leaking in responses. | • HTTP Security Headers: `Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `X-XSS-Protection: 1; mode=block`, `Referrer-Policy: strict-origin-when-cross-origin`, and `Permissions-Policy`.<br>• Production-ready CORS restricted strictly to authorized origins.<br>• Sanitized global error handling: Server-side logs exceptions with tracebacks; clients receive generic 500 error messages with zero tracebacks.<br>• Nginx hardened with `server_tokens off;` and `autoindex off;`. | Verified on all responses. |
| **A06: Vulnerable and Outdated Components** | Vulnerabilities in external dependencies or container runtimes. | • Docker multi-stage builds with unprivileged system user `appuser` (UID 1001).<br>• Pinned binary versions for external security tools (`nuclei` v3.3.8, `subfinder` v2.16.0, `httpx` v1.12.0).<br>• Non-root container operation; restricted sudo only for `/usr/bin/nmap`. | Docker container audits. |
| **A07: Identification and Authentication Failures** | Weak passwords, credential stuffing, disposable email spam, email enumeration. | • Password policy: Minimum 12 characters, requiring uppercase, lowercase, numeric, and special characters.<br>• Dictionary and weak pattern rejection: Blocks passwords containing `password`, `qwerty`, `admin123`, `123456`, or email usernames.<br>• Disposable email domain blocklist: Rejects ~20 common temporary mail domains (`tempmail`, `10minutemail`, `guerrillamail`, etc.).<br>• Email enumeration protection: Registration responses return generic failure message without disclosing whether an email already exists in the database. | Test Case 3 (Weak passwords -> 422); Test Case 4 (Disposable emails -> 422). |
| **A08: Software and Data Integrity Failures** | Large payload buffer overflows, file path traversal. | • Payload body size limit: Middleware enforces 1MB maximum HTTP request body size, rejecting larger requests with `HTTP 413 Payload Too Large`.<br>• Path traversal check: Report downloads canonicalize file paths with `os.path.realpath()` and verify containment strictly within the designated `/app/reports` directory (`HTTP 404` on traversal). | Test Case 6 (Payload > 1MB -> 413); Test Case 8 (Path traversal -> 404). |
| **A09: Security Logging and Monitoring Failures** | Unaudited access, unmonitored security events. | • Structured logging across all scanner execution stages, authentication events, and authorization failures.<br>• In-app Security Notifications stream (`/api/notifications`) providing real-time telemetry on scan completions and verified exploit findings. | Topbar notification events. |
| **A10: Server-Side Request Forgery (SSRF)** | Scanner coerced into pivoting to internal services or cloud IAM metadata. | • Link-local cloud metadata IPs (`169.254.169.254`, `169.254.0.0/16`) and metadata hostnames explicitly blocked.<br>• Configurable `ENABLE_SSRF_PROTECTION` to block loopback targets in sensitive environments. | Test Case 2 (SSRF target -> 422). |

---

## 3. Setup & Production Hardening Guide

### 1. Cryptographic Key Generation & Rotation
Never use default development keys in production. Generate a cryptographically secure random key:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(48))"
```

Configure the generated key in `.env`:
```env
SECRET_KEY=your_generated_cryptographically_secure_key_here
```
> [!IMPORTANT]
> The backend server validates `SECRET_KEY` length on startup. If the key is shorter than 32 characters or matches a known development default, the service will refuse to start.

### 2. Database Isolation
In `docker-compose.yml`, PostgreSQL is exposed only internally on the Docker bridge network (`expose: 5432`). Do not bind port 5432 to host interfaces (`ports: ["5432:5432"]`) in production deployments.

### 3. Container Non-Root Enforcement
Both frontend (Nginx) and backend (FastAPI) run under unprivileged service users:
- Backend: `USER appuser` (UID 1001, GID 1001).
- Frontend: `nginx:alpine` runtime.

---

## 4. Reporting Security Vulnerabilities
If you identify a potential security vulnerability within AEGIS, please report it privately to the security engineering team at `security@aegis.internal`. Do not file public GitHub issues for security vulnerabilities.
