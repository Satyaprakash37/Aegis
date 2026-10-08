"""AEGIS Vulnerability Management Platform - Main FastAPI Application.

Initializes middleware, routing, rate limiting, security headers, and global exception handling.
"""

import logging
from contextlib import asynccontextmanager
from typing import Any, Dict
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded
from slowapi import _rate_limit_exceeded_handler

from app.api.routes import assets, auth, dashboard, health, notifications, reports, scans, vulns
from app.core.config import settings
from app.core.limiter import limiter

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("aegis")


from datetime import datetime, timezone
from sqlalchemy import select
from app.db.session import AsyncSessionLocal
from app.models.scan import Scan, ScanStatus

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle manager: Validate configuration, recover interrupted scans, and fail-fast on insecure settings."""
    logger.info("Initializing AEGIS SecOps Core v%s...", settings.VERSION)

    # Fail fast if SECRET_KEY is missing or dangerously insecure (min 32 chars)
    if not settings.SECRET_KEY or len(settings.SECRET_KEY.strip()) < 32:
        logger.critical("FATAL: SECRET_KEY is not configured or too short (minimum 32 characters required).")
        raise RuntimeError("Insecure configuration: SECRET_KEY must be at least 32 characters.")

    if settings.SECRET_KEY in [
        "super_secret_jwt_key_phase_0",
        "change_this_to_a_secure_random_string_in_production",
        "change_me_to_a_cryptographically_secure_random_key_min_32_chars",
    ]:
        logger.critical("FATAL: Default/insecure development SECRET_KEY detected. Refusing to run in secure mode.")
        raise RuntimeError("Insecure configuration: Default or placeholder SECRET_KEY is forbidden.")

    # Startup recovery routine: mark any lingering/stuck scans from previous runs as failed
    try:
        now_utc = datetime.now(timezone.utc)
        async with AsyncSessionLocal() as db:
            query = select(Scan).where(Scan.status.in_([ScanStatus.pending, ScanStatus.running]))
            result = await db.execute(query)
            stuck_scans = result.scalars().all()
            if stuck_scans:
                logger.warning(
                    "Detected %d stuck scan(s) from previous session. Marking as interrupted/failed...",
                    len(stuck_scans),
                )
                for s in stuck_scans:
                    s.status = ScanStatus.failed
                    s.completed_at = now_utc
                    s.raw_output = {
                        "error": "Scan execution interrupted by platform service restart or process termination.",
                        "error_type": "SystemInterruptionError",
                        "error_hint": "Restart the scan now that the platform services are fully operational.",
                        "failure_stage": "interrupted",
                    }
                await db.commit()
                logger.info("Recovered %d orphaned scan(s) cleanly.", len(stuck_scans))
    except Exception as e:
        logger.error("Failed to run startup stuck-scan recovery: %s", e)

    logger.info("Security hardening verified. Platform ready.")
    yield
    logger.info("Shutting down AEGIS SecOps Core...")


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="AEGIS - Industry-Grade Continuous Vulnerability Management Platform",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# Attach slowapi rate limiter to application state
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS Middleware (Restricted to configured frontend origins)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS if isinstance(settings.CORS_ORIGINS, list) else [settings.CORS_ORIGINS],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)


# Request Body Size Limit Middleware (Max 1MB)
MAX_BODY_SIZE = 1024 * 1024  # 1 Megabyte

@app.middleware("http")
async def limit_body_size(request: Request, call_next):
    """Enforce 1MB maximum payload size limit on incoming requests."""
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_BODY_SIZE:
                return JSONResponse(
                    status_code=413,
                    content={
                        "detail": "Request payload exceeds maximum allowed size of 1MB.",
                        "data": None,
                        "message": "Payload Too Large: maximum body size is 1MB.",
                        "status": "error",
                    },
                )
        except ValueError:
            pass
    return await call_next(request)


# Security Headers Middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Inject industry-standard security headers into all HTTP responses."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; "
        "font-src 'self' data:; "
        "connect-src 'self' http://localhost:8000 http://127.0.0.1:8000 ws:; "
        "frame-ancestors 'none';"
    )
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response


# Global Exception Handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """Handle standard HTTP exceptions with structured response format."""
    return JSONResponse(
        status_code=exc.status_code,
        headers=exc.headers,
        content={
            "detail": exc.detail,
            "data": None,
            "message": exc.detail,
            "status": "error",
        },
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Handle unhandled internal server exceptions."""
    logger.exception("Unhandled server exception: %s", exc)
    return JSONResponse(
        status_code=500,
        content={
            "detail": "Internal server error occurred.",
            "data": None,
            "message": "Internal server error occurred.",
            "status": "error",
        },
    )


# Include Routers
app.include_router(health.router)
app.include_router(auth.router, prefix="/api")
app.include_router(assets.router, prefix="/api")
app.include_router(scans.router, prefix="/api")
app.include_router(vulns.router, prefix="/api")
app.include_router(dashboard.router, prefix="/api")
app.include_router(reports.router, prefix="/api")
app.include_router(notifications.router, prefix="/api")
