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


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle manager: Validate configuration and fail-fast on insecure settings."""
    logger.info("Initializing AEGIS SecOps Core v%s...", settings.VERSION)

    # Fail fast if SECRET_KEY is missing or dangerously insecure
    if not settings.SECRET_KEY or len(settings.SECRET_KEY.strip()) < 16:
        logger.critical("FATAL: SECRET_KEY is not configured or too short (minimum 16 characters required).")
        raise RuntimeError("Insecure configuration: SECRET_KEY must be at least 16 characters.")

    if settings.SECRET_KEY == "change_this_to_a_secure_random_string_in_production":
        logger.warning("SECURITY WARNING: Using default development SECRET_KEY. Ensure a cryptographically secure key is used in production!")

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


# Security Headers Middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Inject industry-standard security headers into all HTTP responses."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
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
