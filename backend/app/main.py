"""AEGIS Vulnerability Management Platform - Main FastAPI Application.

Initializes middleware, routing, and global exception handling.
"""

import logging
from typing import Any, Dict
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.routes import auth, health
from app.core.config import settings

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("aegis")

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="AEGIS - Industry-Grade Continuous Vulnerability Management Platform",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS if isinstance(settings.CORS_ORIGINS, list) else [settings.CORS_ORIGINS],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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
