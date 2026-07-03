"""
k8scan SaaS – FastAPI application entry point.

Run:
    uvicorn backend.main:app --reload --port 8000
"""
import os
import time

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.middleware.base import BaseHTTPMiddleware

from backend.config import get_settings
from backend.database import Base, engine
from backend.routes.auth import router as auth_router
from backend.routes.dashboard import router as dashboard_router
from backend.routes.payments import router as payments_router
from backend.routes.scans import router as scans_router

settings = get_settings()

# ── DB init ───────────────────────────────────────────────────────────────────
Base.metadata.create_all(bind=engine)

# ── Rate limiter ──────────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address, default_limits=["200/minute"])

# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="k8scan API",
    version="1.0.0",
    docs_url="/api/docs"   if settings.APP_ENV != "production" else None,
    redoc_url="/api/redoc" if settings.APP_ENV != "production" else None,
    openapi_url="/api/openapi.json" if settings.APP_ENV != "production" else None,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── Security headers middleware ───────────────────────────────────────────────

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"]    = "nosniff"
        response.headers["X-Frame-Options"]           = "DENY"
        response.headers["X-XSS-Protection"]          = "1; mode=block"
        response.headers["Referrer-Policy"]           = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"]        = "camera=(), microphone=(), geolocation=()"
        if settings.APP_ENV == "production":
            response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
        return response


# ── Request timing middleware ─────────────────────────────────────────────────

class TimingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start = time.perf_counter()
        response = await call_next(request)
        elapsed  = round((time.perf_counter() - start) * 1000, 1)
        response.headers["X-Response-Time"] = f"{elapsed}ms"
        return response


# ── Middleware stack (order matters) ─────────────────────────────────────────
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(TimingMiddleware)

# Trusted hosts – restrict to your domain in production
if settings.APP_ENV == "production":
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["k8scan.io", "www.k8scan.io", "api.k8scan.io"],
    )

# CORS – only allow configured frontend origin
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.FRONTEND_ORIGIN],
    allow_credentials=True,   # required for cookie-based auth
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Accept"],
    expose_headers=["X-Response-Time"],
    max_age=600,
)

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(auth_router)
app.include_router(dashboard_router)
app.include_router(scans_router)
app.include_router(payments_router)


# ── Global error handlers ─────────────────────────────────────────────────────

@app.exception_handler(404)
async def not_found(_request: Request, _exc):
    return JSONResponse(status_code=404, content={"detail": "Not found."})


@app.exception_handler(500)
async def server_error(_request: Request, _exc):
    return JSONResponse(status_code=500, content={"detail": "Internal server error."})


# ── Health check ──────────────────────────────────────────────────────────────

@app.get("/api/health", tags=["meta"])
async def health():
    return {"status": "ok", "service": "k8scan-api"}
