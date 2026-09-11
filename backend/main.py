from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from backend.api.alerts import router as alerts_router
from backend.api.websocket import router as websocket_router
from backend.config.security import security_policy
from backend.config.settings import settings


# ============================================================
# SENTINEL-X APPLICATION
# ============================================================

app = FastAPI(
    title=settings.app_name,
    description=(
        "AI-Based Cyber Threat Detection Platform "
        "for Unidirectional IP Traffic"
    ),
    version=settings.app_version,
)


# ============================================================
# FRONTEND
# ============================================================

frontend_dir = (
    Path(__file__).resolve().parents[1]
    / "frontend"
)


# Mount frontend static files.
#
# Security note:
# This only serves local frontend assets.
# It does NOT provide any network-control capability.
#
app.mount(
    "/static",
    StaticFiles(directory=str(frontend_dir)),
    name="static",
)


# ============================================================
# API ROUTERS
# ============================================================

# PostgreSQL-backed alert REST API
#
# Provides:
#   GET /api/alerts
#   GET /api/alerts/stats
#   GET /api/alerts/{alert_id}
#
app.include_router(alerts_router)


# Real-time alert WebSocket
#
# Provides:
#   WS /ws/alerts
#
app.include_router(websocket_router)


# ============================================================
# ROOT
# ============================================================

@app.get("/")
async def root():
    """
    SENTINEL-X service information.
    """

    return {
        "service": settings.app_name,
        "status": "online",
        "version": settings.app_version,
        "mode": "read-only",
        "architecture": "passive-unidirectional-traffic-detection",
    }


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
async def health():
    """
    Basic application health endpoint.
    """

    return {
        "status": "ok",
        "service": settings.app_name,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ============================================================
# SECURITY POLICY
# ============================================================

@app.get("/security-policy")
async def get_security_policy():
    """
    Exposes the SENTINEL-X security boundary.

    SENTINEL-X is intentionally limited to passive
    observation and cybersecurity intelligence.
    """

    return security_policy()


# ============================================================
# DASHBOARD
# ============================================================

@app.get("/dashboard")
async def dashboard():
    """
    Serve the SOC dashboard frontend.
    """

    index_file = frontend_dir / "index.html"

    if not index_file.exists():
        return {
            "status": "frontend_not_found",
            "message": "SOC dashboard has not been created yet.",
        }

    return FileResponse(index_file)