from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from backend.config.security import security_policy
from backend.config.settings import settings
from backend.streaming.engine import alert_engine


app = FastAPI(
    title=settings.app_name,
    description=(
        "AI-Based Cyber Threat Detection Platform "
        "for Unidirectional IP Traffic"
    ),
    version=settings.app_version,
)

frontend_dir = Path(__file__).resolve().parents[1] / "frontend"
app.mount("/static", StaticFiles(directory=str(frontend_dir)), name="static")


@app.get("/")
async def root():
    return {
        "service": settings.app_name,
        "status": "online",
        "version": settings.app_version,
        "mode": "read-only",
    }


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": settings.app_name,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/security-policy")
async def get_security_policy():
    return security_policy()


@app.get("/api/alerts")
async def get_alerts():
    return {"alerts": alert_engine.latest_alerts or alert_engine.process([]), "count": len(alert_engine.latest_alerts or alert_engine.process([]))}


@app.get("/api/replay")
async def replay_alerts():
    result = alert_engine.replay(count=250)
    return result


@app.get("/dashboard")
async def dashboard():
    return FileResponse(frontend_dir / "index.html")