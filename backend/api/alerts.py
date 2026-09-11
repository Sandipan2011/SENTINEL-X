from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from backend.database.database import get_db
from backend.database.models import AlertModel


router = APIRouter(
    prefix="/api/alerts",
    tags=["Alerts"],
)


def alert_to_dict(alert: AlertModel) -> dict:
    return {
        "id": alert.id,
        "alert_id": alert.alert_id,
        "timestamp": alert.timestamp,
        "threat_class": alert.threat_class,
        "severity": alert.severity,
        "confidence": alert.confidence,
        "risk_score": alert.risk_score,
        "source_ip": alert.source_ip,
        "destination_ip": alert.destination_ip,
        "source_port": alert.source_port,
        "destination_port": alert.destination_port,
        "protocol": alert.protocol,
        "detector": alert.detector,
        "status": alert.status,
        "description": alert.description,
        "evidence": alert.evidence,
        "created_at": alert.created_at,
    }


@router.get("")
def get_alerts(
    limit: int = Query(
        default=50,
        ge=1,
        le=500,
    ),
    severity: str | None = None,
    threat_class: str | None = None,
    status: str | None = None,
    db: Session = Depends(get_db),
):
    """
    Return recent cybersecurity alerts.

    Filters are optional and are intended for
    the SOC dashboard.
    """

    statement = select(AlertModel)

    if severity:
        statement = statement.where(
            AlertModel.severity == severity
        )

    if threat_class:
        statement = statement.where(
            AlertModel.threat_class == threat_class
        )

    if status:
        statement = statement.where(
            AlertModel.status == status
        )

    statement = (
        statement
        .order_by(desc(AlertModel.created_at))
        .limit(limit)
    )

    alerts = db.scalars(statement).all()

    return {
        "count": len(alerts),
        "alerts": [
            alert_to_dict(alert)
            for alert in alerts
        ],
    }


@router.get("/stats")
def get_alert_statistics(
    db: Session = Depends(get_db),
):
    """
    Return high-level alert statistics
    for the SOC dashboard.
    """

    total = db.scalar(
        select(func.count(AlertModel.id))
    ) or 0

    critical = db.scalar(
        select(func.count(AlertModel.id))
        .where(
            AlertModel.severity == "CRITICAL"
        )
    ) or 0

    high = db.scalar(
        select(func.count(AlertModel.id))
        .where(
            AlertModel.severity == "HIGH"
        )
    ) or 0

    medium = db.scalar(
        select(func.count(AlertModel.id))
        .where(
            AlertModel.severity == "MEDIUM"
        )
    ) or 0

    low = db.scalar(
        select(func.count(AlertModel.id))
        .where(
            AlertModel.severity == "LOW"
        )
    ) or 0

    info = db.scalar(
        select(func.count(AlertModel.id))
        .where(
            AlertModel.severity == "INFO"
        )
    ) or 0

    new_alerts = db.scalar(
        select(func.count(AlertModel.id))
        .where(
            AlertModel.status == "NEW"
        )
    ) or 0

    return {
        "total": total,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "info": info,
        "new": new_alerts,
    }


@router.get("/{alert_id}")
def get_alert(
    alert_id: str,
    db: Session = Depends(get_db),
):
    """
    Return one alert by UUID.
    """

    statement = select(AlertModel).where(
        AlertModel.alert_id == alert_id
    )

    alert = db.scalar(statement)

    if alert is None:
        raise HTTPException(
            status_code=404,
            detail="Alert not found",
        )

    return alert_to_dict(alert)