from sqlalchemy.orm import Session

from backend.alerts.schema import SentinelAlert
from backend.database.models import AlertModel


def save_alert(
    db: Session,
    alert: SentinelAlert,
) -> AlertModel:
    alert_data = alert.model_dump()

    db_alert = AlertModel(
        alert_id=str(alert_data["alert_id"]),
        timestamp=alert_data["timestamp"],
        threat_class=alert_data["threat_class"],
        severity=alert_data["severity"],
        confidence=alert_data["confidence"],
        risk_score=alert_data["risk_score"],
        source_ip=alert_data.get("source_ip"),
        destination_ip=alert_data.get("destination_ip"),
        source_port=alert_data.get("source_port"),
        destination_port=alert_data.get("destination_port"),
        protocol=alert_data.get("protocol"),
        detector=alert_data["detector"],
        status=alert_data.get("status", "NEW"),
        description=alert_data.get("description"),
        evidence=alert_data.get("evidence", {}),
    )

    db.add(db_alert)
    db.commit()
    db.refresh(db_alert)

    return db_alert