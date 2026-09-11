from typing import Any

from backend.alerts.schema import SentinelAlert
from backend.scoring.severity import calculate_risk_score


class AlertFactory:
    """
    Converts detector results into the common
    SENTINEL-X alert format.
    """

    @staticmethod
    def create(
        threat_class: str,
        severity: str,
        confidence: float,
        evidence: dict[str, Any],
        detector: str,
        source_ip: str | None = None,
        destination_ip: str | None = None,
        source_port: int | None = None,
        destination_port: int | None = None,
        protocol: str | None = None,
        description: str | None = None,
    ) -> SentinelAlert:

        risk_score = calculate_risk_score(
            confidence=confidence,
            severity=severity,
        )

        return SentinelAlert(
            threat_class=threat_class,
            severity=severity,
            confidence=confidence,
            risk_score=risk_score,
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=source_port,
            destination_port=destination_port,
            protocol=protocol,
            evidence=evidence,
            detector=detector,
            description=description,
        )