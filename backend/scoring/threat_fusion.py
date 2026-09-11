from dataclasses import dataclass
from typing import Any

from backend.alerts.factory import AlertFactory
from backend.alerts.schema import SentinelAlert


@dataclass
class FusionResult:
    """
    Result produced by the threat fusion engine.
    """

    alert: SentinelAlert
    correlated: bool = False


class ThreatFusionEngine:
    """
    Combines detection results into standardized
    SENTINEL-X security alerts.

    Responsibilities:

    - normalize detector output
    - calculate risk
    - preserve evidence
    - correlate related detections
    - suppress obvious duplicates
    """

    def __init__(self):

        self.recent_alerts: dict[
            tuple,
            SentinelAlert
        ] = {}

    def create_alert(
        self,
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
    ) -> FusionResult:

        alert = AlertFactory.create(
            threat_class=threat_class,
            severity=severity,
            confidence=confidence,
            evidence=evidence,
            detector=detector,
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=source_port,
            destination_port=destination_port,
            protocol=protocol,
            description=description,
        )

        key = (
            threat_class,
            source_ip,
            destination_ip,
            destination_port,
        )

        correlated = key in self.recent_alerts

        self.recent_alerts[key] = alert

        return FusionResult(
            alert=alert,
            correlated=correlated,
        )

    def clear(self):
        self.recent_alerts.clear()