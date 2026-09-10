from __future__ import annotations

from collections import deque
from typing import Any

from backend.detection.engine import detect_alerts
from backend.ingest.replay import generate_synthetic_replay


class AlertEngine:
    def __init__(self, max_events: int = 20000):
        self.history: deque[dict[str, Any]] = deque(maxlen=max_events)
        self.latest_alerts: list[dict[str, Any]] = []

    def process(self, flows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        for flow in flows:
            self.history.append(flow)
        self.latest_alerts = detect_alerts(list(self.history))
        return self.latest_alerts

    def replay(self, count: int = 250) -> dict[str, Any]:
        flows = generate_synthetic_replay(count=count)
        alerts = self.process(flows)
        return {
            "flow_count": len(flows),
            "alert_count": len(alerts),
            "alerts": alerts,
        }


alert_engine = AlertEngine()
