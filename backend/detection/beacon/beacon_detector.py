from dataclasses import dataclass
from statistics import mean, pstdev
from typing import Any

from backend.features.window import FeatureWindow


@dataclass
class BeaconResult:
    detected: bool
    threat_class: str
    confidence: float
    severity: str
    evidence: dict[str, Any]


class BeaconDetector:
    """
    Passive botnet C2 beaconing detector.

    Looks for repeated communications between the same
    source and destination with relatively regular
    inter-arrival times.

    No connection, probing, scanning, or payload inspection
    is performed.
    """

    def __init__(
        self,
        minimum_connections: int = 5,
        regularity_threshold: float = 0.25,
        minimum_interval: float = 2.0,
    ):
        self.minimum_connections = minimum_connections
        self.regularity_threshold = regularity_threshold
        self.minimum_interval = minimum_interval

    def detect(
        self,
        window: FeatureWindow,
    ) -> list[BeaconResult]:

        results = []

        if not window.flows:
            return results

        conversations: dict[
            tuple[str, str, int | None],
            list[Any],
        ] = {}

        # Group flows by source, destination and destination port.
        for flow in window.flows:

            key = (
                flow.src_ip,
                flow.dst_ip,
                flow.dst_port,
            )

            conversations.setdefault(
                key,
                [],
            ).append(flow)

        for key, flows in conversations.items():

            if len(flows) < self.minimum_connections:
                continue

            flows.sort(
                key=lambda flow: flow.first_seen
            )

            timestamps = [
                flow.first_seen
                for flow in flows
            ]

            intervals = []

            for index in range(1, len(timestamps)):

                interval = (
                    timestamps[index]
                    - timestamps[index - 1]
                ).total_seconds()

                if interval > 0:
                    intervals.append(interval)

            if len(intervals) < (
                self.minimum_connections - 1
            ):
                continue

            average_interval = mean(intervals)

            if average_interval < self.minimum_interval:
                continue

            interval_stddev = pstdev(intervals)

            regularity = (
                interval_stddev / average_interval
                if average_interval > 0
                else float("inf")
            )

            detected = (
                regularity
                <= self.regularity_threshold
            )

            if not detected:
                continue

            regularity_score = max(
                0.0,
                1.0
                - (
                    regularity
                    / self.regularity_threshold
                ),
            )

            connection_score = min(
                1.0,
                len(flows)
                / (
                    self.minimum_connections * 2
                ),
            )

            confidence = min(
                1.0,
                (
                    regularity_score * 0.7
                    + connection_score * 0.3
                ),
            )

            if regularity <= 0.10:
                severity = "HIGH"

            elif regularity <= 0.18:
                severity = "MEDIUM"

            else:
                severity = "LOW"

            results.append(
                BeaconResult(
                    detected=True,
                    threat_class="C2_BEACONING",
                    confidence=round(
                        confidence,
                        4,
                    ),
                    severity=severity,
                    evidence={
                        "source_ip": key[0],
                        "destination_ip": key[1],
                        "destination_port": key[2],
                        "connection_count": len(flows),
                        "intervals": [
                            round(
                                interval,
                                4,
                            )
                            for interval in intervals
                        ],
                        "average_interval": round(
                            average_interval,
                            4,
                        ),
                        "interval_stddev": round(
                            interval_stddev,
                            4,
                        ),
                        "regularity": round(
                            regularity,
                            4,
                        ),
                        "regularity_threshold": (
                            self.regularity_threshold
                        ),
                        "window_seconds": (
                            window.window_seconds
                        ),
                    },
                )
            )

        return results