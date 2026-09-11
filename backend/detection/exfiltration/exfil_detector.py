from dataclasses import dataclass
from typing import Any

from backend.features.window import FeatureWindow


@dataclass
class ExfiltrationResult:
    detected: bool
    threat_class: str
    confidence: float
    severity: str
    evidence: dict[str, Any]


class ExfiltrationDetector:
    """
    Passive data-exfiltration detector.

    Detects unusual outbound traffic patterns using
    network-flow metadata.

    No packet payload is inspected or decrypted.
    """

    def __init__(
        self,
        outbound_bytes_threshold: int = 100_000,
        byte_ratio_threshold: float = 10.0,
        flow_threshold: int = 3,
    ):
        self.outbound_bytes_threshold = (
            outbound_bytes_threshold
        )

        self.byte_ratio_threshold = (
            byte_ratio_threshold
        )

        self.flow_threshold = flow_threshold

    def detect(
        self,
        window: FeatureWindow,
    ) -> list[ExfiltrationResult]:

        results = []

        if not window.flows:
            return results

        source_data: dict[str, dict[str, Any]] = {}

        for flow in window.flows:

            source = flow.src_ip

            if source not in source_data:
                source_data[source] = {
                    "outbound_bytes": 0,
                    "inbound_bytes": 0,
                    "flow_count": 0,
                    "destinations": set(),
                }

            data = source_data[source]

            data["outbound_bytes"] += (
                flow.bytes_forward
            )

            data["inbound_bytes"] += (
                flow.bytes_reverse
            )

            data["flow_count"] += 1

            data["destinations"].add(
                flow.dst_ip
            )

        for source, data in source_data.items():

            outbound_bytes = data[
                "outbound_bytes"
            ]

            inbound_bytes = data[
                "inbound_bytes"
            ]

            flow_count = data[
                "flow_count"
            ]

            destination_count = len(
                data["destinations"]
            )

            if inbound_bytes > 0:

                byte_ratio = (
                    outbound_bytes
                    / inbound_bytes
                )

            elif outbound_bytes > 0:

                byte_ratio = float("inf")

            else:

                byte_ratio = 0.0

            outbound_signal = (
                outbound_bytes
                >= self.outbound_bytes_threshold
            )

            ratio_signal = (
                byte_ratio
                >= self.byte_ratio_threshold
            )

            flow_signal = (
                flow_count
                >= self.flow_threshold
            )

            signal_count = sum(
                [
                    outbound_signal,
                    ratio_signal,
                    flow_signal,
                ]
            )

            # Require substantial outbound traffic and
            # either strong asymmetry or repeated flows.
            detected = (
                outbound_signal
                and (
                    ratio_signal
                    or flow_signal
                )
            )

            if not detected:
                continue

            volume_score = min(
                1.0,
                outbound_bytes
                / (
                    self.outbound_bytes_threshold
                    * 5
                ),
            )

            ratio_score = min(
                1.0,
                (
                    byte_ratio
                    / (
                        self.byte_ratio_threshold
                        * 5
                    )
                )
                if byte_ratio != float("inf")
                else 1.0,
            )

            flow_score = min(
                1.0,
                flow_count
                / (
                    self.flow_threshold
                    * 5
                ),
            )

            confidence = min(
                1.0,
                (
                    volume_score * 0.45
                    + ratio_score * 0.35
                    + flow_score * 0.20
                ),
            )

            if (
                outbound_bytes
                >= self.outbound_bytes_threshold * 10
            ):
                severity = "CRITICAL"

            elif (
                outbound_bytes
                >= self.outbound_bytes_threshold * 5
            ):
                severity = "HIGH"

            else:
                severity = "MEDIUM"

            results.append(
                ExfiltrationResult(
                    detected=True,
                    threat_class="DATA_EXFILTRATION",
                    confidence=round(
                        confidence,
                        4,
                    ),
                    severity=severity,
                    evidence={
                        "source_ip": source,
                        "outbound_bytes": outbound_bytes,
                        "inbound_bytes": inbound_bytes,
                        "byte_ratio": (
                            round(byte_ratio, 4)
                            if byte_ratio != float("inf")
                            else "infinite"
                        ),
                        "flow_count": flow_count,
                        "destination_count": (
                            destination_count
                        ),
                        "outbound_signal": (
                            outbound_signal
                        ),
                        "ratio_signal": ratio_signal,
                        "flow_signal": flow_signal,
                        "signals_triggered": (
                            signal_count
                        ),
                        "window_seconds": (
                            window.window_seconds
                        ),
                    },
                )
            )

        return results