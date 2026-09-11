from dataclasses import dataclass
from typing import Any

from backend.features.window import FeatureWindow


@dataclass
class VolumetricDDoSResult:
    """
    Result from the passive volumetric DDoS detector.
    """

    detected: bool
    threat_class: str
    confidence: float
    severity: str
    evidence: dict[str, Any]


class VolumetricDDoSDetector:
    """
    Detects suspicious traffic concentration across
    multiple observed flows.

    This detector is passive.

    It never:
    - scans
    - probes
    - connects
    - blocks
    - modifies firewall rules
    """

    def __init__(
        self,
        packet_rate_threshold: float = 100.0,
        source_threshold: int = 5,
        syn_rate_threshold: float = 50.0,
    ):
        self.packet_rate_threshold = packet_rate_threshold
        self.source_threshold = source_threshold
        self.syn_rate_threshold = syn_rate_threshold

    def detect(
        self,
        window: FeatureWindow,
    ) -> list[VolumetricDDoSResult]:

        results = []

        if not window.flows:
            return results

        destination_packets = (
            window.destination_packet_counts()
        )

        destination_sources = (
            window.destination_source_counts()
        )

        destination_syns = (
            window.destination_syn_counts()
        )

        duration = max(
            window.window_seconds,
            1,
        )

        for destination, packet_count in destination_packets.items():

            source_count = destination_sources.get(
                destination,
                0,
            )

            syn_count = destination_syns.get(
                destination,
                0,
            )

            packet_rate = packet_count / duration
            syn_rate = syn_count / duration

            volume_signal = (
                packet_rate >= self.packet_rate_threshold
            )

            distributed_signal = (
                source_count >= self.source_threshold
            )

            syn_signal = (
                syn_rate >= self.syn_rate_threshold
            )

            signal_count = sum(
                [
                    volume_signal,
                    distributed_signal,
                    syn_signal,
                ]
            )

            detected = signal_count >= 2

            if not detected:
                continue

            confidence = min(
                1.0,
                signal_count / 3
                + min(
                    packet_rate
                    / self.packet_rate_threshold,
                    2.0,
                ) * 0.1,
            )

            if signal_count == 3:
                severity = "CRITICAL"
            elif packet_rate >= (
                self.packet_rate_threshold * 2
            ):
                severity = "HIGH"
            else:
                severity = "MEDIUM"

            results.append(
                VolumetricDDoSResult(
                    detected=True,
                    threat_class="VOLUMETRIC_DDOS",
                    confidence=round(
                        confidence,
                        4,
                    ),
                    severity=severity,
                    evidence={
                        "destination_ip": destination,
                        "packet_count": packet_count,
                        "packet_rate": round(
                            packet_rate,
                            4,
                        ),
                        "unique_sources": source_count,
                        "syn_count": syn_count,
                        "syn_rate": round(
                            syn_rate,
                            4,
                        ),
                        "window_seconds": duration,
                        "volume_signal": volume_signal,
                        "distributed_signal": distributed_signal,
                        "syn_signal": syn_signal,
                    },
                )
            )

        return results