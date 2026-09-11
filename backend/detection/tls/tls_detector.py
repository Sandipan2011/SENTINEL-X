from dataclasses import dataclass
from typing import Any

from backend.detection.tls.tls_features import (
    TLSFeatureExtractor,
)


@dataclass
class TLSDetectionResult:
    detected: bool
    threat_class: str
    confidence: float
    severity: str
    evidence: dict[str, Any]


class TLSDetector:
    """
    Passive encrypted-session anomaly detector.

    Uses TLS/QUIC metadata only.

    No payload decryption is performed.
    """

    def __init__(
        self,
        high_packet_rate: float = 100.0,
        high_byte_rate: float = 100000.0,
        asymmetric_ratio: float = 10.0,
        low_packet_variation: float = 5.0,
    ):
        self.high_packet_rate = high_packet_rate
        self.high_byte_rate = high_byte_rate
        self.asymmetric_ratio = asymmetric_ratio
        self.low_packet_variation = low_packet_variation

        self.extractor = TLSFeatureExtractor()

    def detect(
        self,
        protocol: str,
        packet_sizes: list[int],
        duration: float,
        bytes_forward: int,
        bytes_reverse: int,
        tls_version: str | None = None,
        fingerprint: str | None = None,
    ) -> TLSDetectionResult:

        protocol = protocol.upper()

        if protocol not in {
            "TLS",
            "QUIC",
        }:

            return TLSDetectionResult(
                detected=False,
                threat_class="NONE",
                confidence=0.0,
                severity="INFO",
                evidence={
                    "reason": (
                        "Unsupported encrypted "
                        "protocol"
                    ),
                    "protocol": protocol,
                },
            )

        features = self.extractor.extract(
            protocol=protocol,
            packet_sizes=packet_sizes,
            duration=duration,
            bytes_forward=bytes_forward,
            bytes_reverse=bytes_reverse,
            tls_version=tls_version,
            fingerprint=fingerprint,
        )

        signals = {}

        signals["high_packet_rate"] = (
            features.packets_per_second
            >= self.high_packet_rate
        )

        signals["high_byte_rate"] = (
            features.bytes_per_second
            >= self.high_byte_rate
        )

        # Detect strong traffic asymmetry.
        if (
            bytes_forward > 0
            and bytes_reverse > 0
        ):

            ratio = max(
                bytes_forward / bytes_reverse,
                bytes_reverse / bytes_forward,
            )

        elif (
            bytes_forward > 0
            or bytes_reverse > 0
        ):

            ratio = float("inf")

        else:
            ratio = 0.0

        signals["strong_asymmetry"] = (
            ratio >= self.asymmetric_ratio
        )

        signals["low_packet_variation"] = (
            features.packet_size_stddev
            <= self.low_packet_variation
            and features.packet_count >= 5
        )

        signal_count = sum(
            signals.values()
        )

        detected = signal_count >= 2

        if not detected:

            return TLSDetectionResult(
                detected=False,
                threat_class="NONE",
                confidence=0.0,
                severity="INFO",
                evidence={
                    **features.as_dict(),
                    "signals": signals,
                    "signals_triggered": signal_count,
                },
            )

        confidence = min(
            1.0,
            signal_count / 4
            + min(
                ratio
                / self.asymmetric_ratio,
                2.0,
            )
            * 0.10,
        )

        if signal_count >= 4:
            severity = "CRITICAL"

        elif signal_count >= 3:
            severity = "HIGH"

        else:
            severity = "MEDIUM"

        if protocol == "QUIC":
            threat_class = "QUIC_SUSPICIOUS"

        else:
            threat_class = "TLS_SUSPICIOUS"

        evidence = {
            **features.as_dict(),
            "byte_asymmetry_ratio": (
                round(ratio, 4)
                if ratio != float("inf")
                else "infinite"
            ),
            "signals": signals,
            "signals_triggered": signal_count,
        }

        return TLSDetectionResult(
            detected=True,
            threat_class=threat_class,
            confidence=round(
                confidence,
                4,
            ),
            severity=severity,
            evidence=evidence,
        )