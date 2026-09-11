from dataclasses import dataclass
from typing import Any

from backend.detection.dns.dns_features import (
    DNSFeatureExtractor,
)


@dataclass
class DNSDetectionResult:
    detected: bool
    threat_class: str
    confidence: float
    severity: str
    evidence: dict[str, Any]


class DNSDetector:
    """
    Passive DGA and DNS tunneling detector.

    The detector analyzes DNS query metadata only.

    It never:
    - performs DNS resolution
    - contacts external systems
    - decrypts payloads
    - modifies network traffic
    """

    def __init__(
        self,
        entropy_threshold: float = 3.5,
        length_threshold: int = 50,
        digit_ratio_threshold: float = 0.30,
    ):
        self.entropy_threshold = entropy_threshold
        self.length_threshold = length_threshold
        self.digit_ratio_threshold = (
            digit_ratio_threshold
        )

        self.extractor = DNSFeatureExtractor()

    def detect(
        self,
        query: str,
    ) -> DNSDetectionResult:

        features = self.extractor.extract(
            query
        )

        signals = {
            "high_entropy": (
                features.entropy
                >= self.entropy_threshold
            ),
            "long_query": (
                features.query_length
                >= self.length_threshold
            ),
            "high_digit_ratio": (
                features.digit_ratio
                >= self.digit_ratio_threshold
            ),
            "deep_subdomain": (
                features.deep_subdomain
            ),
        }

        signal_count = sum(
            signals.values()
        )

        # Strong DNS tunneling/DGA indication.
        detected = signal_count >= 2

        if not detected:

            return DNSDetectionResult(
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
            + (
                min(
                    features.entropy
                    / self.entropy_threshold,
                    2.0,
                )
                * 0.10
            ),
        )

        if signal_count >= 4:
            severity = "CRITICAL"

        elif signal_count >= 3:
            severity = "HIGH"

        else:
            severity = "MEDIUM"

        # Separate likely tunneling from generic DGA-like behavior.
        if (
            features.query_length >= 60
            and features.entropy >= 3.8
            and features.digit_ratio >= 0.20
        ):
            threat_class = "DNS_TUNNELING"

        else:
            threat_class = "DGA_DOMAIN"

        return DNSDetectionResult(
            detected=True,
            threat_class=threat_class,
            confidence=round(
                confidence,
                4,
            ),
            severity=severity,
            evidence={
                **features.as_dict(),
                "signals": signals,
                "signals_triggered": signal_count,
            },
        )
        