from dataclasses import dataclass
from typing import Any

from backend.ingest.flow import FlowState


@dataclass
class DDoSResult:
    """
    Result produced by the passive SYN-flood detector.
    """

    detected: bool
    threat_class: str
    confidence: float
    severity: str
    evidence: dict[str, Any]


class SynFloodDetector:
    """
    Passive SYN-flood detector.

    This detector analyzes observed TCP metadata only.

    It does NOT:
    - scan hosts
    - probe hosts
    - establish connections
    - modify firewalls
    - block IP addresses
    """

    def __init__(
        self,
        syn_rate_threshold: float = 20.0,
        syn_ratio_threshold: float = 0.80,
    ):
        self.syn_rate_threshold = syn_rate_threshold
        self.syn_ratio_threshold = syn_ratio_threshold

    def detect(
        self,
        flow: FlowState,
    ) -> DDoSResult:

        if flow.key.protocol != "TCP":

            return DDoSResult(
                detected=False,
                threat_class="NONE",
                confidence=0.0,
                severity="INFO",
                evidence={
                    "reason": "Non-TCP flow"
                },
            )

        duration = max(flow.duration, 0.001)

        syn_count = flow.syn_packets

        syn_rate = syn_count / duration

        syn_ratio = (
            syn_count / flow.packets
            if flow.packets > 0
            else 0.0
        )

        detected = (
            syn_rate >= self.syn_rate_threshold
            and syn_ratio >= self.syn_ratio_threshold
        )

        if detected:

            if syn_rate >= self.syn_rate_threshold * 5:
                severity = "CRITICAL"
            elif syn_rate >= self.syn_rate_threshold * 2:
                severity = "HIGH"
            else:
                severity = "MEDIUM"

            confidence = min(
                1.0,
                (
                    syn_rate / self.syn_rate_threshold
                    + syn_ratio
                ) / 2,
            )

            return DDoSResult(
                detected=True,
                threat_class="SYN_FLOOD",
                confidence=round(confidence, 4),
                severity=severity,
                evidence={
                    "syn_count": syn_count,
                    "syn_rate": round(syn_rate, 4),
                    "syn_ratio": round(syn_ratio, 4),
                    "total_packets": flow.packets,
                    "duration": round(duration, 4),
                    "src_ip": flow.src_ip,
                    "dst_ip": flow.dst_ip,
                    "dst_port": flow.dst_port,
                },
            )

        return DDoSResult(
            detected=False,
            threat_class="NONE",
            confidence=0.0,
            severity="INFO",
            evidence={
                "syn_count": syn_count,
                "syn_rate": round(syn_rate, 4),
                "syn_ratio": round(syn_ratio, 4),
            },
        )