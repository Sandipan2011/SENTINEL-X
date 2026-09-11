from dataclasses import dataclass
from typing import Any

from backend.features.window import FeatureWindow


@dataclass
class ReconResult:
    detected: bool
    threat_class: str
    confidence: float
    severity: str
    evidence: dict[str, Any]


class PortScanDetector:
    """
    Passive reconnaissance / port-scan detector.

    Detects sources that communicate with many
    destination ports or hosts inside a short
    observation window.

    SENTINEL-X never performs scanning or probing.
    """

    def __init__(
        self,
        port_threshold: int = 10,
        host_threshold: int = 10,
        flow_threshold: int = 15,
    ):
        self.port_threshold = port_threshold
        self.host_threshold = host_threshold
        self.flow_threshold = flow_threshold

    def detect(
        self,
        window: FeatureWindow,
    ) -> list[ReconResult]:

        results = []

        if not window.flows:
            return results

        source_ports = {}
        source_hosts = {}
        source_flows = {}

        for flow in window.flows:

            source = flow.src_ip

            if source not in source_ports:
                source_ports[source] = set()

            if source not in source_hosts:
                source_hosts[source] = set()

            source_flows[source] = (
                source_flows.get(source, 0) + 1
            )

            if flow.dst_port is not None:
                source_ports[source].add(
                    flow.dst_port
                )

            source_hosts[source].add(
                flow.dst_ip
            )

        for source in source_flows:

            unique_ports = len(
                source_ports.get(source, set())
            )

            unique_hosts = len(
                source_hosts.get(source, set())
            )

            flow_count = source_flows[source]

            port_signal = (
                unique_ports >= self.port_threshold
            )

            host_signal = (
                unique_hosts >= self.host_threshold
            )

            flow_signal = (
                flow_count >= self.flow_threshold
            )

            signal_count = sum(
                [
                    port_signal,
                    host_signal,
                    flow_signal,
                ]
            )

            # Port scan:
            # at least one strong scan characteristic
            detected = (
                port_signal
                or host_signal
            ) and flow_signal

            if not detected:
                continue

            confidence = min(
                1.0,
                (
                    (unique_ports / self.port_threshold)
                    + (unique_hosts / self.host_threshold)
                    + (flow_count / self.flow_threshold)
                ) / 3,
            )

            if (
                unique_ports >= self.port_threshold * 3
                or unique_hosts >= self.host_threshold * 3
            ):
                severity = "CRITICAL"

            elif (
                unique_ports >= self.port_threshold * 2
                or unique_hosts >= self.host_threshold * 2
            ):
                severity = "HIGH"

            else:
                severity = "MEDIUM"

            results.append(
                ReconResult(
                    detected=True,
                    threat_class="PORT_SCAN",
                    confidence=round(
                        confidence,
                        4,
                    ),
                    severity=severity,
                    evidence={
                        "source_ip": source,
                        "unique_destination_ports": unique_ports,
                        "unique_destination_hosts": unique_hosts,
                        "flow_count": flow_count,
                        "port_signal": port_signal,
                        "host_signal": host_signal,
                        "flow_signal": flow_signal,
                        "signals_triggered": signal_count,
                        "window_seconds": window.window_seconds,
                    },
                )
            )

        return results