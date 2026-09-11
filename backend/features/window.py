from collections import defaultdict
from datetime import datetime, timedelta

from backend.ingest.flow import FlowState


class FeatureWindow:
    """
    Maintains a bounded time window of observed network flows.

    The window is used to calculate behavioral security
    features across multiple flows.

    SENTINEL-X remains completely passive and read-only.
    """

    def __init__(self, window_seconds: int = 10):
        self.window_seconds = window_seconds
        self.flows: list[FlowState] = []

    def add_flow(self, flow: FlowState) -> None:
        """
        Add an observed flow and remove expired flows.
        """

        self.flows.append(flow)
        self._cleanup(flow.last_seen)

    def _cleanup(self, current_time: datetime) -> None:
        cutoff = current_time - timedelta(
            seconds=self.window_seconds
        )

        self.flows = [
            flow
            for flow in self.flows
            if flow.last_seen >= cutoff
        ]

    def source_flow_counts(self) -> dict[str, int]:
        counts = defaultdict(int)

        for flow in self.flows:
            counts[flow.src_ip] += 1

        return dict(counts)

    def destination_flow_counts(self) -> dict[str, int]:
        counts = defaultdict(int)

        for flow in self.flows:
            counts[flow.dst_ip] += 1

        return dict(counts)

    def source_destination_counts(self) -> dict[str, int]:
        destinations = defaultdict(set)

        for flow in self.flows:
            destinations[flow.src_ip].add(flow.dst_ip)

        return {
            source: len(destinations_set)
            for source, destinations_set in destinations.items()
        }

    def source_port_counts(self) -> dict[str, int]:
        ports = defaultdict(set)

        for flow in self.flows:
            if flow.dst_port is not None:
                ports[flow.src_ip].add(flow.dst_port)

        return {
            source: len(port_set)
            for source, port_set in ports.items()
        }

    def destination_source_counts(self) -> dict[str, int]:
        """
        Number of unique source IPs communicating with
        each destination.

        Useful for distributed flooding detection.
        """

        sources = defaultdict(set)

        for flow in self.flows:
            sources[flow.dst_ip].add(flow.src_ip)

        return {
            destination: len(source_set)
            for destination, source_set in sources.items()
        }

    def destination_packet_counts(self) -> dict[str, int]:
        """
        Total packets received by each destination.
        """

        counts = defaultdict(int)

        for flow in self.flows:
            counts[flow.dst_ip] += flow.packets

        return dict(counts)

    def destination_byte_counts(self) -> dict[str, int]:
        """
        Total bytes associated with each destination.
        """

        counts = defaultdict(int)

        for flow in self.flows:
            counts[flow.dst_ip] += flow.bytes

        return dict(counts)

    def destination_syn_counts(self) -> dict[str, int]:
        """
        Total observed SYN packets targeting each destination.
        """

        counts = defaultdict(int)

        for flow in self.flows:
            counts[flow.dst_ip] += flow.syn_packets

        return dict(counts)

    def total_packets(self) -> int:
        return sum(
            flow.packets
            for flow in self.flows
        )

    def total_bytes(self) -> int:
        return sum(
            flow.bytes
            for flow in self.flows
        )

    def clear(self) -> None:
        self.flows.clear()