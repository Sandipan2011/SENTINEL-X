import time
from dataclasses import dataclass, field
from typing import Dict, Tuple

from .packet_parser import PacketEvent


@dataclass
class NetworkFlow:
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    protocol: str

    start_time: float
    last_seen: float

    packet_count: int = 0
    total_bytes: int = 0

    min_packet_size: int = 0
    max_packet_size: int = 0

    dns_queries: int = 0
    tls_connections: int = 0

    def add_packet(self, packet: PacketEvent) -> None:
        self.packet_count += 1
        self.total_bytes += packet.packet_length

        self.last_seen = packet.timestamp

        if self.min_packet_size == 0:
            self.min_packet_size = packet.packet_length
        else:
            self.min_packet_size = min(
                self.min_packet_size,
                packet.packet_length,
            )

        self.max_packet_size = max(
            self.max_packet_size,
            packet.packet_length,
        )

        if packet.dns_query:
            self.dns_queries += 1

        if packet.tls_sni:
            self.tls_connections += 1

    @property
    def duration(self) -> float:
        return max(0.0, self.last_seen - self.start_time)

    @property
    def packets_per_second(self) -> float:
        if self.duration <= 0:
            return float(self.packet_count)

        return self.packet_count / self.duration

    @property
    def bytes_per_second(self) -> float:
        if self.duration <= 0:
            return float(self.total_bytes)

        return self.total_bytes / self.duration

    def to_dict(self) -> dict:
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "start_time": self.start_time,
            "last_seen": self.last_seen,
            "duration": round(self.duration, 6),
            "packet_count": self.packet_count,
            "total_bytes": self.total_bytes,
            "min_packet_size": self.min_packet_size,
            "max_packet_size": self.max_packet_size,
            "packets_per_second": round(
                self.packets_per_second,
                3,
            ),
            "bytes_per_second": round(
                self.bytes_per_second,
                3,
            ),
            "dns_queries": self.dns_queries,
            "tls_connections": self.tls_connections,
        }


class FlowAggregator:

    def __init__(self, flow_timeout: float = 15.0):
        self.flow_timeout = flow_timeout

        # Directional flow key.
        self.flows: Dict[
            Tuple[str, str, int | None, int | None, str],
            NetworkFlow,
        ] = {}

    def process_packet(self, packet: PacketEvent) -> list[NetworkFlow]:

        if not packet.src_ip or not packet.dst_ip:
            return []

        key = (
            packet.src_ip,
            packet.dst_ip,
            packet.src_port,
            packet.dst_port,
            packet.protocol or "UNKNOWN",
        )

        current_time = packet.timestamp

        completed_flows = []

        # Check whether this directional flow already exists.
        flow = self.flows.get(key)

        if flow is None:
            flow = NetworkFlow(
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                src_port=packet.src_port,
                dst_port=packet.dst_port,
                protocol=packet.protocol or "UNKNOWN",
                start_time=current_time,
                last_seen=current_time,
            )

            self.flows[key] = flow

        # Expire old flow.
        elif current_time - flow.last_seen > self.flow_timeout:

            completed_flows.append(flow)

            flow = NetworkFlow(
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                src_port=packet.src_port,
                dst_port=packet.dst_port,
                protocol=packet.protocol or "UNKNOWN",
                start_time=current_time,
                last_seen=current_time,
            )

            self.flows[key] = flow

        flow.add_packet(packet)

        return completed_flows

    def flush(self) -> list[NetworkFlow]:
        flows = list(self.flows.values())
        self.flows.clear()

        return flows


if __name__ == "__main__":
    print("SENTINEL-X Flow Aggregator")
    print("Directional flow engine ready.")