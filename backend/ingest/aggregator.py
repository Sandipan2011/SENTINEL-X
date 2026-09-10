from typing import Dict, Iterable

from backend.ingest.flow import FlowKey, FlowState
from backend.ingest.models import NetworkFlow


class FlowAggregator:
    """
    Converts packet-level NetworkFlow records into
    bidirectional aggregated flows.

    This component only processes observed metadata.
    It does not transmit traffic or interact with endpoints.
    """

    def __init__(self):
        self.flows: Dict[FlowKey, FlowState] = {}

    def add_packet(self, packet: NetworkFlow) -> FlowState:
        key = FlowKey.from_packet(
            src_ip=packet.src_ip,
            src_port=packet.src_port,
            dst_ip=packet.dst_ip,
            dst_port=packet.dst_port,
            protocol=packet.protocol,
        )

        flow = self.flows.get(key)

        if flow is None:
            flow = FlowState(
                key=key,
                first_seen=packet.timestamp,
                last_seen=packet.timestamp,
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                src_port=packet.src_port,
                dst_port=packet.dst_port,
            )

            self.flows[key] = flow

        flow.last_seen = packet.timestamp

        forward = (
            packet.src_ip == flow.src_ip
            and packet.src_port == flow.src_port
            and packet.dst_ip == flow.dst_ip
            and packet.dst_port == flow.dst_port
        )

        if forward:
            flow.packets_forward += packet.packets
            flow.bytes_forward += packet.bytes
        else:
            flow.packets_reverse += packet.packets
            flow.bytes_reverse += packet.bytes

        if packet.tcp_flags:
            flow.tcp_flags.add(packet.tcp_flags)

        return flow

    def process(
        self,
        packets: Iterable[NetworkFlow],
    ) -> list[FlowState]:
        """
        Process a collection of packet-level records.
        """

        for packet in packets:
            self.add_packet(packet)

        return list(self.flows.values())

    def clear(self):
        """
        Remove all currently tracked flows.
        """

        self.flows.clear()