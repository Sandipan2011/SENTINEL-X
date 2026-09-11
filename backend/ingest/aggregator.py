from __future__ import annotations

from datetime import datetime, timezone

from backend.ingest.flow import FlowKey, FlowState
from backend.ingest.models import NetworkFlow


class FlowAggregator:
    """
    Aggregates passive network observations into bidirectional flows.

    Security boundary:
    - No active scanning
    - No active probing
    - No packet transmission
    - No automated blocking
    - No payload decryption
    """

    def __init__(self, flow_timeout: float = 60.0):
        self.flow_timeout = flow_timeout
        self.flows: dict[FlowKey, FlowState] = {}

    def add_packet(self, flow: NetworkFlow) -> FlowState:
        """
        Add an observed network event to an active flow.
        """

        key = FlowKey.from_packet(
            src_ip=flow.src_ip,
            src_port=flow.src_port,
            dst_ip=flow.dst_ip,
            dst_port=flow.dst_port,
            protocol=flow.protocol,
        )

        state = self.flows.get(key)

        if state is None:
            state = FlowState(
                key=key,
                first_seen=flow.timestamp,
                last_seen=flow.timestamp,
                src_ip=flow.src_ip,
                dst_ip=flow.dst_ip,
                src_port=flow.src_port,
                dst_port=flow.dst_port,
            )

            self.flows[key] = state

        self._update_state(
            state=state,
            flow=flow,
        )

        return state

    @staticmethod
    def _update_state(
        state: FlowState,
        flow: NetworkFlow,
    ) -> None:
        """
        Update an existing FlowState with one observation.

        Direction is determined using the canonical FlowKey.
        """

        forward_endpoint = (
            state.src_ip,
            state.src_port,
        )

        reverse_endpoint = (
            state.dst_ip,
            state.dst_port,
        )

        observed_endpoint = (
            flow.src_ip,
            flow.src_port,
        )

        if observed_endpoint == forward_endpoint:
            state.packets_forward += flow.packets
            state.bytes_forward += flow.bytes

        elif observed_endpoint == reverse_endpoint:
            state.packets_reverse += flow.packets
            state.bytes_reverse += flow.bytes

        else:
            # This should normally never happen because the FlowKey
            # identifies the same endpoints.
            return

        if flow.timestamp > state.last_seen:
            state.last_seen = flow.timestamp

        if (
            flow.protocol.upper() == "TCP"
            and flow.tcp_flags
        ):
            state.tcp_flags.update(
                flag.strip().upper()
                for flag in flow.tcp_flags.split(",")
                if flag.strip()
            )

            flags = {
                flag.strip().upper()
                for flag in flow.tcp_flags.split(",")
                if flag.strip()
            }

            if "S" in flags and "A" not in flags:
                state.syn_packets += flow.packets

    def expire_flows(
        self,
        now: datetime | None = None,
    ) -> list[FlowState]:
        """
        Finalize flows that have been inactive longer than
        flow_timeout.
        """

        if now is None:
            now = datetime.now(timezone.utc)

        expired: list[FlowState] = []

        for key, state in list(self.flows.items()):

            age = (
                now - state.last_seen
            ).total_seconds()

            if age >= self.flow_timeout:
                expired.append(state)
                del self.flows[key]

        return expired

    def finalize_all(self) -> list[FlowState]:
        """
        Finalize all currently active flows.

        Used at the end of:
        - PCAP replay
        - controlled worker shutdown
        - test execution
        """

        finalized = list(self.flows.values())

        self.flows.clear()

        return finalized

    def get_active_flow_count(self) -> int:
        return len(self.flows)

    def clear(self) -> None:
        self.flows.clear()