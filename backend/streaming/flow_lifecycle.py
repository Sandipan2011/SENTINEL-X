from __future__ import annotations

from datetime import datetime, timezone

from backend.ingest.aggregator import FlowAggregator
from backend.ingest.models import NetworkFlow


class FlowLifecycleManager:
    """
    Controls the lifecycle of passive network flows.

    Lifecycle:

        observed packet
              ↓
        active flow
              ↓
        inactivity timeout
              ↓
        finalized flow
    """

    def __init__(
        self,
        flow_timeout: float = 60.0,
    ):
        self.aggregator = FlowAggregator(
            flow_timeout=flow_timeout
        )

    def process(
        self,
        flow: NetworkFlow,
    ) -> tuple:
        """
        Add an observed flow event and return any flows
        that became inactive.
        """

        self.aggregator.add_packet(flow)

        finalized = self.aggregator.expire_flows(
            now=flow.timestamp
        )

        return finalized

    def flush(self) -> list:
        """
        Finalize every remaining active flow.
        """

        return self.aggregator.finalize_all()

    def active_count(self) -> int:
        return self.aggregator.get_active_flow_count()

    def clear(self):
        self.aggregator.clear()