from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass(frozen=True)
class FlowKey:
    """
    Unique identifier for a bidirectional network flow.

    The endpoints are normalized so that traffic in either
    direction belongs to the same flow.
    """

    endpoint_a: tuple
    endpoint_b: tuple
    protocol: str

    @classmethod
    def from_packet(
        cls,
        src_ip: str,
        src_port: Optional[int],
        dst_ip: str,
        dst_port: Optional[int],
        protocol: str,
    ):
        endpoint_a = (src_ip, src_port)
        endpoint_b = (dst_ip, dst_port)

        if endpoint_a <= endpoint_b:
            first = endpoint_a
            second = endpoint_b
        else:
            first = endpoint_b
            second = endpoint_a

        return cls(
            endpoint_a=first,
            endpoint_b=second,
            protocol=protocol,
        )


@dataclass
class FlowState:
    """
    Aggregated bidirectional flow state.
    """

    key: FlowKey

    first_seen: datetime
    last_seen: datetime

    packets_forward: int = 0
    packets_reverse: int = 0

    bytes_forward: int = 0
    bytes_reverse: int = 0

    src_ip: str = ""
    dst_ip: str = ""

    src_port: Optional[int] = None
    dst_port: Optional[int] = None

    tcp_flags: set[str] | None = None

    def __post_init__(self):
        if self.tcp_flags is None:
            self.tcp_flags = set()

    @property
    def packets(self) -> int:
        return self.packets_forward + self.packets_reverse

    @property
    def bytes(self) -> int:
        return self.bytes_forward + self.bytes_reverse

    @property
    def duration(self) -> float:
        return (
            self.last_seen - self.first_seen
        ).total_seconds()

    @property
    def bytes_ratio(self) -> float:
        """
        Outbound/return traffic ratio.

        Useful later for exfiltration analysis.
        """

        if self.bytes_reverse == 0:
            return float("inf") if self.bytes_forward > 0 else 0.0

        return self.bytes_forward / self.bytes_reverse