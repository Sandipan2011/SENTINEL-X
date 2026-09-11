from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class FlowEvent(BaseModel):
    """
    Event representing an observed network flow.

    SENTINEL-X is passive:
    - no probing
    - no scanning
    - no blocking
    - no return traffic
    - no payload inspection
    """

    event_id: str

    timestamp: datetime

    src_ip: str
    dst_ip: str

    src_port: int | None = None
    dst_port: int | None = None

    protocol: str

    packets: int = Field(default=0, ge=0)
    bytes: int = Field(default=0, ge=0)

    duration: float = Field(default=0.0, ge=0.0)

    packets_per_second: float = 0.0
    bytes_per_second: float = 0.0

    packets_forward: int = 0
    packets_reverse: int = 0

    bytes_forward: int = 0
    bytes_reverse: int = 0

    tcp_flags: list[str] = Field(
        default_factory=list
    )

    metadata: dict[str, Any] = Field(
        default_factory=dict
    )