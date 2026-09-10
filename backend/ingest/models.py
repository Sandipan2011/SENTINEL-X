from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class NetworkFlow(BaseModel):
    """
    Standardized network flow representation used by SENTINEL-X.

    This model contains metadata only.
    No packet payload is stored or processed.
    """

    timestamp: datetime

    src_ip: str
    dst_ip: str

    src_port: Optional[int] = None
    dst_port: Optional[int] = None

    protocol: str

    packets: int = Field(default=1, ge=1)
    bytes: int = Field(default=0, ge=0)

    duration: float = Field(default=0.0, ge=0.0)

    tcp_flags: Optional[str] = None

    interface: Optional[str] = None