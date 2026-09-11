from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class SentinelAlert(BaseModel):
    """
    Standardized SENTINEL-X security alert.

    Every detection engine eventually gets converted
    into this common representation.
    """

    alert_id: str = Field(
        default_factory=lambda: str(uuid4())
    )

    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(
            timezone.utc
        )
    )

    threat_class: str

    severity: str

    confidence: float = Field(
        ge=0.0,
        le=1.0,
    )

    source_ip: str | None = None

    destination_ip: str | None = None

    source_port: int | None = None

    destination_port: int | None = None

    protocol: str | None = None

    evidence: dict[str, Any] = Field(
        default_factory=dict
    )

    detector: str

    status: str = "NEW"
 
    risk_score: float = Field(
    default=0.0,
    ge=0.0,
    le=100.0,
)

    description: str | None = None