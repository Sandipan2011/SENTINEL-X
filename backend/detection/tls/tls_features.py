from dataclasses import dataclass
from statistics import mean, pstdev
from typing import Any


@dataclass
class TLSFeatures:
    """
    Metadata-only TLS/QUIC feature representation.

    No encrypted payload is inspected or decrypted.
    """

    protocol: str
    tls_version: str | None
    fingerprint: str | None

    packet_count: int
    byte_count: int
    duration: float

    average_packet_size: float
    packet_size_stddev: float

    packets_per_second: float
    bytes_per_second: float

    forward_byte_ratio: float
    reverse_byte_ratio: float

    def as_dict(self) -> dict[str, Any]:
        return {
            "protocol": self.protocol,
            "tls_version": self.tls_version,
            "fingerprint": self.fingerprint,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "duration": round(self.duration, 4),
            "average_packet_size": round(
                self.average_packet_size,
                4,
            ),
            "packet_size_stddev": round(
                self.packet_size_stddev,
                4,
            ),
            "packets_per_second": round(
                self.packets_per_second,
                4,
            ),
            "bytes_per_second": round(
                self.bytes_per_second,
                4,
            ),
            "forward_byte_ratio": round(
                self.forward_byte_ratio,
                4,
            ),
            "reverse_byte_ratio": round(
                self.reverse_byte_ratio,
                4,
            ),
        }


class TLSFeatureExtractor:
    """
    Extract metadata-only features from an encrypted session.

    The extractor deliberately does NOT:
    - decrypt TLS
    - inspect HTTPS payloads
    - inspect application data
    - contact the remote endpoint
    """

    def extract(
        self,
        protocol: str,
        packet_sizes: list[int],
        duration: float,
        bytes_forward: int,
        bytes_reverse: int,
        tls_version: str | None = None,
        fingerprint: str | None = None,
    ) -> TLSFeatures:

        packet_count = len(packet_sizes)

        byte_count = (
            bytes_forward
            + bytes_reverse
        )

        safe_duration = max(
            duration,
            0.001,
        )

        average_packet_size = (
            mean(packet_sizes)
            if packet_sizes
            else 0.0
        )

        packet_size_stddev = (
            pstdev(packet_sizes)
            if len(packet_sizes) > 1
            else 0.0
        )

        packets_per_second = (
            packet_count
            / safe_duration
        )

        bytes_per_second = (
            byte_count
            / safe_duration
        )

        forward_byte_ratio = (
            bytes_forward / byte_count
            if byte_count > 0
            else 0.0
        )

        reverse_byte_ratio = (
            bytes_reverse / byte_count
            if byte_count > 0
            else 0.0
        )

        return TLSFeatures(
            protocol=protocol,
            tls_version=tls_version,
            fingerprint=fingerprint,
            packet_count=packet_count,
            byte_count=byte_count,
            duration=duration,
            average_packet_size=average_packet_size,
            packet_size_stddev=packet_size_stddev,
            packets_per_second=packets_per_second,
            bytes_per_second=bytes_per_second,
            forward_byte_ratio=forward_byte_ratio,
            reverse_byte_ratio=reverse_byte_ratio,
        )