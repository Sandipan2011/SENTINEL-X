from typing import Any

from backend.ingest.flow import FlowState


class FlowFeatureExtractor:
    """
    Extract security-relevant features from an aggregated flow.

    SENTINEL-X only uses network metadata.
    Payload contents are never inspected or decrypted.
    """

    def extract(self, flow: FlowState) -> dict[str, Any]:

        duration = max(flow.duration, 0.001)

        packets_per_second = flow.packets / duration
        bytes_per_second = flow.bytes / duration

        forward_packet_ratio = (
            flow.packets_forward / flow.packets
            if flow.packets > 0
            else 0.0
        )

        reverse_packet_ratio = (
            flow.packets_reverse / flow.packets
            if flow.packets > 0
            else 0.0
        )

        forward_byte_ratio = (
            flow.bytes_forward / flow.bytes
            if flow.bytes > 0
            else 0.0
        )

        reverse_byte_ratio = (
            flow.bytes_reverse / flow.bytes
            if flow.bytes > 0
            else 0.0
        )

        return {
            # Flow identity
            "src_ip": flow.src_ip,
            "dst_ip": flow.dst_ip,
            "src_port": flow.src_port,
            "dst_port": flow.dst_port,
            "protocol": flow.key.protocol,

            # Volume
            "packets": flow.packets,
            "bytes": flow.bytes,
            "duration": flow.duration,

            # Traffic rate
            "packets_per_second": packets_per_second,
            "bytes_per_second": bytes_per_second,

            # Direction
            "packets_forward": flow.packets_forward,
            "packets_reverse": flow.packets_reverse,
            "bytes_forward": flow.bytes_forward,
            "bytes_reverse": flow.bytes_reverse,

            "forward_packet_ratio": forward_packet_ratio,
            "reverse_packet_ratio": reverse_packet_ratio,

            "forward_byte_ratio": forward_byte_ratio,
            "reverse_byte_ratio": reverse_byte_ratio,

            # Exfiltration signal
            "byte_ratio": flow.bytes_ratio,

            # TCP metadata
            "tcp_flags": (
                sorted(flow.tcp_flags)
                if flow.tcp_flags
                else []
            ),

            # Protocol indicators
            "is_tcp": flow.key.protocol == "TCP",
            "is_udp": flow.key.protocol == "UDP",

            "is_dns": (
                flow.key.protocol == "UDP"
                and flow.dst_port == 53
            ),

            "is_https": (
                flow.key.protocol == "TCP"
                and flow.dst_port == 443
            ),

            "is_tls": (
                flow.dst_port in (443, 8443)
                or flow.src_port in (443, 8443)
            ),
        }