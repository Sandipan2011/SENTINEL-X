from dataclasses import dataclass
from typing import Optional


@dataclass
class PacketEvent:
    timestamp: float
    src_ip: Optional[str]
    dst_ip: Optional[str]
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: Optional[str]
    packet_length: int
    dns_query: Optional[str] = None
    tls_sni: Optional[str] = None


def parse_packet_line(line: str) -> Optional[PacketEvent]:
    """
    Convert one TShark field-formatted line into a PacketEvent.

    Expected field order:

    timestamp
    ip.src
    ip.dst
    ipv6.src
    ipv6.dst
    tcp.srcport
    tcp.dstport
    udp.srcport
    udp.dstport
    ip.proto
    ipv6.nxt
    frame.len
    dns.qry.name
    tls.handshake.extensions_server_name
    """

    line = line.strip()

    if not line:
        return None

    fields = line.split("|")

    if len(fields) < 14:
        return None

    def get(index: int) -> str:
        return fields[index].strip()

    def to_int(value: str) -> Optional[int]:
        try:
            return int(value) if value else None
        except ValueError:
            return None

    def to_float(value: str) -> Optional[float]:
        try:
            return float(value) if value else None
        except ValueError:
            return None

    timestamp = to_float(get(0))

    if timestamp is None:
        return None

    # Support both IPv4 and IPv6.
    src_ip = get(1) or get(3) or None
    dst_ip = get(2) or get(4) or None

    # TCP or UDP port.
    src_port = to_int(get(5)) or to_int(get(7))
    dst_port = to_int(get(6)) or to_int(get(8))

    # IPv4 protocol number or IPv6 next-header number.
    protocol_number = get(9) or get(10) or None

    protocol_map = {
        "1": "ICMP",
        "6": "TCP",
        "17": "UDP",
        "58": "ICMPv6",
    }

    protocol = protocol_map.get(
        protocol_number,
        protocol_number
    )

    packet_length = to_int(get(11)) or 0

    dns_query = get(12) or None
    tls_sni = get(13) or None

    return PacketEvent(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        packet_length=packet_length,
        dns_query=dns_query,
        tls_sni=tls_sni,
    )