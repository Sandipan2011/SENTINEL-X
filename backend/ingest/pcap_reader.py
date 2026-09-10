from pathlib import Path
from typing import Iterator

from scapy.all import IP, IPv6, TCP, UDP, PcapReader

from backend.ingest.models import NetworkFlow


def read_pcap(file_path: str) -> Iterator[NetworkFlow]:
    """
    Read a PCAP file and convert packets into normalized flows.

    SENTINEL-X operates in passive read-only mode.

    Payload contents are intentionally ignored.
    """

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"PCAP file not found: {file_path}")

    if not path.is_file():
        raise ValueError(f"Path is not a file: {file_path}")

    with PcapReader(str(path)) as packets:

        for packet in packets:

            timestamp = packet.time

            src_ip = None
            dst_ip = None

            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst

            elif IPv6 in packet:
                src_ip = packet[IPv6].src
                dst_ip = packet[IPv6].dst

            else:
                continue

            src_port = None
            dst_port = None
            protocol = "OTHER"
            tcp_flags = None

            if TCP in packet:
                protocol = "TCP"
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                tcp_flags = str(packet[TCP].flags)

            elif UDP in packet:
                protocol = "UDP"
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport

            else:
                protocol = str(packet[IP].proto) if IP in packet else "OTHER"

            yield NetworkFlow(
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                packets=1,
                bytes=len(packet),
                tcp_flags=tcp_flags,
            )