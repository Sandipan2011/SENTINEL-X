import subprocess
import shutil
from typing import Callable, Optional
from .flow_aggregator import FlowAggregator
from .packet_parser import PacketEvent, parse_packet_line


TSHARK_PATH = shutil.which("tshark") or r"C:\Program Files\Wireshark\tshark.exe"
INTERFACE = "4"


TSHARK_FIELDS = [
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "ip.proto",
    "ipv6.nxt",
    "frame.len",
    "dns.qry.name",
    "tls.handshake.extensions_server_name",
]


def build_command(interface: str = INTERFACE) -> list[str]:
    command = [
        TSHARK_PATH,
        "-i",
        interface,
        "-T",
        "fields",
        "-E",
        "separator=|",
        "-E",
        "occurrence=f",
        "-E",
        "aggregator=,",
    ]

    for field in TSHARK_FIELDS:
        command.extend(["-e", field])

    return command


def start_capture(
    callback: Optional[Callable[[PacketEvent], None]] = None,
    interface: str = INTERFACE,
) -> None:

    if not shutil.which("tshark") and TSHARK_PATH:
        print(f"[INFO] Using TShark: {TSHARK_PATH}")

    command = build_command(interface)

    print("[INFO] Starting SENTINEL-X passive packet capture...")
    print("[INFO] Interface:", interface)
    print("[INFO] Command:", " ".join(command))

    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    try:
        assert process.stdout is not None

        for line in process.stdout:
            event = parse_packet_line(line)

            if event is None:
                continue

            if callback:
                callback(event)
            else:
                print_event(event)

    except KeyboardInterrupt:
        print("\n[INFO] Capture stopped by user.")

    finally:
        if process.poll() is None:
            process.terminate()

        process.wait()


def print_event(event: PacketEvent) -> None:
    print(
        f"[PACKET] "
        f"{event.src_ip}:{event.src_port} -> "
        f"{event.dst_ip}:{event.dst_port} | "
        f"{event.protocol} | "
        f"{event.packet_length} bytes"
    )

    if event.dns_query:
        print(f"         DNS: {event.dns_query}")

    if event.tls_sni:
        print(f"         TLS SNI: {event.tls_sni}")


if __name__ == "__main__":

    aggregator = FlowAggregator(flow_timeout=15.0)

    def handle_packet(packet):
        completed_flows = aggregator.process_packet(packet)

        print(
            f"[PACKET] "
            f"{packet.src_ip}:{packet.src_port} -> "
            f"{packet.dst_ip}:{packet.dst_port} | "
            f"{packet.protocol} | "
            f"{packet.packet_length} bytes"
        )

        for flow in completed_flows:
            print("\n[FLOW COMPLETED]")
            print(flow.to_dict())
            print()

    start_capture(callback=handle_packet)