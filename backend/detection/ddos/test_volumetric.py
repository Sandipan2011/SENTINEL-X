from datetime import datetime, timedelta, timezone

from backend.detection.ddos.volumetric import (
    VolumetricDDoSDetector,
)
from backend.features.window import FeatureWindow
from backend.ingest.flow import FlowKey, FlowState


def create_attack_flow(
    source_ip: str,
    destination_ip: str,
    destination_port: int,
):
    start = datetime.now(timezone.utc)

    key = FlowKey.from_packet(
        src_ip=source_ip,
        src_port=40000,
        dst_ip=destination_ip,
        dst_port=destination_port,
        protocol="TCP",
    )

    flow = FlowState(
        key=key,
        first_seen=start,
        last_seen=start + timedelta(seconds=1),
        src_ip=source_ip,
        dst_ip=destination_ip,
        src_port=40000,
        dst_port=destination_port,
    )

    flow.packets_forward = 50
    flow.bytes_forward = 3000

    flow.tcp_flags = {"S"}
    flow.syn_packets = 50

    return flow


def main():

    window = FeatureWindow(
        window_seconds=10
    )

    # Simulated observed traffic from
    # multiple source IPs targeting one destination.
    sources = [
        "192.168.1.10",
        "192.168.1.11",
        "192.168.1.12",
        "192.168.1.13",
        "192.168.1.14",
        "192.168.1.15",
    ]

    for source in sources:

        flow = create_attack_flow(
            source_ip=source,
            destination_ip="10.0.0.50",
            destination_port=443,
        )

        window.add_flow(flow)

    detector = VolumetricDDoSDetector(
        packet_rate_threshold=20.0,
        source_threshold=5,
        syn_rate_threshold=20.0,
    )

    results = detector.detect(window)

    print("=" * 60)
    print("SENTINEL-X VOLUMETRIC DDOS TEST")
    print("=" * 60)

    print()
    print("Flows in window :", len(window.flows))

    print(
        "Unique sources  :",
        window.destination_source_counts(),
    )

    print(
        "Packets         :",
        window.destination_packet_counts(),
    )

    print(
        "SYN packets     :",
        window.destination_syn_counts(),
    )

    print()

    if not results:

        print("No volumetric DDoS detected.")

        return

    for result in results:

        print("Detected   :", result.detected)
        print("Threat     :", result.threat_class)
        print("Confidence :", result.confidence)
        print("Severity   :", result.severity)

        print()
        print("Evidence:")

        for key, value in result.evidence.items():
            print(
                f"  {key:25}: {value}"
            )


if __name__ == "__main__":
    main()