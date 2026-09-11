from datetime import datetime, timedelta, timezone

from backend.detection.ddos.syn_flood import SynFloodDetector
from backend.ingest.flow import FlowKey, FlowState


def create_attack_flow():

    start = datetime.now(timezone.utc)

    key = FlowKey.from_packet(
        src_ip="192.168.100.50",
        src_port=40000,
        dst_ip="10.0.0.10",
        dst_port=443,
        protocol="TCP",
    )

    flow = FlowState(
        key=key,
        first_seen=start,
        last_seen=start + timedelta(seconds=1),
        src_ip="192.168.100.50",
        dst_ip="10.0.0.10",
        src_port=40000,
        dst_port=443,
    )

    # Simulate observed SYN metadata.
    flow.packets_forward = 100
    flow.packets_reverse = 0

    flow.bytes_forward = 6000
    flow.bytes_reverse = 0

    flow.tcp_flags = {"S"}

    flow.syn_packets = 100

    return flow


def main():

    detector = SynFloodDetector(
        syn_rate_threshold=20.0,
        syn_ratio_threshold=0.80,
    )

    flow = create_attack_flow()

    result = detector.detect(flow)

    print("=" * 60)
    print("SENTINEL-X SYN FLOOD DETECTOR TEST")
    print("=" * 60)

    print()
    print("Detected    :", result.detected)
    print("Threat      :", result.threat_class)
    print("Confidence  :", result.confidence)
    print("Severity    :", result.severity)

    print()
    print("Evidence:")

    for key, value in result.evidence.items():
        print(f"  {key:20}: {value}")


if __name__ == "__main__":
    main()