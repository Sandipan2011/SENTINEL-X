from datetime import datetime, timezone

from backend.features.window import FeatureWindow
from backend.ingest.flow import FlowKey, FlowState


def create_flow(
    source_ip: str,
    destination_ip: str,
    destination_port: int,
):
    timestamp = datetime.now(timezone.utc)

    key = FlowKey.from_packet(
        src_ip=source_ip,
        src_port=40000,
        dst_ip=destination_ip,
        dst_port=destination_port,
        protocol="TCP",
    )

    return FlowState(
        key=key,
        first_seen=timestamp,
        last_seen=timestamp,
        src_ip=source_ip,
        dst_ip=destination_ip,
        src_port=40000,
        dst_port=destination_port,
    )


def main():

    window = FeatureWindow(window_seconds=10)

    flows = [
        create_flow(
            "192.168.1.10",
            "10.0.0.20",
            22,
        ),
        create_flow(
            "192.168.1.10",
            "10.0.0.21",
            80,
        ),
        create_flow(
            "192.168.1.10",
            "10.0.0.22",
            443,
        ),
        create_flow(
            "192.168.1.20",
            "10.0.0.20",
            443,
        ),
    ]

    for flow in flows:
        window.add_flow(flow)

    print("=" * 60)
    print("SENTINEL-X STREAMING FEATURE WINDOW TEST")
    print("=" * 60)

    print()
    print("Flows in window       :", len(window.flows))
    print("Total packets         :", window.total_packets())
    print("Total bytes           :", window.total_bytes())

    print()
    print("Flows per source:")
    print(window.source_flow_counts())

    print()
    print("Flows per destination:")
    print(window.destination_flow_counts())

    print()
    print("Unique destinations per source:")
    print(window.source_destination_counts())

    print()
    print("Unique destination ports per source:")
    print(window.source_port_counts())


if __name__ == "__main__":
    main()