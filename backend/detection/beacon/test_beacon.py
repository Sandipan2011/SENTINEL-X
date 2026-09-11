from datetime import datetime, timedelta, timezone

from backend.detection.beacon.beacon_detector import (
    BeaconDetector,
)

from backend.features.window import FeatureWindow

from backend.ingest.flow import (
    FlowKey,
    FlowState,
)


def create_beacon_flow(
    source_ip: str,
    destination_ip: str,
    destination_port: int,
    timestamp: datetime,
):

    key = FlowKey.from_packet(
        src_ip=source_ip,
        src_port=50000,
        dst_ip=destination_ip,
        dst_port=destination_port,
        protocol="TCP",
    )

    flow = FlowState(
        key=key,
        first_seen=timestamp,
        last_seen=timestamp + timedelta(
            milliseconds=100
        ),
        src_ip=source_ip,
        dst_ip=destination_ip,
        src_port=50000,
        dst_port=destination_port,
    )

    flow.packets_forward = 2
    flow.bytes_forward = 120

    return flow


def main():

    window = FeatureWindow(
        window_seconds=60
    )

    source = "192.168.1.50"
    destination = "10.0.0.90"

    start = datetime.now(timezone.utc)

    # Simulate a beacon every 10 seconds.
    for i in range(7):

        timestamp = start + timedelta(
            seconds=i * 10
        )

        flow = create_beacon_flow(
            source_ip=source,
            destination_ip=destination,
            destination_port=443,
            timestamp=timestamp,
        )

        window.add_flow(flow)

    detector = BeaconDetector(
        minimum_connections=5,
        regularity_threshold=0.25,
        minimum_interval=2.0,
    )

    results = detector.detect(window)

    print("=" * 60)
    print("SENTINEL-X C2 BEACONING DETECTION TEST")
    print("=" * 60)

    print()

    print(
        "Flows in window      :",
        len(window.flows),
    )

    print(
        "Source               :",
        source,
    )

    print(
        "Destination          :",
        destination,
    )

    print(
        "Destination port     :",
        443,
    )

    print(
        "Expected interval    :",
        "10 seconds",
    )

    print()

    if not results:

        print(
            "No C2 beaconing detected."
        )

        return

    for result in results:

        print(
            "Detected   :",
            result.detected,
        )

        print(
            "Threat     :",
            result.threat_class,
        )

        print(
            "Confidence :",
            result.confidence,
        )

        print(
            "Severity   :",
            result.severity,
        )

        print()
        print("Evidence:")

        for key, value in result.evidence.items():

            print(
                f"  {key:30}: {value}"
            )


if __name__ == "__main__":
    main()