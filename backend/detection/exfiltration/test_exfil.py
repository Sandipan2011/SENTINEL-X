from datetime import datetime, timedelta, timezone

from backend.detection.exfiltration.exfil_detector import (
    ExfiltrationDetector,
)

from backend.features.window import FeatureWindow

from backend.ingest.flow import (
    FlowKey,
    FlowState,
)


def create_flow(
    source_ip: str,
    destination_ip: str,
    outbound_bytes: int,
    inbound_bytes: int,
    timestamp: datetime,
):

    key = FlowKey.from_packet(
        src_ip=source_ip,
        src_port=50000,
        dst_ip=destination_ip,
        dst_port=443,
        protocol="TCP",
    )

    flow = FlowState(
        key=key,
        first_seen=timestamp,
        last_seen=timestamp + timedelta(
            seconds=2
        ),
        src_ip=source_ip,
        dst_ip=destination_ip,
        src_port=50000,
        dst_port=443,
    )

    flow.packets_forward = 100
    flow.packets_reverse = 10

    flow.bytes_forward = outbound_bytes
    flow.bytes_reverse = inbound_bytes

    return flow


def main():

    window = FeatureWindow(
        window_seconds=60
    )

    source = "192.168.1.50"

    destination = "203.0.113.50"

    start = datetime.now(timezone.utc)

    # Simulate repeated outbound transfers.
    flows = [
        create_flow(
            source_ip=source,
            destination_ip=destination,
            outbound_bytes=200_000,
            inbound_bytes=5_000,
            timestamp=start,
        ),
        create_flow(
            source_ip=source,
            destination_ip=destination,
            outbound_bytes=250_000,
            inbound_bytes=5_000,
            timestamp=start + timedelta(
                seconds=10
            ),
        ),
        create_flow(
            source_ip=source,
            destination_ip=destination,
            outbound_bytes=300_000,
            inbound_bytes=5_000,
            timestamp=start + timedelta(
                seconds=20
            ),
        ),
    ]

    for flow in flows:
        window.add_flow(flow)

    detector = ExfiltrationDetector(
        outbound_bytes_threshold=100_000,
        byte_ratio_threshold=10.0,
        flow_threshold=3,
    )

    results = detector.detect(
        window
    )

    print("=" * 60)
    print("SENTINEL-X DATA EXFILTRATION TEST")
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

    print()

    print(
        "Outbound bytes       :",
        sum(
            flow.bytes_forward
            for flow in window.flows
        ),
    )

    print(
        "Inbound bytes        :",
        sum(
            flow.bytes_reverse
            for flow in window.flows
        ),
    )

    print()

    if not results:

        print(
            "No data exfiltration detected."
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