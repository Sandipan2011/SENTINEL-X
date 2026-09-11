from datetime import datetime, timedelta, timezone

from backend.ingest.flow import (
    FlowKey,
    FlowState,
)
from backend.streaming.detector_pipeline import (
    DetectionPipeline,
)


def create_flow(
    source_ip: str,
    destination_ip: str,
    destination_port: int,
    timestamp: datetime,
):
    key = FlowKey.from_packet(
        src_ip=source_ip,
        src_port=40000,
        dst_ip=destination_ip,
        dst_port=destination_port,
        protocol="TCP",
    )

    flow = FlowState(
        key=key,
        first_seen=timestamp,
        last_seen=timestamp + timedelta(
            seconds=1
        ),
        src_ip=source_ip,
        dst_ip=destination_ip,
        src_port=40000,
        dst_port=destination_port,
    )

    flow.packets_forward = 50
    flow.bytes_forward = 3000
    flow.syn_packets = 50
    flow.tcp_flags = {"S"}

    return flow


def main():

    print("=" * 70)
    print("SENTINEL-X REAL-TIME DETECTION PIPELINE TEST")
    print("=" * 70)

    pipeline = DetectionPipeline(
        window_seconds=10
    )

    timestamp = datetime.now(
        timezone.utc
    )

    # --------------------------------------------------
    # Simulated observed attack traffic
    #
    # This is NOT active traffic.
    # It is locally generated test metadata.
    # --------------------------------------------------

    sources = [
        "192.168.1.10",
        "192.168.1.11",
        "192.168.1.12",
        "192.168.1.13",
        "192.168.1.14",
        "192.168.1.15",
    ]

    total_alerts = 0

    for source in sources:

        flow = create_flow(
            source_ip=source,
            destination_ip="10.0.0.50",
            destination_port=443,
            timestamp=timestamp,
        )

        alerts = pipeline.process_flow(
            flow
        )

        total_alerts += len(alerts)

        for alert in alerts:

            print()
            print("🚨 ALERT GENERATED")
            print("-" * 70)

            print(
                "Threat     :",
                alert.threat_class,
            )

            print(
                "Severity   :",
                alert.severity,
            )

            print(
                "Confidence :",
                alert.confidence,
            )

            print(
                "Risk Score :",
                alert.risk_score,
            )

            print(
                "Source     :",
                alert.source_ip,
            )

            print(
                "Destination:",
                alert.destination_ip,
            )

    # --------------------------------------------------
    # DNS metadata test
    # --------------------------------------------------

    dns_alerts = (
        pipeline.process_dns_query(
            query=(
                "x7k2p9m4q8z1d5f3"
                "a9b8c7d6e5f4"
                "example.com"
            ),
            source_ip="192.168.1.50",
            destination_ip="8.8.8.8",
        )
    )

    total_alerts += len(
        dns_alerts
    )

    for alert in dns_alerts:

        print()
        print("🚨 DNS ALERT")
        print("-" * 70)

        print(
            "Threat     :",
            alert.threat_class,
        )

        print(
            "Severity   :",
            alert.severity,
        )

        print(
            "Confidence :",
            alert.confidence,
        )

        print(
            "Risk Score :",
            alert.risk_score,
        )

    # --------------------------------------------------
    # Statistics
    # --------------------------------------------------

    print()
    print("=" * 70)
    print("PIPELINE STATISTICS")
    print("=" * 70)

    stats = (
        pipeline.get_window_statistics()
    )

    for key, value in stats.items():
        print(
            f"{key:20}: {value}"
        )

    print()
    print(
        "Total alerts generated:",
        total_alerts,
    )

    print()
    print("=" * 70)
    print(
        "PASSIVE PIPELINE TEST COMPLETE"
    )
    print("=" * 70)


if __name__ == "__main__":
    main()