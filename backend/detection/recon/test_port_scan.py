from datetime import datetime, timedelta, timezone

from backend.detection.recon.port_scan import (
    PortScanDetector,
)

from backend.features.window import FeatureWindow

from backend.ingest.flow import (
    FlowKey,
    FlowState,
)


def create_scan_flow(
    source_ip: str,
    destination_ip: str,
    destination_port: int,
    seconds: int,
):

    start = datetime.now(timezone.utc)

    key = FlowKey.from_packet(
        src_ip=source_ip,
        src_port=40000 + destination_port,
        dst_ip=destination_ip,
        dst_port=destination_port,
        protocol="TCP",
    )

    flow = FlowState(
        key=key,
        first_seen=start,
        last_seen=start + timedelta(
            seconds=seconds
        ),
        src_ip=source_ip,
        dst_ip=destination_ip,
        src_port=40000 + destination_port,
        dst_port=destination_port,
    )

    flow.packets_forward = 1
    flow.bytes_forward = 60

    flow.tcp_flags = {"S"}
    flow.syn_packets = 1

    return flow


def main():

    window = FeatureWindow(
        window_seconds=10
    )

    attacker = "192.168.1.100"

    target = "10.0.0.50"

    # Simulate scanning many ports
    ports = [
        21,
        22,
        23,
        25,
        53,
        80,
        110,
        135,
        139,
        143,
        443,
        445,
        3306,
        3389,
        8080,
        8443,
    ]

    for port in ports:

        flow = create_scan_flow(
            source_ip=attacker,
            destination_ip=target,
            destination_port=port,
            seconds=1,
        )

        window.add_flow(flow)

    detector = PortScanDetector(
        port_threshold=10,
        host_threshold=10,
        flow_threshold=15,
    )

    results = detector.detect(window)

    print("=" * 60)
    print("SENTINEL-X PORT SCAN DETECTION TEST")
    print("=" * 60)

    print()

    print(
        "Flows in window       :",
        len(window.flows),
    )

    print(
        "Source                :",
        attacker,
    )

    print(
        "Unique ports scanned  :",
        len(
            {
                flow.dst_port
                for flow in window.flows
            }
        ),
    )

    print()

    if not results:

        print(
            "No reconnaissance activity detected."
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