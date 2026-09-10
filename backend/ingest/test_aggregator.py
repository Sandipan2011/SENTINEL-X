from backend.ingest.aggregator import FlowAggregator
from backend.ingest.models import NetworkFlow


def main():
    aggregator = FlowAggregator()

    packets = [
        NetworkFlow(
            timestamp="2026-09-10T12:00:00Z",
            src_ip="192.168.1.10",
            dst_ip="10.0.0.20",
            src_port=40000,
            dst_port=443,
            protocol="TCP",
            packets=1,
            bytes=60,
            tcp_flags="S",
        ),
        NetworkFlow(
            timestamp="2026-09-10T12:00:01Z",
            src_ip="10.0.0.20",
            dst_ip="192.168.1.10",
            src_port=443,
            dst_port=40000,
            protocol="TCP",
            packets=1,
            bytes=60,
            tcp_flags="SA",
        ),
        NetworkFlow(
            timestamp="2026-09-10T12:00:02Z",
            src_ip="192.168.1.10",
            dst_ip="10.0.0.20",
            src_port=40000,
            dst_port=443,
            protocol="TCP",
            packets=1,
            bytes=52,
            tcp_flags="A",
        ),
    ]

    flows = aggregator.process(packets)

    print(f"Aggregated flows: {len(flows)}")

    for flow in flows:
        print()
        print("Flow:")
        print(f"  Source: {flow.src_ip}:{flow.src_port}")
        print(f"  Destination: {flow.dst_ip}:{flow.dst_port}")
        print(f"  Protocol: {flow.key.protocol}")
        print(f"  Forward packets: {flow.packets_forward}")
        print(f"  Reverse packets: {flow.packets_reverse}")
        print(f"  Forward bytes: {flow.bytes_forward}")
        print(f"  Reverse bytes: {flow.bytes_reverse}")
        print(f"  Total packets: {flow.packets}")
        print(f"  Total bytes: {flow.bytes}")
        print(f"  Duration: {flow.duration:.2f}s")
        print(f"  Byte ratio: {flow.bytes_ratio}")


if __name__ == "__main__":
    main()