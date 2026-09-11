from backend.features.flow_features import FlowFeatureExtractor
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
            bytes=120,
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
            bytes=80,
            tcp_flags="A",
        ),
    ]

    flows = aggregator.process(packets)

    flow = flows[0]

    extractor = FlowFeatureExtractor()

    features = extractor.extract(flow)

    print("=" * 60)
    print("SENTINEL-X FEATURE EXTRACTION TEST")
    print("=" * 60)

    for name, value in features.items():
        print(f"{name:25} : {value}")


if __name__ == "__main__":
    main()