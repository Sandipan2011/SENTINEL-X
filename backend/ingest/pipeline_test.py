import sys

from backend.ingest.aggregator import FlowAggregator
from backend.ingest.pcap_reader import read_pcap


def main():
    if len(sys.argv) != 2:
        print(
            "Usage: "
            "python -m backend.ingest.pipeline_test <pcap_file>"
        )
        return

    pcap_file = sys.argv[1]

    print("=" * 60)
    print("SENTINEL-X PCAP INGESTION PIPELINE")
    print("=" * 60)

    aggregator = FlowAggregator()

    packet_count = 0

    for packet in read_pcap(pcap_file):
        packet_count += 1
        aggregator.add_packet(packet)

    flows = aggregator.flows.values()

    print(f"Packets processed : {packet_count}")
    print(f"Flows generated   : {len(aggregator.flows)}")

    print()
    print("-" * 60)

    for index, flow in enumerate(flows, start=1):
        print(f"Flow #{index}")
        print(
            f"  {flow.src_ip}:{flow.src_port}"
            f" -> "
            f"{flow.dst_ip}:{flow.dst_port}"
        )
        print(f"  Protocol       : {flow.key.protocol}")
        print(f"  Packets        : {flow.packets}")
        print(f"  Bytes          : {flow.bytes}")
        print(f"  Duration       : {flow.duration:.4f}s")
        print(f"  Byte ratio     : {flow.bytes_ratio}")
        print()


if __name__ == "__main__":
    main()