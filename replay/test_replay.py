import sys

from backend.ingest.aggregator import FlowAggregator
from backend.streaming.detector_pipeline import DetectionPipeline
from backend.streaming.redis_stream import RedisStream
from replay.pcap_replay import PCAPReplay


class ReplayApplication:

    def __init__(self):
        self.aggregator = FlowAggregator(
            flow_timeout=60.0
        )

        self.pipeline = DetectionPipeline(
            window_seconds=10
        )

        self.alert_count = 0

    def process_packet(self, packet):

        flow = self.aggregator.add_packet(
            packet
        )

        # Run the current flow through
        # the SENTINEL-X detection pipeline.
        alerts = self.pipeline.process_flow(
            flow
        )

        for alert in alerts:

            self.alert_count += 1

            print()
            print("🚨 SENTINEL-X ALERT")
            print("-" * 70)

            print(
                "Threat     :",
                alert.threat_class
            )

            print(
                "Severity   :",
                alert.severity
            )

            print(
                "Confidence :",
                alert.confidence
            )

            print(
                "Risk Score :",
                alert.risk_score
            )

            print(
                "Source     :",
                alert.source_ip
            )

            print(
                "Destination:",
                alert.destination_ip
            )

            print(
                "Protocol   :",
                alert.protocol
            )

            print(
                "Detector   :",
                alert.detector
            )

            print("-" * 70)

    def run(
        self,
        pcap_file: str,
        speed: float = 1.0,
    ):

        # Redis is used as the internal
        # streaming event bus.
        redis_stream = RedisStream()

        replay = PCAPReplay(
            pcap_file=pcap_file,
            packet_callback=None,
            speed=speed,
            redis_stream=redis_stream,
        )

        result = replay.replay()

        print()
        print("=" * 70)
        print("SENTINEL-X PCAP REPLAY COMPLETE")
        print("=" * 70)

        print(
            "PCAP              :",
            result["pcap_file"]
        )

        print(
            "Packets replayed  :",
            result["packets_replayed"]
        )

        print(
            "Alerts generated  :",
            self.alert_count
        )

        print(
            "Active flows      :",
            len(
                self.aggregator.flows
            )
        )

        print("=" * 70)


def main():

    if len(sys.argv) < 2:

        print("Usage:")

        print(
            "python -m replay.test_replay "
            "<pcap_file> [speed]"
        )

        print()

        print("Example:")

        print(
            "python -m replay.test_replay "
            "datasets/test_traffic.pcap 10"
        )

        return

    pcap_file = sys.argv[1]

    speed = 1.0

    if len(sys.argv) >= 3:

        speed = float(
            sys.argv[2]
        )

    print("=" * 70)

    print(
        "SENTINEL-X REAL-TIME PCAP REPLAY"
    )

    print("=" * 70)

    print(
        "Input PCAP :",
        pcap_file
    )

    print(
        "Replay speed:",
        speed,
        "x"
    )

    print()

    application = ReplayApplication()

    application.run(
        pcap_file=pcap_file,
        speed=speed,
    )


if __name__ == "__main__":
    main()