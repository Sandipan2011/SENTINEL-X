import time
from pathlib import Path
from typing import Callable

from scapy.all import IP, IPv6, PcapReader, TCP, UDP

from backend.ingest.models import NetworkFlow
from backend.streaming.redis_stream import RedisStream


class PCAPReplay:
    """
    SENTINEL-X passive PCAP replay engine.

    Replays observed packet metadata according to the
    original packet timestamps.

    Important security properties:

    - No network packets are transmitted.
    - No destination is contacted.
    - No scanning is performed.
    - No probing is performed.
    - No firewall rules are modified.
    - No traffic is blocked.
    - No payload is inspected or decrypted.

    Redis events:

        FLOW
          |
          v
        Detection Worker
          |
          v
        Detection Pipeline

    At the end of the replay:

        REPLAY_COMPLETE
          |
          v
        Worker flushes active flows
          |
          v
        Final detection
    """

    def __init__(
        self,
        pcap_file: str,
        packet_callback: Callable | None = None,
        speed: float = 1.0,
        redis_stream: RedisStream | None = None,
    ):
        self.pcap_file = Path(pcap_file)

        self.packet_callback = packet_callback

        self.speed = max(
            speed,
            0.01,
        )

        self.redis_stream = redis_stream

        self.packet_count = 0

        self.start_time = None
        self.end_time = None

    # ============================================================
    # PACKET → METADATA FLOW
    # ============================================================

    def _packet_to_flow(
        self,
        packet,
    ) -> NetworkFlow | None:
        """
        Convert an observed packet into metadata-only
        NetworkFlow information.

        Payload contents are intentionally ignored.
        """

        timestamp = packet.time

        src_ip = None
        dst_ip = None

        # --------------------------------------------------------
        # IP / IPv6
        # --------------------------------------------------------

        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

        elif IPv6 in packet:
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst

        else:
            return None

        # --------------------------------------------------------
        # Transport protocol
        # --------------------------------------------------------

        src_port = None
        dst_port = None

        protocol = "OTHER"

        tcp_flags = None

        if TCP in packet:
            protocol = "TCP"

            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

            tcp_flags = str(
                packet[TCP].flags
            )

        elif UDP in packet:
            protocol = "UDP"

            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        else:
            if IP in packet:
                protocol = str(
                    packet[IP].proto
                )

        # --------------------------------------------------------
        # Create metadata-only flow
        # --------------------------------------------------------

        return NetworkFlow(
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            packets=1,
            bytes=len(packet),
            tcp_flags=tcp_flags,
        )

    # ============================================================
    # REPLAY COMPLETE EVENT
    # ============================================================

    def _publish_replay_complete(self):
        """
        Notify the streaming worker that the controlled
        PCAP replay has finished.

        This does NOT transmit anything to the observed
        network. It is only an internal Redis control event.
        """

        if self.redis_stream is None:
            return

        event = {
            "event_type": "REPLAY_COMPLETE",
            "pcap_file": str(
                self.pcap_file
            ),
            "packets_replayed": self.packet_count,
            "start_time": (
                self.start_time
                .isoformat()
                if self.start_time is not None
                else None
            ),
            "end_time": (
                self.end_time
                .isoformat()
                if self.end_time is not None
                else None
            ),
        }

        self.redis_stream.publish(event)

        print(
            "[REPLAY] REPLAY_COMPLETE event published."
        )

    # ============================================================
    # REPLAY
    # ============================================================

    def replay(self):
        """
        Replay the PCAP as a stream of passive metadata events.
        """

        # --------------------------------------------------------
        # Validate PCAP
        # --------------------------------------------------------

        if not self.pcap_file.exists():
            raise FileNotFoundError(
                f"PCAP not found: {self.pcap_file}"
            )

        if not self.pcap_file.is_file():
            raise ValueError(
                f"Not a file: {self.pcap_file}"
            )

        # --------------------------------------------------------
        # Reset statistics
        # --------------------------------------------------------

        self.packet_count = 0

        self.start_time = None
        self.end_time = None

        previous_timestamp = None

        # --------------------------------------------------------
        # Read PCAP
        # --------------------------------------------------------

        print()
        print("=" * 70)
        print("SENTINEL-X PASSIVE PCAP REPLAY")
        print("=" * 70)
        print("PCAP :", self.pcap_file)
        print("Speed:", self.speed, "x")
        print("Mode : PASSIVE / METADATA ONLY")
        print("=" * 70)
        print()

        with PcapReader(
            str(self.pcap_file)
        ) as packets:

            for packet in packets:

                # ----------------------------------------------
                # Packet timestamp
                # ----------------------------------------------

                current_timestamp = float(
                    packet.time
                )

                # ----------------------------------------------
                # Preserve original packet timing
                # ----------------------------------------------

                if (
                    previous_timestamp
                    is not None
                ):
                    delay = (
                        current_timestamp
                        - previous_timestamp
                    )

                    delay = max(
                        delay,
                        0.0,
                    )

                    delay = (
                        delay
                        / self.speed
                    )

                    if delay > 0:
                        time.sleep(delay)

                previous_timestamp = (
                    current_timestamp
                )

                # ----------------------------------------------
                # Convert packet to metadata
                # ----------------------------------------------

                flow = self._packet_to_flow(
                    packet
                )

                if flow is None:
                    continue

                # ----------------------------------------------
                # Statistics
                # ----------------------------------------------

                self.packet_count += 1

                if self.start_time is None:
                    self.start_time = (
                        flow.timestamp
                    )

                self.end_time = (
                    flow.timestamp
                )

                # ----------------------------------------------
                # Publish FLOW event to Redis
                # ----------------------------------------------

                if (
                    self.redis_stream
                    is not None
                ):
                    event = {
                        "event_type": "FLOW",
                        **flow.model_dump(
                            mode="json"
                        ),
                    }

                    self.redis_stream.publish(
                        event
                    )

                # ----------------------------------------------
                # Optional local callback
                # ----------------------------------------------

                if (
                    self.packet_callback
                    is not None
                ):
                    self.packet_callback(
                        flow
                    )

        # --------------------------------------------------------
        # Tell worker replay has finished
        # --------------------------------------------------------

        self._publish_replay_complete()

        # --------------------------------------------------------
        # Replay statistics
        # --------------------------------------------------------

        result = {
            "pcap_file": str(
                self.pcap_file
            ),
            "packets_replayed": (
                self.packet_count
            ),
            "start_time": (
                self.start_time
            ),
            "end_time": (
                self.end_time
            ),
            "event": "REPLAY_COMPLETE",
        }

        print()
        print("=" * 70)
        print("SENTINEL-X PCAP REPLAY COMPLETE")
        print("=" * 70)
        print(
            "Packets replayed :",
            self.packet_count,
        )
        print(
            "Start time       :",
            self.start_time,
        )
        print(
            "End time         :",
            self.end_time,
        )
        print(
            "Redis completion :",
            (
                "PUBLISHED"
                if self.redis_stream is not None
                else "NOT CONFIGURED"
            ),
        )
        print("=" * 70)
        print()

        return result