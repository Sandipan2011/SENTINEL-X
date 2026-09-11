from __future__ import annotations

import signal
import time
from typing import Any

from backend.alerts.schema import SentinelAlert
from backend.database.alert_repository import save_alert
from backend.database.database import SessionLocal
from backend.ingest.models import NetworkFlow
from backend.streaming.detector_pipeline import DetectionPipeline
from backend.streaming.flow_lifecycle import FlowLifecycleManager
from backend.streaming.redis_stream import RedisStream


# ============================================================
# STREAM CONFIGURATION
# ============================================================

FLOW_STREAM = "sentinel:flows"
ALERT_STREAM = "sentinel:alerts"

CONSUMER_GROUP = "sentinel-detectors"
CONSUMER_NAME = "detector-worker-01"

RECOVERY_IDLE_MS = 5000
BATCH_SIZE = 10


class DetectionWorker:
    """
    SENTINEL-X passive streaming detection worker.

    Architecture:

        Redis FLOW Stream
                ↓
        Flow Lifecycle
                ↓
        Finalized Flow
                ↓
        Detection Pipeline
                ↓
              Alert
             ↙     ↘
        Redis       PostgreSQL

    Controlled PCAP replay:

        FLOW
          ↓
        active flow
          ↓
        REPLAY_COMPLETE
          ↓
        flush active flows
          ↓
        Detection Pipeline

    Security boundary:

    - No active probing
    - No active scanning
    - No automated blocking
    - No firewall modification
    - No payload decryption
    - No return-path communication
    """

    def __init__(self):
        # --------------------------------------------------------
        # Redis FLOW stream
        # --------------------------------------------------------

        self.redis_stream = RedisStream(
            stream_name=FLOW_STREAM
        )

        # --------------------------------------------------------
        # Redis ALERT stream
        # --------------------------------------------------------

        self.alert_stream = RedisStream(
            stream_name=ALERT_STREAM
        )

        # --------------------------------------------------------
        # Flow lifecycle
        # --------------------------------------------------------

        self.lifecycle = FlowLifecycleManager(
            flow_timeout=60.0
        )

        # --------------------------------------------------------
        # Detection pipeline
        # --------------------------------------------------------

        self.pipeline = DetectionPipeline(
            window_seconds=10
        )

        # --------------------------------------------------------
        # Worker state
        # --------------------------------------------------------

        self.running = True

    # ============================================================
    # REDIS CONSUMER GROUP
    # ============================================================

    def initialize(self):
        """
        Create the Redis consumer group if it does not already exist.
        """

        print(
            "[WORKER] Initializing Redis consumer group..."
        )

        created = self.redis_stream.create_group(
            group_name=CONSUMER_GROUP,
            start_id="0-0",
        )

        if created:
            print(
                "[WORKER] Redis consumer group created."
            )
        else:
            print(
                "[WORKER] Redis consumer group already exists."
            )

        print(
            "[WORKER] Redis consumer group ready."
        )

    # ============================================================
    # REDIS EVENT → NETWORK FLOW
    # ============================================================

    @staticmethod
    def event_to_flow(
        event: dict[str, Any],
    ) -> NetworkFlow:
        """
        Convert a Redis FLOW event into NetworkFlow.

        Only packet metadata is consumed.
        """

        return NetworkFlow(
            timestamp=event["timestamp"],
            src_ip=event["src_ip"],
            dst_ip=event["dst_ip"],
            src_port=event.get("src_port"),
            dst_port=event.get("dst_port"),
            protocol=event["protocol"],
            packets=event.get("packets", 1),
            bytes=event.get("bytes", 0),
            duration=event.get("duration", 0.0),
            tcp_flags=event.get("tcp_flags"),
            interface=event.get("interface"),
        )

    # ============================================================
    # PUBLISH ALERT
    # ============================================================

    def publish_alert(
        self,
        alert: SentinelAlert,
    ):
        """
        Publish a detection alert to the Redis ALERT stream.
        """

        event = {
            "event_type": "ALERT",
            "alert": alert.model_dump(
                mode="json"
            ),
        }

        message_id = self.alert_stream.publish(
            event
        )

        print(
            f"[ALERT STREAM] Published {message_id}"
        )

    # ============================================================
    # PERSIST ALERT
    # ============================================================

    def persist_alert(
        self,
        alert: SentinelAlert,
    ):
        """
        Persist the alert to PostgreSQL.
        """

        db = SessionLocal()

        try:
            save_alert(
                db=db,
                alert=alert,
            )

            print(
                f"[DATABASE] Saved alert "
                f"{alert.alert_id}"
            )

        except Exception as exc:
            db.rollback()

            print(
                "[DATABASE] Alert persistence failed:"
            )
            print(exc)

        finally:
            db.close()

    # ============================================================
    # HANDLE ALERT
    # ============================================================

    def handle_alert(
        self,
        alert: SentinelAlert,
    ):
        """
        Handle a generated detection alert.

        The alert is:
        1. Printed
        2. Published to Redis
        3. Persisted to PostgreSQL
        """

        print()
        print("=" * 70)
        print("🚨 SENTINEL-X LIVE ALERT")
        print("=" * 70)

        print(
            "Threat      :",
            alert.threat_class,
        )

        print(
            "Severity    :",
            alert.severity,
        )

        print(
            "Confidence  :",
            alert.confidence,
        )

        print(
            "Risk Score  :",
            alert.risk_score,
        )

        print(
            "Source      :",
            alert.source_ip,
        )

        print(
            "Destination :",
            alert.destination_ip,
        )

        print(
            "Protocol    :",
            alert.protocol,
        )

        print(
            "Detector    :",
            alert.detector,
        )

        print(
            "Description :",
            alert.description,
        )

        print("=" * 70)

        # --------------------------------------------------------
        # Redis ALERT stream
        # --------------------------------------------------------

        self.publish_alert(
            alert
        )

        # --------------------------------------------------------
        # PostgreSQL
        # --------------------------------------------------------

        self.persist_alert(
            alert
        )

    # ============================================================
    # PROCESS FINALIZED FLOW
    # ============================================================

    def process_finalized_flow(
        self,
        flow,
    ):
        """
        Send a finalized flow through the detection pipeline.
        """

        alerts = self.pipeline.process_flow(
            flow
        )

        for alert in alerts:
            self.handle_alert(
                alert
            )

    # ============================================================
    # PROCESS REPLAY COMPLETE
    # ============================================================

    def process_replay_complete(
        self,
        event: dict[str, Any],
    ):
        """
        Handle the end of a controlled PCAP replay.

        Any flows still active in the lifecycle manager
        are finalized immediately.

        This prevents the final flows of a PCAP from being
        left waiting for the normal inactivity timeout.
        """

        print()
        print("=" * 70)
        print("[WORKER] PCAP REPLAY COMPLETE")
        print("=" * 70)

        pcap_file = event.get(
            "pcap_file",
            "unknown",
        )

        packets_replayed = event.get(
            "packets_replayed",
            0,
        )

        print(
            "PCAP              :",
            pcap_file,
        )

        print(
            "Packets replayed  :",
            packets_replayed,
        )

        # --------------------------------------------------------
        # Flush active flows
        # --------------------------------------------------------

        remaining_flows = (
            self.lifecycle.flush()
        )

        print(
            "[WORKER] Active flows flushed:",
            len(remaining_flows),
        )

        # --------------------------------------------------------
        # Detect remaining flows
        # --------------------------------------------------------

        for flow in remaining_flows:
            self.process_finalized_flow(
                flow
            )

        print(
            "[WORKER] Replay finalization complete."
        )

        print("=" * 70)
        print()

    # ============================================================
    # PROCESS ONE REDIS EVENT
    # ============================================================

    def process_event(
        self,
        event: dict[str, Any],
    ) -> None:
        """
        Process one Redis stream event.

        Supported event types:

        FLOW
        REPLAY_COMPLETE
        """

        event_type = event.get(
            "event_type",
            "FLOW",
        )

        # --------------------------------------------------------
        # FLOW EVENT
        # --------------------------------------------------------

        if event_type == "FLOW":

            flow = self.event_to_flow(
                event
            )

            finalized_flows = (
                self.lifecycle.process(
                    flow
                )
            )

            for finalized_flow in finalized_flows:
                self.process_finalized_flow(
                    finalized_flow
                )

            return

        # --------------------------------------------------------
        # REPLAY COMPLETE EVENT
        # --------------------------------------------------------

        if event_type == "REPLAY_COMPLETE":

            self.process_replay_complete(
                event
            )

            return

        # --------------------------------------------------------
        # Unknown event
        # --------------------------------------------------------

        print(
            "[WORKER] Unknown event type:",
            event_type,
        )

    # ============================================================
    # RECOVER PENDING MESSAGES
    # ============================================================

    def recover_pending(self):
        """
        Recover messages that were delivered to this
        consumer group but were not acknowledged.
        """

        print(
            "[WORKER] Checking pending messages..."
        )

        try:
            pending = (
                self.redis_stream.pending_messages(
                    group_name=CONSUMER_GROUP,
                    min_idle_time=RECOVERY_IDLE_MS,
                    count=BATCH_SIZE,
                )
            )

            if not pending:
                print(
                    "[WORKER] No pending messages."
                )
                return

            print(
                f"[WORKER] Found "
                f"{len(pending)} pending messages."
            )

            for message in pending:

                message_id = message["id"]
                event = message["data"]

                try:
                    self.process_event(
                        event
                    )

                    self.redis_stream.acknowledge(
                        group_name=CONSUMER_GROUP,
                        message_id=message_id,
                    )

                    print(
                        f"[WORKER] Recovered and ACKed "
                        f"{message_id}"
                    )

                except Exception as exc:

                    print(
                        "[WORKER] Pending message failed:"
                    )

                    print(exc)

        except Exception as exc:

            print(
                "[WORKER] Pending recovery failed:"
            )

            print(exc)

    # ============================================================
    # MAIN WORKER LOOP
    # ============================================================

    def run(self):
        """
        Start the continuous Redis consumer loop.
        """

        self.initialize()

        self.recover_pending()

        print()
        print("=" * 70)
        print("SENTINEL-X DETECTION WORKER")
        print("=" * 70)
        print(
            "Flow stream :",
            FLOW_STREAM,
        )
        print(
            "Alert stream:",
            ALERT_STREAM,
        )
        print(
            "Consumer    :",
            CONSUMER_NAME,
        )
        print(
            "Mode        : PASSIVE / READ-ONLY"
        )
        print("=" * 70)
        print()

        while self.running:

            try:

                messages = (
                    self.redis_stream.read_group(
                        group_name=CONSUMER_GROUP,
                        consumer_name=CONSUMER_NAME,
                        count=BATCH_SIZE,
                        block_ms=1000,
                    )
                )

                if not messages:
                    continue

                for message in messages:

                    message_id = message["id"]
                    event = message["data"]

                    try:

                        self.process_event(
                            event
                        )

                        self.redis_stream.acknowledge(
                            group_name=CONSUMER_GROUP,
                            message_id=message_id,
                        )

                    except Exception as exc:

                        print()
                        print(
                            "[WORKER] Event processing error:"
                        )

                        print(exc)

                        # Do not ACK failed messages.
                        # Redis consumer-group recovery
                        # can process them later.

            except KeyboardInterrupt:

                self.stop()

            except Exception as exc:

                print()
                print(
                    "[WORKER] Main loop error:"
                )

                print(exc)

                time.sleep(1)

        self.shutdown()

    # ============================================================
    # SHUTDOWN / FLUSH
    # ============================================================

    def shutdown(self):
        """
        Gracefully finalize all active flows before shutdown.
        """

        print()

        print(
            "[WORKER] Finalizing active flows..."
        )

        try:

            remaining_flows = (
                self.lifecycle.flush()
            )

            print(
                f"[WORKER] Flushed "
                f"{len(remaining_flows)} active flows."
            )

            for flow in remaining_flows:

                self.process_finalized_flow(
                    flow
                )

        except Exception as exc:

            print(
                "[WORKER] Final flow flush failed:"
            )

            print(exc)

        print(
            "[WORKER] Shutdown complete."
        )

    # ============================================================
    # STOP
    # ============================================================

    def stop(self):
        """
        Request graceful worker shutdown.
        """

        if self.running:

            print()

            print(
                "[WORKER] Shutdown requested..."
            )

        self.running = False


# ================================================================
# GLOBAL WORKER
# ================================================================

worker = DetectionWorker()


# ================================================================
# SIGNAL HANDLER
# ================================================================

def handle_signal(
    signum,
    frame,
):
    print(
        f"\n[WORKER] Received signal {signum}"
    )

    worker.stop()


signal.signal(
    signal.SIGINT,
    handle_signal,
)

signal.signal(
    signal.SIGTERM,
    handle_signal,
)


# ================================================================
# ENTRY POINT
# ================================================================

if __name__ == "__main__":
    worker.run()