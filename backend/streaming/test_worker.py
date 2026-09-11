from datetime import datetime, timezone

from backend.streaming.redis_stream import (
    RedisStream,
)

from backend.streaming.worker import (
    DetectionWorker,
)


def main():

    print("=" * 70)
    print(
        "SENTINEL-X DETECTION WORKER TEST"
    )
    print("=" * 70)

    stream = RedisStream()

    # --------------------------------------------------
    # Check Redis
    # --------------------------------------------------

    try:

        if not stream.ping():

            print(
                "ERROR: Redis unavailable."
            )

            return

    except Exception as exc:

        print(
            "ERROR: Redis connection failed."
        )

        print(
            "Details:",
            exc,
        )

        return

    print()
    print(
        "Redis: CONNECTED"
    )

    # --------------------------------------------------
    # Clean development stream
    # --------------------------------------------------

    stream.clear()

    # --------------------------------------------------
    # Create test flow event
    # --------------------------------------------------

    event = {
        "event_type": "FLOW",

        "timestamp": (
            datetime.now(
                timezone.utc
            ).isoformat()
        ),

        "src_ip": "192.168.1.100",

        "dst_ip": "10.0.0.50",

        "src_port": 45000,

        "dst_port": 443,

        "protocol": "TCP",

        "packets": 50,

        "bytes": 3000,

        "duration": 1.0,

        "tcp_flags": "S",
    }

    # --------------------------------------------------
    # Publish event
    # --------------------------------------------------

    message_id = (
        stream.publish(event)
    )

    print()
    print(
        "Test event published."
    )

    print(
        "Message ID:",
        message_id,
    )

    # --------------------------------------------------
    # Create worker
    # --------------------------------------------------

    worker = DetectionWorker(
        redis_stream=stream
    )

    # --------------------------------------------------
    # Read event directly
    # --------------------------------------------------

    events = stream.read(
        count=10,
        block_ms=1000,
        last_id="0-0",
    )

    print()
    print(
        "Events available:",
        len(events),
    )

    if not events:

        print(
            "ERROR: Event not received."
        )

        return

    # --------------------------------------------------
    # Process event
    # --------------------------------------------------

    print()
    print(
        "Processing event..."
    )

    for event in events:

        alerts = (
            worker.process_event(
                event
            )
        )

        print()
        print(
            "Alerts returned:",
            len(alerts),
        )

    # --------------------------------------------------
    # Statistics
    # --------------------------------------------------

    print()
    print("=" * 70)
    print(
        "WORKER TEST RESULTS"
    )
    print("=" * 70)

    print(
        "Processed events :",
        worker.processed_events,
    )

    print(
        "Generated alerts :",
        worker.generated_alerts,
    )

    print(
        "Active flows     :",
        len(
            worker.aggregator.flows
        ),
    )

    print("=" * 70)


if __name__ == "__main__":
    main()