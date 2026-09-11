from backend.streaming.redis_stream import (
    RedisStream,
)


def main():

    print("=" * 60)
    print("SENTINEL-X REDIS STREAM TEST")
    print("=" * 60)

    stream = RedisStream()

    print()
    print("Redis URL:")
    print(
        stream.redis_url
    )

    print()
    print("Checking Redis...")

    try:

        if not stream.ping():

            print(
                "ERROR: Redis ping failed."
            )

            return

        print(
            "Redis status: CONNECTED"
        )

    except Exception as exc:

        print(
            "ERROR: Could not connect "
            "to Redis."
        )

        print(
            f"Details: {exc}"
        )

        return

    # --------------------------------------------------
    # Remove old development events
    # --------------------------------------------------

    stream.clear()

    print()
    print(
        "Stream cleared."
    )

    # --------------------------------------------------
    # Publish test event
    # --------------------------------------------------

    event = {
        "event_type": "FLOW",
        "source": "SENTINEL-X",
        "src_ip": "192.168.1.10",
        "dst_ip": "10.0.0.50",
        "src_port": 45000,
        "dst_port": 443,
        "protocol": "TCP",
        "packets": 10,
        "bytes": 1200,
    }

    message_id = stream.publish(
        event
    )

    print()
    print(
        "Published event:"
    )

    print(
        "Message ID:",
        message_id,
    )

    print(
        "Stream length:",
        stream.length(),
    )

    # --------------------------------------------------
    # Read event
    # --------------------------------------------------

    events = stream.read(
        count=10,
        block_ms=1000,
        last_id="0-0",
    )

    print()
    print(
        "Events received:",
        len(events),
    )

    for received in events:

        print()
        print(
            "Message ID:",
            received["message_id"],
        )

        print(
            "Stream:",
            received["stream"],
        )

        print(
            "Data:"
        )

        for key, value in (
            received["data"].items()
        ):

            print(
                f"  {key:15}: {value}"
            )

    print()
    print("=" * 60)
    print(
        "REDIS STREAM TEST COMPLETE"
    )
    print("=" * 60)


if __name__ == "__main__":
    main()