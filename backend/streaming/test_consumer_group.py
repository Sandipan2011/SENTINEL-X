from backend.streaming.redis_stream import RedisStream


STREAM_NAME = "sentinel:test:flows"
GROUP_NAME = "sentinel-test-group"
CONSUMER_NAME = "sentinel-test-consumer"


def main():

    redis_stream = RedisStream(
        stream_name=STREAM_NAME
    )

    print("=" * 70)
    print("SENTINEL-X REDIS CONSUMER GROUP TEST")
    print("=" * 70)

    # -------------------------------------------------
    # CONNECT
    # -------------------------------------------------

    if not redis_stream.ping():

        print("Redis connection failed.")

        return

    print("[OK] Redis connected.")

    # -------------------------------------------------
    # CLEAN TEST STREAM
    # -------------------------------------------------

    redis_stream.clear()

    print(
        "[OK] Test stream cleared."
    )

    # -------------------------------------------------
    # CREATE CONSUMER GROUP
    # -------------------------------------------------

    created = redis_stream.create_group(
        group_name=GROUP_NAME,
        start_id="0-0",
    )

    if created:

        print(
            "[OK] Consumer group created."
        )

    else:

        print(
            "[INFO] Consumer group already exists."
        )

    # -------------------------------------------------
    # PUBLISH EVENTS
    # -------------------------------------------------

    for i in range(5):

        message_id = redis_stream.publish(
            {
                "event_type": "FLOW",
                "event_number": i + 1,
                "src_ip": "192.168.1.10",
                "dst_ip": "10.0.0.20",
                "protocol": "TCP",
                "packets": 1,
                "bytes": 60,
            }
        )

        print(
            f"[PUBLISH] {message_id}"
        )

    print()

    # -------------------------------------------------
    # READ USING CONSUMER GROUP
    # -------------------------------------------------

    events = redis_stream.read_group(
        group_name=GROUP_NAME,
        consumer_name=CONSUMER_NAME,
        count=10,
        block_ms=1000,
    )

    print(
        f"[OK] Events received: {len(events)}"
    )

    # -------------------------------------------------
    # PROCESS + ACK
    # -------------------------------------------------

    for event in events:

        print()
        print(
            "Message ID:",
            event["message_id"]
        )

        print(
            "Event:",
            event["data"]
        )

        acknowledged = (
            redis_stream.acknowledge(
                group_name=GROUP_NAME,
                message_id=event[
                    "message_id"
                ],
            )
        )

        print(
            "ACK:",
            acknowledged
        )

    # -------------------------------------------------
    # PENDING
    # -------------------------------------------------

    pending = redis_stream.pending(
        GROUP_NAME
    )

    print()
    print(
        "Pending messages:",
        pending
    )

    # -------------------------------------------------
    # FINAL
    # -------------------------------------------------

    print()
    print("=" * 70)
    print("CONSUMER GROUP TEST COMPLETE")
    print("=" * 70)


if __name__ == "__main__":

    main()