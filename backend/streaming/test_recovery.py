import time

from backend.streaming.redis_stream import RedisStream


STREAM_NAME = "sentinel:recovery:test"
GROUP_NAME = "sentinel-recovery-group"

CRASHED_CONSUMER = "worker-crashed"
RECOVERY_CONSUMER = "worker-recovery"


def main():
    stream = RedisStream(stream_name=STREAM_NAME)

    print("=" * 70)
    print("SENTINEL-X REDIS PENDING MESSAGE RECOVERY TEST")
    print("=" * 70)

    # Check Redis
    if not stream.ping():
        print("[ERROR] Redis is not available.")
        return

    print("[OK] Redis connection successful.")

    # Start clean
    stream.clear()

    # Create consumer group
    created = stream.create_group(
        group_name=GROUP_NAME,
        start_id="0-0",
    )

    if created:
        print("[OK] Consumer group created.")
    else:
        print("[INFO] Consumer group already exists.")

    # Publish one test event
    message_id = stream.publish(
        {
            "event_type": "FLOW",
            "src_ip": "192.168.1.100",
            "dst_ip": "10.0.0.50",
            "protocol": "TCP",
            "packets": 10,
            "bytes": 5000,
        }
    )

    print("[PUBLISH] Message ID:", message_id)

    # Simulate worker A receiving the message
    messages = stream.read_group(
        group_name=GROUP_NAME,
        consumer_name=CRASHED_CONSUMER,
        count=1,
        block_ms=1000,
    )

    print("[CRASH SIMULATION] Messages received:", len(messages))

    if not messages:
        print("[ERROR] Consumer A did not receive the message.")
        return

    # Intentionally DO NOT ACK.
    # This simulates a worker crash after receiving the event.
    print("[CRASH SIMULATION] Message intentionally NOT acknowledged.")

    # Give Redis time to mark the message as idle.
    print("[WAIT] Waiting 6 seconds before recovery...")
    time.sleep(6)

    # Check pending messages.
    pending = stream.pending_messages(
        group_name=GROUP_NAME,
        min_idle_time=5000,
        count=10,
    )

    print()
    print("[PENDING] Messages waiting for recovery:", len(pending))

    if not pending:
        print("[ERROR] No pending message found.")
        return

    # Extract pending IDs.
    pending_ids = [
        item["message_id"]
        for item in pending
    ]

    print("[PENDING IDS]", pending_ids)

    # Consumer B claims the abandoned message.
    recovered = stream.claim_pending(
        group_name=GROUP_NAME,
        consumer_name=RECOVERY_CONSUMER,
        message_ids=pending_ids,
        min_idle_time=5000,
    )

    print("[RECOVERY] Messages claimed:", len(recovered))

    if not recovered:
        print("[ERROR] Recovery failed.")
        return

    # ACK recovered messages.
    for event in recovered:
        recovered_id = event["message_id"]

        acknowledged = stream.acknowledge(
            group_name=GROUP_NAME,
            message_id=recovered_id,
        )

        print(
            "[ACK] Message:",
            recovered_id,
            "| acknowledged:",
            bool(acknowledged),
        )

    # Verify pending queue is empty.
    final_pending = stream.pending(
        group_name=GROUP_NAME,
    )

    print()
    print("[FINAL PENDING]", final_pending)

    print()
    print("=" * 70)
    print("RECOVERY TEST COMPLETE")
    print("=" * 70)

    if final_pending["pending"] == 0:
        print("[SUCCESS] Pending message successfully recovered and acknowledged.")
    else:
        print("[WARNING] Pending messages still remain.")


if __name__ == "__main__":
    main()