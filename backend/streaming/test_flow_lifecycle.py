from datetime import datetime, timedelta, timezone

from backend.ingest.models import NetworkFlow
from backend.streaming.flow_lifecycle import FlowLifecycleManager


def make_flow(timestamp):
    return NetworkFlow(
        timestamp=timestamp,
        src_ip="192.168.1.10",
        dst_ip="10.0.0.20",
        src_port=50000,
        dst_port=443,
        protocol="TCP",
        packets=1,
        bytes=100,
        duration=0.0,
        tcp_flags="S",
    )


def test_flow_lifecycle():
    start = datetime.now(timezone.utc)

    manager = FlowLifecycleManager(
        flow_timeout=10.0
    )

    manager.process(
        make_flow(start)
    )

    assert manager.active_count() == 1

    finalized = manager.process(
        make_flow(
            start + timedelta(seconds=5)
        )
    )

    assert len(finalized) == 0
    assert manager.active_count() == 1

    finalized = manager.process(
        NetworkFlow(
            timestamp=start + timedelta(seconds=20),
            src_ip="192.168.2.10",
            dst_ip="10.0.0.30",
            src_port=50001,
            dst_port=53,
            protocol="UDP",
            packets=1,
            bytes=80,
            duration=0.0,
        )
    )

    assert len(finalized) == 1
    assert finalized[0].src_ip == "192.168.1.10"

    print("Flow lifecycle test PASSED")


if __name__ == "__main__":
    test_flow_lifecycle()