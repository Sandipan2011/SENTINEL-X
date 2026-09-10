from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable


random.seed(42)


def _iso(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).isoformat()


def generate_synthetic_replay(count: int = 250) -> list[dict[str, Any]]:
    """Generate a deterministic mix of benign and malicious traffic records."""
    start = datetime.now(timezone.utc) - timedelta(minutes=12)
    events: list[dict[str, Any]] = []
    flow_id = 10000

    for i in range(60):
        ts = start + timedelta(seconds=i * 2)
        events.append(
            {
                "flow_id": f"flow-{flow_id}",
                "timestamp": _iso(ts),
                "src_ip": "10.10.0.12",
                "dst_ip": "203.0.113.20",
                "src_port": 5201,
                "dst_port": 80,
                "protocol": "tcp",
                "in_bytes": 1200 + (i % 11) * 75,
                "out_bytes": 900 + (i % 7) * 65,
                "packet_count": 12,
                "domain": "cdn.example.net",
                "tls_version": "1.3",
                "ja3": "771,4865-4866-4867-49195-49199-52393-49196-49200-49162-49161-49170-49171-4433-65281",
                "sni": "cdn.example.net",
            }
        )
        flow_id += 1

    for i in range(22):
        ts = start + timedelta(seconds=i * 3)
        events.append(
            {
                "flow_id": f"flow-{flow_id}",
                "timestamp": _iso(ts),
                "src_ip": "198.51.100.8",
                "dst_ip": "203.0.113.90",
                "src_port": random.randint(40000, 65535),
                "dst_port": 80,
                "protocol": "tcp",
                "in_bytes": 70000 + i * 900,
                "out_bytes": 4500,
                "packet_count": 140 + i * 7,
                "domain": "service.example.net",
                "tls_version": "1.2",
                "ja3": "771,4865-4866-4867-49195-49199-52393-49196-49200-49162-49161-49170-49171-4433-65281",
                "sni": "service.example.net",
            }
        )
        flow_id += 1

    for i in range(18):
        ts = start + timedelta(seconds=i * 18)
        for j in range(5):
            events.append(
                {
                    "flow_id": f"flow-{flow_id}",
                    "timestamp": _iso(ts + timedelta(seconds=j)),
                    "src_ip": "172.16.10.7",
                    "dst_ip": "203.0.113.55",
                    "src_port": 50500 + j,
                    "dst_port": 443,
                    "protocol": "udp",
                    "in_bytes": 2000,
                    "out_bytes": 1500,
                    "packet_count": 20,
                    "domain": "api.internal.example",
                    "tls_version": "1.3",
                    "ja3": "771,4865-4866-4867-49195-49199-52393-49196-49200-49162-49161-49170-49171-4433-65281",
                    "sni": "api.internal.example",
                }
            )
            flow_id += 1

    for i in range(14):
        ts = start + timedelta(minutes=2, seconds=i * 12)
        domain = (
            "x" * (18 + i) + "-" + "dga" + "-" + "prefetch" + "-" + ("q" * (i % 6))
        ) + ".net"
        events.append(
            {
                "flow_id": f"flow-{flow_id}",
                "timestamp": _iso(ts),
                "src_ip": "10.1.0.8",
                "dst_ip": "192.0.2.53",
                "src_port": 53,
                "dst_port": 53,
                "protocol": "udp",
                "in_bytes": 140,
                "out_bytes": 220,
                "packet_count": 1,
                "domain": domain,
                "query_type": "TXT",
                "tls_version": "n/a",
                "ja3": "n/a",
                "sni": "",
            }
        )
        flow_id += 1

    for i in range(12):
        ts = start + timedelta(seconds=i * 4)
        events.append(
            {
                "flow_id": f"flow-{flow_id}",
                "timestamp": _iso(ts),
                "src_ip": "203.0.113.44",
                "dst_ip": "10.10.0.15",
                "src_port": 50000 + i,
                "dst_port": 22 + (i % 12),
                "protocol": "tcp",
                "in_bytes": 400,
                "out_bytes": 180,
                "packet_count": 5,
                "domain": "",
                "tls_version": "n/a",
                "ja3": "n/a",
                "sni": "",
            }
        )
        flow_id += 1

    for i in range(18):
        ts = start + timedelta(minutes=4, seconds=i * 5)
        events.append(
            {
                "flow_id": f"flow-{flow_id}",
                "timestamp": _iso(ts),
                "src_ip": "198.51.100.77",
                "dst_ip": "203.0.113.210",
                "src_port": 443,
                "dst_port": 443,
                "protocol": "tcp",
                "in_bytes": 1200,
                "out_bytes": 36000 + i * 1200,
                "packet_count": 33 + i,
                "domain": "mail.dropbox.example",
                "tls_version": "1.2",
                "ja3": "771,4865-4866-4867-49195-49199-52393-49196-49200-49162-49161-49170-49171-4433-65281",
                "sni": "mail.dropbox.example",
            }
        )
        flow_id += 1

    for i in range(20):
        ts = start + timedelta(minutes=6, seconds=i * 11)
        tls_ja3 = "771,4865-4866-4867-49195-49199-52393-49196-49200-49162-49161-49170-49171-4433-65281"
        if i % 4 == 0:
            tls_ja3 = "771,4865-4867-49195-49199-1027-1002-100-47-53-5-10-11-23-24-25-26-27-43-44-45-46"
        events.append(
            {
                "flow_id": f"flow-{flow_id}",
                "timestamp": _iso(ts),
                "src_ip": "203.0.113.99",
                "dst_ip": "198.51.100.21",
                "src_port": 45000 + i,
                "dst_port": 443,
                "protocol": "tcp",
                "in_bytes": 4800,
                "out_bytes": 5200,
                "packet_count": 28,
                "domain": "secure-host.example",
                "tls_version": "1.0",
                "ja3": tls_ja3,
                "sni": "secure-host.example",
            }
        )
        flow_id += 1

    if len(events) > count:
        return events[:count]

    return events


def iter_replay_streams(count: int = 250) -> Iterable[dict[str, Any]]:
    for event in generate_synthetic_replay(count):
        yield event
