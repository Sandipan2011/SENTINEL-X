from __future__ import annotations

import math
from collections import defaultdict
from datetime import datetime
from typing import Any


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = defaultdict(int)
    for char in value:
        counts[char] += 1
    total = len(value)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def _severity(confidence: float) -> str:
    if confidence >= 0.85:
        return "critical"
    if confidence >= 0.65:
        return "high"
    if confidence >= 0.45:
        return "medium"
    return "low"


def _make_alert(flow: dict[str, Any], threat_class: str, confidence: float, evidence: dict[str, Any]) -> dict[str, Any]:
    timestamp = flow.get("timestamp") or datetime.utcnow().isoformat()
    return {
        "timestamp": timestamp,
        "flow_id": flow.get("flow_id", f"flow-{abs(hash((timestamp, threat_class)))}"),
        "threat_class": threat_class,
        "confidence": round(float(confidence), 2),
        "severity": _severity(float(confidence)),
        "source_ip": flow.get("src_ip"),
        "destination_ip": flow.get("dst_ip"),
        "protocol": flow.get("protocol"),
        "evidence": evidence,
    }


def detect_alerts(flows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    if not flows:
        return alerts

    by_source = defaultdict(list)
    by_src_dst = defaultdict(list)
    by_domain = defaultdict(list)
    for flow in flows:
        by_source[flow.get("src_ip", "unknown")].append(flow)
        by_src_dst[(flow.get("src_ip", "unknown"), flow.get("dst_ip", "unknown"))].append(flow)
        domain = flow.get("domain") or ""
        if domain:
            by_domain[domain].append(flow)

    for src_ip, entries in by_source.items():
        total_packets = sum(int(f.get("packet_count", 0) or 0) for f in entries)
        total_in = sum(int(f.get("in_bytes", 0) or 0) for f in entries)
        total_out = sum(int(f.get("out_bytes", 0) or 0) for f in entries)
        unique_dsts = len({f.get("dst_ip") for f in entries})
        unique_ports = len({int(f.get("dst_port", 0) or 0) for f in entries})

        if total_packets >= 180 and total_in >= 700000 and unique_dsts <= 2:
            score = min(0.99, 0.55 + min(0.35, total_packets / 1000.0) + min(0.15, total_in / 4000000.0))
            evidence = {
                "packet_count": total_packets,
                "in_bytes": total_in,
                "unique_destinations": unique_dsts,
                "unique_ports": unique_ports,
                "pattern": "synchronized flood pattern",
            }
            alerts.append(_make_alert(entries[0], "ddos", score, evidence))

        if unique_ports >= 10 and total_packets >= 30:
            score = min(0.96, 0.42 + unique_ports / 30.0)
            evidence = {
                "unique_ports": unique_ports,
                "packet_count": total_packets,
                "source_ip": src_ip,
                "pattern": "fan-out reconnaissance",
            }
            alerts.append(_make_alert(entries[0], "reconnaissance", score, evidence))

    for (src_ip, dst_ip), entries in by_src_dst.items():
        if len(entries) >= 4:
            intervals = []
            previous = None
            for flow in sorted(entries, key=lambda x: x.get("timestamp", "")):
                ts = flow.get("timestamp")
                if ts and previous:
                    try:
                        previous_dt = datetime.fromisoformat(previous)
                        current_dt = datetime.fromisoformat(ts)
                        intervals.append((current_dt - previous_dt).total_seconds())
                    except ValueError:
                        pass
                previous = ts
            if intervals:
                avg_gap = sum(intervals) / len(intervals)
                deviation = (sum((gap - avg_gap) ** 2 for gap in intervals) / len(intervals)) ** 0.5
                if avg_gap >= 10 and deviation <= 5:
                    score = min(0.98, 0.5 + len(entries) / 50.0)
                    evidence = {
                        "interval_seconds": round(avg_gap, 2),
                        "deviation_seconds": round(deviation, 2),
                        "event_count": len(entries),
                        "destination": dst_ip,
                    }
                    alerts.append(_make_alert(entries[0], "beaconing", score, evidence))

    for domain, entries in by_domain.items():
        if not domain:
            continue
        lengths = [len(d) for d in [entry.get("domain", "") for entry in entries if entry.get("domain")]]
        entropies = [_entropy(d) for d in [entry.get("domain", "") for entry in entries if entry.get("domain")]]
        if lengths and (max(lengths) >= 30 or max(entropies) >= 3.8):
            score = min(0.95, 0.45 + (max(lengths) / 80.0) + (max(entropies) / 8.0))
            evidence = {
                "domain": domain,
                "max_length": max(lengths),
                "max_entropy": round(max(entropies), 2),
                "query_types": sorted({entry.get("query_type", "UNKNOWN") for entry in entries}),
            }
            alerts.append(_make_alert(entries[0], "dns_tunneling", score, evidence))

    for src_ip, entries in by_source.items():
        total_in = sum(int(f.get("in_bytes", 0) or 0) for f in entries)
        total_out = sum(int(f.get("out_bytes", 0) or 0) for f in entries)
        if total_out and total_in and total_out / max(total_in, 1) >= 3.0:
            score = min(0.94, 0.45 + (total_out / max(total_in, 1)) / 4.5)
            evidence = {
                "outbound_to_inbound_ratio": round(total_out / max(total_in, 1), 2),
                "outbound_bytes": total_out,
                "inbound_bytes": total_in,
            }
            alerts.append(_make_alert(entries[0], "exfiltration", score, evidence))

    for src_ip, entries in by_source.items():
        suspicious = [
            f for f in entries
            if str(f.get("ja3", "")).lower() not in ("", "n/a")
            and str(f.get("tls_version", "")).lower() in {"1.0", "1.1", "n/a"}
        ]
        if suspicious:
            score = min(0.93, 0.55 + len(suspicious) / 25.0)
            evidence = {
                "suspicious_tls_flows": len(suspicious),
                "sample_ja3": suspicious[0].get("ja3"),
                "sample_tls_version": suspicious[0].get("tls_version"),
                "pattern": "encrypted-session metadata anomaly",
            }
            alerts.append(_make_alert(suspicious[0], "tls_malware", score, evidence))

    deduped: list[dict[str, Any]] = []
    seen = set()
    for alert in alerts:
        key = (alert["flow_id"], alert["threat_class"])
        if key not in seen:
            deduped.append(alert)
            seen.add(key)
    return sorted(deduped, key=lambda item: item["timestamp"])
