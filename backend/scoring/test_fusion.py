from backend.scoring.threat_fusion import (
    ThreatFusionEngine,
)


def main():

    fusion = ThreatFusionEngine()

    print("=" * 60)
    print("SENTINEL-X THREAT FUSION TEST")
    print("=" * 60)

    print()

    result = fusion.create_alert(
        threat_class="SYN_FLOOD",
        severity="CRITICAL",
        confidence=0.96,
        detector="SynFloodDetector",
        source_ip="192.168.1.100",
        destination_ip="10.0.0.50",
        destination_port=443,
        protocol="TCP",
        evidence={
            "syn_count": 500,
            "syn_rate": 250.0,
            "syn_ratio": 0.98,
            "total_packets": 510,
        },
        description=(
            "Potential SYN flood detected "
            "using passive flow metadata."
        ),
    )

    alert = result.alert

    print("Alert ID     :", alert.alert_id)

    print(
        "Threat       :",
        alert.threat_class,
    )

    print(
        "Severity     :",
        alert.severity,
    )

    print(
        "Confidence   :",
        alert.confidence,
    )

    print(
        "Risk Score   :",
        alert.risk_score,
    )

    print(
        "Source       :",
        alert.source_ip,
    )

    print(
        "Destination  :",
        alert.destination_ip,
    )

    print(
        "Protocol     :",
        alert.protocol,
    )

    print(
        "Correlated   :",
        result.correlated,
    )

    print()

    print("JSON ALERT")
    print("-" * 60)

    print(
        alert.model_dump_json(
            indent=2
        )
    )

    print()

    # Test duplicate/correlation
    second = fusion.create_alert(
        threat_class="SYN_FLOOD",
        severity="CRITICAL",
        confidence=0.91,
        detector="SynFloodDetector",
        source_ip="192.168.1.100",
        destination_ip="10.0.0.50",
        destination_port=443,
        protocol="TCP",
        evidence={
            "syn_count": 600,
            "syn_rate": 300.0,
        },
    )

    print(
        "Second alert correlated :",
        second.correlated,
    )

    print()
    print("=" * 60)


if __name__ == "__main__":
    main()