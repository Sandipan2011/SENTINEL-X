from backend.detection.tls.tls_detector import (
    TLSDetector,
)


def main():

    detector = TLSDetector(
        high_packet_rate=20.0,
        high_byte_rate=5000.0,
        asymmetric_ratio=5.0,
        low_packet_variation=5.0,
    )

    print("=" * 60)
    print("SENTINEL-X TLS METADATA DETECTION TEST")
    print("=" * 60)

    print()

    # ---------------------------------------------------------
    # Normal TLS session
    # ---------------------------------------------------------

    normal_packet_sizes = [
        60,
        120,
        250,
        500,
        900,
        300,
        150,
        700,
    ]

    normal = detector.detect(
        protocol="TLS",
        packet_sizes=normal_packet_sizes,
        duration=10.0,
        bytes_forward=1500,
        bytes_reverse=1480,
        tls_version="TLS1.3",
        fingerprint="example-ja4",
    )

    print("-" * 60)
    print("NORMAL TLS SESSION")
    print()

    print(
        "Detected   :",
        normal.detected,
    )

    print(
        "Threat     :",
        normal.threat_class,
    )

    print(
        "Confidence :",
        normal.confidence,
    )

    print(
        "Severity   :",
        normal.severity,
    )

    print()

    # ---------------------------------------------------------
    # Suspicious TLS session
    # ---------------------------------------------------------

    suspicious_packet_sizes = [
        64,
        64,
        64,
        64,
        64,
        64,
        64,
        64,
        64,
        64,
        64,
        64,
    ]

    suspicious = detector.detect(
        protocol="TLS",
        packet_sizes=suspicious_packet_sizes,
        duration=0.5,
        bytes_forward=12000,
        bytes_reverse=500,
        tls_version="TLS1.2",
        fingerprint="suspicious-ja4",
    )

    print("-" * 60)
    print("SUSPICIOUS TLS SESSION")
    print()

    print(
        "Detected   :",
        suspicious.detected,
    )

    print(
        "Threat     :",
        suspicious.threat_class,
    )

    print(
        "Confidence :",
        suspicious.confidence,
    )

    print(
        "Severity   :",
        suspicious.severity,
    )

    print()

    print("Evidence:")

    for key, value in suspicious.evidence.items():

        print(
            f"  {key:30}: {value}"
        )

    print()

    # ---------------------------------------------------------
    # Suspicious QUIC session
    # ---------------------------------------------------------

    quic = detector.detect(
        protocol="QUIC",
        packet_sizes=[
            1200,
            1200,
            1200,
            1200,
            1200,
            1200,
        ],
        duration=0.4,
        bytes_forward=7000,
        bytes_reverse=300,
        tls_version=None,
        fingerprint="quic-metadata-fingerprint",
    )

    print("-" * 60)
    print("SUSPICIOUS QUIC SESSION")
    print()

    print(
        "Detected   :",
        quic.detected,
    )

    print(
        "Threat     :",
        quic.threat_class,
    )

    print(
        "Confidence :",
        quic.confidence,
    )

    print(
        "Severity   :",
        quic.severity,
    )

    print()

    print("=" * 60)


if __name__ == "__main__":
    main()