from backend.detection.dns.dns_detector import (
    DNSDetector,
)


def main():

    detector = DNSDetector()

    test_queries = [
        "www.google.com",

        "api.example.com",

        "x7k2p9m4q8z1d5f3.example.com",

        (
            "a8f91k2m7x4q9z1c5v8b3n6m2"
            "p7r4t9w2y5.example.com"
        ),

        (
            "k9x2m7p4q8z1v5b3n6c9"
            "a7d2f8g4h1j6.example.com"
        ),
    ]

    print("=" * 60)
    print("SENTINEL-X DNS THREAT DETECTION TEST")
    print("=" * 60)

    print()

    for query in test_queries:

        result = detector.detect(
            query
        )

        print("-" * 60)

        print(
            "Query      :",
            query,
        )

        print(
            "Detected   :",
            result.detected,
        )

        print(
            "Threat     :",
            result.threat_class,
        )

        print(
            "Confidence :",
            result.confidence,
        )

        print(
            "Severity   :",
            result.severity,
        )

        print()

        print("Evidence:")

        for key, value in result.evidence.items():

            print(
                f"  {key:25}: {value}"
            )

        print()


if __name__ == "__main__":
    main()