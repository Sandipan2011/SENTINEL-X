from backend.features.entropy import shannon_entropy


def main():

    test_values = [
        "example.com",
        "aaaaaaaaaaaaaaaa",
        "x7k2p9m4q8z1",
        "ajd82k3m9x7q1z8p4n6v",
    ]

    print("=" * 60)
    print("SENTINEL-X ENTROPY TEST")
    print("=" * 60)

    for value in test_values:

        entropy = shannon_entropy(value)

        print(
            f"{value:30} "
            f"entropy = {entropy:.4f}"
        )


if __name__ == "__main__":
    main()