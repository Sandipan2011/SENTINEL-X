import sys

from backend.ingest.pcap_reader import read_pcap


def main():
    if len(sys.argv) != 2:
        print("Usage:")
        print("python -m backend.ingest.test_reader <pcap_file>")
        return

    pcap_file = sys.argv[1]

    count = 0

    try:
        for flow in read_pcap(pcap_file):
            count += 1

            print(flow.model_dump_json())

            if count >= 20:
                break

        print()
        print(f"Packets processed: {count}")

    except Exception as exc:
        print(f"ERROR: {exc}")


if __name__ == "__main__":
    main()