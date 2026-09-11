from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw, wrpcap
from pathlib import Path
from datetime import datetime, timedelta
import random


OUTPUT = Path("datasets/sih_demo_traffic.pcap")

random.seed(26145)


def tcp_packet(src, dst, sport, dport, flags, timestamp):
    packet = IP(src=src, dst=dst) / TCP(
        sport=sport,
        dport=dport,
        flags=flags,
    )
    packet.time = timestamp
    return packet


def udp_packet(src, dst, sport, dport, timestamp, payload=b""):
    packet = IP(src=src, dst=dst) / UDP(
        sport=sport,
        dport=dport,
    ) / Raw(load=payload)

    packet.time = timestamp
    return packet


def dns_packet(src, dst, query, timestamp):
    packet = (
        IP(src=src, dst=dst)
        / UDP(sport=random.randint(20000, 60000), dport=53)
        / DNS(
            rd=1,
            qd=DNSQR(qname=query),
        )
    )

    packet.time = timestamp
    return packet


def generate_syn_flood(packets, start):
    print("[+] Generating SYN flood...")

    src = "192.168.10.50"
    dst = "10.0.0.20"

    for i in range(60):
        timestamp = start + timedelta(milliseconds=i * 25)

        packets.append(
            tcp_packet(
                src,
                dst,
                20000 + i,
                443,
                "S",
                timestamp.timestamp(),
            )
        )


def generate_volumetric_udp(packets, start):
    print("[+] Generating volumetric UDP traffic...")

    dst = "10.0.0.30"

    for i in range(160):
        timestamp = start + timedelta(milliseconds=i * 15)

        packets.append(
            udp_packet(
                "192.168.20.10",
                dst,
                random.randint(20000, 60000),
                443,
                timestamp.timestamp(),
                payload=b"A" * 1200,
            )
        )


def generate_port_scan(packets, start):
    print("[+] Generating port scan...")

    src = "192.168.30.25"

    ports = [
        21,
        22,
        23,
        25,
        53,
        80,
        110,
        135,
        139,
        143,
        443,
        445,
        993,
        995,
        1433,
        3306,
        3389,
        5432,
        5900,
        8080,
    ]

    for i, port in enumerate(ports):
        timestamp = start + timedelta(milliseconds=i * 150)

        packets.append(
            tcp_packet(
                src,
                "10.0.40.10",
                30000 + i,
                port,
                "S",
                timestamp.timestamp(),
            )
        )


def generate_beaconing(packets, start):
    print("[+] Generating C2 beacon traffic...")

    src = "192.168.40.15"
    dst = "10.0.50.50"

    for i in range(8):
        timestamp = start + timedelta(seconds=i * 5)

        packets.append(
            tcp_packet(
                src,
                dst,
                40000 + i,
                443,
                "S",
                timestamp.timestamp(),
            )
        )

        packets.append(
            tcp_packet(
                dst,
                src,
                443,
                40000 + i,
                "SA",
                (timestamp + timedelta(milliseconds=50)).timestamp(),
            )
        )


def generate_dns_anomaly(packets, start):
    print("[+] Generating DGA / DNS tunneling traffic...")

    src = "192.168.50.20"
    dst = "8.8.8.8"

    queries = [
        "x7k29m4q9v2n8p1.example.com",
        "a91k2m8z7q4x6.example.com",
        "9xq7v3m2k8n1.example.com",
        "q8n2m7x4z9k1.example.com",
        "v4x8q2m9n7k3.example.com",
        "m9k4x7q2n8v1.example.com",
        "z2n8q4m7x9k3.example.com",
        "k7m2x9q4v8n1.example.com",
    ]

    for i, query in enumerate(queries):
        timestamp = start + timedelta(milliseconds=i * 250)

        packets.append(
            dns_packet(
                src,
                dst,
                query,
                timestamp.timestamp(),
            )
        )


def generate_tls_anomaly(packets, start):
    print("[+] Generating suspicious TLS metadata...")

    src = "192.168.60.30"
    dst = "10.0.60.60"

    for i in range(120):
        timestamp = start + timedelta(milliseconds=i * 20)

        packets.append(
            tcp_packet(
                src,
                dst,
                50000,
                443,
                "PA",
                timestamp.timestamp(),
            )
        )


def generate_exfiltration(packets, start):
    print("[+] Generating data exfiltration...")

    src = "192.168.70.40"
    dst = "10.0.70.70"

    for i in range(20):
        timestamp = start + timedelta(milliseconds=i * 200)

        packets.append(
            udp_packet(
                src,
                dst,
                55000,
                8443,
                timestamp.timestamp(),
                payload=b"EXFIL_DATA_" + b"X" * 9000,
            )
        )


def main():
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    packets = []

    base_time = datetime.now()

    generate_syn_flood(
        packets,
        base_time,
    )

    generate_volumetric_udp(
        packets,
        base_time + timedelta(seconds=15),
    )

    generate_port_scan(
        packets,
        base_time + timedelta(seconds=30),
    )

    generate_beaconing(
        packets,
        base_time + timedelta(seconds=45),
    )

    generate_dns_anomaly(
        packets,
        base_time + timedelta(seconds=90),
    )

    generate_tls_anomaly(
        packets,
        base_time + timedelta(seconds=110),
    )

    generate_exfiltration(
        packets,
        base_time + timedelta(seconds=125),
    )

    packets.sort(
        key=lambda packet: float(packet.time)
    )

    wrpcap(
        str(OUTPUT),
        packets,
    )

    print()
    print("=" * 70)
    print("SENTINEL-X SIH DEMO PCAP GENERATED")
    print("=" * 70)
    print("Output :", OUTPUT)
    print("Packets:", len(packets))
    print("=" * 70)


if __name__ == "__main__":
    main()