from scapy.all import IP, TCP, UDP, DNS, DNSQR, wrpcap


OUTPUT_FILE = "datasets/test_traffic.pcap"


packets = []


# TCP traffic
for i in range(10):
    packet = (
        IP(src="192.168.1.10", dst="10.0.0.20")
        / TCP(
            sport=40000 + i,
            dport=443,
            flags="S"
        )
    )

    packets.append(packet)


# UDP traffic
for i in range(10):
    packet = (
        IP(src="192.168.1.10", dst="10.0.0.30")
        / UDP(
            sport=50000 + i,
            dport=53
        )
        / DNS(
            rd=1,
            qd=DNSQR(qname=f"example{i}.test")
        )
    )

    packets.append(packet)


wrpcap(OUTPUT_FILE, packets)

print(f"Created PCAP: {OUTPUT_FILE}")
print(f"Packets: {len(packets)}")