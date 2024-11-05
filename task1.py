from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

# Callback function that processes each packet
def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        # Display packet information
        print(f"Source IP: {ip_src} -> Destination IP: {ip_dst} | Protocol: {protocol}")

        # Check for TCP packets
        if packet.haslayer(TCP):
            print(f"TCP Packet | Source Port: {packet[TCP].sport} | Destination Port: {packet[TCP].dport}")

        # Check for UDP packets
        elif packet.haslayer(UDP):
            print(f"UDP Packet | Source Port: {packet[UDP].sport} | Destination Port: {packet[UDP].dport}")

        # Check for ICMP packets
        elif packet.haslayer(ICMP):
            print("ICMP Packet")

# Start the packet sniffer
print("Starting the network sniffer...")
sniff(filter="ip", prn=packet_callback, count=10)  # Adjust count or remove to run indefinitely
