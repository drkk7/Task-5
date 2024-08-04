import sniff
import IP, TCP, UDP, ICMP

def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        
        # Determine the protocol type
        if protocol == 6:  # TCP
            proto_name = "TCP"
        elif protocol == 17:  # UDP
            proto_name = "UDP"
        elif protocol == 1:  # ICMP
            proto_name = "ICMP"
        else:
            proto_name = "Other"
        
        # Display packet information
        print(f"[+] {proto_name} Packet: {ip_src} -> {ip_dst}")
        
        # Display payload if present
        if proto_name == "TCP" and packet.haslayer(TCP):
            payload = packet[TCP].payload
        elif proto_name == "UDP" and packet.haslayer(UDP):
            payload = packet[UDP].payload
        elif proto_name == "ICMP" and packet.haslayer(ICMP):
            payload = packet[ICMP].payload
        else:
            payload = None
        
        if payload:
            print(f"    Payload: {bytes(payload).decode('utf-8', errors='replace')}")
    else:
        print("Non-IP packet captured")

def start_sniffer(interface=None, packet_count=0):
    print("Starting packet sniffer...")
    sniff(prn=packet_callback, store=False, count=packet_count, iface=interface)

if __name__ == "__main__":
    # Specify the network interface and number of packets to capture (0 for infinite)
    interface = "eth0"  # Replace with your network interface
    packet_count = 10  # Set to 0 for continuous capture

    # Start the sniffer
    start_sniffer(interface=interface, packet_count=packet_count)
