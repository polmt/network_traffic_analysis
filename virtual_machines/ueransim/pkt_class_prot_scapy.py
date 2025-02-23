from scapy.all import sniff, wrpcap, IP, TCP, UDP, ICMP, Raw
import os

output_folder = "resources"
os.makedirs(output_folder, exist_ok=True)
pcap_file = os.path.join(output_folder, "cptr_pkt_class_prot_scapy.pcap")

captured_packets = []

def classify_packet(packet):
    if IP in packet:
        protocol = None
        if TCP in packet:
            if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                protocol = "HTTP"
            elif packet[TCP].dport == 443 or packet[TCP].sport == 443:
                protocol = "HTTPS"
            else:
                protocol = "TCP"
        elif UDP in packet:
            if packet[UDP].dport == 53 or packet[UDP].sport == 53:
                protocol = "DNS"
            else:
                protocol = "UDP"
        elif ICMP in packet:
            protocol = "ICMP"
        else:
            protocol = "Other IP Protocol"
        print(f"Captured {protocol} packet: {packet[IP].src} -> {packet[IP].dst}")
    else:
        print("Captured non-IP packet.")
    captured_packets.append(packet)

def main():
    interface = "uesimtun0"
    print(f"Starting packet capture on interface: {interface}")
    print(f"Captured packets will be saved to: {pcap_file}")
    try:
        sniff(iface=interface, prn=classify_packet, store=False)
    except KeyboardInterrupt:
        print("\nStopping packet capture.")
        print(f"Saving {len(captured_packets)} packets to {pcap_file}...")
        wrpcap(pcap_file, captured_packets)
        print("Packets saved successfully.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
