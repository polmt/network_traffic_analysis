from scapy.all import sniff, wrpcap
import os

output_folder = "resources"
os.makedirs(output_folder, exist_ok=True)
pcap_file = os.path.join(output_folder, "cptr_pkt_scapy.pcap")

captured_packets = []

def packet_callback(packet):
    captured_packets.append(packet)
    print(f"Captured packet: {packet.summary()}")

def main():
    interface = "uesimtun0"
    print(f"Starting packet capture on interface: {interface}")
    print(f"Captured packets will be saved to: {pcap_file}")
    try:
        sniff(iface=interface, prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print("\nStopping packet capture.")
        print(f"Saving {len(captured_packets)} packets to {pcap_file}...")
        wrpcap(pcap_file, captured_packets)
        print("Packets saved successfully.")
    except Exception as e:
        print(f"Error occurred: {e}")

if __name__ == "__main__":
    main()
