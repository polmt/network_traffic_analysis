import pcapy
from datetime import datetime
import os

output_folder = "resources"
os.makedirs(output_folder, exist_ok=True)
pcap_file = f"{output_folder}/cptr_pkt_pcapy.pcap"

def capture_packets(interface):
    cap = pcapy.open_live(interface, 65536, 1, 0)
    dumper = None
    try:
        dumper = cap.dump_open(pcap_file)
    except Exception as e:
        print(f"Failed to open pcap file for writing: {e}")
        return

    print(f"Capturing packets on interface {interface}...")
    print(f"Saving packets to {pcap_file}")

    def packet_handler(header, packet):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        print(f"[{timestamp}] Captured packet of length {header.getlen()} bytes")
        if dumper:
            dumper.dump(header, packet)

    try:
        cap.loop(0, packet_handler)
    except KeyboardInterrupt:
        print("\nStopping packet capture.")
    finally:
        if dumper:
            dumper.close()
        cap.close()

if __name__ == "__main__":
    interface = "upfgtp"
    capture_packets(interface)
