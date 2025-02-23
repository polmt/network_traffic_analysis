from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, wrpcap
import os
from datetime import datetime

log_folder = "resources"
os.makedirs(log_folder, exist_ok=True)
log_file_path = os.path.join(log_folder, "suspicious_activity.log")
pcap_file = os.path.join(log_folder, "captured_packets.pcap")
captured_packets = []

def log_suspicious_activity(packet_info):
    with open(log_file_path, "a") as log_file:
        log_file.write(packet_info + "\n")
    print(packet_info)

def is_suspicious(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        if TCP in packet or UDP in packet:
            port = packet[TCP].sport if TCP in packet else packet[UDP].sport
            if port not in range(1, 1024):
                return f"Suspicious Port: {ip_src} -> {ip_dst} | Port: {port}"
        if Raw in packet and len(packet[Raw].load) > 1000:
            return f"Large Payload: {ip_src} -> {ip_dst} | Size: {len(packet[Raw].load)} bytes"
        if ICMP in packet:
            return f"ICMP Packet: {ip_src} -> {ip_dst}"
    return None

def packet_callback(packet):
    captured_packets.append(packet)
    suspicion = is_suspicious(packet)
    if suspicion:
        log_suspicious_activity(f"[{datetime.now()}] {suspicion}")

def main():
    interface = "uesimtun0"
    try:
        sniff(iface=interface, prn=packet_callback, store=False)
    except KeyboardInterrupt:
        wrpcap(pcap_file, captured_packets)

if __name__ == "__main__":
    main()
