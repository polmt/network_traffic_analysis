from scapy.all import sniff, IP, TCP, Raw
import os

interface = "uesimtun0"
output_folder = "resources"
os.makedirs(output_folder, exist_ok=True)
streams = {}

def process_packet(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(Raw):
        src = packet[IP].src
        dst = packet[IP].dst
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        connection = (src, sport, dst, dport)
        if connection not in streams:
            streams[connection] = b""
        streams[connection] += bytes(packet[Raw].load)

sniff(iface=interface, prn=process_packet, timeout=60)

for conn, data in streams.items():
    src_ip, src_port, dst_ip, dst_port = conn
    filename = f"{output_folder}/stream_{src_ip}_{src_port}_to_{dst_ip}_{dst_port}.txt"
    with open(filename, "wb") as f:
        f.write(data)
