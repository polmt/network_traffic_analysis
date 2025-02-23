import os
from scapy.all import rdpcap

packets = rdpcap('../resources/cptr_pkt_pcapy.pcap')

output_folder = 'human_readable'
os.makedirs(output_folder, exist_ok=True)

output_file = os.path.join(output_folder, 'cptr_pkt_pcapy.txt')

with open(output_file, 'w') as f:
    for packet in packets:
        f.write(packet.summary() + '\n')

print(f"Packet summaries saved to: {output_file}")
