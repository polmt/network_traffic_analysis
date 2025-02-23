from scapy.all import sniff, wrpcap, raw
import os

pcap_file = "resources/packet_callback_capture.pcap"
os.makedirs("resources", exist_ok=True)
packets = []

def packet_callback(packet):
    print("Packet Summary:")
    print(packet.summary())
    print("\nPacket Structure (show):")
    packet.show()
    print("\nPacket Structure (show2):")
    packet.show2()
    print("\nHexdump:")
    packet.hexdump()
    print("\nRaw Packet Data:")
    print(raw(packet))
    print("\nPacket Layers:")
    print(packet.layers())
    if packet.haslayer("IP"):
        print("\nThis packet has an IP layer.")
    if packet.haslayer("IP"):
        ip_layer = packet.getlayer("IP")
        print("\nIP Layer Fields:")
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        print(f"Protocol: {ip_layer.proto}")
    print("\nLast Layer in the Packet:")
    print(packet.lastlayer())
    print("\nReconstruction Command:")
    print(packet.command())
    print("\nPacket Length:")
    print(len(packet))
    print("\nTimestamp:")
    print(packet.time)
    packets.append(packet)

try:
    print("Starting packet capture on interface 'uesimtun0'. Press Ctrl+C to stop.")
    sniff(iface="uesimtun0", prn=packet_callback, store=False)
except KeyboardInterrupt:
    print("\nCapture stopped. Saving packets to file...")
    wrpcap(pcap_file, packets)
    print(f"Packets saved to {pcap_file}")
