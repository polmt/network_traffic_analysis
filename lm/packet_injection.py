from scapy.all import IP, TCP, send

def inject_packet():
    src_ip = "192.168.56.1"
    dst_ip = "192.168.56.102"
    src_port = 5353
    dst_port = 2152
    packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="S") / "Injected Payload"
    print(f"Injecting packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
    send(packet, iface="uesimtun0", verbose=False)
    print("Packet injected successfully!")

if __name__ == "__main__":
    try:
        while True:
            inject_packet()
    except KeyboardInterrupt:
        print("\nStopping packet injection.")
