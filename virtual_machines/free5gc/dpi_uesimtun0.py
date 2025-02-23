#!/usr/bin/env python3

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
import os
from datetime import datetime
import binascii

# Create the resources folder if it doesn't exist
log_folder = "resources"
os.makedirs(log_folder, exist_ok=True)

# Log file path
log_file_path = os.path.join(log_folder, "packet_logs.txt")

# Open log file in append mode
log_file = open(log_file_path, "a")


def log_packet(packet_info):
    """
    Write the captured packet's information to the log file.
    """
    log_file.write(packet_info + "\n")
    log_file.flush()  # Ensure data is written to disk immediately


def detect_http_https(packet):
    """
    Check if the packet contains HTTP or HTTPS data.
    """
    if Raw in packet:
        payload = packet[Raw].load.decode(errors="ignore")
        if "HTTP" in payload or "GET" in payload or "POST" in payload:
            return "HTTP"
        elif "TLS" in payload or "SSL" in payload:
            return "HTTPS"
    return None


def packet_callback(packet):
    """
    Callback function to process each captured packet.
    """
    try:
        packet_info = ""
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            protocol = packet[IP].proto

            packet_info += f"\n[{datetime.now()}] Captured Packet: {ip_src} -> {ip_dst} | Protocol: {protocol}\n"

            # Check for TCP packets
            if TCP in packet:
                tcp_src_port = packet[TCP].sport
                tcp_dst_port = packet[TCP].dport
                packet_info += f"TCP Packet: Src Port: {tcp_src_port}, Dst Port: {tcp_dst_port}\n"

                # Detect HTTP/HTTPS
                http_protocol = detect_http_https(packet)
                if http_protocol:
                    packet_info += f"Detected Protocol: {http_protocol}\n"

                # Log payload
                if Raw in packet:
                    payload = packet[Raw].load
                    packet_info += f"Payload (hex): {binascii.hexlify(payload[:100]).decode()}\n"

            # Check for UDP packets
            elif UDP in packet:
                udp_src_port = packet[UDP].sport
                udp_dst_port = packet[UDP].dport
                packet_info += f"UDP Packet: Src Port: {udp_src_port}, Dst Port: {udp_dst_port}\n"

                # Detect DNS, FTP, or other protocols
                if udp_dst_port == 53 or udp_src_port == 53:
                    packet_info += "Detected Protocol: DNS\n"
                elif udp_dst_port in [20, 21] or udp_src_port in [20, 21]:
                    packet_info += "Detected Protocol: FTP\n"

                # Log payload
                if Raw in packet:
                    payload = packet[Raw].load
                    packet_info += f"Payload (hex): {binascii.hexlify(payload[:100]).decode()}\n"

            # Check for ICMP packets
            elif ICMP in packet:
                packet_info += "ICMP Packet Detected\n"
                icmp_type = packet[ICMP].type
                packet_info += f"ICMP Type: {icmp_type}\n"

            # Other Protocols
            else:
                packet_info += "Non-TCP/UDP/ICMP packet detected\n"

        # Print packet info to console
        if packet_info:
            print(packet_info)

        # Log packet info to file
        if packet_info:
            log_packet(packet_info)

    except Exception as e:
        print(f"Error processing packet: {e}")


def main():
    """
    Main function to start packet capture on uesimtun0 interface.
    """
    interface = "uesimtun0"  # Specify the interface to monitor

    print(f"Starting packet capture on interface: {interface}")
    print(f"Logging captured packets to: {log_file_path}\n")
    try:
        sniff(iface=interface, prn=packet_callback, store=False)
    except PermissionError:
        print("Error: Run the script as root or use sudo for capturing packets.")
    except KeyboardInterrupt:
        print("\nPacket capture stopped.")
    except Exception as e:
        print(f"Error occurred: {e}")
    finally:
        log_file.close()


if __name__ == "__main__":
    main()
