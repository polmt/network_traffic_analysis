from scapy.all import IP, TCP, UDP, sr1, sr
import argparse
import os
import csv

def tcp_scan(target, ports):
    open_ports = []
    for port in ports:
        packet = IP(dst=target) / TCP(dport=port, flags="S")
        response = sr1(packet, timeout=1, verbose=0)
        if response and response.haslayer(TCP) and response[TCP].flags == "SA":
            open_ports.append(port)
            print(f"[OPEN] TCP Port {port}")
    return open_ports

def udp_scan(target, ports):
    open_ports = []
    for port in ports:
        packet = IP(dst=target) / UDP(dport=port)
        response = sr1(packet, timeout=1, verbose=0)
        if not response:
            open_ports.append(port)
            print(f"[OPEN or FILTERED] UDP Port {port}")
        elif response.haslayer(UDP):
            open_ports.append(port)
            print(f"[OPEN] UDP Port {port}")
    return open_ports

def save_results_to_file(results, target, output_file):
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Target", "Protocol", "Open Ports"])
        for protocol, ports in results.items():
            writer.writerow([target, protocol, ", ".join(map(str, ports))])
    print(f"[INFO] Results saved to {output_file}")

def main():
    parser = argparse.ArgumentParser(description="Advanced Port Scanner using Scapy")
    parser.add_argument("-t", "--target", required=True, help="Target IP address")
    parser.add_argument("-p", "--ports", default="1-1024", help="Port range (default: 1-1024)")
    parser.add_argument("-s", "--scan", choices=["tcp", "udp", "both"], default="both", help="Type of scan (default: both)")
    parser.add_argument("-o", "--output", default="resources/cptr_port_scan_results.csv", help="Output file (default: resources/cptr_port_scan_results.csv)")
    args = parser.parse_args()

    target = args.target
    port_range = args.ports
    scan_type = args.scan
    output_file = args.output

    start_port, end_port = map(int, port_range.split("-"))
    ports = range(start_port, end_port + 1)

    print(f"[INFO] Starting port scan on target: {target}")
    print(f"[INFO] Port range: {start_port}-{end_port}")
    print(f"[INFO] Scan type: {scan_type}")

    results = {}

    if scan_type in ["tcp", "both"]:
        print("[INFO] Performing TCP scan...")
        results["TCP"] = tcp_scan(target, ports)

    if scan_type in ["udp", "both"]:
        print("[INFO] Performing UDP scan...")
        results["UDP"] = udp_scan(target, ports)

    save_results_to_file(results, target, output_file)
    print("[INFO] Port scan completed.")

if __name__ == "__main__":
    main()

