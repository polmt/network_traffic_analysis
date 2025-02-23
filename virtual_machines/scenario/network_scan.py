from scapy.all import ARP, Ether, srp
import os

def network_scan(interface, subnet):
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
    ans, _ = srp(packet, iface=interface, timeout=2, verbose=0)
    devices = []
    for sent, received in ans:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    for device in devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}")
    return devices

if __name__ == "__main__":
    interface = "uesimtun0"
    subnet = "192.168.1.0/24"
    network_scan(interface, subnet)
