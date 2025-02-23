# Network Traffic Analysis - Deep Packet Inspection

## Setup

```
git clone https://github.com/polmt/network_traffic_analysis
```

### Setup Commands
```
# Create virtual environment
python -m venv venv
```

```
.\myenv\Scripts\activate.bat
pip install -r requirements.txt
```

## Overview
This document provides a guide on how to generate, capture, and analyze network traffic using tools like `wget`, `traceroute`, `ping`, `curl`, `tcpdump`, and `tshark`. The purpose is to conduct deep packet inspection (DPI) for network traffic analysis.

## Prerequisites
Ensure your system has the following tools installed:
- `wget`
- `traceroute`
- `ping`
- `curl`
- `tcpdump`
- `tshark`
- `wireshark`

On Debian-based systems, install them using:
```sh
sudo apt update && sudo apt install wget traceroute curl tcpdump tshark wireshark
```

## Creating Network Traffic

### Generate Network Requests
Run the following commands to generate different types of network traffic:
```sh
# Download a file with limited bandwidth
wget --limit-rate=1K https://dl.google.com/go/go1.21.8.linux-amd64.tar.gz

# Perform an ICMP traceroute using a specific interface with a max TTL of 64
traceroute -I uesimtun0 -m 64 activision.com

# Send ICMP echo requests (ping) using a specific interface
ping -I uesimtun0 activision.com

# Make HTTP/HTTPS requests using a specific interface
curl --interface uesimtun0 https://www.activision.com
curl --interface uesimtun0 --tlsv1.2 https://www.activision.com
```

### Automate Traffic Generation
Create a shell script to run multiple traffic generation commands simultaneously:
```sh
#!/bin/bash

# Start multiple wget downloads with limited bandwidth
wget --limit-rate=1K https://dl.google.com/go/go1.21.8.linux-amd64.tar.gz &
wget --limit-rate=1K https://www.learningcontainer.com/wp-content/uploads/2020/05/sample-mp4-file.mp4 &

# Run network analysis commands
traceroute -I uesimtun0 -m 64 activision.com &
ping -I uesimtun0 activision.com &
curl --interface uesimtun0 --tlsv1.2 https://www.activision.com &

wait
```
Save the script as `network_traffic.sh`, then make it executable and run it:
```sh
chmod +x network_traffic.sh
./network_traffic.sh
```

### System Updates (Optional)
Ensure your system is up to date before running tests:
```sh
sudo apt update && sudo apt upgrade
```

## Capturing Network Traffic

### Using `tcpdump`
Capture and analyze packets with different verbosity levels:
```sh
# Maximum verbosity (-vvv)
sudo tcpdump -i uesimtun0 -w tcpdump_capture_network_traffic_uesimtun0.pcap -vvv

# Verbose output with real-time display
sudo tcpdump -i uesimtun0 -vv -w tcpdump_capture_network_traffic_uesimtun0.pcap

# Verbose output with real-time display and save to file
sudo tcpdump -i uesimtun0 -vv | tee tcpdump_verbose_output.txt
```

### Filtering Traffic
```sh
# Capture only TCP traffic
sudo tcpdump -i uesimtun0 tcp -vv -w tcpdump_capture_network_traffic_uesimtun0.pcap

# Capture traffic to/from a specific host
sudo tcpdump -i uesimtun0 host 8.8.8.8 -vv -w tcpdump_capture_network_traffic_uesimtun0.pcap

# Capture traffic on a specific port (e.g., HTTP)
sudo tcpdump -i uesimtun0 port 80 -vv -w tcpdump_capture_network_traffic_uesimtun0.pcap
```

### Using `tshark`
```sh
# Capture and display traffic live
sudo tshark -i uesimtun0

# Capture traffic and save to a file
sudo tshark -i uesimtun0 -w tshark_capture_network_traffic_uesimtun0.pcap
```

## Analyzing Captured Traffic

### Using `tcpdump`
```sh
sudo tcpdump -r tcpdump_capture_network_traffic_uesimtun0.pcap -vv
```

### Using `Wireshark`
```sh
wireshark tcpdump_capture_network_traffic_uesimtun0.pcap
```

### Using `tshark`
```sh
tshark -r tshark_capture_network_traffic_uesimtun0.pcap
```

---
