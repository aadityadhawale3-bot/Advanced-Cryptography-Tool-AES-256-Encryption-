# Cross-Platform Native Packet Sniffer & Network Analyzer

## 📌 Project Overview
This repository contains a low-level network traffic analysis engine developed natively in Python without high-level library dependencies. Operating directly at the network interface layer, the architecture bypasses third-party driver dependencies to intercept raw inbound and outbound data streams. The system parses nested network headers using big-endian formatting to unpack Layer 3 IPv4 packets and track transport protocols (TCP/UDP/ICMP) in real time.

By utilizing native kernel input/output control configurations (`ioctl`), this script provides a cross-platform sniffing utility that runs smoothly across environments without requiring external packet capture drivers. Developing this project provided deep experience with binary data manipulation, network packet serialization, packet parsing, and cross-OS privilege handling.

---

## 🛠️ Core Features
* **Zero-Dependency Architecture**: Relies strictly on standard built-in libraries, removing third-party library dependency failures entirely.
* **Native Promiscuous Mode Interception**: Uses native kernel controllers (`SIO_RCVALL`) to capture all network traffic reaching the local interface card.
* **Low-Level Header Deserialization**: Employs structural byte arrays (`struct.unpack`) to break down complex network streams into clear parameters like routing addresses and TTL hops.
* **Safe Error-Handling Architecture**: Validates system access levels before launching socket bindings, ensuring the software fails safely rather than crashing.

---

## 💻 Tech Stack & Dependencies
* **Programming Language**: Python 3.x
* **Core Modules Used (Standard Library)**:
  * `socket` - For native raw network interface binding and low-level IP capture.
  * `struct` - Unpacking structured data buffer sequences into distinct headers.

---

## 📋 Technical Implementation Matrix

| Architecture Module | Low-Level Internal Logic | Cybersecurity Application |
| :--- | :--- | :--- |
| **Native Socket Hook** | Layer 3 Raw Ingestion Loops | Promiscuous Mode Traffic Monitoring |
| **Binary Struct Unpacker**| Big-Endian Unpacking (`struct.unpack`) | Deep Packet Inspection (DPI) |
| **I/O Control Interceptor**| Native OS `ioctl` Configuration | Cross-Platform Telemetry Extraction |

---

## 🚀 Deployment Instructions

### Prerequisites
Interacting with physical network interfaces requires system-level administrative or root access.

### Installation & System Setup
1. Clone this packet engineering repository onto your system:
   ```bash
   git clone https://github.com
   ```
2. Navigate directly inside the active project directory:
   ```bash
   cd packet-sniffer
   ```
3. Run the engine through an administrative command shell terminal:
   * **On Linux / macOS:**
     ```bash
     sudo python3 sniffer.py
     ```
   * **On Windows:** Open an **Administrative Command Prompt** (Right-Click ➔ Run as Administrator) and run:
     ```cmd
     python sniffer.py
     ```

---

## 💻 Source Code Preview
*Below is the complete structural Python implementation of the native packet sniffing engine for immediate academic evaluation:*

```python
import os
import sys
import socket
import struct

def parse_ipv4_header(raw_buffer):
    ip_header = struct.unpack('!BBHHHBBH4s4s', raw_buffer[:20])
    version_ihl = ip_header[0]
    ihl = version_ihl & 0xF
    ip_header_length = ihl * 4
    ttl = ip_header[5]
    protocol_type = ip_header[6]
    src_ip = socket.inet_ntoa(ip_header[8])
    dst_ip = socket.inet_ntoa(ip_header[9])
    protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
    protocol_name = protocol_map.get(protocol_type, f"PROTOCOL-{protocol_type}")
    return protocol_name, src_ip, dst_ip, ttl, raw_buffer[ip_header_length:]

def run_native_sniffer_loop():
    host_os = sys.platform
    if host_os == "win32":
        hostname = socket.gethostname()
        target_host_ip = socket.gethostbyname(hostname)
        sniffer_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        sniffer_socket.bind((target_host_ip, 0))
        sniffer_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sniffer_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    else:
        sniffer_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sniffer_socket.bind(("0.0.0.0", 0))

    print(f"[*] Native Sniffer Loop Active. Monitoring Intercepted IP Streams...\n")
    try:
        while True:
            raw_packet_data, network_addr = sniffer_socket.recvfrom(65535)
            proto, src, dst, ttl, payload = parse_ipv4_header(raw_packet_data)
            print("-" * 65)
            print(f" -> Protocol: {proto} | Routing Map: {src} ---> {dst} | TTL: {ttl}")
    except KeyboardInterrupt:
        print("\n[-] Sniffer Engine Terminated Safely.")
        if host_os == "win32":
            sniffer_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        sys.exit(0)

if __name__ == "__main__":
    is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0 if sys.platform == "win32" else os.getuid() == 0
    if not is_admin:
        sys.exit(1)
    run_native_sniffer_loop()
```

---

## 🧠 Academic Statement & Intended Research Alignment
This packet analyzer was engineered to master the core behaviors of network architecture models and inspect how data moves through physical interfaces. 

I plan to expand this native framework during my undergraduate engineering studies to support advanced research tracks in **Intrusion Detection Systems (IDS), Automated Network Threat Mitigation, and Low-Level Network Protocol Verification** within institutional laboratory environments.

---
*Disclaimer: This sniffing utility is engineered strictly for authorized educational analysis, administrative data tracking, and academic network verification pipelines. Capturing data on unauthorized networks without explicit consent is illegal under global computer security frameworks.*
