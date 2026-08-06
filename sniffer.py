import os
import sys
import socket
import struct

def parse_ipv4_header(raw_buffer):
    """
    Parses Layer 3 IPv4 packet structures safely using standard big-endian formatting.
    This works independently of third-party packet sniffing software wrappers.
    """
    # Extract the first 20 bytes of the standard network IP header
    ip_header = struct.unpack('!BBHHHBBH4s4s', raw_buffer[:20])
    
    version_ihl = ip_header[0]
    ihl = version_ihl & 0xF
    ip_header_length = ihl * 4
    
    ttl = ip_header[5]
    protocol_type = ip_header[6]
    
    # Map out clean dotted-quad string IP coordinate definitions
    src_ip = socket.inet_ntoa(ip_header[8])
    dst_ip = socket.inet_ntoa(ip_header[9])
    
    # Resolve the underlying transport layer mapping parameters
    protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
    protocol_name = protocol_map.get(protocol_type, f"PROTOCOL-{protocol_type}")
    
    return protocol_name, src_ip, dst_ip, ttl, raw_buffer[ip_header_length:]

def run_native_sniffer_loop():
    """
    Launches a native raw network socket ingestion hook.
    Bypasses platform translation layers to guarantee execution.
    """
    print("[*] Initializing Safe Native Socket Ingestion Architecture...")
    
    # Determine local host processing parameters
    host_os = sys.platform
    
    if host_os == "win32":
        # Windows requires binding to a concrete local network address interface
        hostname = socket.gethostname()
        target_host_ip = socket.gethostbyname(hostname)
        
        # Instantiate raw network layer sockets natively
        sniffer_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        sniffer_socket.bind((target_host_ip, 0))
        
        # Enforce kernel-level IP header tracking parameters
        sniffer_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        # Force the physical network card adapter driver into Promiscuous Sniffing Mode
        sniffer_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    else:
        # Mac and Linux native handling environments
        sniffer_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sniffer_socket.bind(("0.0.0.0", 0))

    print(f"[*] Native Sniffer Loop Active. Monitoring Intercepted IP Streams...")
    print("[*] (Press Ctrl+C to terminate execution parameters safely)\n")
    
    try:
        while True:
            # Capture the raw binary telemetry buffer stream
            raw_packet_data, network_addr = sniffer_socket.recvfrom(65535)
            
            proto, src, dst, ttl, payload = parse_ipv4_header(raw_packet_data)
            
            print("-" * 65)
            print(f"[+] Network Frame Captured | Layer 3 Ingestion Engine")
            print(f" -> Protocol: {proto} | TTL Hops: {ttl}")
            print(f" -> Routing Map: {src} ---> {dst}")
            if payload:
                print(f" -> Payload Extract (Truncated): {payload[:40]}")
                
    except KeyboardInterrupt:
        print("\n[-] Sniffer Engine Terminated Safely.")
        if host_os == "win32":
            # Safely disengage Promiscuous capture mode before killing socket loops
            sniffer_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        sys.exit(0)

if __name__ == "__main__":
    # Administrative boundaries verification gate
    is_admin = False
    if sys.platform == "win32":
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    else:
        is_admin = os.getuid() == 0

    if not is_admin:
        print("\n[-] CRITICAL PERMISSION ERROR:")
        print("    Interacting with physical network hardware cards requires System Administrative Rights.")
        print("    Please right-click your Terminal/CMD application, select 'Run as Administrator', and try again.\n")
        sys.exit(1)

    run_native_sniffer_loop()
