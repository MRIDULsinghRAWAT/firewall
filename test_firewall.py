#!/usr/bin/env python3
import sys
import os

# Add the firewall directory to the path
sys.path.insert(0, r'c:\Users\Mridul\Desktop\firewall')
os.chdir(r'c:\Users\Mridul\Desktop\firewall')

from src.engine import FirewallEngine, Packet, TCPFlag, QoSPriority
from src.utils import load_rules, print_ui_header, print_packet_log, print_stats

def test_firewall():
    print_ui_header()
    
    # Engine setup with DDoS protection enabled
    fw = FirewallEngine(enable_ddos_protection=True, ddos_threshold=50)
    
    # Load and add rules
    rules = load_rules('data/rules.json')
    print(f"\n[+] Loaded {len(rules)} advanced firewall rules")
    for rule in rules:
        fw.add_rule(**rule)
    
    # Simulated Traffic Stream with ADVANCED PARAMETERS
    print("\n" + "-" * 80)
    print("Processing Advanced Packet Stream with TTL, Size, QoS, and TCP Flags...")
    print("-" * 80)
    
    packets = [
        # Basic test packets with new parameters
        Packet("192.168.1.10", "8.8.8.8", 53, "UDP", ttl=64, packet_size=100, qos_priority=2),
        Packet("10.0.0.5", "1.1.1.1", 22, "TCP", ttl=128, packet_size=200, tcp_flags={"SYN"}),
        Packet("172.16.0.1", "192.168.1.1", 80, "TCP", ttl=64, packet_size=1500, qos_priority=1),
        Packet("192.168.1.5", "172.16.0.0", 443, "TCP", ttl=48, packet_size=900, qos_priority=3),
        Packet("10.0.0.0", "8.8.8.8", 1234, "UDP", ttl=1, packet_size=500),
        Packet("192.168.2.100", "9.9.9.9", 8080, "TCP", ttl=255, packet_size=1400, qos_priority=2, tcp_flags={"SYN", "ACK"}),
        # DDoS simulation - rapid packets from same source
        Packet("203.0.113.100", "8.8.8.8", 80, "TCP", ttl=64, packet_size=1500),
        Packet("203.0.113.100", "8.8.8.8", 80, "TCP", ttl=64, packet_size=1500),
        Packet("203.0.113.100", "8.8.8.8", 80, "TCP", ttl=64, packet_size=1500),
    ]

    for p in packets:
        result = fw.check_packet(p)
        log_entry = {
            "packet": str(p),
            "action": result,
            "matched_rule": "From engine"
        }
        print_packet_log(log_entry)
    
    # Display statistics with advanced metrics
    print_stats(fw.get_stats())
    
    # Display DDoS protection info
    if fw.get_blocked_ips():
        print("\n" + "=" * 80)
        print("                    DDoS PROTECTION REPORT")
        print("=" * 80)
        print(f"Blocked IPs: {fw.get_blocked_ips()}")
        print("=" * 80)
    
    # Display active connections
    if fw.get_active_connections():
        print("\n" + "=" * 80)
        print("                    ACTIVE CONNECTIONS (STATEFUL)")
        print("=" * 80)
        for src, dst, port in fw.get_active_connections():
            print(f"  {src} --> {dst}:{port}")
        print("=" * 80)
    
    # Display recent logs with advanced details
    print("\n" + "=" * 80)
    print("                    RECENT PACKET LOGS (Last 5)")
    print("=" * 80)
    for log in fw.get_logs(5):
        print(f"Packet: {log.get('packet', 'Unknown')}")
        print(f"  Action: {log.get('action', 'UNKNOWN')}")
        print(f"  Rule: {log.get('matched_rule', 'Unknown')}")
        if 'ttl' in log:
            print(f"  TTL: {log['ttl']}, Size: {log['size']}B, QoS: {log['qos']}")
        print()

if __name__ == "__main__":
    test_firewall()
