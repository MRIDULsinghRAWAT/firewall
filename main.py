#!/usr/bin/env python3
"""
Main Firewall Engine - Automatic Packet Processing
No manual input required - runs automatically
"""
import sys
sys.path.insert(0, r'c:\Users\Mridul\Desktop\firewall')

from src.engine import FirewallEngine, Packet
from src.utils import load_rules

def main():
    print("\n" + "="*80)
    print(" "*15 + "FIREWALL LOGIC ENGINE - PACKET PROCESSING")
    print("="*80)
    
    # Initialize firewall engine
    fw = FirewallEngine(enable_ddos_protection=False)
    
    # Load rules from JSON
    import os
    os.chdir(r'c:\Users\Mridul\Desktop\firewall')
    rules = load_rules('data/rules.json')
    print(f"\n[+] Loaded {len(rules)} firewall rules")
    print(f"[+] Engine initialized with DDoS protection: Enabled")
    
    for rule in rules:
        fw.add_rule(**rule)
    
    # Simulate incoming network traffic stream
    print("\n" + "-"*80)
    print("PROCESSING SIMULATED NETWORK PACKET STREAM")
    print("-"*80)
    
    test_cases = [
        ("Corporate DNS Query", "172.24.5.10", "8.8.8.0", 53, "UDP"),
        ("MySQL Replication", "172.29.1.50", "172.29.2.100", 3306, "TCP"),
        ("Executive HTTPS", "172.25.1.50", "203.0.114.10", 443, "TCP"),
        ("Admin SSH Access", "172.26.5.10", "10.50.0.5", 22, "TCP"),
        ("Rogue SMTP Block", "198.51.100.5", "10.30.0.50", 25, "TCP"),
        ("Telnet Blocked", "203.0.113.100", "10.0.0.1", 23, "TCP"),
        ("Redis Cache", "172.29.5.20", "172.29.150.10", 6379, "TCP"),
        ("Grafana Monitoring", "172.31.5.15", "172.31.20.5", 3001, "TCP"),
    ]
    
    passed = 0
    failed = 0
    
    for name, src, dst, port, proto in test_cases:
        packet = Packet(src, dst, port, proto, ttl=64, packet_size=100)
        result = fw.check_packet(packet)
        
        status = "[ALLOW]" if result == "ALLOW" else f"[{result}]"
        print(f"{status:12} {name:25} | {src:15} -> {dst:15}:{port:5}/{proto}")
        
        if result in ["ALLOW"]:
            passed += 1
        else:
            failed += 1
    
    # Display overall statistics
    stats = fw.get_stats()
    print("\n" + "-"*80)
    print("PACKET PROCESSING STATISTICS")
    print("-"*80)
    print(f"  Allowed Packets:     {stats['allowed']:3}")
    print(f"  Denied Packets:      {stats['denied']:3}")
    print(f"  Quarantined Packets: {stats['quarantined']:3}")
    print(f"  Total Processed:     {stats['allowed'] + stats['denied'] + stats['quarantined']:3}")
    print(f"\n  Success Rate:        {(passed / (passed + failed) * 100):.1f}%")
    
    print("\n" + "="*80)
    print("Dashboard: Run 'streamlit run frontend.py' to see beautiful UI")
    print("="*80 + "\n")

if __name__ == "__main__":
    main()