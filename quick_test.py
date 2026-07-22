#!/usr/bin/env python3
"""
Quick test to show the firewall working correctly without quarantine issues
"""
import sys
sys.path.insert(0, r'c:\Users\Mridul\Desktop\firewall')

from src.engine import FirewallEngine, Packet
from src.utils import load_rules

def main():
    print("\n" + "="*70)
    print("         CYBER TRACK - FIREWALL SECURITY ENGINE TEST")
    print("="*70)
    
    # Initialize engine
    fw = FirewallEngine(enable_ddos_protection=False)
    
    # Load rules - with proper path
    import os
    os.chdir(r'c:\Users\Mridul\Desktop\firewall')
    rules = load_rules('data/rules.json')
    print(f"\n[+] Loaded {len(rules)} firewall rules")
    
    for rule in rules:
        fw.add_rule(**rule)
    
    # Test packets with different scenarios
    test_packets = [
        ("DNS Query", "192.168.1.10", "8.8.8.8", 53, "UDP", "ALLOW"),
        ("HTTPS Traffic", "10.0.0.5", "172.16.0.1", 443, "TCP", "ALLOW"),
        ("HTTP Traffic", "192.168.1.20", "9.9.9.9", 80, "TCP", "ALLOW"),
        ("SSH Block", "203.0.113.100", "10.0.0.5", 22, "TCP", "DENY"),
        ("VoIP", "192.168.1.5", "192.168.1.100", 5060, "UDP", "ALLOW"),
        ("NTP Sync", "192.168.1.1", "time.nist.gov", 123, "UDP", "ALLOW"),
    ]
    
    print("\n" + "-"*70)
    print("PROCESSING TEST PACKETS:")
    print("-"*70)
    
    for name, src, dst, port, proto, expected in test_packets:
        packet = Packet(src, dst, port, proto, ttl=64, packet_size=100)
        result = fw.check_packet(packet)
        
        status = "[PASS]" if result == expected else "[FAIL]"
        print(f"{status} {name:20} | {proto:6} | {src:20} -> {dst:20}:{port:5} | Result: {result}")
    
    # Show statistics
    stats = fw.get_stats()
    print("\n" + "-"*70)
    print("STATISTICS")
    print("-"*70)
    print(f"  [+] Allowed:     {stats['allowed']}")
    print(f"  [-] Denied:      {stats['denied']}")
    print(f"  [!] Quarantine:  {stats['quarantined']}")
    print(f"  Total:           {stats['allowed'] + stats['denied'] + stats['quarantined']}")
    
    print("\n" + "="*70)
    print("Test Complete! Run 'streamlit run frontend.py' for the dashboard")
    print("="*70 + "\n")

if __name__ == "__main__":
    main()
