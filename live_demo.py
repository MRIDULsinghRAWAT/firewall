#!/usr/bin/env python3
"""
LIVE PACKET PROCESSING DEMO
Shows each packet being processed in real-time with pause/continue option
"""
import sys
import time
sys.path.insert(0, r'c:\Users\Mridul\Desktop\firewall')

from src.engine import FirewallEngine, Packet
from src.utils import load_rules

def display_banner():
    print("\n" + "="*90)
    print(" "*20 + "LIVE FIREWALL PACKET PROCESSING DEMO")
    print(" "*15 + "Each packet processes in real-time - Press ENTER to continue")
    print("="*90)

def display_packet_info(index, name, src, dst, port, proto):
    """Display packet being processed"""
    print(f"\n{'-'*90}")
    print(f"[PACKET {index}] {name}")
    print(f"{'-'*90}")
    print(f"  Source IP:      {src}")
    print(f"  Destination IP: {dst}")
    print(f"  Port:           {port}")
    print(f"  Protocol:       {proto}")
    print(f"  TTL:            64")
    print(f"  Packet Size:    100 bytes")

def display_processing():
    """Show processing animation"""
    print(f"\n  --> Processing through firewall rules...")
    for i in range(3):
        time.sleep(0.3)
        print(f"      {'.' * (i+1)}", end='\r')
    print("      DONE!              ")

def display_result(result, rule_name):
    """Display the result"""
    if result == "ALLOW":
        print(f"\n  ✓ DECISION: [{result}]  (Matched: {rule_name})")
        print(f"  Status: Traffic PERMITTED")
    elif result == "DENY":
        print(f"\n  ✗ DECISION: [{result}]  (Blocked by rules)")
        print(f"  Status: Traffic BLOCKED")
    elif result == "QUARANTINE":
        print(f"\n  ⚠ DECISION: [{result}]  (Suspicious Pattern)")
        print(f"  Status: Traffic ISOLATED FOR INSPECTION")

def pause_for_user():
    """Wait for user to press Enter"""
    input("\n  Press ENTER to process next packet...")

def main():
    display_banner()
    
    # Initialize firewall engine
    fw = FirewallEngine(enable_ddos_protection=False)
    
    # Load rules from JSON
    import os
    os.chdir(r'c:\Users\Mridul\Desktop\firewall')
    rules = load_rules('data/rules.json')
    print(f"\n[+] Loaded {len(rules)} firewall rules from data/rules.json")
    
    for rule in rules:
        fw.add_rule(**rule)
    
    print(f"[+] Firewall engine initialized and ready\n")
    
    # Test packets - Real-world scenarios
    test_cases = [
        ("Corporate DNS Query", "172.24.5.10", "8.8.8.0", 53, "UDP"),
        ("Executive HTTPS Traffic", "172.25.1.50", "203.0.114.10", 443, "TCP"),
        ("Admin SSH Access", "172.26.5.10", "10.50.0.5", 22, "TCP"),
        ("MySQL Database Replication", "172.29.1.50", "172.29.2.100", 3306, "TCP"),
        ("Rogue SMTP Relay Attempt", "198.51.100.5", "10.30.0.50", 25, "TCP"),
        ("Telnet Protocol Blocked", "203.0.113.100", "10.0.0.1", 23, "TCP"),
        ("Redis Cache Access", "172.29.5.20", "172.29.150.10", 6379, "TCP"),
        ("Grafana Monitoring Access", "172.31.5.15", "172.31.20.5", 3001, "TCP"),
    ]
    
    results = {
        "allowed": 0,
        "denied": 0,
        "quarantined": 0,
        "packets": []
    }
    
    # Process each packet one by one
    for index, (name, src, dst, port, proto) in enumerate(test_cases, 1):
        # Display packet info
        display_packet_info(index, name, src, dst, port, proto)
        
        # Wait for user
        pause_for_user()
        
        # Process packet
        display_processing()
        packet = Packet(src, dst, port, proto, ttl=64, packet_size=100)
        result = fw.check_packet(packet)
        
        # Get rule name from engine (if tracked)
        rule_name = "Default Rule"
        
        # Display result
        display_result(result, rule_name)
        
        # Track results
        if result == "ALLOW":
            results["allowed"] += 1
        elif result == "DENY":
            results["denied"] += 1
        elif result == "QUARANTINE":
            results["quarantined"] += 1
        
        results["packets"].append({
            "name": name,
            "src": src,
            "dst": dst,
            "port": port,
            "proto": proto,
            "result": result
        })
    
    # Final summary
    print("\n" + "="*90)
    print(" "*25 + "PROCESSING COMPLETE - FINAL SUMMARY")
    print("="*90)
    
    print(f"\n  Total Packets Processed: {len(test_cases)}")
    print(f"  [✓] Allowed:      {results['allowed']} packets")
    print(f"  [✗] Denied:       {results['denied']} packets")
    print(f"  [⚠] Quarantined:  {results['quarantined']} packets")
    
    success_rate = (results['allowed'] / len(test_cases)) * 100
    print(f"\n  Success Rate (Allowed + Expected Denials): {success_rate:.1f}%")
    
    # Detailed packet log
    print(f"\n{'-'*90}")
    print("DETAILED PACKET LOG:")
    print(f"{'-'*90}")
    for idx, pkt in enumerate(results['packets'], 1):
        status = "✓ ALLOW" if pkt['result'] == "ALLOW" else f"✗ {pkt['result']}"
        print(f"{idx:2}. [{status:12}] {pkt['name']:30} | {pkt['src']:15} -> {pkt['dst']:15}:{pkt['port']}")
    
    print("\n" + "="*90)
    print("Live Demo Complete!")
    print("="*90 + "\n")

if __name__ == "__main__":
    main()
