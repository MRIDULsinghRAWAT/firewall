import json
import os
from typing import List, Dict

def load_rules(filepath: str) -> List[Dict]:
    """Load firewall rules from JSON file"""
    if os.path.exists(filepath):
        try:
            with open(filepath, 'r') as f:
                rules = json.load(f)
                # Convert tcp_flags from list to set
                for rule in rules:
                    if 'tcp_flags' in rule and isinstance(rule['tcp_flags'], list):
                        rule['tcp_flags'] = set(rule['tcp_flags'])
                return rules
        except json.JSONDecodeError:
            print(f"Error: Invalid JSON in {filepath}")
            return []
    return []

def save_rules(filepath: str, rules: List[Dict]) -> bool:
    """Save firewall rules to JSON file"""
    try:
        with open(filepath, 'w') as f:
            json.dump(rules, f, indent=2)
        return True
    except IOError:
        print(f"Error: Cannot write to {filepath}")
        return False

def print_ui_header():
    print("-" * 60)
    print("      FIREWALL ENGINE - ADVANCED PACKET FILTERING")
    print("-" * 60)

def print_packet_log(log_entry: Dict) -> None:
    """Pretty print a packet log entry"""
    packet = log_entry.get("packet", "Unknown")
    action = log_entry.get("action", "UNKNOWN")
    rule = log_entry.get("matched_rule", "Unknown rule")
    
    color = "\033[92m" if action == "ALLOW" else "\033[91m"
    print(f"Packet: {packet:40} | Action: {color}{action:10}\033[0m | Rule: {rule}")

def print_stats(stats: Dict[str, int]) -> None:
    """Pretty print firewall statistics"""
    print("\n" + "=" * 60)
    print("                    FIREWALL STATISTICS")
    print("=" * 60)
    print(f"[+] Allowed:     {stats.get('allowed', 0):>10}")
    print(f"[-] Denied:      {stats.get('denied', 0):>10}")
    print(f"[!] Quarantined: {stats.get('quarantined', 0):>10}")
    print("=" * 60)