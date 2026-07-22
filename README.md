# Advanced Firewall Logic Engine

A sophisticated network packet filtering engine that processes simulated network packets through configurable firewall rules with support for advanced features like CIDR notation, protocol filtering, and priority-based rule matching.

## Features

### Core Capabilities
- **Advanced Packet Filtering**: Filter packets based on source IP, destination IP, port, and protocol
- **CIDR Notation Support**: Use subnet ranges (e.g., `192.168.1.0/24`) for flexible IP matching
- **Priority-Based Rules**: Higher priority rules are evaluated first
- **Multi-Protocol Support**: TCP, UDP, ICMP
- **Rule Matching Engine**: Sophisticated matching with exact and range-based filtering
- **Statistics Tracking**: Real-time counters for allowed, denied, and quarantined packets
- **Packet Logging**: Detailed logs of all processed packets with rule matching information

### Rule Features
- **Source IP Filtering**: Block/allow based on source address (supports CIDR)
- **Destination IP Filtering**: Block/allow based on destination address (supports CIDR)
- **Port Filtering**: Support for exact ports
- **Protocol Filtering**: TCP, UDP, ICMP
- **Action Types**: ALLOW, DENY, QUARANTINE
- **Priority System**: Control rule evaluation order

## Project Structure

```
firewall/
├── main.py                 # CLI entry point
├── web_app.py             # Streamlit web dashboard
├── test_firewall.py       # Test script
├── data/
│   └── rules.json         # Firewall rules configuration
└── src/
    ├── __init__.py
    ├── engine.py          # Core firewall engine
    └── utils.py           # Utility functions
```

## Core Components

### 1. `Packet` Class
Represents a network packet with validation.

```python
packet = Packet("192.168.1.10", "8.8.8.8", 53, "UDP")
# Validates IP addresses, port range, and protocol
```

### 2. `FirewallRule` Class
Defines a filtering rule with matching logic.

```python
rule = FirewallRule(
    src_ip="192.168.1.0/24",
    protocol="TCP",
    port=80,
    action="ALLOW",
    priority=100
)
```

### 3. `FirewallEngine` Class
Main engine that processes packets through rules.

```python
fw = FirewallEngine()
fw.add_rule(...)
result = fw.check_packet(packet)  # Returns: "ALLOW", "DENY", or "QUARANTINE"
```

## Configuration

### Rules Configuration (data/rules.json)

```json
[
    {
        "src_ip": "192.168.1.0/24",
        "protocol": "TCP",
        "port": 80,
        "action": "ALLOW",
        "priority": 100
    },
    {
        "src_ip": "192.168.0.0/16",
        "protocol": "UDP",
        "port": 53,
        "action": "ALLOW",
        "priority": 90
    },
    {
        "src_ip": "10.0.0.0/8",
        "action": "DENY",
        "priority": 50
    }
]
```

## Usage

### CLI Mode
```bash
# Run with default rules
python test_firewall.py
```

### Web Dashboard
```bash
# Launch interactive Streamlit dashboard
streamlit run web_app.py
```

### Programmatic Usage
```python
from src.engine import FirewallEngine, Packet
from src.utils import load_rules

# Initialize engine
fw = FirewallEngine()

# Load rules from JSON
for rule in load_rules('data/rules.json'):
    fw.add_rule(**rule)

# Process packet
packet = Packet("192.168.1.10", "8.8.8.8", 53, "UDP")
action = fw.check_packet(packet)  # Returns "ALLOW"

# Get statistics
stats = fw.get_stats()  # {'allowed': 1, 'denied': 0, 'quarantined': 0}
```

## Advanced Features

### CIDR Notation
Support for IP ranges using CIDR notation:
- `192.168.1.0/24` - Single /24 subnet
- `10.0.0.0/8` - Entire Class A space
- `172.16.0.0/12` - Multiple subnets

### Priority-Based Evaluation
Rules with higher priority numbers are checked first:
```json
{
    "priority": 100,  // Checked first
    "src_ip": "192.168.1.0/24",
    "action": "ALLOW"
}
```

### Logging and Statistics
- **Packet Logs**: Detailed record of each processed packet
- **Statistics**: Counters for actions (ALLOW/DENY/QUARANTINE)
- **Rule Matching**: Track which rule matched each packet

## Example Scenarios

### Scenario 1: Allow DNS from Internal Network
```json
{
    "src_ip": "192.168.0.0/16",
    "protocol": "UDP",
    "port": 53,
    "action": "ALLOW",
    "priority": 90
}
```

### Scenario 2: Block All Traffic from Subnet
```json
{
    "src_ip": "10.0.0.0/8",
    "action": "DENY",
    "priority": 50
}
```

### Scenario 3: Allow HTTPS from Anywhere
```json
{
    "protocol": "TCP",
    "port": 443,
    "action": "ALLOW",
    "priority": 80
}
```

## Statistics Output

```
============================================================
                    FIREWALL STATISTICS
============================================================
✓ Allowed:              3
✗ Denied:               3
⚠ Quarantined:          0
============================================================
```

## Key Implementation Details

1. **Packet Validation**: All packets are validated for proper IP format and port range
2. **Rule Sorting**: Rules are automatically sorted by priority for efficient evaluation
3. **Default Policy**: Packets matching no rules are DENIED by default (deny-all policy)
4. **Log Retention**: Recent packet logs are retained for audit purposes
5. **Type Safety**: Full type hints for better IDE support and code clarity

## Testing

Run the test script to verify the engine:
```bash
python test_firewall.py
```

Expected output shows:
- 6 processed packets
- 3 ALLOWED (DNS, HTTPS to 172.16.0.0/12, web-alt on 8080)
- 3 DENIED (SSH attempt from 10.0.0.5, TCP 80 from 172.16.0.1, UDP 1234 from 10.0.0.0)

## Performance Considerations

- **Rule Evaluation**: O(n) where n is the number of rules
- **IP Matching**: O(1) for exact match, O(log n) for CIDR lookup using ipaddress module
- **Suitable for**: Moderate traffic volumes, testing, educational purposes

## Future Enhancements

Potential features:
- Port range support (e.g., `8000-8999`)
- Connection state tracking (stateful firewall)
- Rate limiting rules
- Geo-IP blocking
- Advanced logging with syslog support
- Rule hot-reload without restart
- Performance metrics and profiling

## Author Notes

This is a **production-like** teaching example of a firewall engine. For actual production use, consider:
- Kernel-level packet filtering (iptables, pf)
- Stateful inspection capabilities
- Load balancing and clustering
- Comprehensive audit logging
- Performance optimization for high throughput

---

**Built with for network security enthusiasts**
