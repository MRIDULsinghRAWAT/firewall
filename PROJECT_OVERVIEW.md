# Firewall Logic Engine - Quick Overview

## Problem Statement
Modern networks need intelligent filtering to permit/deny traffic based on packet headers (IP addresses, ports, protocols). Manual traffic control is inefficient and error-prone.

## Solution
Developed a **Firewall Logic Engine** - automated packet filtering system that processes network packets through priority-based rules to allow, deny, or quarantine traffic.

---

## What It Does
1. **Receives network packets** with source/destination IPs, ports, protocols
2. **Validates packet headers** using ipaddress module
3. **Matches against 29 pre-defined rules** in priority order (highest first)
4. **Returns action**: ALLOW, DENY, or QUARANTINE
5. **Logs decisions** and tracks real-time statistics

---

## Core Parameters (10 Total)

### Packet Parameters (7):
- **src_ip** - Source IP address
- **dst_ip** - Destination IP address
- **port** - Port number (1-65535)
- **protocol** - TCP, UDP, or ICMP
- **ttl** - Time to live (0-255)
- **packet_size** - Payload size in bytes
- **timestamp** - Packet arrival time

### Rule Parameters (3):
- **action** - ALLOW, DENY, or QUARANTINE
- **priority** - Execution order (100-1000)
- **rule_name** - Identifier

---

## 29 Firewall Rules Summary (Enterprise Architecture)

| Category | Ports | Priority | Special Features | Count |
|----------|-------|----------|-----------------|-------|
| **Critical Security** | 23, 21 | 150-149 | DENY (Legacy protocols) | 2 |
| **Anomaly Detection** | N/A | 140-130 | QUARANTINE (Size/TTL) | 2 |
| **Hardened Access** | 22, 3389 | 120-102 | Admin-only, Bidirectional IP | 2 |
| **Core Services** | 80, 443 | 105-95 | Department-specific gateways | 2 |
| **DNS/Time** | 53, 123 | 110-80 | Optimized packet sizes | 2 |
| **Email Stack** | 25, 110, 143 | 92-84 | SMTP relay prevention | 3 |
| **Database Tier** | 3306, 5432, 27017 | 100-90 | Replication + Analytics | 3 |
| **Cache/Search** | 6379, 9200 | 91-87 | Cluster access patterns | 2 |
| **Auth Services** | 88, 389 | 93-86 | Kerberos + LDAP | 2 |
| **Monitoring Stack** | 161, 514, 3001 | 82-81 | Centralized collection | 3 |
| **Microservices** | 3000, 5000, 5060, 8080 | 89-78 | Service discovery + APIs | 4 |

---

## Advanced Rule Matching Logic

**Multi-Parameter Filtering (AND Gate):**
```
IF source_ip MATCHES AND
   destination_ip MATCHES AND
   port MATCHES AND
   protocol MATCHES AND
   ttl_in_range AND
   packet_size_in_range
THEN execute action
```

**Example - MySQL Database Replication:**
```
Rule: "MySQL Database Replication"
  source_ip:      172.29.1.0/24  (Master server)
  destination_ip: 172.29.2.0/24  (Slave server)
  port:           3306
  protocol:       TCP
  ttl_range:      64-255         (Standard routes)
  packet_size:    100-65535      (All sizes allowed)
  action:         ALLOW
  priority:       100
```

---

## How It Works (Flow)
```
Incoming Packet → Validate Headers → Check Rules (by priority) → 
Match Found? YES → Execute Action + Log + Update Stats ✓
Match Found? NO → Default DENY action
```

---

## Files Structure
```
src/engine.py      → Packet, FirewallRule, FirewallEngine classes
src/utils.py       → Load rules, logging utilities
data/rules.json    → 29 rules database (JSON format)
main.py            → CLI interface (manual packet testing)
frontend.py        → Streamlit web UI (dark theme dashboard)
test_firewall.py   → Automated test suite
```

---

## Advanced Key Features

✅ **Enterprise CIDR Notation** - Corporate subnet ranges (172.24.0.0/16 to 172.31.0.0/16)
✅ **Bidirectional IP Filtering** - Both source AND destination verification
✅ **Smart Priority System** - 150 (Critical) → 1 (Default Deny)
✅ **TTL-Based Filtering** - Service-specific TTL ranges (32/48/64)
✅ **Packet Size Optimization** - DNS (20-512B) to Email (50-32KB)
✅ **Three-Action Model** - ALLOW, DENY, QUARANTINE (suspicious patterns)
✅ **Real-Time Statistics** - Track allowed/denied/quarantined counts
✅ **Complete Packet Logging** - Full decision history with rule matching
✅ **Interactive Dashboard** - Dark-theme Streamlit UI with 4 modes
✅ **CLI Testing** - Quick command-line packet validation

---

## Real-World Examples

**Example 1: Enterprise DNS Resolution**
```
Packet: 172.24.5.10 → 8.8.8.0 : 53/UDP
Packet Size: 45 bytes | TTL: 48
Rule Match: "Tier-1 DNS Resolution from Corporate Network"
            (Priority 110, Size: 20-512B, TTL: 32-255)
Action: ALLOW ✓ Logged
```

**Example 2: Database Replication**
```
Packet: 172.29.1.50 → 172.29.2.100 : 3306/TCP
Packet Size: 8500 bytes | TTL: 64
Rule Match: "MySQL Database Replication"
            (Priority 100, Size: 100-65535B, TTL: 64-255)
Action: ALLOW ✓ Logged
```

**Example 3: Security Block**
```
Packet: 198.51.100.5 → 10.30.0.50 : 25/TCP
Packet Size: 250 bytes | TTL: 32
Rule Match: "Rogue SMTP Relay Prevention"
            (Priority 140)
Action: QUARANTINE ⚠ Logged & Isolated
```

---

## Technologies
**Language:** Python 3.x | **UI:** Streamlit | **Validation:** ipaddress module

---

**Status:** ✅ Complete & Tested (100% solves Question 8 requirements)
