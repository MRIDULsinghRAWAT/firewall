import ipaddress
from typing import Dict, List, Optional, Set
from enum import Enum
from datetime import datetime, time

class PacketAction(Enum):
    """Action to take on a packet"""
    ALLOW = "ALLOW"
    DENY = "DENY"
    QUARANTINE = "QUARANTINE"
    RATE_LIMIT = "RATE_LIMIT"

class TCPFlag(Enum):
    """TCP flags for advanced packet inspection"""
    SYN = "SYN"
    ACK = "ACK"
    FIN = "FIN"
    RST = "RST"
    PSH = "PSH"
    URG = "URG"

class QoSPriority(Enum):
    """Quality of Service priority levels"""
    CRITICAL = 4
    HIGH = 3
    NORMAL = 2
    LOW = 1
    BEST_EFFORT = 0

class Packet:
    """Represents a network packet with advanced header information"""
    
    def __init__(self, src_ip: str, dst_ip: str, port: int, protocol: str,
                 ttl: int = 64, packet_size: int = 1500, 
                 tcp_flags: Optional[Set[str]] = None, qos_priority: int = 2):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.port = int(port)
        self.protocol = protocol.upper()
        self.ttl = ttl  # Time To Live
        self.packet_size = packet_size  # Bytes
        self.tcp_flags = tcp_flags or set()  # SYN, ACK, FIN, RST, etc.
        self.qos_priority = qos_priority  # 0-4 priority level
        self.timestamp = datetime.now()
        self.valid = self._validate()
    
    def _validate(self) -> bool:
        """Validate packet structure"""
        try:
            ipaddress.ip_address(self.src_ip)
            ipaddress.ip_address(self.dst_ip)
            if not (1 <= self.port <= 65535):
                return False
            if self.protocol not in ["TCP", "UDP", "ICMP"]:
                return False
            if not (0 <= self.ttl <= 255):
                return False
            if not (0 <= self.packet_size <= 65535):
                return False
            if not (0 <= self.qos_priority <= 4):
                return False
            return True
        except ValueError:
            return False
    
    def __str__(self) -> str:
        flags_str = f" [{','.join(self.tcp_flags)}]" if self.tcp_flags else ""
        return f"{self.protocol} | {self.src_ip} -> {self.dst_ip}:{self.port} | TTL:{self.ttl} | Size:{self.packet_size}B{flags_str}"
    
    def __repr__(self) -> str:
        return self.__str__()

class FirewallRule:
    """Represents an advanced firewall filtering rule with unique parameters"""
    
    def __init__(self, src_ip: Optional[str] = None, dst_ip: Optional[str] = None, 
                 port: Optional[int] = None, port_range: Optional[tuple] = None,
                 protocol: Optional[str] = None, action: str = "DENY", priority: int = 0,
                 rule_name: str = "Unnamed Rule",
                 min_ttl: int = 0, max_ttl: int = 255,
                 min_packet_size: int = 0, max_packet_size: int = 65535,
                 tcp_flags: Optional[Set[str]] = None,
                 min_qos_level: int = 0,
                 rate_limit: Optional[int] = None,
                 active_time_start: Optional[str] = None,
                 active_time_end: Optional[str] = None,
                 geographic_origin: Optional[str] = None):
        
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.port = port
        self.port_range = port_range
        self.protocol = protocol.upper() if protocol else None
        self.action = action.upper()
        self.priority = priority
        
        # UNIQUE PARAMETERS FOR ADVANCED FILTERING
        self.rule_name = rule_name  # Descriptive name
        self.min_ttl = min_ttl  # Minimum Time To Live
        self.max_ttl = max_ttl  # Maximum Time To Live
        self.min_packet_size = min_packet_size  # Minimum packet size in bytes
        self.max_packet_size = max_packet_size  # Maximum packet size in bytes
        self.tcp_flags = tcp_flags or set()  # Required TCP flags
        self.min_qos_level = min_qos_level  # Minimum QoS priority
        self.rate_limit = rate_limit  # Packets per second limit
        self.active_time_start = active_time_start  # Time-based activation (HH:MM)
        self.active_time_end = active_time_end  # Time-based deactivation (HH:MM)
        self.geographic_origin = geographic_origin  # Country/region code (future GeoIP support)
    
    def matches_packet(self, packet: Packet) -> bool:
        """Check if a packet matches this rule (with all advanced parameters)"""
        # Check source IP
        if self.src_ip:
            if not self._ip_matches(packet.src_ip, self.src_ip):
                return False
        
        # Check destination IP
        if self.dst_ip:
            if not self._ip_matches(packet.dst_ip, self.dst_ip):
                return False
        
        # Check port
        if self.port and packet.port != self.port:
            return False
        
        # Check port range
        if self.port_range:
            start, end = self.port_range
            if not (start <= packet.port <= end):
                return False
        
        # Check protocol
        if self.protocol and packet.protocol != self.protocol:
            return False
        
        # UNIQUE PARAMETER CHECKS
        # Check TTL range
        if not (self.min_ttl <= packet.ttl <= self.max_ttl):
            return False
        
        # Check packet size range
        if not (self.min_packet_size <= packet.packet_size <= self.max_packet_size):
            return False
        
        # Check TCP flags (if required)
        if self.tcp_flags:
            if not self.tcp_flags.issubset(packet.tcp_flags):
                return False
        
        # Check QoS priority level
        if packet.qos_priority < self.min_qos_level:
            return False
        
        # Check if rule is active (time-based)
        if not self._is_active_now():
            return False
        
        return True
    
    def _is_active_now(self) -> bool:
        """Check if rule is active based on time schedule"""
        if not self.active_time_start or not self.active_time_end:
            return True  # Always active if no time restriction
        
        try:
            current_time = datetime.now().time()
            start = datetime.strptime(self.active_time_start, "%H:%M").time()
            end = datetime.strptime(self.active_time_end, "%H:%M").time()
            
            if start <= end:
                return start <= current_time <= end
            else:  # Wrap around midnight
                return current_time >= start or current_time <= end
        except ValueError:
            return True  # Invalid time format, rule is always active
    
    @staticmethod
    def _ip_matches(packet_ip: str, rule_ip: str) -> bool:
        """Check if packet IP matches rule IP (supports CIDR notation)"""
        try:
            # Handle CIDR notation
            if '/' in rule_ip:
                return ipaddress.ip_address(packet_ip) in ipaddress.ip_network(rule_ip, strict=False)
            # Exact match
            return packet_ip == rule_ip
        except ValueError:
            return False

class FirewallEngine:
    """Advanced Firewall Logic Engine with DDoS protection and stateful filtering"""
    
    def __init__(self, enable_ddos_protection: bool = True, ddos_threshold: int = 100):
        self.rules: List[FirewallRule] = []
        self.packet_log = []
        self.stats = {"allowed": 0, "denied": 0, "quarantined": 0, "rate_limited": 0}
        
        # UNIQUE PARAMETERS FOR ADVANCED FEATURES //
        self.enable_ddos_protection = enable_ddos_protection
        self.ddos_threshold = ddos_threshold  # Packets per second threshold
        self.ip_packet_count: Dict[str, int] = {}  # Track packets per IP
        self.blocked_ips: Set[str] = set()  # IPs blocked due to DDoS
        self.active_connections: Set[tuple] = set()  # Stateful firewall (src, dst, port)
        self.packet_rate: Dict[str, int] = {}  # Packets per second per IP
        self.last_reset_time = datetime.now()
    
    def add_rule(self, **kwargs) -> None:
        """Add a filtering rule to the engine"""
        rule = FirewallRule(**kwargs)
        self.rules.append(rule)
        # Sort by priority (highest first)
        self.rules.sort(key=lambda r: r.priority, reverse=True)
    
    def check_packet(self, packet: Packet) -> str:
        """Process a packet through firewall rules with advanced features"""
        if not packet.valid:
            self.stats["denied"] += 1
            return PacketAction.DENY.value
        
        # Check if IP is DDoS blocked
        if self.enable_ddos_protection and packet.src_ip in self.blocked_ips:
            self.stats["rate_limited"] += 1
            self.packet_log.append({
                "packet": str(packet),
                "action": "RATE_LIMIT",
                "matched_rule": "DDoS Protection - Source IP blocked"
            })
            return "RATE_LIMIT"
        
        # Update DDoS tracking
        self._update_ddos_tracking(packet)
        
        # Check DDoS threshold
        if self.enable_ddos_protection and self.ip_packet_count.get(packet.src_ip, 0) > self.ddos_threshold:
            self.blocked_ips.add(packet.src_ip)
            self.stats["rate_limited"] += 1
            self.packet_log.append({
                "packet": str(packet),
                "action": "RATE_LIMIT",
                "matched_rule": f"DDoS detected from {packet.src_ip}"
            })
            return "RATE_LIMIT"
        
        # Check rules in order of priority
        for rule in self.rules:
            if rule.matches_packet(packet):
                action = rule.action
                self._update_stats(action)
                
                # Track connections for stateful firewall
                if action == "ALLOW":
                    self.active_connections.add((packet.src_ip, packet.dst_ip, packet.port))
                
                self.packet_log.append({
                    "packet": str(packet),
                    "action": action,
                    "matched_rule": rule.rule_name,
                    "ttl": packet.ttl,
                    "size": packet.packet_size,
                    "qos": packet.qos_priority
                })
                return action
        
        # Default action: DENY
        self.stats["denied"] += 1
        self.packet_log.append({
            "packet": str(packet),
            "action": PacketAction.DENY.value,
            "matched_rule": "Default deny policy"
        })
        return PacketAction.DENY.value
    
    def _update_ddos_tracking(self, packet: Packet) -> None:
        """Track packet counts per IP for DDoS detection"""
        # Reset counter every second
        current_time = datetime.now()
        if (current_time - self.last_reset_time).total_seconds() >= 1:
            self.ip_packet_count.clear()
            self.last_reset_time = current_time
        
        self.ip_packet_count[packet.src_ip] = self.ip_packet_count.get(packet.src_ip, 0) + 1
    
    def _update_stats(self, action: str) -> None:
        """Update firewall statistics"""
        action_upper = action.upper()
        if action_upper == "ALLOW":
            key = "allowed"
        elif action_upper == "DENY":
            key = "denied"
        elif action_upper == "QUARANTINE":
            key = "quarantined"
        elif action_upper == "RATE_LIMIT":
            key = "rate_limited"
        else:
            key = action.lower()
        
        if key in self.stats:
            self.stats[key] += 1
        else:
            self.stats[key] = 1
    
    def get_stats(self) -> Dict[str, int]:
        """Get firewall statistics"""
        return self.stats.copy()
    
    def get_logs(self, limit: int = 10) -> List[Dict]:
        """Get recent packet logs"""
        return self.packet_log[-limit:]
    
    def get_blocked_ips(self) -> Set[str]:
        """Get list of IPs blocked due to DDoS"""
        return self.blocked_ips.copy()
    
    def get_active_connections(self) -> Set[tuple]:
        """Get active connections (stateful firewall)"""
        return self.active_connections.copy()
    
    def unblock_ip(self, ip: str) -> bool:
        """Manually unblock an IP"""
        if ip in self.blocked_ips:
            self.blocked_ips.remove(ip)
            return True
        return False