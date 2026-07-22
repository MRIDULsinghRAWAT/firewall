import streamlit as st
import pandas as pd
import json
from datetime import datetime
from src.engine import FirewallEngine, Packet
from src.utils import load_rules

# Page Configuration - CYBER TRACK STYLE
st.set_page_config(
    page_title="CYBER TRACK - Firewall Security Engine",
    page_icon="shield",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for CYBER TRACK Style - All Black Dark Theme
dark_theme_css = """
<style>
    * {
        margin: 0;
        padding: 0;
        font-family: 'Segoe UI', Arial, sans-serif;
    }
    
    html, body, [data-testid="stAppViewContainer"], [data-testid="stSidebar"] {
        background-color: #0a0a0a !important;
        color: #ffffff !important;
    }
    
    [data-testid="stAppViewContainer"] {
        background: linear-gradient(180deg, #0a0a0a 0%, #0f0f0f 100%) !important;
    }
    
    .header-title {
        font-size: 3.5em;
        font-weight: 900;
        text-align: center;
        color: #ffffff !important;
        letter-spacing: 8px;
        margin: 40px 0 20px 0;
        text-transform: uppercase;
    }
    
    .header-subtitle {
        text-align: center;
        color: #00bfff !important;
        font-size: 0.85em;
        letter-spacing: 3px;
        text-transform: uppercase;
        margin-bottom: 40px;
    }
    
    .metric-card {
        background: rgba(15, 15, 15, 0.8) !important;
        border: 2px solid #00bfff !important;
        border-radius: 8px;
        padding: 25px;
        margin: 10px 0;
        box-shadow: 0 0 20px rgba(0, 191, 255, 0.2);
    }
    
    .metric-value {
        font-size: 3em;
        font-weight: bold;
        color: #00ff88 !important;
        text-shadow: 0 0 15px rgba(0, 255, 136, 0.6);
    }
    
    .metric-label {
        color: #00bfff !important;
        font-size: 1em;
        margin-top: 15px;
        text-transform: uppercase;
        letter-spacing: 2px;
    }
    
    .status-allowed {
        background: rgba(0, 255, 136, 0.1) !important;
        border-left: 5px solid #00ff88 !important;
        padding: 15px;
        margin: 10px 0;
        border-radius: 5px;
        color: #00ff88 !important;
    }
    
    .status-denied {
        background: rgba(255, 71, 87, 0.1) !important;
        border-left: 5px solid #ff4757 !important;
        padding: 15px;
        margin: 10px 0;
        border-radius: 5px;
        color: #ff4757 !important;
    }
    
    .status-quarantine {
        background: rgba(255, 159, 64, 0.1) !important;
        border-left: 5px solid #ff9f40 !important;
        padding: 15px;
        margin: 10px 0;
        border-radius: 5px;
        color: #ff9f40 !important;
    }
    
    .divider {
        border-top: 2px solid #00bfff;
        margin: 40px 0;
        opacity: 0.3;
    }
    
    /* Streamlit Components Styling */
    [data-testid="stMetricValue"] {
        color: #00ff88 !important;
    }
    
    [data-testid="stMetricLabel"] {
        color: #00bfff !important;
    }
    
    .stButton > button {
        background: linear-gradient(90deg, #9d00ff, #00bfff) !important;
        color: #ffffff !important;
        border: none !important;
        border-radius: 8px !important;
        padding: 12px 30px !important;
        font-weight: bold !important;
        box-shadow: 0 0 20px rgba(157, 0, 255, 0.4) !important;
    }
    
    .stButton > button:hover {
        background: linear-gradient(90deg, #00bfff, #9d00ff) !important;
        box-shadow: 0 0 30px rgba(0, 191, 255, 0.6) !important;
    }
    
    .stSelectbox [data-testid="baseButton-secondary"] {
        border-color: #00bfff !important;
    }
    
    .stTextInput input {
        background-color: #1a1a1a !important;
        border: 1px solid #00bfff !important;
        color: #ffffff !important;
    }
    
    .stNumberInput input {
        background-color: #1a1a1a !important;
        border: 1px solid #00bfff !important;
        color: #ffffff !important;
    }
    
    .stSlider {
        color: #00bfff !important;
    }
    
    .stSidebar {
        background: linear-gradient(180deg, #0a0a0a 0%, #0f0f0f 100%) !important;
    }
    
    .stSidebar [data-testid="stMarkdownContainer"] {
        color: #ffffff !important;
    }
    
    .stRadio {
        color: #ffffff !important;
    }
    
    .stRadio label {
        color: #ffffff !important;
    }
    
    [data-testid="stDataFrame"] {
        background: rgba(15, 15, 15, 0.5) !important;
    }
    
    table {
        background-color: #0f0f0f !important;
        color: #ffffff !important;
    }
    
    th {
        background-color: #1a1a1a !important;
        color: #00bfff !important;
        border-bottom: 1px solid #00bfff !important;
    }
    
    td {
        border-bottom: 1px solid rgba(0, 191, 255, 0.2) !important;
        color: #ffffff !important;
    }
    
    .stInfo {
        background: rgba(0, 191, 255, 0.1) !important;
        border: 1px solid #00bfff !important;
        border-radius: 8px !important;
    }
    
    .stError {
        background: rgba(255, 71, 87, 0.1) !important;
        border: 1px solid #ff4757 !important;
    }
    
    /* Custom Scrollbar for Terminal */
    ::-webkit-scrollbar {
        width: 8px;
        height: 8px;
    }
    ::-webkit-scrollbar-track {
        background: #111;
        border-radius: 4px;
    }
    ::-webkit-scrollbar-thumb {
        background: #00bfff;
        border-radius: 4px;
    }
    ::-webkit-scrollbar-thumb:hover {
        background: #9d00ff;
    }
</style>
"""

st.markdown(dark_theme_css, unsafe_allow_html=True)

# Header
col1, col2, col3 = st.columns([1, 2, 1])
with col2:
    st.markdown('<div class="header-title">CYBER TRACK</div>', unsafe_allow_html=True)
st.markdown('<div class="header-subtitle">Advanced Security Intelligence Platform</div>', unsafe_allow_html=True)

# Sidebar
with st.sidebar:
    st.markdown("### [CONFIG] FIREWALL CONFIGURATION")
    
    mode = st.radio(
        "Select Mode:",
        ["Dashboard", "Traffic Simulator", "Rules Management", "Analytics"]
    )

# Initialize Session State
if 'fw' not in st.session_state:
    st.session_state.fw = FirewallEngine(enable_ddos_protection=False)
    rules = load_rules('data/rules.json')
    for rule in rules:
        st.session_state.fw.add_rule(**rule)

fw = st.session_state.fw

# MODE: DASHBOARD
if mode == "Dashboard":
    st.markdown('<div class="divider"></div>', unsafe_allow_html=True)
    
    # Real-time Statistics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown(f'<div class="metric-card"><div class="metric-value">{fw.get_stats()["allowed"]}</div><div class="metric-label">ALLOWED</div></div>', unsafe_allow_html=True)
    
    with col2:
        st.markdown(f'<div class="metric-card"><div class="metric-value" style="color: #ff4757;">{fw.get_stats()["denied"]}</div><div class="metric-label">DENIED</div></div>', unsafe_allow_html=True)
    
    with col3:
        st.markdown(f'<div class="metric-card"><div class="metric-value" style="color: #ff9f40;">{fw.get_stats()["quarantined"]}</div><div class="metric-label">QUARANTINE</div></div>', unsafe_allow_html=True)
    
    with col4:
        st.markdown(f'<div class="metric-card"><div class="metric-value" style="color: #00bfff;">{len(fw.get_logs())}</div><div class="metric-label">TOTAL LOG</div></div>', unsafe_allow_html=True)
    
    st.markdown('<div class="divider"></div>', unsafe_allow_html=True)
    
    st.markdown("### [RULES] FIREWALL RULES")
    
    rules_df = []
    for rule in fw.rules:
        rules_df.append({
            "Rule Name": rule.rule_name,
            "Source IP": rule.src_ip or "ANY",
            "Destination IP": rule.dst_ip or "ANY",
            "Protocol": rule.protocol or "ANY",
            "Port": rule.port or "ANY",
            "Action": rule.action,
            "Priority": rule.priority
        })
    
    df_rules = pd.DataFrame(rules_df)
    st.dataframe(df_rules, width='stretch', hide_index=True)

# MODE: TRAFFIC SIMULATOR
elif mode == "Traffic Simulator":
    st.markdown('<div class="divider"></div>', unsafe_allow_html=True)
    st.markdown("### <span style='color: #00bfff;'>[LIVE & TEST]</span> TRAFFIC SIMULATOR & PACKET STREAM", unsafe_allow_html=True)
    
    st.markdown("<p style='color: #888; font-size: 0.9em; margin-bottom: 20px;'>Manually inject packets or start the automated live traffic engine to battle-test the firewall rules continuously.</p>", unsafe_allow_html=True)
    
    if 'streaming' not in st.session_state:
        st.session_state.streaming = False
    if 'live_logs' not in st.session_state:
        st.session_state.live_logs = []
        
    # --- MANUAL PACKET TEST SECTION ---
    st.markdown("""
        <div style="background: linear-gradient(135deg, rgba(15,15,15,0.9), rgba(25,25,25,0.9)); 
             border-left: 4px solid #9d00ff; border-radius: 8px; padding: 15px; margin-bottom: 20px;">
            <h4 style="color: #fff; margin-top: 0;">Manual Packet Injection</h4>
        </div>
    """, unsafe_allow_html=True)
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        src_ip = st.text_input("Source IP", "192.168.1.10", key="src")
    with col2:
        dst_ip = st.text_input("Destination IP", "8.8.8.8", key="dst")
    with col3:
        protocol = st.selectbox("Protocol", ["TCP", "UDP", "ICMP"], key="proto")
    with col4:
        port = st.number_input("Port", 1, 65535, 80, key="prt")
        
    t_col1, t_col2 = st.columns([1, 2])
    with t_col1:
        if st.button("[INJECT] MANUAL PACKET", use_container_width=True):
            from src.engine import Packet
            from datetime import datetime
            try:
                packet = Packet(src_ip, dst_ip, port, protocol, ttl=64, packet_size=100)
                result = fw.check_packet(packet)
                log_entry = {
                    "time": datetime.now().strftime("%H:%M:%S.%f")[:-3],
                    "src": src_ip,
                    "dst": dst_ip,
                    "proto": protocol,
                    "port": port,
                    "action": result
                }
                st.session_state.live_logs.insert(0, log_entry)
                if len(st.session_state.live_logs) > 200:
                    st.session_state.live_logs.pop()
            except Exception as e:
                st.error(f"Error: {str(e)}")
                
    st.markdown('<div class="divider" style="margin: 20px 0;"></div>', unsafe_allow_html=True)
    
    # --- LIVE STREAM SECTION ---
    st.markdown("""
        <div style="background: linear-gradient(135deg, rgba(15,15,15,0.9), rgba(25,25,25,0.9)); 
             border-left: 4px solid #00ff88; border-radius: 8px; padding: 15px; margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center;">
            <h4 style="color: #fff; margin: 0;">Automated Live Traffic Stream</h4>
        </div>
    """, unsafe_allow_html=True)
    
    c1, c2, c3 = st.columns([1,1,2])
    with c1:
        if st.button("[START] LIVE STREAM", use_container_width=True, type="primary" if not st.session_state.streaming else "secondary"):
            st.session_state.streaming = True
            if hasattr(st, 'rerun'): st.rerun()
            else: st.experimental_rerun()
    with c2:
        if st.button("[STOP] STREAM", use_container_width=True):
            st.session_state.streaming = False
            if hasattr(st, 'rerun'): st.rerun()
            else: st.experimental_rerun()
    with c3:
        if st.button("[CLEAR] LOGS", use_container_width=True):
            st.session_state.live_logs = []
            st.session_state.streaming = False
            if hasattr(st, 'rerun'): st.rerun()
            else: st.experimental_rerun()

    stream_container = st.empty()
    
    if st.session_state.streaming:
        import random
        import time
        from datetime import datetime
        from src.engine import Packet
        
        # Simulate ONE packet per rerun using realistic intelligent scenarios to match rules
        scenarios = [
            # Public HTTP (ALLOW)
            {"src": "192.168.1.10", "dst": "8.8.8.8", "proto": "TCP", "port": 80},
            # DNS Corporate (ALLOW)
            {"src": "172.24.5.10", "dst": "8.8.8.8", "proto": "UDP", "port": 53},
            # Executive HTTPS (ALLOW)
            {"src": "172.25.1.50", "dst": "203.0.114.10", "proto": "TCP", "port": 443},
            # Hardened SSH (ALLOW)
            {"src": "172.26.5.10", "dst": "10.50.0.5", "proto": "TCP", "port": 22},
            # Internal Mail Server (ALLOW)
            {"src": "10.10.5.5", "dst": "10.30.2.10", "proto": "TCP", "port": 25},
            # Rogue SMTP (QUARANTINE)
            {"src": "198.51.100.5", "dst": "10.30.0.50", "proto": "TCP", "port": 25},
            # Random Exploit Attempt (DENY)
            {"src": "203.0.113.100", "dst": "10.0.0.1", "proto": "TCP", "port": 23},
            # Random Unknown UDP (DENY)
            {"src": "10.0.0.5", "dst": "172.16.5.5", "proto": "UDP", "port": 6379},
            # Anomalous Large Packet (QUARANTINE)
            {"src": "192.168.1.100", "dst": "10.0.0.1", "proto": "ICMP", "port": 0, "size": 65500},
            # Database Access (ALLOW)
            {"src": "172.29.1.50", "dst": "172.29.2.10", "proto": "TCP", "port": 3306}
        ]
        
        scenario = random.choice(scenarios)
        src_ip = scenario["src"]
        dst_ip = scenario["dst"]
        protocol = scenario["proto"]
        port = scenario["port"]
        packet_size = scenario.get("size", random.randint(40, 1500))
        
        packet = Packet(src_ip, dst_ip, port, protocol, ttl=64, packet_size=packet_size)
        result = fw.check_packet(packet)
        
        log_entry = {
            "time": datetime.now().strftime("%H:%M:%S.%f")[:-3],
            "src": src_ip,
            "dst": dst_ip,
            "proto": protocol,
            "port": port,
            "action": result
        }
        
        st.session_state.live_logs.insert(0, log_entry)
        if len(st.session_state.live_logs) > 200: # keep last 200 packets on screen
            st.session_state.live_logs.pop()
            
        time.sleep(0.3) # Fast stream delay
        
    # Terminal Display
    html = """
    <div style='background: #020202; padding: 25px; border-radius: 12px; border: 1px solid rgba(0, 191, 255, 0.3); 
                height: 550px; overflow: hidden; box-shadow: 0 10px 30px rgba(0, 0, 0, 0.8), inset 0 0 40px rgba(0, 191, 255, 0.05);
                position: relative;'>
        <div style="position: absolute; top: 0; left: 0; right: 0; height: 30px; background: #111; display: flex; align-items: center; padding: 0 15px; border-bottom: 1px solid #333; border-top-left-radius: 12px; border-top-right-radius: 12px;">
            <div style="width: 12px; height: 12px; border-radius: 50%; background: #ff4757; margin-right: 8px;"></div>
            <div style="width: 12px; height: 12px; border-radius: 50%; background: #ff9f40; margin-right: 8px;"></div>
            <div style="width: 12px; height: 12px; border-radius: 50%; background: #00ff88;"></div>
            <span style="color: #666; font-family: sans-serif; font-size: 12px; margin-left: 15px; letter-spacing: 1px;">CYBER_TRACK_CORE // LIVE_SIM_ENGINE</span>
        </div>
        <div style="margin-top: 15px; padding-top: 10px; height: calc(100% - 15px); overflow-y: auto; overflow-x: hidden; font-family: 'Fira Code', 'Courier New', monospace; padding-right: 5px;">
    """
    if not st.session_state.live_logs:
        html += "<div style='color: #444; text-align: center; margin-top: 200px; font-size: 1.2em;'>[ SYSTEM IDLE - WAITING FOR TRAFFIC ]</div>"
    else:
        for log in st.session_state.live_logs:
            color = "#00ff88" if log["action"] == "ALLOW" else "#ff4757" if log["action"] == "DENY" else "#ff9f40"
            bg_color = "rgba(0, 255, 136, 0.05)" if log["action"] == "ALLOW" else "rgba(255, 71, 87, 0.05)" if log["action"] == "DENY" else "rgba(255, 159, 64, 0.05)"
            icon = "[OK]" if log["action"] == "ALLOW" else "[BLOCK]" if log["action"] == "DENY" else "[WARN]"
            
            port_str = str(log['port']).ljust(5)
            proto_str = log['proto'].ljust(4)
            
            html += f"<div style='margin-bottom: 6px; padding: 6px 12px; background: {bg_color}; border-left: 4px solid {color}; border-radius: 4px; display: flex; justify-content: space-between; align-items: center; font-size: 0.9em; transition: all 0.2s;'>"
            html += f"<div><span style='color: #666;'>[{log['time']}]</span> <span style='color: #00bfff; font-weight: 600; letter-spacing: 0.5px;'>{log['src']:15} ⟶ <span style='color: #aaa;'>{log['dst']:15}</span></span> <span style='color: #888; margin-left: 15px; font-size: 0.9em;'>PORT: <span style='color: #ddd;'>{port_str}</span> | <span style='color: #ddd;'>{proto_str}</span></span></div>"
            html += f"<span style='color: {color}; font-weight: 800; letter-spacing: 1px; text-shadow: 0 0 5px {color}aa;'>{icon} {log['action']}</span>"
            html += "</div>"
    html += "</div></div>"
    
    stream_container.markdown(html, unsafe_allow_html=True)
    
    if st.session_state.streaming:
        if hasattr(st, 'rerun'): st.rerun()
        else: st.experimental_rerun()

# MODE: RULES MANAGEMENT
elif mode == "Rules Management":
    st.markdown('<div class="divider"></div>', unsafe_allow_html=True)
    st.markdown("### [RULES] FIREWALL RULES")
    
    rules_df = []
    for i, rule in enumerate(fw.rules):
        rules_df.append({
            "ID": i + 1,
            "Rule Name": rule.rule_name,
            "Source IP": rule.src_ip or "ANY",
            "Destination IP": rule.dst_ip or "ANY",
            "Protocol": rule.protocol or "ANY",
            "Port": rule.port or "ANY",
            "Action": rule.action,
            "Priority": rule.priority
        })
    
    df = pd.DataFrame(rules_df)
    st.dataframe(df, width='stretch', hide_index=True)
    
    st.markdown('<div class="divider"></div>', unsafe_allow_html=True)
    st.info("[INFO] Total Rules Loaded: " + str(len(fw.rules)))

# MODE: ANALYTICS
elif mode == "Analytics":
    st.markdown('<div class="divider"></div>', unsafe_allow_html=True)
    st.markdown("### [ANALYTICS] PACKET ANALYTICS")
    
    stats = fw.get_stats()
    total = stats["allowed"] + stats["denied"] + stats["quarantined"]
    
    if total > 0:
        col1, col2, col3 = st.columns(3)
        
        with col1:
            allowed_pct = (stats["allowed"] / total) * 100
            st.metric("Allowed Rate", f"{allowed_pct:.1f}%", f"{stats['allowed']} packets")
        
        with col2:
            denied_pct = (stats["denied"] / total) * 100
            st.metric("Denied Rate", f"{denied_pct:.1f}%", f"{stats['denied']} packets")
        
        with col3:
            quarantine_pct = (stats["quarantined"] / total) * 100
            st.metric("Quarantine Rate", f"{quarantine_pct:.1f}%", f"{stats['quarantined']} packets")
        
        # Charts
        st.markdown("### [STATS] Traffic Distribution")
        chart_data = pd.DataFrame({
            "Status": ["Allowed", "Denied", "Quarantined"],
            "Count": [stats["allowed"], stats["denied"], stats["quarantined"]]
        })
        st.bar_chart(chart_data.set_index("Status"))
    else:
        st.info("No packets processed yet. Go to 'Test Packets' mode to process packets.")

# Footer
st.markdown('<div class="divider"></div>', unsafe_allow_html=True)
st.markdown(
    '<div style="text-align: center; color: #00bfff; font-size: 0.9em; margin-top: 30px;">2026 CYBER TRACK - Advanced Firewall Security Engine</div>',
    unsafe_allow_html=True
)
