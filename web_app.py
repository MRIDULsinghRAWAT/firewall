import streamlit as st
import pandas as pd
import random
import time
from src.engine import FirewallEngine, Packet
from src.utils import load_rules

# Page Configuration
st.set_page_config(
    page_title="Firewall Security Engine",
    page_icon="",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Professional Dark Theme CSS (Like IP Vulnerability Tracker)
dark_theme_css = """
<style>
    * {
        margin: 0;
        padding: 0;
    }
    
    /* Dark Background */
    body, .main, [data-testid="stAppViewContainer"] {
        background: #0a0e27 !important;
        color: #ffffff;
        font-family: 'Segoe UI', 'Georgia', serif;
    }
    
    [data-testid="stAppViewContainer"] > section {
        background: #0a0e27 !important;
    }
    
    /* Main Content */
    .stContainer {
        background: transparent !important;
    }
    
    /* Header Styles */
    .header-section {
        text-align: center;
        padding: 60px 20px 40px 20px;
        background: #0a0e27;
    }
    
    .main-title {
        font-size: 56px;
        font-weight: 700;
        color: #ffffff;
        letter-spacing: 2px;
        margin-bottom: 20px;
        text-transform: uppercase;
    }
    
    .subtitle {
        font-size: 16px;
        color: #b0b0b0;
        line-height: 1.6;
        max-width: 800px;
        margin: 0 auto 50px;
    }
    
    /* Navigation Tabs */
    .nav-tabs {
        display: flex;
        justify-content: center;
        gap: 30px;
        margin-bottom: 50px;
        flex-wrap: wrap;
    }
    
    .nav-tab {
        border: 2px solid #ffffff;
        color: #ffffff;
        padding: 10px 30px;
        border-radius: 25px;
        cursor: pointer;
        font-size: 14px;
        letter-spacing: 1px;
        transition: all 0.3s ease;
        background: transparent;
    }
    
    .nav-tab:hover {
        background: #ffffff;
        color: #0a0e27;
    }
    
    /* Dark Cards */
    .dark-card {
        background: #1a1f3a;
        border: 1px solid #2a3150;
        border-radius: 12px;
        padding: 25px;
        margin-bottom: 20px;
        transition: all 0.3s ease;
    }
    
    .dark-card:hover {
        border-color: #667eea;
        box-shadow: 0 0 20px rgba(102, 126, 234, 0.3);
    }
    
    /* Metric Cards */
    .metric-card {
        background: #1a1f3a;
        border: 1px solid #2a3150;
        border-radius: 12px;
        padding: 25px;
        text-align: center;
        transition: all 0.3s ease;
    }
    
    .metric-card:hover {
        border-color: #667eea;
        transform: translateY(-5px);
    }
    
    .metric-label {
        font-size: 12px;
        letter-spacing: 1px;
        color: #b0b0b0;
        text-transform: uppercase;
    }
    
    .metric-value {
        font-size: 36px;
        font-weight: 700;
        color: #ffffff;
        margin-top: 10px;
    }
    
    /* Color Codes */
    .color-allowed {
        border-left: 4px solid #00d084;
    }
    
    .color-denied {
        border-left: 4px solid #ff1744;
    }
    
    .color-warning {
        border-left: 4px solid #ffb300;
    }
    
    /* Buttons */
    .stButton > button {
        background: #667eea;
        color: white;
        border: none;
        border-radius: 8px;
        padding: 12px 30px;
        font-weight: 600;
        font-size: 14px;
        letter-spacing: 1px;
        transition: all 0.3s ease;
        width: 100%;
    }
    
    .stButton > button:hover {
        background: #764ba2;
        box-shadow: 0 0 20px rgba(102, 126, 234, 0.5);
    }
    
    /* Slider */
    .stSlider {
        background: transparent;
    }
    
    .stSlider > div {
        background: transparent;
    }
    
    /* Table Styles */
    .dataframe {
        background: #1a1f3a;
        border-radius: 8px;
    }
    
    .dataframe th {
        background: #2a3150;
        color: #ffffff;
    }
    
    .dataframe td {
        background: #1a1f3a;
        color: #ffffff;
    }
    
    /* Divider */
    hr {
        border: none;
        height: 1px;
        background: #2a3150;
        margin: 40px 0;
    }
    
    /* Text Styles */
    h3 {
        font-size: 20px;
        font-weight: 600;
        letter-spacing: 1px;
        margin: 30px 0 20px 0;
    }
    
    /* Status Messages */
    .stSuccess {
        background: rgba(0, 208, 132, 0.1);
        border-left: 4px solid #00d084;
    }
    
    .stInfo {
        background: rgba(102, 126, 234, 0.1);
        border-left: 4px solid #667eea;
    }
</style>
"""

st.markdown(dark_theme_css, unsafe_allow_html=True)

# Initialize Engine
@st.cache_resource
def init_firewall():
    fw = FirewallEngine()
    rules = load_rules('data/rules.json')
    for r in rules:
        fw.add_rule(**r)
    return fw

fw = init_firewall()
rules = load_rules('data/rules.json')

# Session State
if 'logs' not in st.session_state:
    st.session_state.logs = []
if 'stats' not in st.session_state:
    st.session_state.stats = {"allowed": 0, "denied": 0, "quarantined": 0, "rate_limited": 0}

# Header Section
st.markdown('<div class="header-section">', unsafe_allow_html=True)
st.markdown('<h1 class="main-title">FIREWALL SECURITY ENGINE</h1>', unsafe_allow_html=True)
st.markdown(
    '<p class="subtitle">Advanced packet filtering and network security analysis system with real-time threat detection '
    'and comprehensive firewall rule evaluation. Monitor and control network traffic with intelligent filtering mechanisms.</p>',
    unsafe_allow_html=True
)

# Navigation Tabs
st.markdown('<div class="nav-tabs">', unsafe_allow_html=True)
col1, col2, col3 = st.columns(3)
with col1:
    st.markdown('<button class="nav-tab">TRAFFIC</button>', unsafe_allow_html=True)
with col2:
    st.markdown('<button class="nav-tab">ANALYSIS</button>', unsafe_allow_html=True)
with col3:
    st.markdown('<button class="nav-tab">SECURITY</button>', unsafe_allow_html=True)
st.markdown('</div>', unsafe_allow_html=True)
st.markdown('</div>', unsafe_allow_html=True)

st.markdown('---')

# Metrics Dashboard
st.markdown('### LIVE METRICS')
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.markdown(
        f'<div class="dark-card metric-card color-allowed">'
        f'<div class="metric-label">Allowed</div>'
        f'<div class="metric-value">{st.session_state.stats["allowed"]}</div>'
        f'</div>',
        unsafe_allow_html=True
    )

with col2:
    st.markdown(
        f'<div class="dark-card metric-card color-denied">'
        f'<div class="metric-label">Denied</div>'
        f'<div class="metric-value">{st.session_state.stats["denied"]}</div>'
        f'</div>',
        unsafe_allow_html=True
    )

with col3:
    st.markdown(
        f'<div class="dark-card metric-card color-warning">'
        f'<div class="metric-label">Quarantined</div>'
        f'<div class="metric-value">{st.session_state.stats["quarantined"]}</div>'
        f'</div>',
        unsafe_allow_html=True
    )

with col4:
    st.markdown(
        f'<div class="dark-card metric-card color-warning">'
        f'<div class="metric-label">Rate Limited</div>'
        f'<div class="metric-value">{st.session_state.stats.get("rate_limited", 0)}</div>'
        f'</div>',
        unsafe_allow_html=True
    )

st.markdown('---')

# Control Section
st.markdown('### PACKET GENERATION')
col1, col2 = st.columns([2, 1])

with col1:
    st.markdown('<div class="dark-card">', unsafe_allow_html=True)
    packet_count = st.slider("Number of Packets:", min_value=1, max_value=100, value=25, step=1)
    st.markdown('</div>', unsafe_allow_html=True)

with col2:
    st.markdown('<div class="dark-card">', unsafe_allow_html=True)
    col_a, col_b = st.columns(2)
    with col_a:
        run = st.button("START", use_container_width=True)
    with col_b:
        if st.button("CLEAR", use_container_width=True):
            st.session_state.logs = []
            st.session_state.stats = {"allowed": 0, "denied": 0, "quarantined": 0, "rate_limited": 0}
            st.rerun()
    st.markdown('</div>', unsafe_allow_html=True)

st.markdown('---')

# Live Inspection
st.markdown('### PACKET INSPECTION')
st.markdown('<div class="dark-card">', unsafe_allow_html=True)
log_container = st.empty()
st.markdown('</div>', unsafe_allow_html=True)

# Traffic Simulation
if run:
    ips = ["192.168.1.10", "192.168.2.50", "10.0.0.5", "172.16.0.1", "8.8.8.8", "1.1.1.1", "192.168.1.100"]
    protos = ["TCP", "UDP", "ICMP"]
    ports = [22, 53, 80, 443, 8080, 3306, 25]
    
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    for i in range(packet_count):
        p = Packet(
            random.choice(ips),
            random.choice(ips),
            random.choice(ports),
            random.choice(protos)
        )
        result = fw.check_packet(p)
        
        # Add to logs
        log_entry = {
            "Time": time.strftime("%H:%M:%S"),
            "Protocol": p.protocol,
            "Source": p.src_ip,
            "Destination": p.dst_ip,
            "Port": p.port,
            "Action": result
        }
        st.session_state.logs.insert(0, log_entry)
        
        # Map action to stats key properly
        action_key = result.upper()
        if action_key == "ALLOW":
            stats_key = "allowed"
        elif action_key == "DENY":
            stats_key = "denied"
        elif action_key == "QUARANTINE":
            stats_key = "quarantined"
        else:
            stats_key = result.lower()
        
        st.session_state.stats[stats_key] = st.session_state.stats.get(stats_key, 0) + 1
        
        # Display Table
        df = pd.DataFrame(st.session_state.logs[:20])  # Show last 20 packets
        
        # Color coding
        def style_action(val):
            if val == 'ALLOW':
                return 'background-color: #90EE90; color: black;'
            elif val == 'DENY':
                return 'background-color: #FF6B6B; color: white;'
            else:
                return 'background-color: #FFD700; color: black;'
        
        styled_df = df.style.applymap(style_action, subset=['Action'])
        log_container.dataframe(styled_df, use_container_width=True, hide_index=True)
        
        # Update progress
        progress_bar.progress((i + 1) / packet_count)
        status_text.info(f"Processing packet {i + 1}/{packet_count}...")
        time.sleep(0.25)
    
    progress_bar.empty()
    status_text.success(f"Processed {packet_count} packets!")
    
    st.markdown('<hr style="border-color: #2a2f45; margin: 30px 0;">', unsafe_allow_html=True)
    
    # Final Statistics
    st.markdown('<h3 style="color: #ffffff; text-transform: uppercase; letter-spacing: 2px; font-family: Georgia, serif; margin: 20px 0;">FINAL TRANSMISSION SUMMARY</h3>', unsafe_allow_html=True)
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown('<div class="metric-card" style="border-left: 4px solid #00d084;">', unsafe_allow_html=True)
        st.markdown(f'<div style="color: #999; font-size: 12px; text-transform: uppercase; letter-spacing: 1px; font-weight: 600;">ALLOWED</div>', unsafe_allow_html=True)
        st.markdown(f'<div style="color: #00d084; font-size: 32px; font-weight: bold; margin: 10px 0;">{st.session_state.stats["allowed"]}</div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col2:
        st.markdown('<div class="metric-card" style="border-left: 4px solid #ff1744;">', unsafe_allow_html=True)
        st.markdown(f'<div style="color: #999; font-size: 12px; text-transform: uppercase; letter-spacing: 1px; font-weight: 600;">DENIED</div>', unsafe_allow_html=True)
        st.markdown(f'<div style="color: #ff1744; font-size: 32px; font-weight: bold; margin: 10px 0;">{st.session_state.stats["denied"]}</div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col3:
        st.markdown('<div class="metric-card" style="border-left: 4px solid #ffb300;">', unsafe_allow_html=True)
        st.markdown(f'<div style="color: #999; font-size: 12px; text-transform: uppercase; letter-spacing: 1px; font-weight: 600;">QUARANTINED</div>', unsafe_allow_html=True)
        st.markdown(f'<div style="color: #ffb300; font-size: 32px; font-weight: bold; margin: 10px 0;">{st.session_state.stats["quarantined"]}</div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col4:
        st.markdown('<div class="metric-card" style="border-left: 4px solid #667eea;">', unsafe_allow_html=True)
        st.markdown(f'<div style="color: #999; font-size: 12px; text-transform: uppercase; letter-spacing: 1px; font-weight: 600;">RATE LIMITED</div>', unsafe_allow_html=True)
        st.markdown(f'<div style="color: #667eea; font-size: 32px; font-weight: bold; margin: 10px 0;">{st.session_state.stats.get("rate_limited", 0)}</div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

st.markdown('<hr style="border-color: #2a2f45; margin: 30px 0;">', unsafe_allow_html=True)

# Rules Section
st.markdown('<h3 style="color: #ffffff; text-transform: uppercase; letter-spacing: 2px; font-family: Georgia, serif; margin: 20px 0;">ACTIVE FIREWALL RULES</h3>', unsafe_allow_html=True)
st.markdown(f'<div style="color: #999; margin-bottom: 20px;">TOTAL RULES: <span style="color: #667eea; font-weight: bold;">{len(rules)}</span></div>', unsafe_allow_html=True)

rule_col1, rule_col2 = st.columns([1, 1])

with rule_col1:
    st.markdown('<div class="dark-card">', unsafe_allow_html=True)
    st.markdown('<div style="color: #667eea; font-size: 14px; text-transform: uppercase; letter-spacing: 1px; font-weight: 600; margin-bottom: 15px;">PRIORITY RULES</div>', unsafe_allow_html=True)
    for rule in sorted(rules, key=lambda r: r.get('priority', 0), reverse=True)[:3]:
        priority = rule.get('priority', 0)
        action = rule.get('action', 'DENY')
        rule_name = rule.get('rule_name', 'Unknown Rule')
        color = "#00d084" if action == "ALLOW" else "#ff1744"
        st.markdown(f"<div style='padding: 10px; border-left: 3px solid {color}; margin-bottom: 8px;'><span style='color: #999; font-size: 12px;'>[P{priority}]</span> <span style='color: {color}; font-weight: bold; text-transform: uppercase;'>{action}</span> - <span style='color: #ccc;'>{rule_name}</span></div>", unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)

with rule_col2:
    st.markdown('<div class="dark-card">', unsafe_allow_html=True)
    st.markdown('<div style="color: #667eea; font-size: 14px; text-transform: uppercase; letter-spacing: 1px; font-weight: 600; margin-bottom: 15px;">RULE DETAILS</div>', unsafe_allow_html=True)
    st.json(rules[:2])
    st.markdown('</div>', unsafe_allow_html=True)

st.markdown('<hr style="border-color: #2a2f45; margin: 30px 0;">', unsafe_allow_html=True)

# Footer
st.markdown('<hr style="border-color: #2a2f45; margin: 30px 0;">', unsafe_allow_html=True)
st.markdown('<div style="text-align: center; color: #666; font-size: 11px; margin-top: 30px; margin-bottom: 20px; text-transform: uppercase; letter-spacing: 1px;">', unsafe_allow_html=True)
st.markdown("© 2026 ADVANCED FIREWALL SECURITY ENGINE | PROFESSIONAL DARK THEME")
st.markdown('</div>', unsafe_allow_html=True)
