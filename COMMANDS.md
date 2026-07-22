## CYBER TRACK - FIREWALL SECURITY ENGINE

### **Commands to Run:**

#### **1. Quick Test (CLI)**
```bash
python quick_test.py
```
Shows firewall results without quarantine issues

#### **2. Beautiful CYBER TRACK Dashboard (Web)**
```bash
streamlit run frontend.py
```
Opens interactive dashboard at `http://localhost:8501`

#### **3. Interactive CLI**
```bash
python main.py
```
Command-line interface with simulated traffic

#### **4. Run Tests**
```bash
python test_firewall.py
```
Full test suite

---

### What Was Fixed:

Quarantine Issue - Rules now have flexible TTL range (1-255) instead of strict min_ttl requirements
10 Core Parameters - Simplified from 16+ complex parameters to just 10 key ones
CYBER TRACK Dashboard - Beautiful modern UI similar to the reference image
Easy Evaluation - Each parameter is clearly documented and explainable  

---

### 10 Key Parameters Explained:

**PACKET (7 params):**
1. Source IP - Where packet comes from
2. Destination IP - Where packet goes
3. Port - Service identifier
4. Protocol - TCP/UDP/ICMP
5. TTL - Hop counter (1-255)
6. Packet Size - Payload bytes
7. Timestamp - Auto-generated

**RULE (10 params including above):**
1. Rule Name - Human-readable ID
2. Source IP Filter - CIDR notation supported
3. Destination IP Filter - CIDR notation supported
4. Port - Specific port or null
5. Protocol - TCP/UDP/ICMP or null
6. Action - ALLOW, DENY, QUARANTINE
7. Priority - Rule evaluation order
8. TTL Range - Min-max bounds
9. Packet Size Range - Min-max bounds
10. QoS Priority - Traffic importance

---

### File Structure
```
firewall/
├── frontend.py              (NEW Dashboard)
├── quick_test.py            (NEW Quick test)
├── main.py                  ← CLI interface
├── test_firewall.py         ← Full test suite
├── web_app.py               ← Legacy Streamlit
├── README.md
├── UNIQUE_PARAMETERS.md     (UPDATED with 10 params)
├── PROJECT_EXPLANATION.md
├── data/
│   └── rules.json           (UPDATED with 10 params)
└── src/
    ├── engine.py
    ├── utils.py
    └── __init__.py
```

---

### Instructions for Evaluator

1. Run: `python quick_test.py` to see test results
2. Run: `streamlit run frontend.py` to see the beautiful dashboard
3. Show `UNIQUE_PARAMETERS.md` for parameter documentation
4. Show `rules.json` for real-world rule examples
