import datetime
import textwrap
import urllib.parse
import streamlit as st

# ============================================================
# GRAPH AWARE PREDICTIVE THREAT CONTAINMENT
# Enterprise Security Operations Center (SOC) Dashboard
# ============================================================

st.set_page_config(
    page_title="Graph Aware Predictive Threat Containment",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

def render_html(html_str: str):
    """Renders HTML cleanly using st.html with textwrap.dedent."""
    st.html(textwrap.dedent(html_str).strip())

# ------------------------------------------------------------
# SESSION STATE INITIALIZATION
# ------------------------------------------------------------

if "dark_mode" not in st.session_state:
    st.session_state.dark_mode = True

if "selected_attack" not in st.session_state:
    st.session_state.selected_attack = "Web Attack"

if "approval_states" not in st.session_state:
    st.session_state.approval_states = {}

if "active_tab" not in st.session_state:
    st.session_state.active_tab = "Dashboard"

def toggle_theme():
    """Toggles theme cleanly without widget key collision."""
    st.session_state.dark_mode = not st.session_state.dark_mode

# ------------------------------------------------------------
# THREAT SCENARIOS DATABASE
# ------------------------------------------------------------

SCENARIOS = {
    "Web Attack": {
        "id": "INC-8492-WAF",
        "attack_type": "Web Attack (SQLi / XSS)",
        "source": "Web_Server",
        "risk": 0.91,
        "severity": "CRITICAL",
        "priority": "IMMEDIATE",
        "blast": 3,
        "affected": ["App_Server", "Database", "Finance_PC"],
        "action": "Isolate Web Server & Inject WAF Rules",
        "confidence": "HIGH (94.8%)",
        "reason": "Anomalous ingress SQL payload patterns and high GNN propagation likelihood detected on Web_Server. Immediate network segment isolation prevents lateral pivot to the Database cluster.",
        "pills": ["Prevent Lateral Pivot", "Preserve DB Integrity", "Zero-Trust Isolation"],
    },
    "Brute Force": {
        "id": "INC-7319-SSH",
        "attack_type": "Brute Force (Credential Stuffing)",
        "source": "Finance_PC",
        "risk": 0.78,
        "severity": "HIGH",
        "priority": "IMMEDIATE",
        "blast": 2,
        "affected": ["Finance_PC", "App_Server"],
        "action": "Revoke Active Kerberos Ticket & Lock Endpoint",
        "confidence": "HIGH (91.2%)",
        "reason": "340+ failed authentication requests in 60 seconds with credential spray vectors originating from Finance_PC and attempting to pivot toward App_Server.",
        "pills": ["Kill Active Sessions", "Trigger MFA Reset", "Quarantine Endpoint"],
    },
    "DoS Attack": {
        "id": "INC-6104-DOS",
        "attack_type": "DoS Attack (SYN Flood)",
        "source": "Web_Server",
        "risk": 0.84,
        "severity": "HIGH",
        "priority": "HIGH",
        "blast": 2,
        "affected": ["Web_Server", "App_Server"],
        "action": "Deploy Ingress Rate-Limiting & IP Blackhole",
        "confidence": "MEDIUM (88.5%)",
        "reason": "Traffic spike exceeding 14 Gbps with irregular TCP flag distribution threatening Web_Server and upstream Application Gateway availability.",
        "pills": ["Scrub Malicious Ingress", "Scale Gateway Shards", "Enforce Rate Limits"],
    },
    "Botnet Activity": {
        "id": "INC-4820-C2",
        "attack_type": "Botnet Activity (C2 Beaconing)",
        "source": "App_Server",
        "risk": 0.67,
        "severity": "MEDIUM",
        "priority": "HIGH",
        "blast": 3,
        "affected": ["App_Server", "Database", "Finance_PC"],
        "action": "Sever C2 DNS Tunnel & Quarantine Container",
        "confidence": "MEDIUM (86.0%)",
        "reason": "DNS tunneling requests and periodic outbound HTTPS beacons to unclassified IP blocks detected from App_Server microservice container.",
        "pills": ["Block Egress Gateway", "Extract Memory Dump", "Redeploy Microservice"],
    },
    "Ransomware Spread": {
        "id": "INC-9941-RANSOM",
        "attack_type": "Lateral Ransomware Spread",
        "source": "Database",
        "risk": 0.96,
        "severity": "CRITICAL",
        "priority": "EMERGENCY",
        "blast": 4,
        "affected": ["Database", "App_Server", "Finance_PC", "Web_Server"],
        "action": "Air-Gap Database VLAN & Lock Storage Snapshots",
        "confidence": "CRITICAL (98.2%)",
        "reason": "Mass shadow-copy deletion activity and rapid SMB file encryption telemetry detected on Database cluster. Emergency segmentation required immediately.",
        "pills": ["Air-Gap DB Cluster", "Lock Immutable Snapshot", "Isolate Broadcast Domain"],
    },
}

# ------------------------------------------------------------
# CURRENT THREAT & APPROVAL STATUS
# ------------------------------------------------------------

selected_name = st.session_state.selected_attack
if selected_name not in SCENARIOS:
    selected_name = "Web Attack"
    st.session_state.selected_attack = selected_name

threat = SCENARIOS[selected_name]

if selected_name not in st.session_state.approval_states:
    st.session_state.approval_states[selected_name] = "PENDING"

current_approval = st.session_state.approval_states[selected_name]
dark = st.session_state.dark_mode

# ------------------------------------------------------------
# COMPREHENSIVE THEME SYSTEM (LIGHT & DARK MODE)
# ------------------------------------------------------------

if dark:
    C = {
        "bg": "#070e1b",
        "panel": "#0d1728",
        "panel2": "#111f36",
        "border": "#1d304f",
        "border_subtle": "#172740",
        "text": "#f3f7fc",
        "text_secondary": "#cbd5e1",
        "muted": "#94a3b8",
        "faint": "#64748b",
        "blue": "#38bdf8",
        "blue_bg": "#0d2847",
        "blue_border": "#1e4976",
        "red": "#ef4444",
        "red_bg": "#2e111a",
        "red_border": "#7f1d1d",
        "orange": "#f97316",
        "orange_bg": "#2d1d07",
        "orange_border": "#78350f",
        "green": "#10b981",
        "green_bg": "#062c21",
        "green_border": "#065f46",
        "grid": "#162744",
        "edge": "#4c668a",
        "edge_threat": "#f97316",
        "track": "#1e2d45",
        "node_bg": "#0d1728",
        "sidebar_bg": "#091222",
        "button_bg": "#15243d",
        "button_text": "#f1f5f9",
        "button_border": "#2b456e",
        "button_hover_bg": "#1e3559",
    }
else:
    C = {
        "bg": "#f4f7fb",
        "panel": "#ffffff",
        "panel2": "#f8fafc",
        "border": "#d8e2ee",
        "border_subtle": "#cbd5e1",
        "text": "#0f172a",
        "text_secondary": "#334155",
        "muted": "#475569",
        "faint": "#64748b",
        "blue": "#0284c7",
        "blue_bg": "#e0f2fe",
        "blue_border": "#bae6fd",
        "red": "#dc2626",
        "red_bg": "#fee2e2",
        "red_border": "#fca5a5",
        "orange": "#ea580c",
        "orange_bg": "#ffedd5",
        "orange_border": "#fed7aa",
        "green": "#059669",
        "green_bg": "#d1fae5",
        "green_border": "#6ee7b7",
        "grid": "#dce4ee",
        "edge": "#64748b",
        "edge_threat": "#ea580c",
        "track": "#e2e8f0",
        "node_bg": "#ffffff",
        "sidebar_bg": "#ffffff",
        "button_bg": "#f8fafc",
        "button_text": "#0f172a",
        "button_border": "#cbd5e1",
        "button_hover_bg": "#e2e8f0",
    }

# ------------------------------------------------------------
# GLOBAL CSS INJECTION
# ------------------------------------------------------------

render_html(f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap');

html, body, [class*="css"], .stApp {{
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif !important;
}}

.stApp {{
    background: {C["bg"]} !important;
    color: {C["text"]} !important;
}}

/* Streamlit main block tuning */
.block-container {{
    max-width: 1420px !important;
    padding: 1.2rem 2.2rem 3.5rem !important;
}}

/* Sidebar styling */
[data-testid="stSidebar"] {{
    background: {C["sidebar_bg"]} !important;
    border-right: 1px solid {C["border"]} !important;
    min-width: 290px !important;
    max-width: 290px !important;
}}

[data-testid="stSidebar"] > div:first-child {{
    padding: 1.2rem 1.1rem !important;
}}

/* Sidebar Selectbox Custom Theme */
div[data-baseweb="select"] > div {{
    background: {C["panel2"]} !important;
    border-color: {C["border"]} !important;
    color: {C["text"]} !important;
    border-radius: 10px !important;
}}

div[data-baseweb="select"] span {{
    color: {C["text"]} !important;
    font-weight: 700 !important;
}}

/* Sidebar Re-Open & Collapse Controls ALWAYS Visible */
[data-testid="collapsedControl"] {{
    display: flex !important;
    visibility: visible !important;
    z-index: 999999 !important;
    top: 14px !important;
    left: 14px !important;
    background: {C["panel"]} !important;
    border: 1px solid {C["border"]} !important;
    border-radius: 8px !important;
    color: {C["text"]} !important;
    box-shadow: 0 4px 14px rgba(0,0,0,{'0.3' if dark else '0.1'}) !important;
    transition: all 0.2s ease !important;
}}

[data-testid="collapsedControl"]:hover {{
    border-color: {C["blue"]} !important;
    background: {C["panel2"]} !important;
}}

[data-testid="collapsedControl"] svg {{
    fill: {C["text"]} !important;
    stroke: {C["text"]} !important;
}}

[data-testid="stSidebarCollapseButton"] {{
    color: {C["text"]} !important;
}}

[data-testid="stSidebarCollapseButton"] svg {{
    fill: {C["text"]} !important;
}}

/* Streamlit Header clean styling */
header[data-testid="stHeader"] {{
    background: transparent !important;
    z-index: 99999 !important;
}}
footer {{visibility: hidden !important;}}

/* Button Text Visibility at all times (Idle, Hover, Active) */
.stButton > button {{
    background: {C["button_bg"]} !important;
    color: {C["button_text"]} !important;
    border: 1.5px solid {C["button_border"]} !important;
    font-weight: 700 !important;
    font-size: 13px !important;
    border-radius: 10px !important;
    padding: 0.65rem 1.25rem !important;
    box-shadow: 0 2px 8px rgba(0,0,0,{'0.2' if dark else '0.04'}) !important;
    transition: all 0.2s ease !important;
    opacity: 1 !important;
    visibility: visible !important;
}}

.stButton > button * {{
    color: {C["button_text"]} !important;
    opacity: 1 !important;
    visibility: visible !important;
    font-weight: 700 !important;
}}

.stButton > button:hover {{
    background: {C["button_hover_bg"]} !important;
    color: {C["text"]} !important;
    border-color: {C["blue"]} !important;
    transform: translateY(-1px);
    box-shadow: 0 4px 14px rgba(0,0,0,{'0.3' if dark else '0.1'}) !important;
}}

.stButton > button:hover * {{
    color: {C["text"]} !important;
}}

/* Primary Action Button (Approve) */
.stButton > button[kind="primary"], .stButton > button[data-testid="stBaseButton-primary"] {{
    background: linear-gradient(135deg, #0284c7, #2563eb) !important;
    color: #ffffff !important;
    border: 1.5px solid #38bdf8 !important;
    box-shadow: 0 4px 16px rgba(37,99,235,0.35) !important;
}}

.stButton > button[kind="primary"] * {{
    color: #ffffff !important;
}}

.stButton > button[kind="primary"]:hover {{
    background: linear-gradient(135deg, #0369a1, #1d4ed8) !important;
    color: #ffffff !important;
    box-shadow: 0 6px 20px rgba(37,99,235,0.5) !important;
}}

/* Card container */
.tg-card {{
    background: {C["panel"]};
    border: 1px solid {C["border"]};
    border-radius: 14px;
    padding: 18px 20px;
    box-shadow: 0 4px 20px rgba(0,0,0,{'0.25' if dark else '0.04'});
    transition: all 0.2s ease-in-out;
}}

.tg-card:hover {{
    border-color: {C["border_subtle"]};
}}

.tg-section-header {{
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    margin-bottom: 12px;
}}

.tg-section-title {{
    font-size: 15px;
    font-weight: 800;
    color: {C["text"]};
    letter-spacing: -0.01em;
}}

.tg-section-sub {{
    font-size: 12px;
    color: {C["muted"]};
    font-weight: 500;
}}

/* Incident Header Banner */
.incident-banner {{
    padding: 16px 22px;
    border-radius: 14px;
    margin-bottom: 18px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    border: 1px solid {C["red_border"] if current_approval == "PENDING" else (C["green_border"] if current_approval == "APPROVED" else C["orange_border"])};
    background: {C["red_bg"] if current_approval == "PENDING" else (C["green_bg"] if current_approval == "APPROVED" else C["orange_bg"])};
    box-shadow: 0 4px 20px rgba(0,0,0,{'0.3' if dark else '0.05'});
}}

.incident-badge {{
    padding: 4px 10px;
    border-radius: 99px;
    font-size: 11px;
    font-weight: 800;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    display: inline-block;
    background: {C["red"] if current_approval == "PENDING" else (C["green"] if current_approval == "APPROVED" else C["orange"])};
    color: #ffffff;
}}

/* KPI Metric Cards */
.kpi-box {{
    background: {C["panel"]};
    border: 1px solid {C["border"]};
    border-radius: 14px;
    padding: 16px 18px;
    box-shadow: 0 4px 16px rgba(0,0,0,{'0.2' if dark else '0.03'});
    position: relative;
    overflow: hidden;
}}

.kpi-label {{
    font-size: 11px;
    font-weight: 800;
    letter-spacing: 0.07em;
    text-transform: uppercase;
    color: {C["muted"]};
    margin-bottom: 6px;
}}

.kpi-value {{
    font-size: 26px;
    font-weight: 900;
    line-height: 1.1;
    letter-spacing: -0.03em;
    margin-bottom: 4px;
}}

.kpi-footer {{
    font-size: 12px;
    color: {C["muted"]};
    font-weight: 500;
}}

/* ============================================================
   TOPOLOGY CANVAS & CONNECTION PATHS
   ============================================================ */
.topology-container {{
    position: relative;
    height: 400px;
    border-radius: 14px;
    border: 1px solid {C["border"]};
    background: {C["panel2"]};
    background-image: 
        radial-gradient({C["grid"]} 2px, transparent 2px);
    background-size: 24px 24px;
    overflow: hidden;
}}

.topology-svg {{
    position: absolute !important;
    top: 0 !important;
    left: 0 !important;
    width: 100% !important;
    height: 100% !important;
    z-index: 2 !important;
    pointer-events: none !important;
    overflow: visible !important;
}}

.topology-lines-img {{
    position: absolute !important;
    top: 0 !important;
    left: 0 !important;
    width: 100% !important;
    height: 100% !important;
    z-index: 2 !important;
    pointer-events: none !important;
    display: block !important;
    object-fit: fill !important;
}}

.topology-lines-bg {{
    position: absolute !important;
    top: 0 !important;
    left: 0 !important;
    width: 100% !important;
    height: 100% !important;
    z-index: 1 !important;
    pointer-events: none !important;
    background-size: 100% 100% !important;
    background-repeat: no-repeat !important;
}}

.edge-normal {{
    stroke: {C["edge"]} !important;
    stroke-width: 3.5px !important;
    stroke-linecap: round !important;
    opacity: 0.85 !important;
    transition: all 0.4s ease !important;
}}

/* Active Orange Blast Radius Vector Line */
.edge-threat-orange {{
    stroke: {C["orange"]} !important;
    stroke-width: 5px !important;
    stroke-dasharray: 10 7 !important;
    stroke-linecap: round !important;
    filter: drop-shadow(0 0 5px {C["orange"]}) !important;
    animation: flow-orange 1.2s linear infinite !important;
    opacity: 1 !important;
    transition: all 0.4s ease !important;
}}

@keyframes flow-orange {{
    to {{ stroke-dashoffset: -34; }}
}}

.net-node {{
    position: absolute;
    transform: translate(-50%, -50%);
    width: 112px;
    padding: 9px 7px;
    border-radius: 12px;
    text-align: center;
    background: {C["node_bg"]};
    border: 1.5px solid {C["border"]};
    box-shadow: 0 8px 24px rgba(0,0,0,{'0.35' if dark else '0.08'});
    z-index: 6;
    transition: all 0.25s ease;
}}

.net-node:hover {{
    transform: translate(-50%, -54%) scale(1.05);
    box-shadow: 0 12px 30px rgba(0,0,0,{'0.5' if dark else '0.12'});
    z-index: 10;
}}

.net-node.danger {{
    border-color: {C["red"]};
    background: {C["red_bg"]};
    box-shadow: 0 0 0 3px rgba(239,68,68,0.25), 0 10px 28px rgba(239,68,68,0.3);
    animation: danger-pulse 2.2s infinite;
}}

.net-node.risk {{
    border-color: {C["orange"]};
    background: {C["orange_bg"]};
    box-shadow: 0 0 0 2.5px rgba(249,115,22,0.25), 0 8px 20px rgba(249,115,22,0.25);
}}

.net-node.secured {{
    border-color: {C["green"]};
    background: {C["green_bg"]};
    box-shadow: 0 0 0 2.5px rgba(16,185,129,0.25), 0 8px 20px rgba(16,185,129,0.2);
}}

@keyframes danger-pulse {{
    0% {{ box-shadow: 0 0 0 0 rgba(239,68,68,0.5), 0 8px 24px rgba(239,68,68,0.3); }}
    70% {{ box-shadow: 0 0 0 9px rgba(239,68,68,0), 0 8px 24px rgba(239,68,68,0.3); }}
    100% {{ box-shadow: 0 0 0 0 rgba(239,68,68,0), 0 8px 24px rgba(239,68,68,0.3); }}
}}

.node-icon-wrapper {{
    width: 38px;
    height: 38px;
    margin: 0 auto 5px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 19px;
    background: {C["panel2"]};
    border: 1.5px solid {C["border"]};
}}

.net-node.danger .node-icon-wrapper {{
    border-color: {C["red"]};
    background: {C["panel"]};
}}

.net-node.risk .node-icon-wrapper {{
    border-color: {C["orange"]};
    background: {C["panel"]};
}}

.net-node.secured .node-icon-wrapper {{
    border-color: {C["green"]};
    background: {C["panel"]};
}}

.node-title {{
    font-size: 11px;
    font-weight: 800;
    color: {C["text"]};
    letter-spacing: -0.01em;
}}

.node-subtitle {{
    font-size: 9.5px;
    color: {C["muted"]};
    font-weight: 600;
    margin-top: 2px;
}}

.node-badge-tag {{
    position: absolute;
    top: -8px;
    right: -6px;
    padding: 2px 6px;
    border-radius: 99px;
    font-size: 8.5px;
    font-weight: 900;
    letter-spacing: 0.05em;
    background: {C["panel"]};
    border: 1px solid {C["border"]};
    color: {C["muted"]};
}}

.net-node.danger .node-badge-tag {{
    background: {C["red"]};
    color: #ffffff;
    border-color: {C["red"]};
}}

.net-node.risk .node-badge-tag {{
    background: {C["orange"]};
    color: #ffffff;
    border-color: {C["orange"]};
}}

.net-node.secured .node-badge-tag {{
    background: {C["green"]};
    color: #ffffff;
    border-color: {C["green"]};
}}

/* Agent Pipeline Cards */
.agent-step-card {{
    background: {C["panel2"]};
    border: 1px solid {C["border"]};
    border-radius: 12px;
    padding: 14px 12px;
    position: relative;
}}

.agent-num-badge {{
    width: 24px;
    height: 24px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 11px;
    font-weight: 900;
    background: {C["blue_bg"]};
    color: {C["blue"]};
    border: 1px solid {C["blue_border"]};
    margin-bottom: 8px;
}}

/* Timeline event items */
.timeline-item {{
    display: flex;
    gap: 14px;
    padding: 8px 0;
    border-bottom: 1px solid {C["border_subtle"]};
}}
.timeline-item:last-child {{ border-bottom: none; }}
</style>
""")

# ------------------------------------------------------------
# SIDEBAR CONTENT
# ------------------------------------------------------------

with st.sidebar:
    render_html(f"""
    <div style="display:flex;align-items:center;gap:12px;padding:8px 0 16px 0;border-bottom:1px solid {C['border']};">
        <div style="width:42px;height:42px;border-radius:12px;background:linear-gradient(135deg,#38bdf8,#1d4ed8);display:flex;align-items:center;justify-content:center;font-size:22px;box-shadow:0 6px 18px rgba(56,189,248,0.35);">
            🛡️
        </div>
        <div>
            <div style="color:{C['text']};font-size:17px;font-weight:900;letter-spacing:-0.02em;line-height:1.1;">ThreatGuard</div>
            <div style="color:{C['blue']};font-size:11px;font-weight:600;letter-spacing:0.04em;">Graph Aware Defense</div>
        </div>
    </div>
    """)

    render_html(f"<div style='margin-top:16px;color:{C['muted']};font-size:11px;font-weight:800;letter-spacing:0.08em;text-transform:uppercase;'>Threat Scenario Selector</div>")

    scenario_options = list(SCENARIOS.keys())
    current_idx = scenario_options.index(selected_name)
    
    new_attack = st.selectbox(
        "ACTIVE THREAT SCENARIO",
        scenario_options,
        index=current_idx,
        label_visibility="collapsed",
        key="scenario_select_box"
    )

    if new_attack != st.session_state.selected_attack:
        st.session_state.selected_attack = new_attack
        st.rerun()

    # Active Scenario Card in Sidebar
    render_html(f"""
    <div style="margin-top:14px;padding:14px;border-radius:12px;background:{C['panel2']};border:1px solid {C['border']};">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
            <span style="color:{C['text']};font-size:13px;font-weight:800;">⚡ {threat['attack_type']}</span>
            <span style="padding:2px 8px;border-radius:6px;font-size:10px;font-weight:800;background:{C['red_bg'] if threat['severity']=='CRITICAL' else C['orange_bg']};color:{C['red'] if threat['severity']=='CRITICAL' else C['orange']};border:1px solid {C['red_border'] if threat['severity']=='CRITICAL' else C['orange_border']};">
                {threat['severity']}
            </span>
        </div>
        <div style="display:flex;justify-content:space-between;padding:5px 0;font-size:12px;border-bottom:1px solid {C['border_subtle']};">
            <span style="color:{C['muted']};">Incident ID</span>
            <span style="color:{C['text']};font-weight:700;font-family:monospace;">{threat['id']}</span>
        </div>
        <div style="display:flex;justify-content:space-between;padding:5px 0;font-size:12px;border-bottom:1px solid {C['border_subtle']};">
            <span style="color:{C['muted']};">Source Asset</span>
            <span style="color:{C['red']};font-weight:700;">{threat['source']}</span>
        </div>
        <div style="display:flex;justify-content:space-between;padding:5px 0;font-size:12px;border-bottom:1px solid {C['border_subtle']};">
            <span style="color:{C['muted']};">GNN Risk Score</span>
            <span style="color:{C['red']};font-weight:800;">{threat['risk']:.2f} / 1.00</span>
        </div>
        <div style="display:flex;justify-content:space-between;padding:5px 0;font-size:12px;">
            <span style="color:{C['muted']};">Blast Radius</span>
            <span style="color:{C['orange']};font-weight:800;">{threat['blast']} Nodes</span>
        </div>
    </div>
    """)

    # Navigation Section
    render_html(f"<div style='margin-top:18px;color:{C['muted']};font-size:11px;font-weight:800;letter-spacing:0.08em;text-transform:uppercase;'>Navigation</div>")

    nav_items = [
        ("▣", "Dashboard"),
        ("♧", "Network Topology"),
        ("⚠", "Active Incidents"),
        ("◈", "AI Recommendations"),
        ("▤", "Audit & Logs"),
    ]

    for icon, nav_name in nav_items:
        is_act = (st.session_state.active_tab == nav_name)
        bg = C["panel2"] if is_act else "transparent"
        col = C["text"] if is_act else C["muted"]
        border = f"border-left: 3px solid {C['blue']};" if is_act else "border-left: 3px solid transparent;"
        render_html(f"""
        <div style="display:flex;align-items:center;gap:10px;padding:9px 12px;margin:3px 0;border-radius:8px;background:{bg};color:{col};font-size:13px;font-weight:{'700' if is_act else '500'};{border}">
            <span>{icon}</span> <span>{nav_name}</span>
        </div>
        """)

    # Analysis Engine
    render_html(f"""
    <div style="margin-top:18px;padding:12px;border-radius:10px;background:{C['panel2']};border:1px solid {C['border']};">
        <div style="color:{C['blue']};font-size:11px;font-weight:800;letter-spacing:0.06em;text-transform:uppercase;margin-bottom:6px;">Analysis Engine</div>
        <div style="color:{C['text_secondary']};font-size:12px;line-height:1.7;">
            <span style="color:{C['blue']};">●</span> Graph Neural Net (GNN-v3)<br>
            <span style="color:{C['orange']};">●</span> Topology Propagation Engine<br>
            <span style="color:{C['green']};">●</span> Multi-Agent Decision Pipeline
        </div>
    </div>
    """)

    # System Status
    render_html(f"""
    <div style="margin-top:14px;padding:10px 12px;border-radius:10px;background:{C['green_bg']};border:1px solid {C['green_border']};display:flex;align-items:center;gap:10px;">
        <span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:{C['green']};box-shadow:0 0 10px {C['green']};"></span>
        <div>
            <div style="color:{C['text']};font-size:12px;font-weight:800;">SOC Pipeline Active</div>
            <div style="color:{C['green']};font-size:11px;font-weight:600;">GNN Latency: 14ms · High Fidelity</div>
        </div>
    </div>
    """)

    # Clean Sidebar Theme Button
    render_html("<div style='margin-top:16px;'></div>")
    side_theme_label = "☀️ Switch to Light Mode" if dark else "🌙 Switch to Dark Mode"
    st.button(side_theme_label, key="theme_btn_sidebar", on_click=toggle_theme, use_container_width=True)

    render_html(f"""
    <div style="color:{C['faint']};font-size:11px;text-align:center;margin-top:14px;padding-top:12px;border-top:1px solid {C['border']};">
        ThreatGuard Enterprise v2.4<br>© 2026 Predictive SecOps
    </div>
    """)

# ------------------------------------------------------------
# TOP HEADER BAR (TITLE & THEME TOGGLE)
# ------------------------------------------------------------

head_left, head_mid, head_right = st.columns([2.3, 1.2, 1.5], vertical_alignment="center")

with head_left:
    render_html(f"""
    <div>
        <div style="color:{C['blue']};font-size:11.5px;font-weight:800;letter-spacing:0.08em;text-transform:uppercase;">
            Real-Time Enterprise Network Defense
        </div>
        <div style="color:{C['text']};font-size:27px;font-weight:900;letter-spacing:-0.03em;line-height:1.15;margin-top:2px;">
            Graph Aware <span style="color:{C['blue']};">Predictive Threat Containment</span>
        </div>
        <div style="color:{C['muted']};font-size:12.5px;margin-top:4px;">
            Topology GNN Analysis &nbsp;•&nbsp; Multi-Agent Reasoner &nbsp;•&nbsp; Human-in-the-Loop Governance
        </div>
    </div>
    """)

with head_mid:
    render_html(f"""
    <div style="display:flex;align-items:center;gap:8px;padding:9px 14px;border-radius:10px;background:{C['panel']};border:1px solid {C['border']};color:{C['muted']};font-size:12px;">
        <span>🔍</span>
        <span>Filter topology, CVEs, logs...</span>
    </div>
    """)

with head_right:
    now_str = datetime.datetime.now().strftime("%a, %d %b %Y • %H:%M:%S UTC")
    h_r1, h_r2 = st.columns([1.1, 1.0], vertical_alignment="center")
    with h_r1:
        top_theme_label = "☀️ Light Mode" if dark else "🌙 Dark Mode"
        st.button(top_theme_label, key="theme_btn_topbar", on_click=toggle_theme, use_container_width=True)
    with h_r2:
        render_html(f"""
        <div style="text-align:right;border-left:1px solid {C['border']};padding-left:10px;">
            <div style="color:{C['faint']};font-size:10px;font-weight:700;text-transform:uppercase;">System Clock</div>
            <div style="color:{C['text']};font-size:11px;font-weight:800;font-family:monospace;">{now_str}</div>
        </div>
        """)

render_html("<div style='margin-bottom:14px;'></div>")

# ------------------------------------------------------------
# INCIDENT STATUS BANNER
# ------------------------------------------------------------

if current_approval == "PENDING":
    status_tag = "⚠ ACTION REQUIRED • AWAITING APPROVAL"
    status_title = f"{threat['attack_type']} on {threat['source']}"
    status_desc = f"GNN predicts elevated propagation across {threat['blast']} connected entities. Proposed containment: {threat['action']}."
    status_badge_bg = C["red"]
    resp_state = "Awaiting Admin Approval"
    resp_color = C["red"]
elif current_approval == "APPROVED":
    status_tag = "🛡️ CONTAINMENT ACTIVE • NODE ISOLATED"
    status_title = f"{threat['action']} Successfully Executed"
    status_desc = f"Perimeter isolation injected. Threat on {threat['source']} contained and lateral spread neutralized across topology."
    status_badge_bg = C["green"]
    resp_state = "Containment Enforced (Secured)"
    resp_color = C["green"]
else:
    status_tag = "✕ CONTAINMENT OVERRIDDEN"
    status_title = f"Manual Monitoring Mode for {threat['source']}"
    status_desc = "Automated isolation was rejected by the SOC administrator. Continuous telemetry monitoring enabled."
    status_badge_bg = C["orange"]
    resp_state = "Manual Override (Monitoring)"
    resp_color = C["orange"]

render_html(f"""
<div class="incident-banner">
    <div style="display:flex;align-items:center;gap:16px;">
        <div style="width:48px;height:48px;border-radius:12px;background:{C['panel']};border:1.5px solid {resp_color};display:flex;align-items:center;justify-content:center;font-size:24px;">
            {'⚠️' if current_approval == 'PENDING' else ('✅' if current_approval == 'APPROVED' else '🛑')}
        </div>
        <div>
            <div style="display:flex;align-items:center;gap:10px;margin-bottom:4px;">
                <span class="incident-badge" style="background:{status_badge_bg};">{status_tag}</span>
                <span style="color:{C['faint']};font-size:12px;font-family:monospace;font-weight:700;">{threat['id']}</span>
            </div>
            <div style="color:{C['text']};font-size:17px;font-weight:900;letter-spacing:-0.01em;">{status_title}</div>
            <div style="color:{C['muted']};font-size:12px;margin-top:2px;">{status_desc}</div>
        </div>
    </div>
    <div style="text-align:right;border-left:1px solid {C['border_subtle']};padding-left:20px;">
        <div style="color:{C['faint']};font-size:11px;font-weight:800;letter-spacing:0.08em;text-transform:uppercase;">Response State</div>
        <div style="color:{resp_color};font-size:14px;font-weight:900;margin-top:4px;">{resp_state}</div>
    </div>
</div>
""")

# ------------------------------------------------------------
# KPI SUMMARY ROW
# ------------------------------------------------------------

k1, k2, k3, k4 = st.columns(4)

with k1:
    sev_col = C["red"] if threat["severity"] in ["HIGH", "CRITICAL"] else C["orange"]
    render_html(f"""
    <div class="kpi-box">
        <div class="kpi-label">Threat Severity</div>
        <div class="kpi-value" style="color:{sev_col};">{threat['severity']}</div>
        <div class="kpi-footer">Priority: <b>{threat['priority']}</b></div>
    </div>
    """)

with k2:
    risk_pct = int(threat["risk"] * 100)
    render_html(f"""
    <div class="kpi-box">
        <div class="kpi-label">Predicted Risk Score</div>
        <div class="kpi-value" style="color:{C['red']};">{threat['risk']:.2f} <span style="font-size:15px;color:{C['muted']};font-weight:600;">/ 1.0</span></div>
        <div class="kpi-footer">GNN Propagation Probability: <b>{risk_pct}%</b></div>
    </div>
    """)

with k3:
    render_html(f"""
    <div class="kpi-box">
        <div class="kpi-label">Blast Radius Impact</div>
        <div class="kpi-value" style="color:{C['orange']};">{threat['blast']} <span style="font-size:15px;color:{C['muted']};font-weight:600;">Nodes</span></div>
        <div class="kpi-footer">Target: <b>{', '.join(threat['affected'][:2])} +more</b></div>
    </div>
    """)

with k4:
    render_html(f"""
    <div class="kpi-box">
        <div class="kpi-label">Classification</div>
        <div class="kpi-value" style="color:{C['blue']};font-size:20px;line-height:1.35;">{selected_name}</div>
        <div class="kpi-footer">Source Anchor: <b>{threat['source']}</b></div>
    </div>
    """)

render_html("<div style='margin-bottom:18px;'></div>")

# ------------------------------------------------------------
# UNCLUSTERED TOPOLOGY MAP (LEFT) + GNN RISK & AGENTS (RIGHT)
# ------------------------------------------------------------

map_col, reason_col = st.columns([1.65, 1.0], gap="medium")

# Unclustered node coordinates (% of container, spacious layout)
node_positions = {
    "Internet": (8, 50, "🌐", "Gateway"),
    "Firewall": (26, 50, "🛡️", "Perimeter"),
    "Web_Server": (46, 50, "🖥️", "DMZ Server"),
    "App_Server": (69, 24, "⚙️", "App Tier"),
    "Database": (69, 76, "🗄️", "Data Layer"),
    "Finance_PC": (91, 50, "💻", "Internal PC"),
}

# Determine state of each node
node_states = {}
for n in node_positions:
    if current_approval == "APPROVED" and n == threat["source"]:
        node_states[n] = "secured"
    elif current_approval == "APPROVED":
        node_states[n] = "normal"  # All returned to normal when contained!
    elif n == threat["source"]:
        node_states[n] = "danger"
    elif n in threat["affected"]:
        node_states[n] = "risk"
    else:
        node_states[n] = "normal"

# Defined enterprise topology connection lines
edges = [
    ("Internet", "Firewall"),
    ("Firewall", "Web_Server"),
    ("Web_Server", "App_Server"),
    ("Web_Server", "Database"),
    ("App_Server", "Finance_PC"),
    ("Database", "Finance_PC"),
]

# EXACT THREAT PROPAGATION LINE CHECKER FOR ALL ATTACK TYPES
def is_threat_propagation_line(a, b, attack_name, source, affected, is_approved):
    """Returns True if the connection between node a and node b is an active attack/blast-radius vector."""
    if is_approved:
        return False  # When approved by admin, ALL lines return back to normal!

    # Scenario 1: Web Attack (Source: Web_Server)
    if source == "Web_Server" and attack_name == "Web Attack":
        return (a, b) in {
            ("Web_Server", "App_Server"),
            ("Web_Server", "Database"),
            ("App_Server", "Finance_PC"),
            ("Database", "Finance_PC"),
        }

    # Scenario 2: Brute Force (Source: Finance_PC)
    elif source == "Finance_PC":
        return (a, b) in {
            ("App_Server", "Finance_PC"),
            ("Database", "Finance_PC"),
        }

    # Scenario 3: DoS Attack (Source: Web_Server)
    elif attack_name == "DoS Attack":
        return (a, b) in {
            ("Firewall", "Web_Server"),
            ("Web_Server", "App_Server"),
        }

    # Scenario 4: Botnet Activity (Source: App_Server)
    elif source == "App_Server":
        return (a, b) in {
            ("Web_Server", "App_Server"),
            ("App_Server", "Finance_PC"),
            ("Database", "Finance_PC"),
        }

    # Scenario 5: Ransomware Spread (Source: Database)
    elif source == "Database":
        return (a, b) in {
            ("Web_Server", "Database"),
            ("Database", "Finance_PC"),
            ("App_Server", "Finance_PC"),
            ("Web_Server", "App_Server"),
        }

    return False

# Build SVG paths and animated elements for topology connections
svg_elements = []
for a, b in edges:
    x1, y1, _, _ = node_positions[a]
    x2, y2, _, _ = node_positions[b]
    # Scale % (0-100) to 1000x400 viewBox
    px1, py1 = int(x1 * 10), int(y1 * 4)
    px2, py2 = int(x2 * 10), int(y2 * 4)

    is_orange_threat = is_threat_propagation_line(
        a, b, selected_name, threat["source"], threat["affected"], (current_approval == "APPROVED")
    )
    
    if is_orange_threat:
        # Active Threat Vector: glowing vibrant orange animated dash and moving pulse
        svg_elements.append(
            f'<path d="M {px1} {py1} L {px2} {py2}" stroke="{C["orange"]}" stroke-width="6" stroke-dasharray="14 10" stroke-linecap="round" fill="none" filter="url(#glow)">'
            f'<animate attributeName="stroke-dashoffset" from="0" to="-48" dur="1.2s" repeatCount="indefinite"/>'
            f'</path>'
            f'<circle r="5.5" fill="{C["orange"]}" filter="url(#glow)">'
            f'<animateMotion path="M {px1} {py1} L {px2} {py2}" dur="1.4s" repeatCount="indefinite"/>'
            f'</circle>'
        )
    else:
        # Normal healthy connection link
        svg_elements.append(
            f'<path d="M {px1} {py1} L {px2} {py2}" stroke="{C["edge"]}" stroke-width="3.5" stroke-linecap="round" fill="none" opacity="0.85"/>'
        )

# Construct full standalone SVG
raw_svg = (
    f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1000 400" preserveAspectRatio="none" width="1000" height="400">'
    f'<defs>'
    f'<filter id="glow" x="-30%" y="-30%" width="160%" height="160%">'
    f'<feDropShadow dx="0" dy="0" stdDeviation="5" flood-color="{C["orange"]}" flood-opacity="0.9"/>'
    f'</filter>'
    f'</defs>'
    f'{"".join(svg_elements)}'
    f'</svg>'
)

encoded_svg = urllib.parse.quote(raw_svg)
svg_data_uri = f"data:image/svg+xml;utf8,{encoded_svg}"

# Generate Node DOM Elements
nodes_markup = []
for name, (x, y, icon, role) in node_positions.items():
    stt = node_states[name]
    if stt == "danger":
        badge_text = "COMPROMISED"
    elif stt == "secured":
        badge_text = "ISOLATED"
    elif stt == "risk":
        badge_text = "AT RISK"
    else:
        badge_text = "NORMAL"

    nodes_markup.append(f"""
    <div class="net-node {stt}" style="left:{x}%;top:{y}%;">
        <div class="node-badge-tag">{badge_text}</div>
        <div class="node-icon-wrapper">{icon}</div>
        <div class="node-title">{name}</div>
        <div class="node-subtitle">{role}</div>
    </div>
    """)

with map_col:
    render_html(f"""
    <div class="tg-card">
        <div class="tg-section-header">
            <div>
                <div class="tg-section-title">Enterprise Network Threat Topology</div>
                <div class="tg-section-sub">Real-time GNN node embeddings & orange attack propagation vectors</div>
            </div>
            <div style="font-size:12px;font-weight:700;color:{C['blue']};">
                6 Monitored Assets
            </div>
        </div>

        <div class="topology-container">
            <!-- Data URI img layer (bypasses DOMPurify svg stripping completely) -->
            <img src="{svg_data_uri}" class="topology-lines-img" alt="Network Topology Connections" />
            <!-- CSS background fallback layer -->
            <div class="topology-lines-bg" style="background-image: url('{svg_data_uri}');"></div>
            <!-- Raw SVG layer -->
            <svg class="topology-svg" viewBox="0 0 1000 400" preserveAspectRatio="none" xmlns="http://www.w3.org/2000/svg">
                {''.join(svg_elements)}
            </svg>
            {''.join(nodes_markup)}

            <!-- Topology Legend -->
            <div style="position:absolute;bottom:12px;left:14px;z-index:10;display:flex;align-items:center;gap:14px;padding:8px 12px;border-radius:10px;background:{C['panel']};border:1px solid {C['border']};font-size:11px;color:{C['muted']};box-shadow:0 4px 14px rgba(0,0,0,{'0.25' if dark else '0.08'});">
                <div style="display:flex;align-items:center;gap:5px;">
                    <span style="display:inline-block;width:16px;height:3px;background:{C['edge']};border-radius:2px;"></span>
                    <span>Normal Link</span>
                </div>
                <div style="display:flex;align-items:center;gap:5px;">
                    <span style="display:inline-block;width:16px;height:3px;background:{C['orange']};border-radius:2px;box-shadow:0 0 5px {C['orange']};"></span>
                    <span>Blast Radius Vector (Orange)</span>
                </div>
                <div style="display:flex;align-items:center;gap:5px;">
                    <span style="display:inline-block;width:9px;height:9px;border-radius:50%;background:{C['red']};"></span>
                    <span>Compromised</span>
                </div>
                <div style="display:flex;align-items:center;gap:5px;">
                    <span style="display:inline-block;width:9px;height:9px;border-radius:50%;background:{C['orange']};"></span>
                    <span>At Risk</span>
                </div>
                <div style="display:flex;align-items:center;gap:5px;">
                    <span style="display:inline-block;width:9px;height:9px;border-radius:50%;background:{C['green']};"></span>
                    <span>Secured</span>
                </div>
            </div>
        </div>
    </div>
    """)

with reason_col:
    # GNN Risk Score Conic Ring
    deg = max(5, min(355, int(threat["risk"] * 360)))
    ring_color = C["red"] if threat["risk"] >= 0.75 else (C["orange"] if threat["risk"] >= 0.5 else C["green"])

    render_html(f"""
    <div class="tg-card" style="margin-bottom:14px;">
        <div class="tg-section-header">
            <div>
                <div class="tg-section-title">GNN Risk Prediction</div>
                <div class="tg-section-sub">Graph attention propagation weight</div>
            </div>
            <div style="font-size:11px;font-weight:800;color:{ring_color};">
                {threat['severity']} LEVEL
            </div>
        </div>

        <div style="display:flex;align-items:center;gap:18px;">
            <div style="width:92px;height:92px;border-radius:50%;background:conic-gradient({ring_color} 0deg {deg}deg, {C['track']} {deg}deg 360deg);display:flex;align-items:center;justify-content:center;flex-shrink:0;">
                <div style="width:72px;height:72px;border-radius:50%;background:{C['panel']};display:flex;flex-direction:column;align-items:center;justify-content:center;">
                    <div style="color:{ring_color};font-size:22px;font-weight:900;line-height:1;">{threat['risk']:.2f}</div>
                    <div style="color:{C['faint']};font-size:9px;font-weight:700;text-transform:uppercase;margin-top:2px;">Risk Score</div>
                </div>
            </div>
            <div>
                <div style="color:{C['text']};font-size:14px;font-weight:800;margin-bottom:4px;">Elevated Ingress Threat</div>
                <div style="color:{C['muted']};font-size:12px;line-height:1.45;">
                    Graph neural net identifies high lateral movement affinity across topology.
                </div>
            </div>
        </div>

        <div style="height:6px;border-radius:99px;background:{C['track']};margin-top:14px;overflow:hidden;">
            <div style="height:100%;width:{threat['risk']*100:.0f}%;background:{ring_color};border-radius:99px;"></div>
        </div>
        <div style="display:flex;justify-content:space-between;color:{C['faint']};font-size:10px;font-weight:700;margin-top:4px;">
            <span>0.0 (LOW)</span>
            <span>0.5 (MED)</span>
            <span>0.8 (HIGH)</span>
            <span>1.0 (CRITICAL)</span>
        </div>
    </div>
    """)

    # Agent Pipeline Execution
    a1_status = "✓ Completed (12ms)"
    a2_status = "✓ Completed (24ms)"
    if current_approval == "APPROVED":
        a3_status = "✓ Executed (Secured)"
        a3_badge_bg = C["green_bg"]
        a3_col = C["green"]
    elif current_approval == "REJECTED":
        a3_status = "✕ Overridden (Admin)"
        a3_badge_bg = C["red_bg"]
        a3_col = C["red"]
    else:
        a3_status = "○ Awaiting Decision"
        a3_badge_bg = C["orange_bg"]
        a3_col = C["orange"]

    render_html(f"""
    <div class="tg-card">
        <div class="tg-section-header">
            <div>
                <div class="tg-section-title">Autonomous Agent Pipeline</div>
                <div class="tg-section-sub">Multi-stage zero-trust reasoning</div>
            </div>
            <div style="font-size:11px;color:{C['blue']};font-weight:800;">STAGES (3/3)</div>
        </div>

        <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:8px;">
            <div class="agent-step-card">
                <div class="agent-num-badge">1</div>
                <div style="color:{C['text']};font-size:12px;font-weight:800;">Triage Agent</div>
                <div style="color:{C['muted']};font-size:11px;line-height:1.5;margin-top:4px;">
                    • Parse alert<br>• GNN feature map<br>• Score anomaly
                </div>
                <div style="margin-top:8px;padding:3px 6px;border-radius:6px;background:{C['green_bg']};color:{C['green']};font-size:10px;font-weight:800;display:inline-block;">
                    {a1_status}
                </div>
            </div>

            <div class="agent-step-card">
                <div class="agent-num-badge">2</div>
                <div style="color:{C['text']};font-size:12px;font-weight:800;">Planning Agent</div>
                <div style="color:{C['muted']};font-size:11px;line-height:1.5;margin-top:4px;">
                    • Blast estimation<br>• Graph traversal<br>• Synthesize plan
                </div>
                <div style="margin-top:8px;padding:3px 6px;border-radius:6px;background:{C['green_bg']};color:{C['green']};font-size:10px;font-weight:800;display:inline-block;">
                    {a2_status}
                </div>
            </div>

            <div class="agent-step-card">
                <div class="agent-num-badge" style="background:{a3_badge_bg};color:{a3_col};">3</div>
                <div style="color:{C['text']};font-size:12px;font-weight:800;">Response Agent</div>
                <div style="color:{C['muted']};font-size:11px;line-height:1.5;margin-top:4px;">
                    • Draft rule<br>• Explain impact<br>• Human gate
                </div>
                <div style="margin-top:8px;padding:3px 6px;border-radius:6px;background:{a3_badge_bg};color:{a3_col};font-size:10px;font-weight:800;display:inline-block;">
                    {a3_status}
                </div>
            </div>
        </div>
    </div>
    """)

render_html("<div style='margin-bottom:18px;'></div>")

# ------------------------------------------------------------
# BOTTOM ROW: RECOMMENDATION + TIMELINE AUDIT
# ------------------------------------------------------------

rec_col, audit_col = st.columns([1.15, 1.0], gap="medium")

with rec_col:
    render_html(f"""
    <div class="tg-card">
        <div class="tg-section-header">
            <div>
                <div class="tg-section-title">Explainable AI Recommendation</div>
                <div class="tg-section-sub">Deterministic containment policy for SOC administrator</div>
            </div>
            <div style="padding:3px 8px;border-radius:6px;background:{C['blue_bg']};color:{C['blue']};font-size:11px;font-weight:800;border:1px solid {C['blue_border']};">
                Confidence: {threat['confidence']}
            </div>
        </div>

        <div style="padding:16px;border-radius:12px;background:{C['panel2']};border:1px solid {C['blue_border']};margin-bottom:14px;">
            <div style="color:{C['blue']};font-size:11px;font-weight:800;letter-spacing:0.07em;text-transform:uppercase;">Proposed Action</div>
            <div style="color:{C['text']};font-size:18px;font-weight:900;margin-top:4px;letter-spacing:-0.02em;">{threat['action']}</div>
            <div style="color:{C['muted']};font-size:13px;line-height:1.5;margin-top:8px;">
                <b style="color:{C['text']};">SOC Rationale:</b> {threat['reason']}
            </div>

            <div style="display:flex;flex-wrap:wrap;gap:8px;margin-top:12px;">
                {''.join(f'<span style="padding:4px 9px;border-radius:6px;background:{C["panel"]};border:1px solid {C["border"]};color:{C["text"]};font-size:11px;font-weight:700;">✓ {p}</span>' for p in threat['pills'])}
            </div>
        </div>

        <!-- Affected Assets Grid -->
        <div style="font-size:12px;font-weight:800;color:{C['muted']};letter-spacing:0.06em;text-transform:uppercase;margin-bottom:8px;">
            Blast Radius Scope ({threat['blast']} Assets)
        </div>
        <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:8px;">
            <div style="padding:10px;border-radius:10px;background:{C['red_bg']};border:1px solid {C['red_border']};">
                <div style="font-size:16px;">🖥️</div>
                <div style="color:{C['text']};font-size:12px;font-weight:800;margin-top:2px;">{threat['source']}</div>
                <div style="color:{C['red']};font-size:10px;font-weight:800;">SOURCE NODE</div>
            </div>
            {''.join(f"""
            <div style="padding:10px;border-radius:10px;background:{C['panel2']};border:1px solid {C['border']};">
                <div style="font-size:16px;">⚙️</div>
                <div style="color:{C['text']};font-size:12px;font-weight:800;margin-top:2px;">{n}</div>
                <div style="color:{C['orange']};font-size:10px;font-weight:800;">POTENTIAL IMPACT</div>
            </div>
            """ for n in threat['affected'] if n != threat['source'])}
        </div>
    </div>
    """)

with audit_col:
    # Audit log timeline items
    events = [
        ("T+00s", C["red"], "Anomaly Triggered", f"{threat['attack_type']} telemetry ingested from {threat['source']}"),
        ("T+14s", C["blue"], "GNN Triage Scored", f"Severity classified as {threat['severity']} (Risk: {threat['risk']:.2f})"),
        ("T+28s", C["orange"], "Blast Radius Computed", f"{threat['blast']} connected nodes flagged in propagation path"),
        ("T+42s", C["blue"], "Action Synthesized", threat["action"]),
    ]

    if current_approval == "APPROVED":
        events.append(("T+58s", C["green"], "Admin Approval Received", "Automated firewall rule applied & isolation active"))
    elif current_approval == "REJECTED":
        events.append(("T+58s", C["orange"], "Admin Override Received", "Containment rejected — manual investigation active"))
    else:
        events.append(("T+45s", C["faint"], "Human-in-the-Loop Gate", "Awaiting SOC administrator decision"))

    events_html = []
    for tm, col, title, desc in events:
        events_html.append(f"""
        <div class="timeline-item">
            <div style="font-size:11px;font-family:monospace;font-weight:800;color:{C['faint']};min-width:44px;padding-top:2px;">{tm}</div>
            <div style="width:10px;height:10px;border-radius:50%;background:{col};margin-top:4px;flex-shrink:0;box-shadow:0 0 6px {col};"></div>
            <div style="flex:1;">
                <div style="color:{C['text']};font-size:13px;font-weight:800;">{title}</div>
                <div style="color:{C['muted']};font-size:12px;margin-top:1px;">{desc}</div>
            </div>
        </div>
        """)

    render_html(f"""
    <div class="tg-card">
        <div class="tg-section-header">
            <div>
                <div class="tg-section-title">Incident Audit & Response Log</div>
                <div class="tg-section-sub">Immutable telemetry and agent decision timestamps</div>
            </div>
            <div style="font-size:11px;color:{C['muted']};">{len(events)} Recorded Events</div>
        </div>

        <div style="padding:4px 0;">
            {''.join(events_html)}
        </div>
    </div>
    """)

render_html("<div style='margin-bottom:18px;'></div>")

# ------------------------------------------------------------
# ADMINISTRATOR DECISION PANEL (INTERACTIVE ACTIONS)
# ------------------------------------------------------------

render_html(f"""
<div class="tg-card" style="border:1.5px solid {C['blue_border'] if current_approval == 'PENDING' else (C['green_border'] if current_approval == 'APPROVED' else C['orange_border'])};">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;">
        <div style="display:flex;align-items:center;gap:12px;">
            <div style="width:36px;height:36px;border-radius:10px;background:{C['blue_bg']};display:flex;align-items:center;justify-content:center;font-size:18px;">
                ⚙️
            </div>
            <div>
                <div style="color:{C['text']};font-size:15px;font-weight:800;">SOC Administrator Decision Console</div>
                <div style="color:{C['muted']};font-size:12px;">Zero-Trust policy requires explicit human sign-off before enforcing automated network isolation.</div>
            </div>
        </div>
        <div>
            <span style="padding:5px 12px;border-radius:8px;font-size:12px;font-weight:800;background:{C['panel2']};color:{resp_color};border:1px solid {C['border']};">
                STATUS: {resp_state.upper()}
            </span>
        </div>
    </div>
</div>
""")

act_col1, act_col2 = st.columns(2, gap="medium")

with act_col1:
    if current_approval != "APPROVED":
        if st.button("🛡️  APPROVE CONTAINMENT ACTION", use_container_width=True, type="primary"):
            st.session_state.approval_states[selected_name] = "APPROVED"
            st.toast(f"Containment Action Approved for {selected_name}!", icon="🛡️")
            st.rerun()
    else:
        st.success(f"Containment protocol ACTIVE for {threat['source']}. Firewall rules enforced.")

with act_col2:
    if current_approval == "PENDING":
        if st.button("✕  REJECT / MANUAL OVERRIDE", use_container_width=True):
            st.session_state.approval_states[selected_name] = "REJECTED"
            st.toast("Containment Action Overridden by Administrator.", icon="⚠️")
            st.rerun()
    else:
        if st.button("↺  RESET SCENARIO STATE", use_container_width=True):
            st.session_state.approval_states[selected_name] = "PENDING"
            st.toast("Scenario state reset to Pending.", icon="🔄")
            st.rerun()

# Footer
render_html(f"""
<div style="text-align:center;color:{C['faint']};font-size:11px;margin-top:28px;padding-top:14px;border-top:1px solid {C['border']};">
    Graph Aware Predictive Threat Containment System • Powered by Graph Neural Networks (GNN) & Multi-Agent Reasoning Pipeline
</div>
""")
