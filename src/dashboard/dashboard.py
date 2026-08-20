import streamlit as st

st.set_page_config(
    page_title="Predictive Threat Containment",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# =========================================================
# CSS - LIGHT THEME
# =========================================================

st.html("""
<style>

.stApp {
    background: #f4f7fb;
    color: #172033;
}

.block-container {
    padding-top: 2rem;
    padding-bottom: 2rem;
    max-width: 1450px;
}

/* SIDEBAR */

[data-testid="stSidebar"] {
    background: #ffffff;
    border-right: 1px solid #dbe3ee;
}

/* HERO */

.hero {
    padding: 25px 28px;
    border: 1px solid #dbe3ee;
    border-radius: 16px;
    background: linear-gradient(135deg, #ffffff, #f8fafc);
    margin-bottom: 22px;
    box-shadow: 0 4px 15px rgba(15, 23, 42, 0.05);
}

.hero-title {
    font-size: 30px;
    font-weight: 750;
    color: #172033;
}

.hero-subtitle {
    color: #64748b;
    font-size: 14px;
    margin-top: 6px;
}

.live {
    float: right;
    color: #15803d;
    font-weight: 700;
    font-size: 13px;
}

/* METRICS */

.metric-card {
    padding: 20px;
    border: 1px solid #dbe3ee;
    border-radius: 14px;
    background: #ffffff;
    min-height: 105px;
    box-shadow: 0 3px 12px rgba(15, 23, 42, 0.04);
}

.metric-label {
    color: #64748b;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.08em;
}

.metric-value {
    color: #172033;
    font-size: 25px;
    font-weight: 750;
    margin-top: 9px;
}

/* SECTION */

.section-title {
    color: #172033;
    font-size: 17px;
    font-weight: 700;
    margin: 24px 0 11px 0;
}

/* PANEL */

.panel {
    padding: 20px;
    border: 1px solid #dbe3ee;
    border-radius: 14px;
    background: #ffffff;
    min-height: 300px;
    box-shadow: 0 3px 12px rgba(15, 23, 42, 0.04);
}

/* TOPOLOGY */

.topology {
    font-family: Consolas, monospace;
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-radius: 11px;
    padding: 18px;
    color: #334155;
    line-height: 1.9;
    min-height: 220px;
}

.node-green {
    color: #15803d;
    font-weight: 700;
}

.node-red {
    color: #dc2626;
    font-weight: 700;
}

.node-orange {
    color: #ea580c;
    font-weight: 700;
}

/* THREAT */

.alert-box {
    padding: 15px;
    border: 1px solid #fecaca;
    border-radius: 11px;
    background: #fff1f2;
    margin-bottom: 15px;
}

.alert-title {
    color: #b91c1c;
    font-weight: 750;
    font-size: 17px;
}

.muted {
    color: #64748b;
    font-size: 13px;
    margin-top: 4px;
}

/* RECOMMENDATION */

.recommendation {
    padding: 17px;
    border: 1px solid #dbe3ee;
    border-radius: 11px;
    background: #f8fafc;
}

.recommendation-title {
    color: #172033;
    font-size: 19px;
    font-weight: 750;
}

.reason {
    color: #334155;
    line-height: 1.55;
    margin-top: 10px;
}

/* ASSETS */

.asset {
    display: inline-block;
    padding: 9px 13px;
    margin: 4px 6px 4px 0;
    border-radius: 9px;
    background: #f1f5f9;
    border: 1px solid #cbd5e1;
    color: #334155;
    font-size: 13px;
}

.asset-danger {
    border-color: #fecaca;
    background: #fff1f2;
    color: #b91c1c;
}

/* FOOTER */

.footer {
    text-align: center;
    color: #64748b;
    font-size: 12px;
    padding-top: 28px;
}

</style>
""")


# =========================================================
# MOCK DATA
# =========================================================

threat = {
    "attack_type": "Web Attack",
    "source_node": "Web_Server",
    "risk_score": 0.91,
    "severity": "HIGH",
    "blast_radius": 3,
    "affected_nodes": [
        "App_Server",
        "Database",
        "Finance_PC"
    ],
    "recommended_action": "Isolate Web Server",
    "reason": (
        "The Web Server has a high predicted risk score "
        "and a blast radius of 3 connected nodes."
    ),
    "confidence": "HIGH"
}


# =========================================================
# SIDEBAR
# =========================================================

with st.sidebar:

    st.html("""
    <div style="
        font-size:22px;
        font-weight:750;
        color:#172033;
        margin-bottom:5px;
    ">
        🛡️ Threat Console
    </div>

    <div style="
        color:#64748b;
        font-size:13px;
        margin-bottom:20px;
    ">
        Graph-Aware Cyber Defense
    </div>
    """)

    st.divider()

    st.markdown("### System Status")

    st.success("System Online")
    st.info("Agent Pipeline Ready")

    st.markdown("### Current Model")
    st.write("GNN + Agentic AI")

    st.markdown("### Environment")
    st.write("Local / Simulation")

    st.divider()

    st.caption("Review 2 Prototype")


# =========================================================
# HEADER
# =========================================================

st.html("""
<div class="hero">

    <div class="live">
        ● SYSTEM ONLINE
    </div>

    <div class="hero-title">
        🛡️ Predictive Network Threat Containment
    </div>

    <div class="hero-subtitle">
        Graph-Aware Cyber Defense using Agentic AI
    </div>

</div>
""")


# =========================================================
# METRICS
# =========================================================

c1, c2, c3, c4 = st.columns(4)

with c1:
    st.html(f"""
    <div class="metric-card">
        <div class="metric-label">Severity</div>
        <div class="metric-value">{threat["severity"]}</div>
    </div>
    """)

with c2:
    st.html(f"""
    <div class="metric-card">
        <div class="metric-label">Risk Score</div>
        <div class="metric-value">{threat["risk_score"]:.2f}</div>
    </div>
    """)

with c3:
    st.html(f"""
    <div class="metric-card">
        <div class="metric-label">Blast Radius</div>
        <div class="metric-value">{threat["blast_radius"]} nodes</div>
    </div>
    """)

with c4:
    st.html(f"""
    <div class="metric-card">
        <div class="metric-label">Attack Type</div>
        <div class="metric-value">{threat["attack_type"]}</div>
    </div>
    """)


# =========================================================
# MAIN PANELS
# =========================================================

left, right = st.columns([1.15, 0.85], gap="large")


# =========================================================
# NETWORK TOPOLOGY
# =========================================================

with left:

    st.html("""
    <div class="section-title">
        🌐 Network Topology
    </div>

    <div class="panel">

        <div class="topology">

            <span class="node-green">
                Internet
            </span>

            <br>
            &nbsp;&nbsp;&nbsp;│
            <br>
            &nbsp;&nbsp;&nbsp;▼
            <br>

            <span class="node-green">
                Firewall
            </span>

            <br>
            &nbsp;&nbsp;&nbsp;│
            <br>
            &nbsp;&nbsp;&nbsp;▼
            <br>

            <span class="node-red">
                🔴 Web_Server [COMPROMISED]
            </span>

            <br>

            &nbsp;&nbsp;&nbsp;├──────────────┐

            <br>

            &nbsp;&nbsp;&nbsp;▼
            &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
            ▼

            <br>

            <span class="node-orange">
                🟠 App_Server
            </span>

            &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;

            <span class="node-orange">
                🟠 Database
            </span>

            <br>

            &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
            │

            <br>

            &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
            ▼

            <br>

            <span class="node-orange">
                🟠 Finance_PC
            </span>

        </div>

    </div>
    """)


# =========================================================
# AGENT RECOMMENDATION
# =========================================================

with right:

    st.html(f"""
    <div class="section-title">
        🤖 Agent Recommendation
    </div>

    <div class="panel">

        <div class="alert-box">

            <div class="alert-title">
                ⚠ HIGH-SEVERITY THREAT
            </div>

            <div class="muted">
                {threat["source_node"]}
                •
                {threat["attack_type"]}
            </div>

        </div>

        <div class="recommendation">

            <div class="recommendation-title">
                {threat["recommended_action"]}
            </div>

            <div class="reason">
                <b>Reason:</b>
                {threat["reason"]}
            </div>

            <div class="muted">
                Confidence:
                <b>{threat["confidence"]}</b>
            </div>

        </div>

    </div>
    """)


# =========================================================
# AFFECTED ASSETS
# =========================================================

st.html("""
<div class="section-title">
    🎯 Affected Assets
</div>
""")

asset_html = f"""
<span class="asset asset-danger">
    🔴 {threat["source_node"]} — COMPROMISED
</span>
"""

for node in threat["affected_nodes"]:
    asset_html += f"""
    <span class="asset">
        🟠 {node}
    </span>
    """

st.html(asset_html)


# =========================================================
# ADMIN DECISION
# =========================================================

st.html("""
<div class="section-title">
    ⚙ Administrator Decision
</div>
""")

b1, b2 = st.columns(2)

with b1:

    if st.button(
        "✅ APPROVE RECOMMENDATION",
        use_container_width=True,
        type="primary"
    ):
        st.success(
            "Recommendation approved by administrator."
        )

with b2:

    if st.button(
        "❌ REJECT RECOMMENDATION",
        use_container_width=True
    ):
        st.warning(
            "Recommendation rejected by administrator."
        )


# =========================================================
# FOOTER
# =========================================================

st.html("""
<div class="footer">
    Graph-Aware Predictive Threat Containment
    •
    Review 2 Prototype
    •
    GNN + Agentic AI
</div>
""")