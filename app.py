import json
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

import crypto_agility
import engine

st.set_page_config(page_title="SENTINEL-Q", layout="wide", page_icon="🛡️")

SEVERITY_COLORS = {
    "CRITICAL": "#ff4b4b",
    "HIGH": "#ff9f40",
    "MEDIUM": "#f4d35e",
    "LOW": "#9aa5b1",
}
TIMELINE_COLORS = {"cyber": "#4cc9f0", "txn": "#f72585"}

TIER_ORDER = [crypto_agility.PQC_READY, crypto_agility.QUANTUM_VULNERABLE, crypto_agility.CRITICAL]
TIER_RANK = {tier: i for i, tier in enumerate(TIER_ORDER)}
TIER_COLORS = {
    crypto_agility.PQC_READY: "#2dd4a7",
    crypto_agility.QUANTUM_VULNERABLE: SEVERITY_COLORS["HIGH"],
    crypto_agility.CRITICAL: SEVERITY_COLORS["CRITICAL"],
}

HNDL_DISCLAIMER = (
    "SENTINEL-Q does not detect quantum computers. It detects data being "
    "harvested today under quantum-vulnerable encryption — exposed on a "
    "5-10 year horizon."
)

DARK_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap');

* { font-family: 'Inter', sans-serif; }

.stApp { background-color: #F0F7F4; color: #0A1628; }

[data-testid="stSidebar"] { background-color: #1A5C42 !important; border-right: 2px solid #00A99D; }
[data-testid="stSidebar"] * { color: #FFFFFF !important; }
[data-testid="stSidebar"] .stButton button { background-color: #00A99D !important; color: #FFFFFF !important; font-weight: 700; border-radius: 8px; border: none; width: 100%; }
[data-testid="stSidebar"] .stButton button:hover { background-color: #007A72 !important; }

div[data-testid="stMetric"] {
    background-color: #0A2E22;
    border: 1px solid #00A99D;
    border-radius: 10px;
    padding: 16px 20px;
    box-shadow: 0 2px 8px rgba(0,169,157,0.3);
}
div[data-testid="stMetric"] label { color: #A8D5C8 !important; font-weight: 600; font-size: 0.85em; }
div[data-testid="stMetric"] div { color: #FFFFFF !important; font-weight: 700; }

.severity-badge {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 4px;
    font-weight: 700;
    font-size: 0.8em;
    color: #FFFFFF;
}

h1, h2, h3, h4 { color: #0A4A3A !important; }
.stDataFrame { border: 1px solid #CBD5E0; border-radius: 8px; background-color: #FFFFFF; }
.stSelectbox label { color: #0A4A3A; font-weight: 600; }
</style>
"""


@st.cache_data
def load_alerts(mtime):
    path = Path(__file__).parent / "data" / "alerts.json"
    if not path.exists():
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


@st.cache_data
def load_cyber_events(mtime):
    path = Path(__file__).parent / "data" / "cyber_events.csv"
    if not path.exists():
        return None
    return pd.read_csv(path)


def compute_actor_tiers(cyber_df):
    """Worst crypto_agility tier per actor (customer_id, incl. internal
    sys_ actors) seen anywhere in cyber_events.csv, plus their total
    bytes_out (used to rank migration priority)."""
    rows = []
    for actor_id, group in cyber_df.groupby("customer_id"):
        tiers = [crypto_agility.classify(ke)["tier"] for ke in group["key_exchange"]]
        worst_tier = max(tiers, key=lambda t: TIER_RANK[t])
        display_id = engine.pseudonymize_customer_id(actor_id) if actor_id.startswith("cust_") else actor_id
        rows.append({
            "actor_id": display_id,
            "tier": worst_tier,
            "total_bytes_out": int(group["bytes_out"].sum()),
        })
    return pd.DataFrame(rows)


def severity_badge(sev):
    color = SEVERITY_COLORS.get(sev, "#9aa5b1")
    return f'<span class="severity-badge" style="background-color:{color}">{sev}</span>'


def render_timeline(events):
    fig = go.Figure()
    for etype in ("cyber", "txn"):
        typed = [e for e in events if e["type"] == etype]
        if not typed:
            continue
        fig.add_trace(go.Scatter(
            x=[e["ts"] for e in typed],
            y=[etype] * len(typed),
            mode="markers",
            marker=dict(size=18, color=TIMELINE_COLORS[etype], line=dict(width=2, color="#FFFFFF")),
            name="Cyber event" if etype == "cyber" else "Transaction",
            hovertemplate="<b>%{customdata}</b><br>%{x}<extra></extra>",
            customdata=[e["label"] for e in typed],
        ))
    fig.update_layout(
       template="plotly_white",
        paper_bgcolor="#F0F7F4",
        plot_bgcolor="#F0F7F4",
        height=280,
        showlegend=True,
        yaxis=dict(title="", categoryorder="array", categoryarray=["txn", "cyber"]),
        xaxis=dict(title="Time"),
        margin=dict(l=40, r=20, t=20, b=40),
    )
    return fig


def render_detail(alert):
    st.markdown(f"### {alert['alert_id']} — {severity_badge(alert['severity'])}", unsafe_allow_html=True)
    st.markdown(
        f"**Customer:** `{alert['customer_id']}`  |  **Risk score:** {alert['risk_score']}  |  "
        f"**Quantum tier:** {alert['quantum_exposure']['tier']}"
        + (" ⚛️ **HNDL FLAGGED**" if alert["quantum_exposure"]["hndl_flag"] else "")
    )

    st.markdown("#### Explanation")
    st.markdown(
        f"<div style='font-size:1.15em; line-height:1.5; background-color:#F0F4F8; "
        f"border-left:4px solid {SEVERITY_COLORS.get(alert['severity'],'#9aa5b1')}; "
        f"padding:14px 18px; border-radius:6px;'>{alert['explanation']}</div>",
        unsafe_allow_html=True,
    )

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("#### Triggered rules")
        for r in alert["triggered_rules"]:
            st.markdown(f"- **{r['rule_id']}** {r['name']} {severity_badge(r['severity'])}", unsafe_allow_html=True)

    with col2:
        st.markdown("#### Recommended action")
        st.info(alert["recommended_action"])

    st.markdown("#### Contributing features")
    feat_df = pd.DataFrame(alert["contributing_features"])
    if not feat_df.empty:
        fig = go.Figure(go.Bar(
            x=feat_df["value"],
            y=feat_df["label"],
            orientation="h",
            marker=dict(color="#00A99D"),
        ))
        fig.update_layout(
            template="plotly_white",
            paper_bgcolor="#F0F7F4",
            plot_bgcolor="#F0F7F4",
            height=max(120, 60 * len(feat_df)),
            margin=dict(l=10, r=10, t=10, b=10),
            yaxis=dict(autorange="reversed", tickfont=dict(color="#0A1628", size=12)),
xaxis=dict(tickfont=dict(color="#0A1628")),
font=dict(color="#0A1628"),
        )
        st.plotly_chart(fig, use_container_width=True)

    st.markdown("#### Event timeline")
    st.plotly_chart(render_timeline(alert["timeline"]), use_container_width=True)


def render_quantum_tab(cyber_df, alerts):
    actor_tiers = compute_actor_tiers(cyber_df)
    tier_counts = actor_tiers["tier"].value_counts().reindex(TIER_ORDER, fill_value=0)

    st.markdown("#### Crypto posture across monitored systems")
    c1, c2, c3 = st.columns(3)
    c1.metric("PQC-Ready", int(tier_counts[crypto_agility.PQC_READY]))
    c2.metric("Quantum-Vulnerable", int(tier_counts[crypto_agility.QUANTUM_VULNERABLE]))
    c3.metric("Critical", int(tier_counts[crypto_agility.CRITICAL]))

    fig = go.Figure(go.Bar(
        x=TIER_ORDER,
        y=[int(tier_counts[t]) for t in TIER_ORDER],
        marker=dict(color=[TIER_COLORS[t] for t in TIER_ORDER]),
        text=[int(tier_counts[t]) for t in TIER_ORDER],
        textposition="outside",
    ))
    fig.update_layout(
        template="plotly_white",
        paper_bgcolor="#F0F7F4",
        plot_bgcolor="#F0F7F4",
        height=320,
        showlegend=False,
        xaxis=dict(title=""),
        yaxis=dict(title="Systems"),
        margin=dict(l=20, r=20, t=20, b=20),
    )
    st.plotly_chart(fig, use_container_width=True)

    st.markdown("#### HNDL alerts — harvest now, decrypt later")
    st.warning(HNDL_DISCLAIMER)
    hndl_alerts = [a for a in alerts if a["quantum_exposure"]["hndl_flag"]]
    if not hndl_alerts:
        st.info("No HNDL-flagged alerts in data/alerts.json.")
    else:
        for a in hndl_alerts:
            with st.expander(f"⚛️ {a['alert_id']} — {a['customer_id']} — {a['quantum_exposure']['tier']}"):
                render_detail(a)

    st.markdown("#### Migration priority — top 10")
    ranked = actor_tiers.copy()
    ranked["tier_rank"] = ranked["tier"].map(TIER_RANK)
    ranked = ranked.sort_values(["tier_rank", "total_bytes_out"], ascending=[False, False]).head(10)
    display_df = ranked[["actor_id", "tier", "total_bytes_out"]].rename(columns={
        "actor_id": "System",
        "tier": "Quantum tier",
        "total_bytes_out": "Total bytes out",
    })
    st.dataframe(display_df, use_container_width=True, hide_index=True)


def main():
    st.markdown(DARK_CSS, unsafe_allow_html=True)
    st.markdown("""
<div style='background-color:#0A4A3A; padding:18px 24px; border-radius:10px; margin-bottom:20px;'>
<span style='color:#FFFFFF; font-size:1.6em; font-weight:700;'>🛡️ SENTINEL-Q</span>
<span style='color:#A8D5C8; font-size:1em; margin-left:16px;'>Correlated Threat & Quantum Risk Intelligence</span>
<span style='color:#A8D5C8; font-size:0.85em; float:right; margin-top:6px;'>🔬 Demo · Synthetic Data</span>
</div>
""", unsafe_allow_html=True)

    alerts_path = Path(__file__).parent / "data" / "alerts.json"
    mtime = alerts_path.stat().st_mtime if alerts_path.exists() else None
    data = load_alerts(mtime)
    if data is None:
        st.warning("Run mock_alerts.py or engine.py to generate alerts.")
        return

    alerts = data.get("alerts", [])
    kpis = data.get("kpis", {})

    cyber_path = Path(__file__).parent / "data" / "cyber_events.csv"
    cyber_mtime = cyber_path.stat().st_mtime if cyber_path.exists() else None
    cyber_df = load_cyber_events(cyber_mtime) if cyber_mtime else None

    k1, k2, k3, k4 = st.columns(4)
    k1.metric("⚡ Events Analyzed", f"{kpis.get('events_analyzed', 0):,}")
    k2.metric("🚨 Active Alerts", kpis.get("active_alerts", len(alerts)))
    k3.metric("✅ False Positives Suppressed", kpis.get("fp_suppressed", 0))
    k4.metric("⚛️ Quantum-Exposed Systems", kpis.get("quantum_exposed_systems", 0))

    st.sidebar.header("Filters")
    severity_options = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

    st.sidebar.markdown("---")
    st.sidebar.subheader("Scenario replay")
    if st.sidebar.button("Load account-takeover scenario"):
        s1_alert = next(
            (a for a in alerts if any(r["rule_id"] == "R4" for r in a["triggered_rules"])),
            None,
        )
        if s1_alert is not None:
            st.session_state["view"] = "Alert Queue"
            st.session_state["severity_filter"] = severity_options
            st.session_state["alert_select"] = s1_alert["alert_id"]
            st.sidebar.success(f"Loaded {s1_alert['alert_id']} in the Alert Queue view below.")
        else:
            st.sidebar.error("S1 scenario alert not found in data/alerts.json.")

    if "severity_filter" not in st.session_state:
        st.session_state["severity_filter"] = severity_options
    selected_severities = st.sidebar.multiselect(
        "Severity", severity_options, key="severity_filter"
    )

    with st.sidebar.expander("About SENTINEL-Q"):
        st.write(
            "SENTINEL-Q correlates bank cyber telemetry with transaction data to "
            "surface a single explainable risk score per alert, and flags accounts "
            "whose crypto posture leaves them exposed to future quantum decryption "
            "risk (\"harvest now, decrypt later\")."
        )

    if "view" not in st.session_state:
        st.session_state["view"] = "Alert Queue"
    view = st.segmented_control(
        "View", ["Alert Queue", "Quantum Risk Monitor"], key="view"
    )

    if view == "Quantum Risk Monitor":
        st.markdown("### Quantum Risk Monitor")
        if cyber_df is None:
            st.info("Run generate_data.py to produce data/cyber_events.csv.")
        else:
            render_quantum_tab(cyber_df, alerts)
        return

    if not alerts:
        st.info("No alerts in data/alerts.json.")
        return

    filtered = [a for a in alerts if a["severity"] in selected_severities]
    filtered.sort(key=lambda a: a["risk_score"], reverse=True)

    if not filtered:
        st.info("No alerts match the selected severity filter.")
        return

    st.markdown("### Alert queue")

    table_rows = []
    for a in filtered:
        table_rows.append({
            "Alert ID": a["alert_id"],
            "Severity": a["severity"],
            "Risk score": a["risk_score"],
            "Customer": a["customer_id"],
            "Quantum tier": a["quantum_exposure"]["tier"],
            "HNDL": "⚛️" if a["quantum_exposure"]["hndl_flag"] else "",
            "Explanation": a["explanation"][:90] + ("…" if len(a["explanation"]) > 90 else ""),
        })
    df = pd.DataFrame(table_rows)

    def highlight_severity(row):
        color = SEVERITY_COLORS.get(row["Severity"], "#9aa5b1")
        return [f"background-color: {color}; color: #0e1117; font-weight: 700;" if col == "Severity" else "" for col in row.index]

    st.dataframe(
        df.style.apply(highlight_severity, axis=1),
        use_container_width=True,
        hide_index=True,
        height=min(38 * (len(df) + 1), 560),
    )

    st.markdown("### Alert detail")
    alert_ids = [a["alert_id"] for a in filtered]
    if st.session_state.get("alert_select") not in alert_ids:
        st.session_state.pop("alert_select", None)
    selected_id = st.selectbox("Select an alert to inspect", alert_ids, key="alert_select")
    selected_alert = next(a for a in filtered if a["alert_id"] == selected_id)
    render_detail(selected_alert)


if __name__ == "__main__":
    main()
