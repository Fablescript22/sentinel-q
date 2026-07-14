import json
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

st.set_page_config(page_title="SENTINEL-Q", layout="wide", page_icon="🛡️")

SEVERITY_COLORS = {
    "CRITICAL": "#ff4b4b",
    "HIGH": "#ff9f40",
    "MEDIUM": "#f4d35e",
    "LOW": "#9aa5b1",
}
TIMELINE_COLORS = {"cyber": "#4cc9f0", "txn": "#f72585"}

DARK_CSS = """
<style>
.stApp { background-color: #0e1117; color: #e6e6e6; }
[data-testid="stSidebar"] { background-color: #131722; }
div[data-testid="stMetric"] {
    background-color: #171b26;
    border: 1px solid #262b3a;
    border-radius: 8px;
    padding: 12px 16px;
}
.severity-badge {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 4px;
    font-weight: 700;
    font-size: 0.8em;
    color: #0e1117;
}
</style>
"""


@st.cache_data
def load_alerts(mtime):
    path = Path(__file__).parent / "data" / "alerts.json"
    if not path.exists():
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


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
            mode="markers+text",
            marker=dict(size=16, color=TIMELINE_COLORS[etype], line=dict(width=1, color="#0e1117")),
            text=[e["label"] for e in typed],
            textposition="top center",
            name="Cyber event" if etype == "cyber" else "Transaction",
            hovertemplate="%{text}<br>%{x}<extra></extra>",
        ))
    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="#0e1117",
        plot_bgcolor="#0e1117",
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
        f"<div style='font-size:1.15em; line-height:1.5; background-color:#171b26; "
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
            marker=dict(color="#4cc9f0"),
        ))
        fig.update_layout(
            template="plotly_dark",
            paper_bgcolor="#0e1117",
            plot_bgcolor="#0e1117",
            height=max(120, 60 * len(feat_df)),
            margin=dict(l=10, r=10, t=10, b=10),
            yaxis=dict(autorange="reversed"),
        )
        st.plotly_chart(fig, use_container_width=True)

    st.markdown("#### Event timeline")
    st.plotly_chart(render_timeline(alert["timeline"]), use_container_width=True)


def main():
    st.markdown(DARK_CSS, unsafe_allow_html=True)
    st.title("🛡️ SENTINEL-Q — Correlated Threat & Quantum Risk Intelligence")

    alerts_path = Path(__file__).parent / "data" / "alerts.json"
    mtime = alerts_path.stat().st_mtime if alerts_path.exists() else None
    data = load_alerts(mtime)
    if data is None:
        st.warning("Run mock_alerts.py or engine.py to generate alerts.")
        return

    alerts = data.get("alerts", [])
    kpis = data.get("kpis", {})

    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Events analyzed", f"{kpis.get('events_analyzed', 0):,}")
    k2.metric("Active alerts", kpis.get("active_alerts", len(alerts)))
    k3.metric("False positives suppressed", kpis.get("fp_suppressed", 0))
    k4.metric("Quantum-exposed systems", kpis.get("quantum_exposed_systems", 0))

    st.sidebar.header("Filters")
    severity_options = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    selected_severities = st.sidebar.multiselect(
        "Severity", severity_options, default=severity_options
    )

    with st.sidebar.expander("About SENTINEL-Q"):
        st.write(
            "SENTINEL-Q correlates bank cyber telemetry with transaction data to "
            "surface a single explainable risk score per alert, and flags accounts "
            "whose crypto posture leaves them exposed to future quantum decryption "
            "risk (\"harvest now, decrypt later\")."
        )

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
    selected_id = st.selectbox("Select an alert to inspect", alert_ids)
    selected_alert = next(a for a in filtered if a["alert_id"] == selected_id)
    render_detail(selected_alert)


if __name__ == "__main__":
    main()
