import json
import pandas as pd
import streamlit as st
from pathlib import Path

from database import init_db, save_alerts, fetch_alerts, clear_alerts
from log_analyzer import load_sample_logs, parse_uploaded_file, normalize_events, summarize_events
from detection_engine import run_detections
from alert_triage import triage_alerts
from ai_copilot import explain_alert
from reporting import build_incident_report, alerts_to_csv

st.set_page_config(page_title="SentinelAI | SOC Copilot", page_icon="🛡️", layout="wide")
st.markdown("""
<style>
.stApp {background: radial-gradient(circle at 15% 0%, #14243a 0, #0b1220 42%, #080d17 100%); color:#e7eef8;}
[data-testid="stSidebar"] {background:#0b1524; border-right:1px solid #20344d;}
[data-testid="stMetric"] {background:#111f31; border:1px solid #243a55; padding:14px; border-radius:12px;}
div[data-testid="stDataFrame"] {border:1px solid #243a55; border-radius:10px;}
.stTabs [data-baseweb="tab"] {color:#c9d7e8;}
div.stButton > button {background:#176b87; color:white; border:0; border-radius:8px;}
.small-muted {color:#91a6bd;font-size:0.88rem}
</style>
""", unsafe_allow_html=True)

init_db()
st.title("🛡️ SentinelAI — AI-Powered SOC Copilot")
st.caption("Rule-based security detection • Alert triage • MITRE ATT&CK context • Optional AI explanations")
st.warning("Training/demo application. Sample events are synthetic. Validate detections before using any workflow in a real SOC.", icon="⚠️")

with st.sidebar:
    st.header("Control Center")
    if st.button("Load / reset demo dataset", use_container_width=True):
        clear_alerts()
        events = load_sample_logs()
        alerts = triage_alerts(run_detections(events))
        save_alerts(alerts)
        st.session_state["events"] = events
        st.success(f"Loaded {len(events)} synthetic events and generated {len(alerts)} alerts.")
    st.markdown("---")
    st.markdown("**Data source**")
    uploaded = st.file_uploader("Upload CSV or JSONL security events", type=["csv", "jsonl", "ndjson"])
    if uploaded is not None and st.button("Analyze uploaded events", use_container_width=True):
        try:
            events = parse_uploaded_file(uploaded)
            alerts = triage_alerts(run_detections(events))
            save_alerts(alerts)
            st.session_state["events"] = events
            st.success(f"Analyzed {len(events)} events; generated {len(alerts)} alerts.")
        except Exception as exc:
            st.error(f"Could not analyze file: {exc}")
    st.markdown("---")
    st.markdown('<p class="small-muted">Expected fields: timestamp, host, username, source_ip, event_type, process, command_line, status, message</p>', unsafe_allow_html=True)

events = st.session_state.get("events")
if events is None:
    events = load_sample_logs()
    st.session_state["events"] = events
    if not fetch_alerts():
        save_alerts(triage_alerts(run_detections(events)))

alerts = fetch_alerts()
df_events = pd.DataFrame(events)
df_alerts = pd.DataFrame(alerts)

tab_overview, tab_events, tab_alerts, tab_copilot, tab_reports = st.tabs(
    ["◈ Overview", "⌁ Event Explorer", "⚑ Alert Triage", "✧ AI Copilot", "▤ Reports"]
)

with tab_overview:
    st.subheader("Security Operations Overview")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Events analyzed", len(events))
    c2.metric("Alerts generated", len(alerts))
    c3.metric("High / Critical", sum(1 for a in alerts if a["severity"] in ("High", "Critical")))
    c4.metric("Hosts observed", df_events["host"].nunique() if "host" in df_events else 0)
    left, right = st.columns([1.2, 1])
    with left:
        st.markdown("#### Alert severity distribution")
        if not df_alerts.empty:
            sev = df_alerts.groupby("severity").size().reindex(["Critical","High","Medium","Low"], fill_value=0)
            st.bar_chart(sev)
        else:
            st.info("No alerts yet. Load the demo dataset or upload events.")
    with right:
        st.markdown("#### Detection categories")
        if not df_alerts.empty:
            cats = df_alerts.groupby("rule_name").size().sort_values(ascending=False)
            st.bar_chart(cats)
        else:
            st.info("No detection categories available.")
    st.markdown("#### Analyst priorities")
    st.markdown("- Validate critical/high alerts first.")
    st.markdown("- Review correlated authentication failures and successful logins.")
    st.markdown("- Preserve original logs and document investigation decisions.")

with tab_events:
    st.subheader("Event Explorer")
    if not df_events.empty:
        event_types = sorted(df_events["event_type"].fillna("unknown").unique().tolist())
        chosen = st.multiselect("Filter event types", event_types, default=event_types)
        view = df_events[df_events["event_type"].isin(chosen)]
        st.dataframe(view, use_container_width=True, hide_index=True)
        st.download_button("Download normalized events (CSV)", view.to_csv(index=False).encode(), "normalized_events.csv", "text/csv")
        st.markdown("#### Dataset summary")
        st.json(summarize_events(events))
    else:
        st.info("No events loaded.")

with tab_alerts:
    st.subheader("Alert Triage Queue")
    if not df_alerts.empty:
        f1, f2 = st.columns(2)
        with f1:
            severity_filter = st.multiselect("Severity", ["Critical","High","Medium","Low"], default=["Critical","High","Medium","Low"])
        with f2:
            status_filter = st.multiselect("Status", ["New","Needs Review"], default=["New","Needs Review"])
        view = df_alerts[df_alerts["severity"].isin(severity_filter) & df_alerts["status"].isin(status_filter)]
        st.dataframe(view[["alert_id","timestamp","severity","rule_name","title","source_ip","host","mitre_technique","status","recommended_action"]], use_container_width=True, hide_index=True)
        selected_id = st.selectbox("Select alert for investigation", view["alert_id"].tolist() if not view.empty else [])
        if selected_id:
            selected = next(a for a in alerts if a["alert_id"] == selected_id)
            st.markdown(f"**{selected['title']}**")
            st.write(selected["description"])
            st.write("**Evidence:**", selected["evidence"])
            st.write("**Recommended action:**", selected["recommended_action"])
            st.write("**MITRE mapping:**", selected["mitre_technique"])
    else:
        st.info("No alerts generated.")

with tab_copilot:
    st.subheader("AI SOC Copilot")
    if alerts:
        selected_id = st.selectbox("Choose an alert", [a["alert_id"] for a in alerts], key="copilot_alert")
        selected = next(a for a in alerts if a["alert_id"] == selected_id)
        st.markdown(f"**{selected['title']}** · {selected['severity']}")
        if st.button("Generate investigation explanation", type="primary"):
            with st.spinner("Preparing analyst explanation..."):
                result = explain_alert(selected)
            st.markdown(result)
        st.caption("Without API credentials, the Copilot uses a deterministic local analyst playbook. AI API mode is optional.")
    else:
        st.info("Generate alerts first.")

with tab_reports:
    st.subheader("Incident Reporting")
    if alerts:
        report_alert = st.selectbox("Alert to include in report", [a["alert_id"] for a in alerts], key="report_alert")
        chosen_alert = next(a for a in alerts if a["alert_id"] == report_alert)
        report = build_incident_report(chosen_alert)
        st.markdown(report)
        st.download_button("Download incident report (Markdown)", report.encode(), f"{report_alert}_incident_report.md", "text/markdown")
        st.download_button("Download all alerts (CSV)", alerts_to_csv(alerts), "soc_alerts.csv", "text/csv")
        st.download_button("Download all alerts (JSON)", json.dumps(alerts, indent=2).encode(), "soc_alerts.json", "application/json")
    else:
        st.info("No alerts available for reporting.")

st.markdown("---")
st.caption("SentinelAI Portfolio Project • Synthetic training data • Detection logic is illustrative and requires environment-specific tuning.")
