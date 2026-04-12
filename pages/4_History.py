"""
History — Browse past pipeline runs with cumulative token/cost analytics.
"""

import json
import streamlit as st
import pandas as pd

from dashboard_utils import ensure_session_state, save_history, require_api_key

st.set_page_config(page_title="History", page_icon="\U0001f4c2", layout="wide")
ensure_session_state()
require_api_key()

st.title("Run History")
st.caption("Browse past pipeline runs and track cumulative token usage and costs.")

history = st.session_state.history

if not history:
    st.info("No runs yet. Submit a query from the main page to get started.")
    st.stop()

# ── Cumulative metrics ───────────────────────────────────────────────
total_runs = len(history)
total_cost = sum(
    r.get("token_usage", {}).get("cost_usd", 0)
    for r in history
    if isinstance(r.get("token_usage", {}).get("cost_usd", 0), (int, float))
)
total_tokens = sum(
    r.get("token_usage", {}).get("total_tokens", 0) for r in history
)
total_latency = sum(
    r.get("token_usage", {}).get("latency_seconds", 0) for r in history
)

m1, m2, m3, m4 = st.columns(4)
m1.metric("Total Runs", total_runs)
m2.metric("Total Cost", f"${total_cost:.4f}")
m3.metric("Total Tokens", f"{total_tokens:,}")
m4.metric("Avg Latency", f"{total_latency / total_runs:.1f}s")

st.divider()

# ── History table ────────────────────────────────────────────────────
st.subheader("All Runs")

rows = []
for i, r in enumerate(reversed(history)):
    usage = r.get("token_usage", {})
    report = r.get("final_report", {})

    if isinstance(report, dict):
        confidence = report.get("assessment", {}).get("confidence", "n/a")
    else:
        confidence = "n/a (raw)"

    query_text = r.get("query", "")
    rows.append({
        "#": len(history) - i,
        "Timestamp": r.get("timestamp", "N/A"),
        "Query": query_text[:80] + "..." if len(query_text) > 80 else query_text,
        "Mode": r.get("mode", ""),
        "Confidence": confidence,
        "Tokens": usage.get("total_tokens", 0),
        "Cost ($)": f"${usage.get('cost_usd', 0):.4f}" if isinstance(usage.get("cost_usd", 0), (int, float)) else "$0.0000",
        "Latency (s)": f"{usage.get('latency_seconds', 0):.1f}",
    })

df = pd.DataFrame(rows)
st.dataframe(df, use_container_width=True, height=400)

st.divider()

# ── Select a run to inspect ──────────────────────────────────────────
st.subheader("Inspect a Run")

run_options = [f"#{len(history)-i}: {r.get('query', '')[:60]} ({r.get('mode', '')})"
               for i, r in enumerate(reversed(history))]

selected_idx = st.selectbox("Select a run", range(len(run_options)), format_func=lambda i: run_options[i])

if selected_idx is not None:
    selected_trace = list(reversed(history))[selected_idx]

    col1, col2 = st.columns(2)
    with col1:
        st.markdown(f"**Query:** {selected_trace.get('query', '')}")
        st.markdown(f"**Mode:** `{selected_trace.get('mode', '')}`")
        st.markdown(f"**Timestamp:** {selected_trace.get('timestamp', 'N/A')}")
    with col2:
        usage = selected_trace.get("token_usage", {})
        st.markdown(f"**Tokens:** {usage.get('total_tokens', 0):,}")
        st.markdown(f"**Cost:** ${usage.get('cost_usd', 0):.4f}" if isinstance(usage.get("cost_usd", 0), (int, float)) else "**Cost:** $0.0000")
        st.markdown(f"**Latency:** {usage.get('latency_seconds', 0):.1f}s")

    if st.button("Load into Pipeline Viewer"):
        st.session_state.current_trace = selected_trace
        st.success("Loaded! Navigate to Pipeline Viewer to inspect.")

    with st.expander("Full Report"):
        report = selected_trace.get("final_report", {})
        if isinstance(report, str):
            st.markdown(report)
        else:
            st.json(report)

    with st.expander("Full Trace JSON"):
        st.json(selected_trace)

st.divider()

# ── Charts ───────────────────────────────────────────────────────────
st.subheader("Analytics")

chart_col1, chart_col2 = st.columns(2)

with chart_col1:
    st.markdown("**Cost per Run**")
    cost_series = [
        r.get("token_usage", {}).get("cost_usd", 0)
        for r in history
        if isinstance(r.get("token_usage", {}).get("cost_usd", 0), (int, float))
    ]
    if cost_series:
        st.line_chart(pd.DataFrame({"Cost ($)": cost_series}))

with chart_col2:
    st.markdown("**Runs by Mode**")
    mode_counts = {}
    for r in history:
        m = r.get("mode", "unknown")
        mode_counts[m] = mode_counts.get(m, 0) + 1
    if mode_counts:
        st.bar_chart(pd.DataFrame({"Runs": mode_counts}))

st.divider()

# ── Export / Clear ───────────────────────────────────────────────────
exp_col1, exp_col2 = st.columns(2)

with exp_col1:
    st.download_button(
        "Export History (JSON)",
        data=json.dumps(history, default=str, indent=2),
        file_name="threat_intel_history.json",
        mime="application/json",
    )

with exp_col2:
    if st.button("Clear History", type="secondary"):
        st.session_state.history = []
        save_history()
        st.rerun()
