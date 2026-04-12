"""
Pipeline Viewer — Stage-by-stage visualization of the last pipeline run.
"""

import streamlit as st
import pandas as pd
from dashboard_utils import ensure_session_state, require_api_key

st.set_page_config(page_title="Pipeline Viewer", page_icon="\U0001f50d", layout="wide")
ensure_session_state()
require_api_key()

st.title("Pipeline Viewer")
st.caption("Inspect the 3-stage pipeline trace from your last query.")

trace = st.session_state.current_trace
if trace is None:
    st.info("Run a query first from the main page.")
    st.stop()

current_mode = trace.get("mode", "")
st.markdown(f"**Query:** {trace.get('query', '')}  \n**Mode:** `{current_mode}`")
st.divider()

# ── Raw mode ─────────────────────────────────────────────────────────
if current_mode == "raw":
    st.info("Raw mode uses a single LLM call with no pipeline stages.")
    with st.expander("Raw Response"):
        st.write(trace.get("final_report", ""))
    st.stop()

# ── Stage 1: Routing ─────────────────────────────────────────────────
st.subheader("Stage 1: Task Routing")
routing = trace.get("stage1_routing", {})

if current_mode == "no_tools":
    st.info("no_tools mode: synthetic routing (all tools disabled).")
else:
    col1, col2, col3, col4 = st.columns(4)
    flags = [
        ("needs_cve", "CVE Lookup"),
        ("needs_attck", "ATT&CK Retrieval"),
        ("needs_file_analysis", "File Analysis"),
        ("off_topic", "Off-Topic"),
    ]
    for col, (key, label) in zip([col1, col2, col3, col4], flags):
        val = routing.get(key, False)
        icon = "\u2705" if val else "\u274c"
        col.metric(label, icon)

with st.expander("Requested Artifacts"):
    artifacts = routing.get("requested_artifacts", {})
    if artifacts:
        st.json(artifacts)
    else:
        st.write("No artifacts requested.")

with st.expander("Reasoning Checklist"):
    checklist = routing.get("reasoning_checklist", [])
    if checklist:
        for item in checklist:
            st.markdown(f"- {item}")
    else:
        st.write("No reasoning checklist available.")

st.divider()

# ── Tool Execution ───────────────────────────────────────────────────
st.subheader("Tool Execution Results")
evidence = trace.get("evidence_package", {})

tool_keys = [
    ("cve_evidence", "CVE Evidence"),
    ("attck_evidence", "ATT&CK Evidence"),
    ("file_evidence", "File Analysis Evidence"),
]

tcol1, tcol2, tcol3 = st.columns(3)
for col, (key, label) in zip([tcol1, tcol2, tcol3], tool_keys):
    with col:
        if key in evidence:
            st.markdown(f"**{label}** \u2705")
            with st.expander(f"View {label}"):
                st.json(evidence[key])
        else:
            st.markdown(f"**{label}** \u2014 Not executed")

# Evidence gating note (RAG mode)
if "file_evidence_note" in evidence:
    st.warning(evidence["file_evidence_note"])

st.divider()

# ── Stage 2: Evidence Analysis ───────────────────────────────────────
st.subheader("Stage 2: Evidence Analysis")
analysis = trace.get("stage2_analysis", {})

if not analysis:
    st.info("No Stage 2 analysis available.")
else:
    # Case assessment
    case = analysis.get("case_assessment", {})
    if case:
        st.markdown(f"**Request Type:** {case.get('request_type', 'N/A')}")
        st.markdown(f"**Summary:** {case.get('overall_summary', 'N/A')}")
        confidence = case.get("confidence", "N/A")
        st.markdown(f"**Confidence:** `{confidence}` — {case.get('confidence_rationale', '')}")

    # Evidence inventory
    inventory = analysis.get("evidence_inventory", {})
    if inventory:
        with st.expander("Evidence Inventory"):
            for key, label in [
                ("direct_user_inputs", "User Inputs"),
                ("retrieved_cve_facts", "CVE Facts"),
                ("retrieved_attck_facts", "ATT&CK Facts"),
                ("file_observations", "File Observations"),
            ]:
                items = inventory.get(key, [])
                if items:
                    st.markdown(f"**{label}:**")
                    for item in items:
                        st.markdown(f"- {item}")

            gaps = inventory.get("gaps_and_unknowns", [])
            if gaps:
                st.warning("**Gaps & Unknowns:**")
                for g in gaps:
                    st.markdown(f"- {g}")

            conflicts = inventory.get("conflicts", [])
            if conflicts:
                st.error("**Conflicts:**")
                for c in conflicts:
                    st.markdown(f"- {c}")

    # Reasoning
    reasoning = analysis.get("reasoning", {})
    if reasoning:
        with st.expander("Reasoning"):
            supported = reasoning.get("supported_conclusions", [])
            if supported:
                for s in supported:
                    st.success(s)

            inferences = reasoning.get("possible_inferences", [])
            if inferences:
                for inf in inferences:
                    st.warning(inf)

            rejected = reasoning.get("rejected_or_unjustified_claims", [])
            if rejected:
                for r in rejected:
                    st.error(r)

    # Citation map
    citation_map = analysis.get("citation_map", [])
    if citation_map:
        with st.expander("Citation Map"):
            df = pd.DataFrame(citation_map)
            st.dataframe(df, use_container_width=True)

st.divider()

# ── Stage 3 summary ──────────────────────────────────────────────────
st.subheader("Stage 3: Final Report")
st.page_link("app.py", label="View formatted report on main page")

with st.expander("Raw Report JSON"):
    st.json(trace.get("final_report", {}))

st.divider()

# ── Raw trace + console log ──────────────────────────────────────────
with st.expander("Full Trace JSON"):
    st.json(trace)

with st.expander("Pipeline Console Log"):
    st.code(st.session_state.get("current_log", ""), language="text")
