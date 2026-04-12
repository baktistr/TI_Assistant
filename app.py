"""
Threat Intelligence Assistant — Streamlit Dashboard
Main entry point: Query Interface + Report Display
"""

import os
import tempfile
import streamlit as st
import pandas as pd

import data_setup
import pipeline
from pipeline import set_api_key
from dashboard_utils import (
    init_knowledge_base,
    run_pipeline_quiet,
    ensure_session_state,
    save_history,
)
from eval import TEST_CASES

# ── Page config ──────────────────────────────────────────────────────
st.set_page_config(
    page_title="Threat Intel Assistant",
    page_icon="\U0001f6e1\ufe0f",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Init ─────────────────────────────────────────────────────────────
ensure_session_state()

# API key setup — every user provides their own key
if "api_key" not in st.session_state:
    st.session_state.api_key = ""

if not st.session_state.api_key:
    st.title("Threat Intelligence Assistant")
    st.warning("Enter your OpenAI API key to get started.")
    api_key_input = st.text_input(
        "OpenAI API Key",
        type="password",
        placeholder="sk-proj-...",
        help="Your key is stored in memory only for this session. It is not saved to disk.",
    )
    if st.button("Confirm API Key", type="primary", disabled=not api_key_input):
        st.session_state.api_key = api_key_input
        set_api_key(api_key_input)
        st.rerun()
    st.stop()

# Ensure client is set (e.g. after page navigation)
if pipeline.oai is None:
    set_api_key(st.session_state.api_key)

# Load knowledge base (cached — runs once)
try:
    init_knowledge_base()
except Exception as e:
    st.error(f"Failed to initialize knowledge base: {e}")
    st.info("Make sure ChromaDB data exists. Run `data_setup.initialize()` first.")
    st.stop()

# ── Sidebar ──────────────────────────────────────────────────────────
with st.sidebar:
    st.header("Settings")

    MODE_HELP = {
        "full": "3-stage pipeline with all tools (CVE + ATT&CK + file analysis)",
        "rag": "3-stage pipeline with CVE + ATT&CK retrieval (no file analysis)",
        "no_tools": "3-stage pipeline without any tool calls",
        "raw": "Single LLM call, plain text response (baseline)",
    }
    mode = st.selectbox(
        "Pipeline Mode",
        options=["full", "rag", "no_tools", "raw"],
        format_func=lambda m: f"{m} — {MODE_HELP[m]}",
    )

    st.divider()
    uploaded_file = st.file_uploader(
        "Upload file for analysis",
        type=["jar", "xml", "ps1", "exe", "py", "txt", "dll", "bin"],
        help="Only used in 'full' mode when Stage 1 routes to file analysis.",
    )

    st.divider()
    st.subheader("System Status")
    cve_count = data_setup.cve_col.count() if data_setup.cve_col else 0
    attck_count = data_setup.attck_col.count() if data_setup.attck_col else 0
    st.markdown(f"**Model:** `{pipeline.MODEL}`")
    st.markdown(f"**CVE KB:** {cve_count} documents")
    st.markdown(f"**ATT&CK KB:** {attck_count} documents")
    st.markdown(f"**API Key:** {'configured' if st.session_state.get('api_key') else 'missing'}")

# ── Main area ────────────────────────────────────────────────────────
st.title("Threat Intelligence Assistant")
st.caption("RAG-powered threat analysis with CVE lookup, MITRE ATT&CK mapping, and static file analysis.")

# Example query launcher
EXAMPLE_OPTIONS = ["(custom query)"] + [tc["name"] for tc in TEST_CASES]
example_choice = st.selectbox("Load example query", EXAMPLE_OPTIONS, index=0)

if example_choice != "(custom query)":
    selected_tc = next(tc for tc in TEST_CASES if tc["name"] == example_choice)
    default_query = selected_tc["query"]
    example_file_hint = selected_tc.get("file_path")
    if example_file_hint:
        st.info(f"This example uses test file: `{example_file_hint}` (auto-loaded, no upload needed)")
else:
    default_query = ""
    example_file_hint = None

query = st.text_area(
    "Enter your threat intelligence query",
    value=default_query,
    height=100,
    placeholder="e.g., What can you tell me about CVE-2021-44228?",
)

run_btn = st.button("Run Analysis", type="primary", disabled=not query.strip())

if run_btn and query.strip():
    # Handle file: uploaded file takes priority, then example test file
    file_path = None
    tmp_created = False
    if uploaded_file is not None:
        if uploaded_file.size > 10 * 1024 * 1024:
            st.error("File too large (max 10 MB).")
            st.stop()
        suffix = os.path.splitext(uploaded_file.name)[1]
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
        tmp.write(uploaded_file.getvalue())
        tmp.close()
        file_path = tmp.name
        tmp_created = True
    elif example_file_hint and os.path.isfile(example_file_hint):
        file_path = example_file_hint

    with st.spinner("Running pipeline... this may take a few seconds."):
        try:
            trace, log_text = run_pipeline_quiet(query.strip(), file_path=file_path, mode=mode)
        except Exception as e:
            st.error(f"Pipeline error: {e}")
            if tmp_created and file_path:
                os.unlink(file_path)
            st.stop()

    # Clean up temp file (only if we created it)
    if tmp_created and file_path:
        try:
            os.unlink(file_path)
        except OSError:
            pass

    # Store results
    st.session_state.current_trace = trace
    st.session_state.current_log = log_text
    st.session_state.history.append(trace)
    save_history()

# ── Display results ──────────────────────────────────────────────────
trace = st.session_state.current_trace
if trace is None:
    st.info("Submit a query above to get started.")
    st.stop()

report = trace.get("final_report")
usage = trace.get("token_usage", {})
current_mode = trace.get("mode", "")

st.divider()

# ── Token metrics ────────────────────────────────────────────────────
st.subheader("Run Metrics")
m1, m2, m3, m4, m5 = st.columns(5)
m1.metric("Total Tokens", f"{usage.get('total_tokens', 0):,}")
m2.metric("Prompt Tokens", f"{usage.get('prompt_tokens', 0):,}")
m3.metric("Completion Tokens", f"{usage.get('completion_tokens', 0):,}")
m4.metric("Cost (USD)", f"${usage.get('cost_usd', 0):.4f}")
m5.metric("Latency", f"{usage.get('latency_seconds', 0):.1f}s")

st.divider()

# ── Raw mode: plain text ─────────────────────────────────────────────
if current_mode == "raw":
    st.subheader("Response (Raw Mode)")
    st.markdown(report if isinstance(report, str) else str(report))
    st.stop()

# ── Pipeline modes: structured report ────────────────────────────────
if not isinstance(report, dict):
    st.warning("Unexpected report format.")
    st.json(report)
    st.stop()

# Summary
st.subheader("Summary")
st.markdown(report.get("summary", "*No summary available.*"))

# Assessment
st.subheader("Assessment")
assessment = report.get("assessment", {})
c1, c2, c3 = st.columns(3)

confidence = assessment.get("confidence", "unknown")
conf_colors = {"high": "red", "medium": "orange", "low": "green"}
conf_color = conf_colors.get(confidence, "gray")
c1.markdown(f"**Confidence:** :{conf_color}[{confidence.upper()}]")

status = assessment.get("status", "unknown")
c2.markdown(f"**Status:** `{status}`")

scope_limits = assessment.get("scope_limits", [])
if scope_limits:
    limits_md = "\n".join(f"- {s}" for s in scope_limits)
    c3.markdown(f"**Scope Limits:**\n{limits_md}")
else:
    c3.markdown("**Scope Limits:** None noted")

# ATT&CK Mapping
st.subheader("ATT&CK Mapping")
attack_mapping = report.get("attack_mapping", [])
if attack_mapping:
    df = pd.DataFrame(attack_mapping)
    display_cols = []
    if "technique_id" in df.columns:
        display_cols.append("technique_id")
    if "technique_name" in df.columns:
        display_cols.append("technique_name")
    if "confidence" in df.columns:
        display_cols.append("confidence")
    if "evidence_citations" in df.columns:
        df["evidence_citations"] = df["evidence_citations"].apply(
            lambda x: ", ".join(x) if isinstance(x, list) else str(x)
        )
        display_cols.append("evidence_citations")
    st.dataframe(df[display_cols] if display_cols else df, use_container_width=True)
else:
    st.info("No ATT&CK mapping produced for this query.")

# Key Evidence
st.subheader("Key Evidence")
key_evidence = report.get("key_evidence", [])
if key_evidence:
    for i, ev in enumerate(key_evidence, 1):
        statement = ev.get("statement", "")
        citations = ev.get("evidence_citations", [])
        citation_str = f" `[{', '.join(citations)}]`" if citations else ""
        st.markdown(f"**{i}.** {statement}{citation_str}")
else:
    st.info("No key evidence items in this report.")

# Analyst Notes
st.subheader("Analyst Notes")
notes = report.get("analyst_notes", {})

with st.expander("What is supported", expanded=True):
    supported = notes.get("what_is_supported", [])
    if supported:
        for item in supported:
            st.markdown(f"- {item}")
    else:
        st.write("None listed.")

with st.expander("What is NOT supported"):
    not_supported = notes.get("what_is_not_supported", [])
    if not_supported:
        for item in not_supported:
            st.markdown(f"- {item}")
    else:
        st.write("None listed.")

with st.expander("Recommended next steps"):
    next_steps = notes.get("recommended_next_steps", [])
    if next_steps:
        for item in next_steps:
            st.markdown(f"- {item}")
    else:
        st.write("None listed.")

# Console log
with st.expander("Pipeline Console Log"):
    st.code(st.session_state.get("current_log", ""), language="text")
