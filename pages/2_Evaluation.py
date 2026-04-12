"""
Evaluation Suite — Run the 5x4 test matrix and display results with charts.
"""

import streamlit as st
import pandas as pd
from collections import defaultdict

from dashboard_utils import init_knowledge_base, run_pipeline_quiet, ensure_session_state, require_api_key
from eval import (
    TEST_CASES, MODES, create_test_files,
    eval_keywords, eval_schema, eval_confidence_consistency, eval_citation_integrity,
)

st.set_page_config(page_title="Evaluation Suite", page_icon="\U0001f4ca", layout="wide")
ensure_session_state()
require_api_key()

try:
    init_knowledge_base()
except Exception as e:
    st.error(f"Failed to initialize knowledge base: {e}")
    st.stop()

st.title("Evaluation Suite")
st.caption("Run the full 5-test x 4-mode evaluation matrix and inspect results.")

# ── Test case overview ───────────────────────────────────────────────
with st.expander("Test Cases Overview"):
    for i, tc in enumerate(TEST_CASES, 1):
        st.markdown(f"**{tc['name']}**")
        st.markdown(f"- Query: *{tc['query']}*")
        st.markdown(f"- File: `{tc.get('file_path') or 'None'}`")
        mentions = [" | ".join(group) for group in tc["expected"].get("should_mention", [])]
        st.markdown(f"- Should mention: {mentions}")
        st.markdown(f"- Should NOT claim: {tc['expected'].get('should_not_claim', [])}")
        if i < len(TEST_CASES):
            st.markdown("---")

st.divider()

# ── Run evaluation ───────────────────────────────────────────────────
total_runs = len(TEST_CASES) * len(MODES)

if st.button(f"Run Full Evaluation Suite ({total_runs} runs)", type="primary"):
    create_test_files()

    results = []
    bar = st.progress(0, text="Starting evaluation...")
    status_text = st.empty()

    step = 0
    for tc in TEST_CASES:
        for mode in MODES:
            step += 1
            bar.progress(step / total_runs, text=f"[{step}/{total_runs}] {tc['name']} | {mode}")
            status_text.markdown(f"Running **{tc['name']}** in `{mode}` mode...")

            try:
                trace, _ = run_pipeline_quiet(
                    tc["query"], file_path=tc.get("file_path"), mode=mode,
                )
            except Exception as e:
                trace = {"mode": mode, "final_report": {"error": str(e)}, "token_usage": {}}

            results.append({
                "test": tc["name"],
                "mode": mode,
                "trace": trace,
                "expected": tc["expected"],
            })

    bar.progress(1.0, text="Evaluation complete!")
    status_text.empty()
    st.session_state.eval_results = results
    st.success(f"Completed {total_runs} pipeline runs.")

# ── Display results ──────────────────────────────────────────────────
if "eval_results" not in st.session_state or not st.session_state.eval_results:
    st.info("Click the button above to run the evaluation suite.")
    st.stop()

results = st.session_state.eval_results

# Build evaluation details
eval_rows = []
eval_details = []

for r in results:
    report = r["trace"].get("final_report", {})
    is_raw = r["mode"] == "raw"
    kw = eval_keywords(report, r["expected"])
    sch = eval_schema(report, is_raw=is_raw)
    cc = eval_confidence_consistency(r["trace"])
    ci = eval_citation_integrity(r["trace"])

    eval_details.append({
        "test": r["test"], "mode": r["mode"],
        "keywords": kw, "schema": sch,
        "confidence_consistency": cc, "citations": ci,
    })

    # Confidence from report
    if is_raw:
        conf_str = "n/a"
    elif isinstance(report, dict):
        conf_str = report.get("assessment", {}).get("confidence", "n/a")
    else:
        conf_str = "n/a"

    eval_rows.append({
        "Test": r["test"],
        "Mode": r["mode"],
        "Mention Rate": f"{kw['mention_rate']:.0%}",
        "Hallucinations": kw["hallucination_count"],
        "Schema Valid": "n/a" if sch["valid"] is None else ("Pass" if sch["valid"] else "FAIL"),
        "Confidence OK": "n/a" if cc["consistent"] is None else ("Pass" if cc["consistent"] else "FAIL"),
        "Citation Status": ci["status"],
        "Confidence": conf_str,
    })

# ── Results table ────────────────────────────────────────────────────
st.subheader("Results Table")
df = pd.DataFrame(eval_rows)
st.dataframe(df, use_container_width=True, height=750)

st.divider()

# ── Mode comparison ──────────────────────────────────────────────────
st.subheader("Mode Comparison")

mode_stats = defaultdict(lambda: {
    "mention_sum": 0, "halluc_sum": 0,
    "schema_pass": 0, "schema_applicable": 0,
    "conf_pass": 0, "conf_applicable": 0,
    "cite_grounded": 0, "cite_empty": 0, "cite_unused": 0, "cite_orphaned": 0,
    "cite_applicable": 0,
    "n": 0,
})

for d in eval_details:
    m = mode_stats[d["mode"]]
    m["mention_sum"] += d["keywords"]["mention_rate"]
    m["halluc_sum"] += d["keywords"]["hallucination_count"]
    m["n"] += 1
    if d["schema"]["valid"] is not None:
        m["schema_applicable"] += 1
        m["schema_pass"] += int(d["schema"]["valid"])
    if d["confidence_consistency"]["consistent"] is not None:
        m["conf_applicable"] += 1
        m["conf_pass"] += int(d["confidence_consistency"]["consistent"])
    cit_status = d["citations"]["status"]
    if cit_status != "n/a":
        m["cite_applicable"] += 1
        m["cite_grounded"] += int(cit_status == "grounded")
        m["cite_empty"] += int(cit_status == "empty")
        m["cite_unused"] += int(cit_status == "unused")
        m["cite_orphaned"] += int(cit_status == "orphaned")

# Summary table
summary_rows = []
for mode in MODES:
    m = mode_stats[mode]
    n = m["n"]
    def _frac(num, denom):
        return f"{num}/{denom}" if denom > 0 else "n/a"
    summary_rows.append({
        "Mode": mode,
        "Avg Mention Rate": f"{m['mention_sum']/n:.0%}" if n else "n/a",
        "Total Hallucinations": m["halluc_sum"],
        "Schema Pass": _frac(m["schema_pass"], m["schema_applicable"]),
        "Confidence OK": _frac(m["conf_pass"], m["conf_applicable"]),
        "Citations Grounded": _frac(m["cite_grounded"], m["cite_applicable"]),
        "Citations Empty": _frac(m["cite_empty"], m["cite_applicable"]),
        "Citations Unused": _frac(m["cite_unused"], m["cite_applicable"]),
    })

st.dataframe(pd.DataFrame(summary_rows), use_container_width=True)

# Charts
chart_col1, chart_col2 = st.columns(2)

with chart_col1:
    st.markdown("**Average Mention Rate by Mode**")
    mention_data = {mode: mode_stats[mode]["mention_sum"] / max(mode_stats[mode]["n"], 1) * 100 for mode in MODES}
    st.bar_chart(pd.DataFrame({"Mention Rate (%)": mention_data}))

with chart_col2:
    st.markdown("**Citation Status Distribution**")
    cite_data = []
    for mode in MODES:
        m = mode_stats[mode]
        cite_data.append({
            "Mode": mode,
            "Grounded": m["cite_grounded"],
            "Empty": m["cite_empty"],
            "Unused": m["cite_unused"],
            "Orphaned": m["cite_orphaned"],
        })
    cite_df = pd.DataFrame(cite_data).set_index("Mode")
    st.bar_chart(cite_df)

st.divider()

# ── Failure report ───────────────────────────────────────────────────
st.subheader("Detailed Failure Report")

any_issues = False
for d in eval_details:
    is_raw = d["mode"] == "raw"
    issues = []

    missed = [k for k, v in d["keywords"]["detail"]["hits"].items() if not v]
    if missed:
        issues.append(f"Missing keywords: {missed}")

    halluc = [k for k, v in d["keywords"]["detail"]["false_claims"].items() if v]
    if halluc:
        issues.append(f"Hallucinated claims containing: {halluc}")

    if not is_raw:
        if d["schema"]["valid"] is False:
            for iss in d["schema"]["issues"]:
                issues.append(f"Schema: {iss}")
        if d["confidence_consistency"]["consistent"] is False:
            issues.append(
                f"Confidence mismatch: "
                f"S2='{d['confidence_consistency']['stage2_confidence']}' "
                f"vs S3='{d['confidence_consistency']['stage3_confidence']}'"
            )
        cit = d["citations"]
        if cit["status"] == "empty":
            issues.append("Citations: Stage 2 produced no citation_map entries.")
        elif cit["status"] == "unused":
            issues.append(
                f"Citations: Stage 2 has {cit['available_citations']} labels "
                f"but Stage 3 referenced none."
            )
        elif cit["status"] == "orphaned":
            issues.append(f"Citations: orphaned refs = {cit['orphaned_citations']}")

    if issues:
        any_issues = True
        with st.expander(f"{d['test']} | {d['mode']}", expanded=False):
            for iss in issues:
                if "Hallucinated" in iss or "orphaned" in iss or "mismatch" in iss:
                    st.error(iss)
                elif "Missing" in iss or "empty" in iss or "unused" in iss:
                    st.warning(iss)
                else:
                    st.info(iss)

if not any_issues:
    st.success("All checks passed across all test cases and modes.")

st.divider()

# ── Token summary ────────────────────────────────────────────────────
st.subheader("Token & Cost Summary")

mode_tokens = defaultdict(lambda: {
    "prompt": 0, "completion": 0, "cost": 0.0, "latency": 0.0, "n": 0,
})

for r in results:
    u = r["trace"].get("token_usage", {})
    m = mode_tokens[r["mode"]]
    m["prompt"] += u.get("prompt_tokens", 0)
    m["completion"] += u.get("completion_tokens", 0)
    cost_val = u.get("cost_usd", 0)
    m["cost"] += cost_val if isinstance(cost_val, (int, float)) else 0
    m["latency"] += u.get("latency_seconds", 0)
    m["n"] += 1

# Grand totals
grand_cost = sum(m["cost"] for m in mode_tokens.values())
grand_tokens = sum(m["prompt"] + m["completion"] for m in mode_tokens.values())
grand_latency = sum(m["latency"] for m in mode_tokens.values())

tc1, tc2, tc3 = st.columns(3)
tc1.metric("Total Cost", f"${grand_cost:.4f}")
tc2.metric("Total Tokens", f"{grand_tokens:,}")
tc3.metric("Total Latency", f"{grand_latency:.1f}s")

# Per-mode table
token_rows = []
for mode in MODES:
    m = mode_tokens[mode]
    n = m["n"]
    total = m["prompt"] + m["completion"]
    avg_lat = m["latency"] / n if n else 0
    token_rows.append({
        "Mode": mode,
        "Prompt Tokens": f"{m['prompt']:,}",
        "Completion Tokens": f"{m['completion']:,}",
        "Total Tokens": f"{total:,}",
        "Cost (USD)": f"${m['cost']:.4f}",
        "Avg Latency": f"{avg_lat:.1f}s",
    })

st.dataframe(pd.DataFrame(token_rows), use_container_width=True)

# Cost chart
cost_col1, cost_col2 = st.columns(2)
with cost_col1:
    st.markdown("**Cost by Mode**")
    cost_data = {mode: mode_tokens[mode]["cost"] for mode in MODES}
    st.bar_chart(pd.DataFrame({"Cost ($)": cost_data}))

with cost_col2:
    st.markdown("**Average Latency by Mode**")
    lat_data = {mode: mode_tokens[mode]["latency"] / max(mode_tokens[mode]["n"], 1) for mode in MODES}
    st.bar_chart(pd.DataFrame({"Avg Latency (s)": lat_data}))
