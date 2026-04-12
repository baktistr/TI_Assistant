"""
LLM orchestration pipeline for Threat Intelligence Assistant.

Provides:
  - llm_json_call(): JSON-mode LLM call helper (returns result + usage stats)
  - run_pipeline():  3-stage orchestrator (Task Analyzer -> Tools -> Evidence Analyst -> Report)
  - Token/cost/latency tracking per pipeline run
"""

import os
import json
import time
from typing import Any

from dotenv import load_dotenv
from openai import OpenAI

from prompts import (
    PROMPT_1_TASK_ANALYZER,
    PROMPT_2_EVIDENCE_ANALYST,
    PROMPT_3_REPORT_GENERATOR,
)
from tools import lookup_cve, retrieve_attck, analyze_file

load_dotenv()

oai = None  # initialized lazily via set_api_key()
MODEL = "gpt-4o-mini"


def set_api_key(api_key: str):
    """Set the OpenAI API key and create the client."""
    global oai
    oai = OpenAI(api_key=api_key)

# ── Model pricing (USD per 1M tokens): (input, output) ───────────────
MODEL_PRICING = {
    "gpt-4o-mini":  (0.15,  0.60),
    "gpt-4o":       (2.50,  10.00),
    "gpt-4.1":      (2.00,  8.00),
    "gpt-4.1-mini": (0.40,  1.60),
    "gpt-4.1-nano": (0.10,  0.40),
    "o3-mini":      (1.10,  4.40),
}

# ── Simple system prompt for raw baseline mode ────────────────────────
PROMPT_RAW = "You are a cybersecurity analyst. Answer the user's question."


# ── LLM call helper (with token + latency tracking) ──────────────────

def llm_json_call(
    system_prompt: str,
    user_content: str,
    *,
    json_mode: bool = True,
) -> tuple[dict, dict]:
    """
    Call the LLM with a system prompt.

    Returns:
        (parsed_result, call_stats)
        - parsed_result: parsed JSON dict, or {"_raw_text": str} if json_mode=False
        - call_stats: {"prompt_tokens", "completion_tokens", "latency_s"}
    """
    t0 = time.time()
    stats: dict[str, Any] = {
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "latency_s": 0.0,
    }
    try:
        kwargs: dict[str, Any] = dict(
            model=MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content},
            ],
            temperature=0.0,
        )
        if json_mode:
            kwargs["response_format"] = {"type": "json_object"}

        resp = oai.chat.completions.create(**kwargs)
        stats["latency_s"] = round(time.time() - t0, 3)

        # Extract token usage
        if resp.usage:
            stats["prompt_tokens"] = resp.usage.prompt_tokens
            stats["completion_tokens"] = resp.usage.completion_tokens

        text = resp.choices[0].message.content

        if json_mode:
            return json.loads(text), stats
        else:
            return {"_raw_text": text}, stats

    except json.JSONDecodeError as e:
        stats["latency_s"] = round(time.time() - t0, 3)
        return {"error": f"JSON parse failed: {e}", "raw": text}, stats
    except Exception as e:
        stats["latency_s"] = round(time.time() - t0, 3)
        return {"error": str(e)}, stats


def _aggregate_usage(call_stats_list: list[dict]) -> dict:
    """Aggregate token usage and cost across multiple LLM calls."""
    total_prompt = sum(s["prompt_tokens"] for s in call_stats_list)
    total_completion = sum(s["completion_tokens"] for s in call_stats_list)
    total_latency = sum(s["latency_s"] for s in call_stats_list)
    pricing = MODEL_PRICING.get(MODEL)
    if pricing:
        cost = (
            total_prompt * pricing[0] / 1_000_000
            + total_completion * pricing[1] / 1_000_000
        )
        cost_usd = round(cost, 6)
    else:
        cost_usd = "unknown"
    return {
        "prompt_tokens": total_prompt,
        "completion_tokens": total_completion,
        "total_tokens": total_prompt + total_completion,
        "cost_usd": cost_usd,
        "latency_seconds": round(total_latency, 3),
        "num_calls": len(call_stats_list),
        "model": MODEL,
    }


# ── Orchestration pipeline ────────────────────────────────────────────

def run_pipeline(
    user_query: str,
    file_path: str | None = None,
    mode: str = "full",  # "raw" | "no_tools" | "rag" | "full"
    verbose: bool = True,
) -> dict:
    """
    Execute the threat intelligence pipeline.

    Modes:
      - raw      : single LLM call, no pipeline stages, plain text response
      - no_tools : 3-stage pipeline but skip all tool calls
      - rag      : 3-stage pipeline with CVE/ATT&CK retrieval, skip file analysis
      - full     : 3-stage pipeline with all tools as directed by Stage 1
    """
    trace: dict[str, Any] = {"query": user_query, "mode": mode}
    all_call_stats: list[dict] = []

    # ══════════════════════════════════════════════════════════════════
    # RAW MODE — single call, no pipeline, no JSON schema
    # ══════════════════════════════════════════════════════════════════
    if mode == "raw":
        result, stats = llm_json_call(PROMPT_RAW, user_query, json_mode=False)
        all_call_stats.append(stats)
        raw_text = result.get("_raw_text", result.get("error", ""))
        trace["final_report"] = raw_text   # plain string
        trace["token_usage"] = _aggregate_usage(all_call_stats)
        if verbose:
            print("=== Raw Mode: Single LLM Call ===")
            print(raw_text[:500])
            print(f"\n[tokens: {stats['prompt_tokens']}+{stats['completion_tokens']}, "
                  f"latency: {stats['latency_s']:.1f}s]")
        return trace

    # ══════════════════════════════════════════════════════════════════
    # PIPELINE MODES — no_tools / rag / full
    # ══════════════════════════════════════════════════════════════════

    # ── Stage 1: Task Analyzer ────────────────────────────────────────
    if mode == "no_tools":
        routing = {
            "needs_cve": False, "needs_attck": False,
            "needs_file_analysis": False, "off_topic": False,
            "missing_context": [],
            "requested_artifacts": {
                "cve_ids": [], "file_targets": [],
                "threat_entities": [], "user_intent": user_query,
            },
            "reasoning_checklist": ["no_tools mode; no tools invoked."],
        }
    else:
        routing, s1_stats = llm_json_call(PROMPT_1_TASK_ANALYZER, user_query)
        all_call_stats.append(s1_stats)
    trace["stage1_routing"] = routing
    if verbose:
        print("=== Stage 1: Routing ===")
        print(json.dumps(routing, indent=2))

    # ── Tool execution ────────────────────────────────────────────────
    evidence_package: dict[str, Any] = {"user_query": user_query}

    if mode in ("rag", "full"):
        # CVE
        if routing.get("needs_cve"):
            cve_ids = routing.get("requested_artifacts", {}).get("cve_ids", [])
            cve_results = []
            if cve_ids:
                for cid in cve_ids:
                    cve_results.append(lookup_cve(cid))
            else:
                cve_results.append(lookup_cve(user_query))
            evidence_package["cve_evidence"] = cve_results

        # ATT&CK
        if routing.get("needs_attck"):
            intent = routing.get("requested_artifacts", {}).get(
                "user_intent", user_query
            )
            evidence_package["attck_evidence"] = retrieve_attck(intent)

    # File analysis — ONLY in full mode
    if mode == "full" and routing.get("needs_file_analysis"):
        targets = routing.get("requested_artifacts", {}).get(
            "file_targets", []
        )
        fp = file_path or (targets[0] if targets else None)
        if fp and os.path.isfile(fp):
            evidence_package["file_evidence"] = analyze_file(fp)
        else:
            evidence_package["file_evidence"] = {
                "errors": [f"No valid file path provided (received: {fp})."]
            }
    elif mode == "rag" and routing.get("needs_file_analysis"):
        # ── EVIDENCE GATING: explicitly tell the LLM that file
        # analysis was requested but NOT performed in RAG mode.
        evidence_package["file_evidence_note"] = (
            "File analysis was requested but NOT performed in this mode. "
            "Do NOT make any claims about file contents or behavior."
        )

    trace["evidence_package"] = evidence_package
    if verbose:
        print("\n=== Tool Evidence (keys) ===")
        print(list(evidence_package.keys()))

    # ── Stage 2: Evidence Analyst ─────────────────────────────────────
    stage2_input = json.dumps(evidence_package, indent=2, default=str)
    analysis, s2_stats = llm_json_call(PROMPT_2_EVIDENCE_ANALYST, stage2_input)
    all_call_stats.append(s2_stats)
    trace["stage2_analysis"] = analysis
    if verbose:
        print("\n=== Stage 2: Analysis ===")
        print(json.dumps(analysis, indent=2)[:1500], "…")

    # ── Stage 3: Report Generator ────────────────────────────────────
    stage3_input = json.dumps(
        {"user_request": user_query, "intermediate_analysis": analysis},
        indent=2, default=str,
    )
    report, s3_stats = llm_json_call(PROMPT_3_REPORT_GENERATOR, stage3_input)
    all_call_stats.append(s3_stats)
    trace["final_report"] = report
    if verbose:
        print("\n=== Stage 3: Final Report ===")
        print(json.dumps(report, indent=2))

    # ── Aggregate token usage ─────────────────────────────────────────
    trace["token_usage"] = _aggregate_usage(all_call_stats)
    if verbose:
        u = trace["token_usage"]
        print(f"\n[Total tokens: {u['total_tokens']} "
              f"(prompt={u['prompt_tokens']}, completion={u['completion_tokens']}), "
              f"cost=${u['cost_usd']:.4f}, latency={u['latency_seconds']:.1f}s]")

    return trace
