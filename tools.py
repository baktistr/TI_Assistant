"""
Tool functions for Threat Intelligence Assistant.

Provides three tools for the pipeline:
  1. lookup_cve()     — exact + semantic CVE search in ChromaDB
  2. retrieve_attck() — semantic ATT&CK technique retrieval
  3. analyze_file()   — static file analysis with YARA, strings, metadata
"""

import os
import subprocess
import math
import re
import json
import time
import urllib.request
from collections import Counter
from typing import Any

import data_setup


# ═══════════════════════════════════════════════════════════════════════
# Tool 1: CVE Lookup
# ═══════════════════════════════════════════════════════════════════════

def lookup_cve(cve_id: str, n_results: int = 3) -> dict:
    """
    Look up a CVE by ID in the local ChromaDB knowledge base.
    Tries exact-match first, then falls back to semantic search.
    """
    cve_id = cve_id.strip().upper()
    # Exact match
    try:
        exact = data_setup.cve_col.get(ids=[cve_id], include=["documents", "metadatas"])
        if exact["ids"]:
            return {
                "source": "cve_kb",
                "match_type": "exact",
                "results": [
                    {"id": exact["ids"][0], "text": exact["documents"][0],
                     "metadata": exact["metadatas"][0]}
                ],
            }
    except Exception:
        pass
    # Semantic fallback
    sem = data_setup.cve_col.query(
        query_texts=[cve_id], n_results=n_results,
        include=["documents", "metadatas", "distances"],
    )
    results = [
        {"id": sem["ids"][0][i], "text": sem["documents"][0][i],
         "metadata": sem["metadatas"][0][i],
         "distance": sem["distances"][0][i]}
        for i in range(len(sem["ids"][0]))
    ]
    return {"source": "cve_kb", "match_type": "semantic", "results": results}


# ═══════════════════════════════════════════════════════════════════════
# Tool 2: ATT&CK Retrieval
# ═══════════════════════════════════════════════════════════════════════

ATTCK_DISTANCE_THRESHOLD = 1.2  # L2² cutoff; higher = less relevant

def retrieve_attck(query: str, n_results: int = 5) -> dict:
    """
    Semantic search over the local ATT&CK ChromaDB collection.
    Filters out results with L2² distance > ATTCK_DISTANCE_THRESHOLD
    and adds a relevance_score (cosine similarity approximation).
    """
    # Fetch more candidates than needed, then filter by relevance
    sem = data_setup.attck_col.query(
        query_texts=[query], n_results=n_results,
        include=["documents", "metadatas", "distances"],
    )
    results = []
    filtered_count = 0
    for i in range(len(sem["ids"][0])):
        dist = sem["distances"][0][i]
        if dist > ATTCK_DISTANCE_THRESHOLD:
            filtered_count += 1
            continue
        # Approximate cosine similarity from L2² distance
        # For normalized embeddings: L2² = 2 - 2*cos_sim
        relevance = round(1.0 - dist / 2.0, 4)
        results.append({
            "id": sem["ids"][0][i],
            "text": sem["documents"][0][i],
            "metadata": sem["metadatas"][0][i],
            "distance": dist,
            "relevance_score": relevance,
        })
    return {
        "source": "attck_kb",
        "results": results,
        "filtered_out": filtered_count,
    }


# ═══════════════════════════════════════════════════════════════════════
# Tool 3: Enhanced Static File Analysis
# ═══════════════════════════════════════════════════════════════════════

# ── YARAify Remote Scan ───────────────────────────────────────────────
# Scans files via YARAify (abuse.ch) API against their full community
# ruleset instead of local hardcoded rules.

YARAIFY_API_URL = "https://yaraify-api.abuse.ch/api/v1/"
YARAIFY_POLL_INTERVAL = 3  # seconds between status checks
YARAIFY_POLL_MAX = 10  # max poll attempts (~30s total)


def _yaraify_api_key() -> str:
    """Read YARAify API key from environment."""
    return os.environ.get("YARAIFY_API_KEY", "")


def yaraify_scan_file(file_path: str) -> list[dict]:
    """
    Upload a file to YARAify for scanning against their full YARA ruleset.
    Returns a list of matched rules with metadata.
    Raises RuntimeError if the scan fails or times out.
    """
    api_key = _yaraify_api_key()
    if not api_key:
        raise RuntimeError("YARAIFY_API_KEY not set")

    file_name = os.path.basename(file_path)
    with open(file_path, "rb") as f:
        file_data = f.read()

    # Build multipart form data
    boundary = "----YARAifyBoundary9876543210"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{file_name}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode() + file_data + (
        f"\r\n--{boundary}\r\n"
        f'Content-Disposition: form-data; name="clamav_scan"\r\n\r\n1\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="share_file"\r\n\r\n0\r\n'
        f"--{boundary}--\r\n"
    ).encode()

    # Submit file
    req = urllib.request.Request(YARAIFY_API_URL, data=body, method="POST")
    req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
    req.add_header("Auth-Key", api_key)

    with urllib.request.urlopen(req, timeout=30) as resp:
        submit_data = json.loads(resp.read().decode())

    if submit_data.get("query_status") != "queued":
        raise RuntimeError(f"YARAify submit failed: {submit_data}")

    task_id = submit_data["data"]["task_id"]

    # Poll for results
    for _ in range(YARAIFY_POLL_MAX):
        time.sleep(YARAIFY_POLL_INTERVAL)
        payload = json.dumps({"query": "get_results", "task_id": task_id}).encode()
        req = urllib.request.Request(YARAIFY_API_URL, data=payload, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Auth-Key", api_key)

        with urllib.request.urlopen(req, timeout=30) as resp:
            result_data = json.loads(resp.read().decode())

        if result_data.get("query_status") == "ok":
            data = result_data.get("data")
            # Still processing — data is a string like "queued"
            if not isinstance(data, dict):
                continue
            matches = []
            for rule in data.get("static_results", []):
                matches.append({
                    "rule": rule.get("rule_name", ""),
                    "author": rule.get("author", ""),
                    "description": rule.get("description", ""),
                    "reference": rule.get("reference", ""),
                    "tlp": rule.get("tlp", ""),
                })
            return matches

    raise RuntimeError(f"YARAify scan timed out after {YARAIFY_POLL_MAX * YARAIFY_POLL_INTERVAL}s")


# ── File Metadata Helpers ─────────────────────────────────────────────

MAGIC_SIGS = [
    (b"PK\x03\x04",       "ZIP/JAR/DOCX archive"),
    (b"PK\x05\x06",       "ZIP (empty archive)"),
    (b"\x7fELF",           "ELF executable"),
    (b"MZ",                "PE executable (Windows)"),
    (b"\xca\xfe\xba\xbe", "Java class / Mach-O fat binary"),
    (b"\x89PNG",           "PNG image"),
    (b"\xff\xd8\xff",      "JPEG image"),
    (b"%PDF",              "PDF document"),
    (b"Rar!",              "RAR archive"),
    (b"\x1f\x8b",          "GZIP compressed"),
]


def detect_magic(file_path: str) -> str:
    """Read first 8 bytes and match against known magic signatures."""
    try:
        with open(file_path, "rb") as f:
            header = f.read(8)
        for sig, label in MAGIC_SIGS:
            if header[:len(sig)] == sig:
                return label
        try:
            header.decode("utf-8")
            return "text/script (UTF-8 compatible)"
        except UnicodeDecodeError:
            return f"unknown (header hex: {header[:8].hex()})"
    except Exception as e:
        return f"error reading header: {e}"


def shannon_entropy(file_path: str) -> float:
    """
    Calculate Shannon entropy of the file (0-8 scale for byte data).
    Values > 7.0 suggest encryption/compression/packing.
    Values < 4.5 suggest plaintext.
    """
    try:
        with open(file_path, "rb") as f:
            data = f.read()
        if not data:
            return 0.0
        counts = Counter(data)
        length = len(data)
        entropy = -sum(
            (c / length) * math.log2(c / length)
            for c in counts.values()
        )
        return round(entropy, 4)
    except Exception:
        return -1.0


def extract_file_metadata(file_path: str) -> dict:
    """Extract file size, magic type, and entropy."""
    size = os.path.getsize(file_path)
    magic = detect_magic(file_path)
    ent = shannon_entropy(file_path)
    return {
        "file_size_bytes": size,
        "file_type_magic": magic,
        "shannon_entropy": ent,
        "entropy_assessment": (
            "low (plaintext-like)" if ent < 4.5 else
            "moderate" if ent < 6.5 else
            "high (compressed/packed/encrypted)" if ent < 7.5 else
            "very high (likely encrypted or random)"
        ),
    }


# ── Categorized String Extraction ─────────────────────────────────────

STRING_PATTERNS = {
    "urls":            re.compile(r"https?://[^\s'\"<>]{5,}"),
    "ip_addresses":    re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "email_addresses": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    "file_paths":      re.compile(r"(?:[A-Z]:\\|/(?:usr|etc|tmp|var|bin|home))[^\s]{3,}"),
    "registry_keys":   re.compile(r"HKEY_[A-Z_]+\\[^\s]{3,}", re.IGNORECASE),
    "base64_blobs":    re.compile(r"[A-Za-z0-9+/=]{40,}"),
}


def categorize_strings(raw_strings: list[str]) -> dict:
    """
    Categorize extracted strings into buckets (URLs, IPs, emails, etc.).
    Returns a dict of category -> deduplicated list.
    """
    categorized = {cat: set() for cat in STRING_PATTERNS}
    categorized["suspicious_commands"] = set()

    cmd_keywords = [
        "cmd.exe", "powershell", "/bin/sh", "/bin/bash",
        "wget", "curl", "chmod", "eval(", "exec(",
        "Invoke-Expression", "IEX", "DownloadString",
        "subprocess", "os.system", "Runtime.getRuntime",
    ]

    for s in raw_strings:
        for cat, pattern in STRING_PATTERNS.items():
            for match in pattern.findall(s):
                categorized[cat].add(match)
        for kw in cmd_keywords:
            if kw.lower() in s.lower():
                categorized["suspicious_commands"].add(s.strip()[:200])

    return {
        cat: sorted(list(vals))[:30]
        for cat, vals in categorized.items()
        if vals
    }


# ── Main File Analysis Function ───────────────────────────────────────

def analyze_file(
    file_path: str,
    max_strings: int = 500,
) -> dict:
    """
    Enhanced static analysis:
      1. File metadata (size, magic bytes, entropy)
      2. Strings extraction + categorization
      3. YARAify remote scan (community YARA ruleset via abuse.ch)
    """
    result: dict[str, Any] = {
        "file_path": file_path,
        "metadata": {},
        "string_categories": {},
        "total_strings_extracted": 0,
        "yara_matches": [],
        "errors": [],
    }

    if not os.path.isfile(file_path):
        result["errors"].append(f"File not found: {file_path}")
        return result

    # 1) File metadata
    result["metadata"] = extract_file_metadata(file_path)

    # 2) Strings extraction + categorization
    try:
        proc = subprocess.run(
            ["strings", file_path],
            capture_output=True, text=True, timeout=30,
        )
        raw_lines = proc.stdout.strip().splitlines()[:max_strings]
        result["total_strings_extracted"] = len(raw_lines)
        result["string_categories"] = categorize_strings(raw_lines)
    except FileNotFoundError:
        result["errors"].append("`strings` command not found.")
    except subprocess.TimeoutExpired:
        result["errors"].append("`strings` timed out.")

    # 3) YARAify remote scan
    try:
        matches = yaraify_scan_file(file_path)
        for m in matches:
            result["yara_matches"].append({
                "rule": m["rule"],
                "tags": [],
                "meta": {
                    "author": m.get("author", ""),
                    "description": m.get("description", ""),
                    "reference": m.get("reference", ""),
                    "tlp": m.get("tlp", ""),
                },
                "matched_strings": [],
            })
    except RuntimeError as e:
        result["errors"].append(f"YARAify scan: {e}")
    except Exception as e:
        result["errors"].append(f"YARAify error: {e}")

    return result
