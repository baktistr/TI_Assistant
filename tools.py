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

# ── YARA Rules ────────────────────────────────────────────────────────
# Four targeted rulesets instead of one catch-all.

YARA_RULES = r"""
rule Log4Shell_Indicators {
    meta:
        description = "Detects Log4Shell (CVE-2021-44228) JNDI injection patterns including obfuscation variants"
        severity = "critical"
        cve = "CVE-2021-44228"
    strings:
        // Direct JNDI patterns
        $jndi1 = "${jndi:ldap://" ascii nocase
        $jndi2 = "${jndi:rmi://" ascii nocase
        $jndi3 = "${jndi:dns://" ascii nocase
        $jndi4 = "${jndi:ldaps://" ascii nocase
        $jndi5 = "jndi:ldap" ascii nocase
        // Common obfuscation variants using Log4j lookup nesting
        $obf1 = "${${lower:j}" ascii nocase
        $obf2 = "${${upper:j}" ascii nocase
        $obf3 = "${${::-j}" ascii
        $obf4 = "${${env:" ascii nocase
        $obf5 = "${${date:" ascii nocase
        // Log4j component strings (context indicators, not proof of vuln)
        $comp1 = "log4j-core" ascii nocase
        $comp2 = "org.apache.logging.log4j" ascii nocase
        $comp3 = "JndiLookup.class" ascii nocase
    condition:
        any of ($jndi*) or any of ($obf*) or (2 of ($comp*))
}

rule Webshell_Indicators {
    meta:
        description = "Detects common webshell patterns in scripts"
        severity = "high"
    strings:
        $ws1 = "eval(base64_decode(" ascii nocase
        $ws2 = "eval($_POST[" ascii nocase
        $ws3 = "eval($_GET[" ascii nocase
        $ws4 = "eval($_REQUEST[" ascii nocase
        $ws5 = "assert($_POST[" ascii nocase
        $ws6 = "Runtime.getRuntime().exec(" ascii
        $ws7 = "ProcessBuilder" ascii
        $ws8 = "shell_exec(" ascii nocase
        $ws9 = "passthru(" ascii nocase
    condition:
        any of them
}

rule Suspicious_Script_Patterns {
    meta:
        description = "Detects suspicious command execution and script patterns"
        severity = "medium"
    strings:
        $cmd1 = "cmd.exe /c" ascii nocase
        $cmd2 = "cmd /c" ascii nocase
        $ps1  = "powershell -enc" ascii nocase
        $ps2  = "powershell -e " ascii nocase
        $ps3  = "powershell -nop" ascii nocase
        $ps4  = "Invoke-Expression" ascii nocase
        $ps5  = "IEX(" ascii nocase
        $ps6  = "New-Object Net.WebClient" ascii nocase
        $ps7  = "DownloadString(" ascii nocase
        $sh1  = "/bin/sh -c" ascii
        $sh2  = "/bin/bash -c" ascii
        $sh3  = "curl " ascii
        $sh4  = "wget " ascii
        $py1  = "__import__('os').system" ascii
        $py2  = "subprocess.call" ascii
    condition:
        2 of them
}

rule Encoded_Executable_Content {
    meta:
        description = "Detects base64-encoded PE headers or ELF magic inside text files"
        severity = "high"
    strings:
        // Base64 of "MZ" (PE header) -- common patterns
        $b64pe1 = "TVqQAAMAAAA" ascii
        $b64pe2 = "TVpQAAIAAAA" ascii
        // Base64 of ELF header
        $b64elf = "f0VMRg" ascii
        // PowerShell encoded command marker
        $b64ps = "-EncodedCommand" ascii nocase
        // Large base64 blob (100+ chars of base64 alphabet in a row)
        $b64blob = /[A-Za-z0-9+\/=]{100,}/
    condition:
        any of ($b64pe*) or $b64elf or ($b64ps and $b64blob)
}
"""


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
    yara_rule_text: str = YARA_RULES,
    max_strings: int = 500,
) -> dict:
    """
    Enhanced static analysis:
      1. File metadata (size, magic bytes, entropy)
      2. Strings extraction + categorization
      3. Multi-rule YARA scan
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

    # 3) YARA scan (fixed for yara-python 4.x StringMatch API)
    try:
        import yara
        rules = yara.compile(source=yara_rule_text)
        matches = rules.match(file_path)
        for m in matches:
            match_entry = {
                "rule": m.rule,
                "tags": m.tags,
                "meta": {k: v for k, v in m.meta.items()},
                "matched_strings": [],
            }
            for s in m.strings[:20]:
                for inst in s.instances:
                    match_entry["matched_strings"].append({
                        "offset": inst.offset,
                        "identifier": s.identifier,
                        "data": inst.matched_data.decode("utf-8", errors="replace")[:100],
                    })
            result["yara_matches"].append(match_entry)
    except ImportError:
        result["errors"].append(
            "yara-python not installed; skipping YARA scan. "
            "Install with: pip install yara-python"
        )
    except Exception as e:
        result["errors"].append(f"YARA error: {e}")

    return result
