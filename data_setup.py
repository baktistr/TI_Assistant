"""
Data setup module for Threat Intelligence Assistant.

Handles NVD CVE download (2.0 API with 120-day window splitting),
MITRE ATT&CK STIX parsing, ChromaDB initialization with
sentence-transformer embeddings, and high-profile CVE injection.
"""

import os
import json
import time
import urllib.request
from pathlib import Path
from datetime import datetime, timedelta

from dotenv import load_dotenv

load_dotenv()

# ── Module-level shared objects (set by initialize()) ────────────────
DATA_DIR = Path("data")
cve_col = None
attck_col = None
client = None  # ChromaDB client
ef = None  # embedding function


# ═══════════════════════════════════════════════════════════════════════
# NVD 2.0 REST API Download
# ═══════════════════════════════════════════════════════════════════════

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_DATE_RANGE_DAYS = 120


def _nvd_get(url: str, api_key: str) -> dict:
    """Send a single GET request to NVD with proper headers."""
    req = urllib.request.Request(url)
    req.add_header("User-Agent", "ThreatIntelPipeline/1.0")
    if api_key:
        req.add_header("apiKey", api_key)
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode())


def _date_windows(year: int) -> list[tuple[str, str]]:
    """Split a full year into <=120-day ISO windows for NVD API."""
    start = datetime(year, 1, 1)
    end = datetime(year, 12, 31, 23, 59, 59)
    windows = []
    cursor = start
    while cursor <= end:
        window_end = min(cursor + timedelta(days=MAX_DATE_RANGE_DAYS - 1), end)
        windows.append((
            cursor.strftime("%Y-%m-%dT%H:%M:%S.000"),
            window_end.strftime("%Y-%m-%dT%H:%M:%S.999"),
        ))
        cursor = window_end + timedelta(seconds=1)
    return windows


def fetch_nvd_cves(
    api_key: str,
    year: int = 2021,
    target: int = 200,
    page_size: int = 100,
) -> list[dict]:
    """
    Fetch CVEs from NVD 2.0 API.
    Splits the year into <=120-day windows and paginates within each.
    """
    all_vulns = []
    windows = _date_windows(year)
    sleep_sec = 0.8 if api_key else 6

    for win_start, win_end in windows:
        if len(all_vulns) >= target:
            break
        start_index = 0

        while len(all_vulns) < target:
            url = (
                f"{NVD_BASE}"
                f"?pubStartDate={win_start}"
                f"&pubEndDate={win_end}"
                f"&resultsPerPage={page_size}"
                f"&startIndex={start_index}"
            )
            print(f"  [{win_start[:10]} – {win_end[:10]}] "
                  f"startIndex={start_index} …", end=" ")
            data = _nvd_get(url, api_key)

            batch = data.get("vulnerabilities", [])
            if not batch:
                print("0 results, moving on.")
                break
            all_vulns.extend(batch)
            total_in_window = data.get("totalResults", 0)
            print(f"got {len(batch)} (window total: {total_in_window}, "
                  f"cumulative: {len(all_vulns)})")

            start_index += page_size
            if start_index >= total_in_window:
                break

            time.sleep(sleep_sec)

        time.sleep(sleep_sec)

    return all_vulns[:target]


# ═══════════════════════════════════════════════════════════════════════
# CVE Parsing (NVD 2.0 format)
# ═══════════════════════════════════════════════════════════════════════

MAX_CVE = 200


def parse_cve_item_v2(vuln_wrapper: dict) -> dict | None:
    """Flatten one NVD 2.0 vulnerability object into a simple dict."""
    cve = vuln_wrapper.get("cve", {})
    cve_id = cve.get("id", "")

    descs = cve.get("descriptions", [])
    desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")
    if not desc or desc.startswith("** REJECT"):
        return None

    metrics = cve.get("metrics", {})
    cvss_list = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))
    score, severity, vector = None, "UNKNOWN", ""
    if cvss_list:
        primary = next((m for m in cvss_list if m.get("type") == "Primary"), cvss_list[0])
        cvss_data = primary.get("cvssData", {})
        score = cvss_data.get("baseScore")
        severity = cvss_data.get("baseSeverity", "UNKNOWN")
        vector = cvss_data.get("vectorString", "")

    refs = cve.get("references", [])
    ref_urls = [r["url"] for r in refs[:3]]

    return {
        "cve_id": cve_id,
        "description": desc,
        "cvss3_score": score,
        "severity": severity,
        "vector": vector,
        "references": ref_urls,
    }


# ═══════════════════════════════════════════════════════════════════════
# ATT&CK Parsing
# ═══════════════════════════════════════════════════════════════════════

MAX_ATTCK = None  # load all techniques (typically ~600)


def parse_attck_technique(obj: dict) -> dict | None:
    """Flatten one STIX attack-pattern into a simple dict."""
    if obj.get("type") != "attack-pattern":
        return None
    if obj.get("revoked") or obj.get("x_mitre_deprecated"):
        return None
    ext_refs = obj.get("external_references", [])
    mitre_ref = next(
        (r for r in ext_refs if r.get("source_name") == "mitre-attack"), None
    )
    if not mitre_ref:
        return None
    tid = mitre_ref.get("external_id", "")
    tactics = [
        p["phase_name"]
        for p in obj.get("kill_chain_phases", [])
        if p.get("kill_chain_name") == "mitre-attack"
    ]
    return {
        "technique_id": tid,
        "name": obj.get("name", ""),
        "description": obj.get("description", "")[:800],
        "tactics": tactics,
    }


# ═══════════════════════════════════════════════════════════════════════
# High-Profile CVEs for Injection
# ═══════════════════════════════════════════════════════════════════════

HIGH_PROFILE_CVES = [
    {
        "cve_id": "CVE-2021-44228",
        "description": (
            "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security "
            "releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in "
            "configuration, log messages, and parameters do not protect "
            "against attacker controlled LDAP and other JNDI related "
            "endpoints. An attacker who can control log messages or log "
            "message parameters can execute arbitrary code loaded from "
            "LDAP servers when message lookup substitution is enabled."
        ),
        "cvss3_score": 10.0,
        "severity": "CRITICAL",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    },
    {
        "cve_id": "CVE-2021-45046",
        "description": (
            "It was found that the fix to address CVE-2021-44228 in Apache "
            "Log4j 2.15.0 was incomplete in certain non-default configurations. "
            "This could allow attackers to craft malicious input data using a "
            "JNDI Lookup pattern resulting in an information leak and remote "
            "code execution in some environments and local code execution in "
            "all environments."
        ),
        "cvss3_score": 9.0,
        "severity": "CRITICAL",
        "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H",
    },
    {
        "cve_id": "CVE-2021-34527",
        "description": (
            "A remote code execution vulnerability exists when the Windows "
            "Print Spooler service improperly performs privileged file "
            "operations. An attacker who successfully exploited this "
            "vulnerability could run arbitrary code with SYSTEM privileges. "
            "An attacker could then install programs; view, change, or "
            "delete data; or create new accounts with full user rights. "
            "This vulnerability is known as PrintNightmare."
        ),
        "cvss3_score": 8.8,
        "severity": "HIGH",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    },
    {
        "cve_id": "CVE-2021-34473",
        "description": (
            "Microsoft Exchange Server Remote Code Execution Vulnerability. "
            "This is part of the ProxyShell exploit chain. A pre-authentication "
            "path confusion vulnerability allows an unauthenticated attacker "
            "to access backend URLs intended for authenticated users, leading "
            "to remote code execution when chained with CVE-2021-34523 and "
            "CVE-2021-31207."
        ),
        "cvss3_score": 9.8,
        "severity": "CRITICAL",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    },
    {
        "cve_id": "CVE-2021-26855",
        "description": (
            "Microsoft Exchange Server Remote Code Execution Vulnerability. "
            "This vulnerability is part of the ProxyLogon exploit chain. "
            "A server-side request forgery (SSRF) vulnerability in Exchange "
            "allows an attacker to send arbitrary HTTP requests and "
            "authenticate as the Exchange server."
        ),
        "cvss3_score": 9.8,
        "severity": "CRITICAL",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    },
]


# ═══════════════════════════════════════════════════════════════════════
# Initialization
# ═══════════════════════════════════════════════════════════════════════

def initialize():
    """
    Run the full data pipeline:
      1. Download / load NVD CVE data
      2. Download / load MITRE ATT&CK data
      3. Parse CVEs and ATT&CK techniques
      4. Set up ChromaDB with sentence-transformer embeddings
      5. Populate CVE and ATT&CK collections
      6. Inject high-profile CVEs

    Sets module-level cve_col and attck_col for use by other modules.
    """
    global cve_col, attck_col, client, ef

    import chromadb
    from chromadb.utils import embedding_functions

    DATA_DIR.mkdir(exist_ok=True)

    # ── 1. NVD CVE download / cache ──────────────────────────────────
    NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
    CVE_CACHE = DATA_DIR / "nvd_cve_2021_sample.json"

    if not CVE_CACHE.exists():
        if NVD_API_KEY:
            print(f"API key detected (ends …{NVD_API_KEY[-4:]})")
        else:
            print("No NVD_API_KEY found — using public rate limit (slow).")
        print("Fetching CVEs from NVD 2.0 API …")
        try:
            raw_vulns = fetch_nvd_cves(NVD_API_KEY)
            with open(CVE_CACHE, "w") as f:
                json.dump(raw_vulns, f)
            print(f"Cached {len(raw_vulns)} CVEs → {CVE_CACHE}")
        except Exception as e:
            print(f"NVD API failed ({e}); will use synthetic fallback.")
            raw_vulns = None
    else:
        with open(CVE_CACHE, "r") as f:
            raw_vulns = json.load(f)
        print(f"Loaded {len(raw_vulns)} cached CVEs from {CVE_CACHE}")

    # ── 2. ATT&CK download / cache ──────────────────────────────────
    ATTCK_JSON = DATA_DIR / "enterprise-attack.json"
    ATTCK_URL = (
        "https://raw.githubusercontent.com/mitre/cti/master/"
        "enterprise-attack/enterprise-attack.json"
    )

    if not ATTCK_JSON.exists():
        print("Downloading MITRE ATT&CK enterprise JSON …")
        try:
            urllib.request.urlretrieve(ATTCK_URL, ATTCK_JSON)
        except Exception as e:
            print(f"Download failed ({e}); will use synthetic sample.")

    attck_raw = None
    if ATTCK_JSON.exists():
        with open(ATTCK_JSON, "r") as f:
            attck_raw = json.load(f)

    print("Raw data loaded.")

    # ── 3. Parse CVEs ────────────────────────────────────────────────
    if raw_vulns:
        cve_entries = []
        for item in raw_vulns:
            parsed = parse_cve_item_v2(item)
            if parsed:
                cve_entries.append(parsed)
            if len(cve_entries) >= MAX_CVE:
                break
    else:
        cve_entries = [
            {
                "cve_id": "CVE-2021-44228",
                "description": (
                    "Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features do not "
                    "protect against attacker controlled LDAP and other JNDI related "
                    "endpoints. An attacker who can control log messages can execute "
                    "arbitrary code loaded from LDAP servers when message lookup "
                    "substitution is enabled."
                ),
                "cvss3_score": 10.0, "severity": "CRITICAL",
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                "references": ["https://logging.apache.org/log4j/2.x/security.html"],
            },
            {
                "cve_id": "CVE-2021-34527",
                "description": (
                    "Windows Print Spooler Remote Code Execution Vulnerability "
                    "(PrintNightmare)."
                ),
                "cvss3_score": 8.8, "severity": "HIGH",
                "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                "references": ["https://msrc.microsoft.com/update-guide"],
            },
        ]
        print("Using synthetic CVE sample (2 entries).")

    print(f"CVE entries ready: {len(cve_entries)}")

    # ── 4. Parse ATT&CK techniques ──────────────────────────────────
    if attck_raw:
        attck_techniques = []
        for obj in attck_raw.get("objects", []):
            parsed = parse_attck_technique(obj)
            if parsed:
                attck_techniques.append(parsed)
    else:
        attck_techniques = [
            {
                "technique_id": "T1190",
                "name": "Exploit Public-Facing Application",
                "description": (
                    "Adversaries may attempt to exploit a weakness in an "
                    "Internet-facing host or system to initially access a network."
                ),
                "tactics": ["initial-access"],
            },
            {
                "technique_id": "T1059",
                "name": "Command and Scripting Interpreter",
                "description": (
                    "Adversaries may abuse command and script interpreters to "
                    "execute commands, scripts, or binaries."
                ),
                "tactics": ["execution"],
            },
        ]
        print("Using synthetic ATT&CK sample (2 entries).")

    print(f"ATT&CK techniques ready: {len(attck_techniques)}")

    # ── 5. ChromaDB setup ────────────────────────────────────────────
    EMBED_MODEL_PRIMARY = "multi-qa-mpnet-base-dot-v1"
    EMBED_MODEL_FALLBACK = "all-MiniLM-L6-v2"

    try:
        ef = embedding_functions.SentenceTransformerEmbeddingFunction(
            model_name=EMBED_MODEL_PRIMARY
        )
        _ = ef(["test"])
        embed_model = EMBED_MODEL_PRIMARY
        print(f"Loaded primary model: {EMBED_MODEL_PRIMARY} (768d)")
    except Exception as e:
        print(f"Primary model failed ({e}), falling back to MiniLM.")
        ef = embedding_functions.SentenceTransformerEmbeddingFunction(
            model_name=EMBED_MODEL_FALLBACK
        )
        embed_model = EMBED_MODEL_FALLBACK

    CHROMA_DIR = str(DATA_DIR / "chromadb")
    client = chromadb.PersistentClient(path=CHROMA_DIR)

    print(f"ChromaDB client ready  (persist dir: {CHROMA_DIR})")
    print(f"Embedding model: {embed_model}")

    # ── 6. Populate CVE collection ───────────────────────────────────
    cve_col = client.get_or_create_collection(
        name="cve_kb", embedding_function=ef
    )

    if cve_col.count() == 0:
        print(f"Embedding {len(cve_entries)} CVE entries …")
        cve_col.add(
            ids=[e["cve_id"] for e in cve_entries],
            documents=[
                f"{e['cve_id']}: {e['description']}" for e in cve_entries
            ],
            metadatas=[
                {
                    "cve_id": e["cve_id"],
                    "severity": e["severity"],
                    "cvss3_score": e["cvss3_score"] or 0.0,
                    "vector": e["vector"],
                }
                for e in cve_entries
            ],
        )
        print("Done.")
    else:
        print(f"CVE collection already populated ({cve_col.count()} docs).")

    # ── 7. Populate ATT&CK collection ────────────────────────────────
    attck_col = client.get_or_create_collection(
        name="attck_kb", embedding_function=ef
    )

    if attck_col.count() == 0:
        print(f"Embedding {len(attck_techniques)} ATT&CK techniques …")
        attck_col.add(
            ids=[t["technique_id"] for t in attck_techniques],
            documents=[
                f"{t['technique_id']} {t['name']}: {t['description']}"
                for t in attck_techniques
            ],
            metadatas=[
                {
                    "technique_id": t["technique_id"],
                    "name": t["name"],
                    "tactics": ", ".join(t["tactics"]),
                }
                for t in attck_techniques
            ],
        )
        print("Done.")
    else:
        print(f"ATT&CK collection already populated ({attck_col.count()} docs).")

    print(f"\nCVE docs:   {cve_col.count()}")
    print(f"ATT&CK docs: {attck_col.count()}")

    # ── 8. Inject high-profile CVEs ──────────────────────────────────
    existing_ids = set(cve_col.get()["ids"])
    to_add = [c for c in HIGH_PROFILE_CVES if c["cve_id"] not in existing_ids]

    if to_add:
        cve_col.add(
            ids=[c["cve_id"] for c in to_add],
            documents=[f"{c['cve_id']}: {c['description']}" for c in to_add],
            metadatas=[
                {
                    "cve_id": c["cve_id"],
                    "severity": c["severity"],
                    "cvss3_score": c["cvss3_score"],
                    "vector": c["vector"],
                }
                for c in to_add
            ],
        )
        print(f"Injected {len(to_add)} high-profile CVEs: "
              f"{[c['cve_id'] for c in to_add]}")
    else:
        print("High-profile CVEs already present in collection.")

    verify = cve_col.get(ids=["CVE-2021-44228"])
    print(f"Verification — CVE-2021-44228 in DB: {bool(verify['ids'])}")
    print(f"Total CVE docs: {cve_col.count()}")

    print("\n✓ Initialization complete.")
