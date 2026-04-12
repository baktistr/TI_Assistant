"""
Knowledge Base Explorer — Browse and search CVE and ATT&CK ChromaDB collections.
"""

import streamlit as st
import pandas as pd

import data_setup
from dashboard_utils import init_knowledge_base, ensure_session_state, require_api_key

st.set_page_config(page_title="Knowledge Base", page_icon="\U0001f4da", layout="wide")
ensure_session_state()
require_api_key()

try:
    init_knowledge_base()
except Exception as e:
    st.error(f"Failed to initialize knowledge base: {e}")
    st.stop()

st.title("Knowledge Base Explorer")
st.caption("Browse and search the CVE and ATT&CK vector database collections.")

cve_col = data_setup.cve_col
attck_col = data_setup.attck_col

if not cve_col or not attck_col:
    st.error("Knowledge base collections not loaded.")
    st.stop()

# ── Collection stats ─────────────────────────────────────────────────
cve_count = cve_col.count()
attck_count = attck_col.count()

s1, s2 = st.columns(2)
s1.metric("CVE Documents", cve_count)
s2.metric("ATT&CK Techniques", attck_count)

st.divider()

# ── Collection selector ──────────────────────────────────────────────
collection_choice = st.radio(
    "Select Collection",
    ["CVE Knowledge Base", "ATT&CK Techniques"],
    horizontal=True,
)

is_cve = collection_choice == "CVE Knowledge Base"
col = cve_col if is_cve else attck_col
doc_count = cve_count if is_cve else attck_count

st.divider()

# ── Tabs: Browse / Search ────────────────────────────────────────────
browse_tab, search_tab = st.tabs(["Browse", "Semantic Search"])

# ── Browse tab ───────────────────────────────────────────────────────
with browse_tab:
    PAGE_SIZE = 25
    total_pages = max(1, (doc_count + PAGE_SIZE - 1) // PAGE_SIZE)
    page = st.number_input("Page", min_value=1, max_value=total_pages, value=1, step=1)
    offset = (page - 1) * PAGE_SIZE

    data = col.get(
        limit=PAGE_SIZE,
        offset=offset,
        include=["documents", "metadatas"],
    )

    if data and data["ids"]:
        rows = []
        for i, doc_id in enumerate(data["ids"]):
            meta = data["metadatas"][i] if data["metadatas"] else {}
            doc_text = data["documents"][i] if data["documents"] else ""

            if is_cve:
                rows.append({
                    "ID": doc_id,
                    "CVSS Score": meta.get("cvss3_score", "N/A"),
                    "Severity": meta.get("severity", "N/A"),
                    "Description": doc_text[:200] + "..." if len(doc_text) > 200 else doc_text,
                })
            else:
                rows.append({
                    "Technique ID": meta.get("technique_id", doc_id),
                    "Name": meta.get("name", "N/A"),
                    "Tactics": meta.get("tactics", "N/A"),
                    "Description": doc_text[:200] + "..." if len(doc_text) > 200 else doc_text,
                })

        st.dataframe(pd.DataFrame(rows), use_container_width=True, height=650)
        st.caption(f"Page {page} of {total_pages} ({doc_count} total documents)")
    else:
        st.info("No documents found at this offset.")

# ── Search tab ───────────────────────────────────────────────────────
with search_tab:
    search_query = st.text_input(
        "Enter a semantic search query",
        placeholder="e.g., Log4Shell JNDI injection" if is_cve else "e.g., lateral movement techniques",
    )
    n_results = st.slider("Number of results", min_value=1, max_value=25, value=10)

    if st.button("Search", type="primary") and search_query.strip():
        with st.spinner("Searching..."):
            results = col.query(
                query_texts=[search_query.strip()],
                n_results=n_results,
                include=["documents", "metadatas", "distances"],
            )

        if results and results["ids"] and results["ids"][0]:
            rows = []
            for i, doc_id in enumerate(results["ids"][0]):
                meta = results["metadatas"][0][i] if results["metadatas"] else {}
                doc_text = results["documents"][0][i] if results["documents"] else ""
                distance = results["distances"][0][i] if results["distances"] else None
                relevance = round(1.0 - distance / 2.0, 3) if distance is not None else None

                if is_cve:
                    rows.append({
                        "ID": doc_id,
                        "CVSS": meta.get("cvss3_score", "N/A"),
                        "Severity": meta.get("severity", "N/A"),
                        "Relevance": relevance,
                        "Distance": round(distance, 4) if distance is not None else "N/A",
                        "Description": doc_text[:300] + "..." if len(doc_text) > 300 else doc_text,
                    })
                else:
                    rows.append({
                        "Technique ID": meta.get("technique_id", doc_id),
                        "Name": meta.get("name", "N/A"),
                        "Tactics": meta.get("tactics", "N/A"),
                        "Relevance": relevance,
                        "Distance": round(distance, 4) if distance is not None else "N/A",
                        "Description": doc_text[:300] + "..." if len(doc_text) > 300 else doc_text,
                    })

            df = pd.DataFrame(rows)
            st.dataframe(df, use_container_width=True)
            st.caption(f"Found {len(rows)} results. Lower distance = more relevant.")
        else:
            st.warning("No results found for this query.")
