"""
Shared utilities for the Streamlit dashboard.

Provides:
  - init_knowledge_base(): cached ChromaDB + embedding init (runs once)
  - run_pipeline_quiet(): stdout-suppressed pipeline runner
  - ensure_session_state(): session state initializer
  - save_history() / load_history(): JSON persistence for run history
"""

import io
import os
import json
import contextlib
from datetime import datetime
from pathlib import Path

import streamlit as st
import data_setup
import pipeline
from pipeline import run_pipeline, set_api_key

HISTORY_FILE = Path("data/dashboard_history.json")


def require_api_key():
    """Ensure API key is set. Shows input form and stops if not provided."""
    if "api_key" not in st.session_state:
        st.session_state.api_key = ""
    if not st.session_state.api_key:
        st.warning("Enter your OpenAI API key on the main page first.")
        st.stop()
    if pipeline.oai is None:
        set_api_key(st.session_state.api_key)


@st.cache_resource(show_spinner="Loading knowledge base (first run only)...")
def _init_kb_cached():
    """Internal cached init. Runs once per server process."""
    data_setup.initialize()
    return True


def init_knowledge_base():
    """Initialize ChromaDB collections. Re-initializes if globals were lost."""
    _init_kb_cached()
    # Safety: if module globals got reset (e.g. module reload), re-init
    if data_setup.cve_col is None or data_setup.attck_col is None:
        data_setup.initialize()


def run_pipeline_quiet(user_query: str, file_path: str = None, mode: str = "full"):
    """Run the pipeline while capturing stdout. Returns (trace_dict, log_str)."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        trace = run_pipeline(user_query, file_path=file_path, mode=mode, verbose=True)
    trace["timestamp"] = datetime.now().isoformat()
    return trace, buf.getvalue()


def ensure_session_state():
    """Initialize session state keys if not already present."""
    if "history" not in st.session_state:
        st.session_state.history = load_history()
    if "current_trace" not in st.session_state:
        st.session_state.current_trace = None
    if "current_log" not in st.session_state:
        st.session_state.current_log = ""


def save_history():
    """Persist run history to a JSON file."""
    HISTORY_FILE.parent.mkdir(exist_ok=True)
    with open(HISTORY_FILE, "w") as f:
        json.dump(st.session_state.history, f, default=str, indent=2)


def load_history() -> list:
    """Load run history from JSON file."""
    if HISTORY_FILE.exists():
        try:
            with open(HISTORY_FILE) as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return []
    return []
