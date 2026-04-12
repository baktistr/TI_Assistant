---
title: TI_Assistant
emoji: "\U0001f6e1\ufe0f"
colorFrom: blue
colorTo: red
sdk: streamlit
sdk_version: "1.56.0"
app_file: app.py
pinned: false
license: mit
short_description: RAG-powered Threat Intelligence Assistant
---

# Threat Intelligence Assistant

RAG-powered threat analysis dashboard with CVE lookup, MITRE ATT&CK mapping, and static file analysis (YARA).

## Features

- **3-stage LLM pipeline**: Task Routing -> Evidence Analysis -> Report Generation
- **4 modes**: full, rag, no_tools, raw
- **CVE Knowledge Base**: 205 CVEs from NVD (2021) with semantic search
- **ATT&CK Knowledge Base**: 691 MITRE ATT&CK techniques
- **Static File Analysis**: YARA rules + string extraction + entropy analysis
- **Evaluation Suite**: 5 test cases x 4 modes with 4-dimensional scoring

## Setup

1. Enter your OpenAI API key when prompted (or set `OPENAI_API_KEY` in Space Secrets)
2. The knowledge base initializes automatically on first load

## Built with

Python, Streamlit, OpenAI (gpt-4o-mini), ChromaDB, sentence-transformers, YARA
