# Sentinel Local

## Purpose
Build a local-first email analysis and triage tool for macOS.

## Core rules
- Use FastAPI for backend APIs.
- Use Streamlit for the Version 1 UI.
- Use SQLite for local storage.
- Keep parsing, extraction, rules, scoring, and verdict logic deterministic.
- Use the LLM only for summary, explanation, and narrative reporting.
- Never hard-code secrets.
- Keep enrichment modular and optional.
- Do not auto-submit attachments to external services.

## Engineering rules
- Use Python type hints.
- Keep functions focused and testable.
- Use Pydantic models for structured schemas.
- Add tests for new behavior where practical.
- Fail safely and log clearly.
