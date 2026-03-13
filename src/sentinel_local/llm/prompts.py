"""Prompt assembly for local LLM narrative generation."""

from __future__ import annotations

import json

from sentinel_local.domain.models import AnalysisResult, ExtractionResult, ParsedEmail


SYSTEM_PROMPT = """
You are assisting with email security analysis.
Use only the evidence provided.
Do not invent findings, checks, or enrichment results.
Do not change the deterministic verdict.
Return strict JSON with keys: summary, verdict_rationale, recommended_actions.
recommended_actions must be an array of short strings.
""".strip()


def build_narrative_prompt(
    *,
    parsed_email: ParsedEmail,
    extraction_result: ExtractionResult,
    analysis_result: AnalysisResult,
    analyst_note: str | None = None,
) -> str:
    """Build a concise evidence-first prompt for local narrative generation.

    Deliberately minimal — only the facts the LLM needs to narrate findings.
    Dumping the full ParsedEmail produces prompts that are too large for local
    models and cause timeouts or hallucination from context overflow.
    """
    sender = None
    if parsed_email.sender:
        sender = parsed_email.sender.email or parsed_email.sender.name

    # Body preview — cap at 600 chars to keep the prompt short
    body_preview = (parsed_email.text_body or "").strip()[:600]
    if len(parsed_email.text_body or "") > 600:
        body_preview += "…"

    # Top rule hits only (max 6, enough for narrative grounding)
    top_hits = [
        {
            "rule": h.rule_id,
            "title": h.title,
            "severity": h.severity,
            "score_delta": h.score_delta,
            "description": h.description,
        }
        for h in analysis_result.rule_hits[:6]
    ]

    # Key indicators — URLs and IPs only, capped at 8
    key_indicators = [
        {"type": ind.type, "value": ind.normalized_value}
        for ind in extraction_result.indicators
        if ind.type in {"url", "ip", "domain"}
    ][:8]

    payload = {
        "subject": parsed_email.subject,
        "sender": sender,
        "recipients": [r.email for r in parsed_email.recipients[:3] if r.email],
        "sent_at": parsed_email.sent_at.isoformat() if parsed_email.sent_at else None,
        "attachment_count": len(parsed_email.attachments),
        "attachment_names": [a.filename for a in parsed_email.attachments[:4]],
        "body_preview": body_preview,
        "verdict": analysis_result.verdict,
        "disposition": analysis_result.disposition,
        "confidence": analysis_result.confidence,
        "score": analysis_result.score,
        "rule_hits": top_hits,
        "key_indicators": key_indicators,
        "analyst_note": analyst_note,
    }
    return json.dumps(payload, indent=2, default=str)
