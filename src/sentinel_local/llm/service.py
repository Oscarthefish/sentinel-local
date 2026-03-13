"""LLM narrative generation service."""

from __future__ import annotations

import httpx
from pydantic import ValidationError

from sentinel_local.core.config import Settings
from sentinel_local.domain.models import AnalysisResult, ExtractionResult, NarrativeReport, ParsedEmail
from sentinel_local.llm.prompts import SYSTEM_PROMPT, build_narrative_prompt
from sentinel_local.llm.providers import invoke_ollama, invoke_openai_compatible, parse_json_response


def generate_narrative_report(
    *,
    settings: Settings,
    parsed_email: ParsedEmail,
    extraction_result: ExtractionResult,
    analysis_result: AnalysisResult,
    analyst_note: str | None = None,
    client: httpx.Client | None = None,
) -> NarrativeReport:
    """Generate a local LLM narrative grounded in deterministic evidence."""
    prompt = build_narrative_prompt(
        parsed_email=parsed_email,
        extraction_result=extraction_result,
        analysis_result=analysis_result,
        analyst_note=analyst_note,
    )

    if settings.llm_provider == "ollama":
        if not settings.ollama_model:
            raise ValueError("SENTINEL_OLLAMA_MODEL is not configured.")
        raw = invoke_ollama(
            base_url=settings.ollama_base_url,
            model=settings.ollama_model,
            system_prompt=SYSTEM_PROMPT,
            prompt=prompt,
            timeout_seconds=settings.llm_timeout_seconds,
            client=client,
        )
    elif settings.llm_provider == "lm_studio":
        if not settings.lm_studio_model:
            raise ValueError("SENTINEL_LM_STUDIO_MODEL is not configured.")
        raw = invoke_openai_compatible(
            base_url=settings.lm_studio_base_url or "http://127.0.0.1:1234",
            model=settings.lm_studio_model,
            system_prompt=SYSTEM_PROMPT,
            prompt=prompt,
            timeout_seconds=settings.llm_timeout_seconds,
            client=client,
        )
    else:
        raise ValueError(f"Unsupported LLM provider: {settings.llm_provider}")

    try:
        return NarrativeReport.model_validate(parse_json_response(raw))
    except (ValidationError, ValueError) as exc:
        raise ValueError(f"Local model returned an invalid narrative payload: {exc}") from exc
