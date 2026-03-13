import json

import httpx

from sentinel_local.core.config import Settings
from sentinel_local.domain.models import AnalysisResult, ExtractionResult, ParsedEmail
from sentinel_local.llm import generate_narrative_report
from sentinel_local.llm.prompts import build_narrative_prompt


def test_build_narrative_prompt_contains_deterministic_sections() -> None:
    prompt = build_narrative_prompt(
        parsed_email=ParsedEmail(source_type="pasted", subject="Test"),
        extraction_result=ExtractionResult(),
        analysis_result=AnalysisResult(score=10, verdict="benign", confidence="low"),
        analyst_note="SOC ticket",
    )

    assert '"parsed_email"' in prompt
    assert '"analysis"' in prompt
    assert '"analyst_note": "SOC ticket"' in prompt


def test_generate_narrative_report_uses_ollama_json_contract() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/chat"
        payload = json.loads(request.content.decode())
        assert payload["model"] == "qwen2.5:7b-instruct"
        return httpx.Response(
            200,
            json={
                "message": {
                    "content": json.dumps(
                        {
                            "summary": "Suspicious login lure targeting the analyst.",
                            "verdict_rationale": "Deterministic rules identified domain mismatch and lure language.",
                            "recommended_actions": ["Block sender", "Reset exposed credentials"],
                        }
                    )
                }
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    settings = Settings(ENABLE_LLM=True, LLM_PROVIDER="ollama", OLLAMA_MODEL="qwen2.5:7b-instruct")

    report = generate_narrative_report(
        settings=settings,
        parsed_email=ParsedEmail(source_type="pasted", subject="Test"),
        extraction_result=ExtractionResult(),
        analysis_result=AnalysisResult(score=30, verdict="suspicious", confidence="medium"),
        client=client,
    )

    assert report.summary.startswith("Suspicious login")
    assert report.recommended_actions == ["Block sender", "Reset exposed credentials"]
