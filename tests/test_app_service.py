from sentinel_local.app.service import build_analysis_stage_plan, run_local_analysis
from sentinel_local.core.config import Settings, get_settings


def test_run_local_analysis_degrades_gracefully_when_optional_steps_fail(monkeypatch) -> None:
    monkeypatch.setattr(
        "sentinel_local.app.service.enrich_indicators",
        lambda **kwargs: (_ for _ in ()).throw(RuntimeError("enrichment timeout")),
    )
    monkeypatch.setattr(
        "sentinel_local.app.service.generate_narrative_report",
        lambda **kwargs: (_ for _ in ()).throw(RuntimeError("llm timeout")),
    )
    monkeypatch.setattr(
        "sentinel_local.app.service.get_settings",
        lambda: Settings(enable_enrichment=True, enable_llm=True),
    )

    bundle = run_local_analysis(
        source_type="pasted",
        content="Subject: Test\n\nPlease review this login alert.",
        generate_narrative=True,
        run_enrichment=True,
    )

    assert bundle.analysis_result.verdict in {"benign", "suspicious", "malicious"}
    assert bundle.analyst_summary_result.summary
    assert len(bundle.warnings) == 2
    assert any("Enrichment skipped" in warning for warning in bundle.warnings)
    assert any("Local LLM narrative skipped" in warning for warning in bundle.warnings)


def test_build_analysis_stage_plan_reflects_enabled_optional_steps() -> None:
    stage_plan = build_analysis_stage_plan(
        generate_narrative=True,
        run_enrichment=True,
        run_attachment_scans=True,
        resolve_urls=True,
        capture_screenshots=True,
    )

    stage_ids = [stage_id for stage_id, _ in stage_plan]
    url_stage = dict(stage_plan)["urls"]

    assert stage_ids == [
        "parse",
        "extract",
        "headers",
        "urls",
        "attachments",
        "score",
        "attachment_scans",
        "enrichment",
        "narrative",
        "summary",
        "reports",
        "save",
    ]
    assert "resolve redirects" in url_stage
    assert "screenshots" in url_stage
