from pathlib import Path

from sentinel_local.analyzers import analyze_email
from sentinel_local.domain.models import EnrichmentResult
from sentinel_local.extractors import extract_indicators
from sentinel_local.parsers import ParseRequest, parse_email_input
from sentinel_local.reports import render_html_report, render_markdown_report


FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_markdown_report_includes_core_sections() -> None:
    parsed = parse_email_input(
        ParseRequest(source_type="eml", file_path=FIXTURES_DIR / "sample_email.eml")
    ).parsed_email
    extraction = extract_indicators(parsed)
    analysis = analyze_email(parsed, extraction)

    report = render_markdown_report(
        parsed_email=parsed,
        extraction_result=extraction,
        analysis_result=analysis,
        analyst_note="Raised by help desk",
    )

    assert "# Sentinel Local Report" in report
    assert "## Summary" in report
    assert "## Analyst Summary" in report
    assert "## Rule Hits" in report
    assert "## Local Attachment Scans" in report
    assert "## Indicators" in report
    assert "Raised by help desk" in report
    assert parsed.subject in report


def test_html_report_includes_core_sections() -> None:
    parsed = parse_email_input(
        ParseRequest(source_type="eml", file_path=FIXTURES_DIR / "sample_email.eml")
    ).parsed_email
    extraction = extract_indicators(parsed)
    analysis = analyze_email(parsed, extraction)

    report = render_html_report(
        parsed_email=parsed,
        extraction_result=extraction,
        analysis_result=analysis,
        analyst_note="Raised by help desk",
        enrichment_result=EnrichmentResult(),
    )

    assert "<!DOCTYPE html>" in report
    assert "Sentinel Local Report" in report
    assert "Analyst Summary" in report
    assert "Local Attachment Scans" in report
    assert "Raised by help desk" in report
    assert parsed.subject in report
