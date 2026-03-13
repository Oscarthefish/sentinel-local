"""Local analysis orchestration."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from tempfile import NamedTemporaryFile
from uuid import UUID

from pydantic import BaseModel, Field

from sentinel_local.attachment_scanners import scan_attachments_from_source
from sentinel_local.attachment_analysis import analyze_attachments
from sentinel_local.analyzers import analyze_email
from sentinel_local.case_summary import build_analyst_summary
from sentinel_local.core.config import get_settings
from sentinel_local.domain.models import (
    AnalysisResult,
    AnalystSummaryResult,
    AttachmentScanResult,
    EnrichmentResult,
    ExtractionResult,
    HeaderAnalysisResult,
    ParsedEmail,
    AttachmentAnalysisResult,
    UrlAnalysisResult,
)
from sentinel_local.enrichers import enrich_indicators
from sentinel_local.extractors import extract_indicators
from sentinel_local.header_analysis import analyze_headers
from sentinel_local.llm import generate_narrative_report
from sentinel_local.parsers import ParseRequest, parse_email_input
from sentinel_local.reports import render_html_report, render_markdown_report
from sentinel_local.storage.db import initialise_storage
from sentinel_local.storage.repository import get_saved_analysis, list_saved_analyses, save_analysis
from sentinel_local.url_analysis import analyze_urls


class AnalysisBundle(BaseModel):
    """Complete local analysis output for one email."""

    parsed_email: ParsedEmail
    extraction_result: ExtractionResult
    header_analysis_result: HeaderAnalysisResult = Field(default_factory=HeaderAnalysisResult)
    analysis_result: AnalysisResult
    analyst_summary_result: AnalystSummaryResult
    url_analysis_result: UrlAnalysisResult
    attachment_analysis_result: AttachmentAnalysisResult
    attachment_scan_result: AttachmentScanResult = Field(default_factory=AttachmentScanResult)
    enrichment_result: EnrichmentResult
    markdown_report: str
    html_report: str
    analyst_note: str | None = None
    narrative_report: dict | None = None
    analysis_id: str | None = None
    warnings: list[str] = Field(default_factory=list)


ProgressCallback = Callable[[str], None]


def build_analysis_stage_plan(
    *,
    generate_narrative: bool = False,
    run_enrichment: bool = False,
    run_attachment_scans: bool = False,
    resolve_urls: bool = False,
    capture_screenshots: bool = False,
) -> list[tuple[str, str]]:
    """Return the ordered stage plan used for one analysis run."""
    url_label = "Review links and HTML artifacts"
    if resolve_urls and capture_screenshots:
        url_label = "Review links, resolve redirects, and prepare screenshots"
    elif resolve_urls:
        url_label = "Review links and resolve redirects"
    elif capture_screenshots:
        url_label = "Review links and prepare screenshots"

    stages: list[tuple[str, str]] = [
        ("parse", "Parse message structure"),
        ("extract", "Extract indicators"),
        ("headers", "Analyze headers and mail flow"),
        ("urls", url_label),
        ("attachments", "Inspect attachment metadata"),
        ("score", "Score deterministic findings"),
    ]

    if run_attachment_scans:
        stages.append(("attachment_scans", "Run local attachment scanners"))
    if run_enrichment:
        stages.append(("enrichment", "Run optional enrichment"))
    if generate_narrative:
        stages.append(("narrative", "Draft local LLM narrative"))

    stages.extend(
        [
            ("summary", "Build analyst summary"),
            ("reports", "Render reports"),
            ("save", "Save case locally"),
        ]
    )

    return stages


def run_local_analysis(
    *,
    source_type: str,
    content: bytes | str | None = None,
    filename: str | None = None,
    raw_headers: str | None = None,
    analyst_note: str | None = None,
    generate_narrative: bool = False,
    run_enrichment: bool = False,
    run_attachment_scans: bool = False,
    resolve_urls: bool = False,
    capture_screenshots: bool = False,
    progress_callback: ProgressCallback | None = None,
) -> AnalysisBundle:
    """Run parsing, extraction, analysis, and report generation locally."""
    settings = get_settings()
    initialise_storage(settings)
    _notify_progress(progress_callback, "parse")
    parse_result = _parse_input(
        source_type=source_type,
        content=content,
        filename=filename,
        raw_headers=raw_headers,
        analyst_note=analyst_note,
    )
    _notify_progress(progress_callback, "extract")
    extraction_result = extract_indicators(parse_result.parsed_email)
    _notify_progress(progress_callback, "headers")
    header_analysis_result = analyze_headers(parse_result.parsed_email)
    _notify_progress(progress_callback, "urls")
    url_analysis_result = analyze_urls(
        parsed_email=parse_result.parsed_email,
        extraction_result=extraction_result,
        resolve_redirects=resolve_urls,
        enable_screenshots=capture_screenshots and settings.enable_url_screenshots,
        screenshot_provider=settings.screenshot_provider,
        screenshot_base_url=settings.screenshot_base_url,
        timeout_seconds=settings.url_resolution_timeout_seconds,
    )
    _notify_progress(progress_callback, "attachments")
    attachment_analysis_result = analyze_attachments(parse_result.parsed_email)
    attachment_scan_result = AttachmentScanResult()
    _notify_progress(progress_callback, "score")
    analysis_result = analyze_email(
        parse_result.parsed_email,
        extraction_result,
        attachment_analysis_result,
        header_analysis_result,
    )
    enrichment_result = EnrichmentResult()
    warnings: list[str] = []
    if run_attachment_scans and settings.enable_attachment_scanning:
        _notify_progress(progress_callback, "attachment_scans")
        try:
            attachment_scan_result = scan_attachments_from_source(
                settings=settings,
                source_type=source_type,
                content=content,
                filename=filename,
            )
            warnings.extend(attachment_scan_result.warnings)
        except Exception as exc:
            warnings.append(f"Attachment scanning skipped: {exc}")
    if run_enrichment and settings.enable_enrichment:
        _notify_progress(progress_callback, "enrichment")
        try:
            enrichment_result = enrich_indicators(
                settings=settings,
                extraction_result=extraction_result,
                parsed_email=parse_result.parsed_email,
            )
        except Exception as exc:
            warnings.append(f"Enrichment skipped: {exc}")
    narrative_report = None
    if generate_narrative and settings.enable_llm:
        _notify_progress(progress_callback, "narrative")
        try:
            narrative = generate_narrative_report(
                settings=settings,
                parsed_email=parse_result.parsed_email,
                extraction_result=extraction_result,
                analysis_result=analysis_result,
                analyst_note=parse_result.analyst_note,
            )
            narrative_report = narrative.model_dump()
        except Exception as exc:
            warnings.append(f"Local LLM narrative skipped: {exc}")
    _notify_progress(progress_callback, "summary")
    analyst_summary_result = build_analyst_summary(
        parsed_email=parse_result.parsed_email,
        extraction_result=extraction_result,
        header_analysis_result=header_analysis_result,
        analysis_result=analysis_result,
        url_analysis_result=url_analysis_result,
        attachment_analysis_result=attachment_analysis_result,
        attachment_scan_result=attachment_scan_result,
    )
    _notify_progress(progress_callback, "reports")
    markdown_report = render_markdown_report(
        parsed_email=parse_result.parsed_email,
        extraction_result=extraction_result,
        analysis_result=analysis_result,
        analyst_summary_result=analyst_summary_result,
        header_analysis_result=header_analysis_result,
        analyst_note=parse_result.analyst_note,
        narrative_report=narrative_report,
        url_analysis_result=url_analysis_result,
        attachment_analysis_result=attachment_analysis_result,
        attachment_scan_result=attachment_scan_result,
        enrichment_result=enrichment_result,
    )
    html_report = render_html_report(
        parsed_email=parse_result.parsed_email,
        extraction_result=extraction_result,
        analysis_result=analysis_result,
        analyst_summary_result=analyst_summary_result,
        header_analysis_result=header_analysis_result,
        analyst_note=parse_result.analyst_note,
        narrative_report=narrative_report,
        url_analysis_result=url_analysis_result,
        attachment_analysis_result=attachment_analysis_result,
        attachment_scan_result=attachment_scan_result,
        enrichment_result=enrichment_result,
    )
    _notify_progress(progress_callback, "save")
    saved = save_analysis(
        database_path=settings.sqlite_path,
        subject=parse_result.parsed_email.subject,
        sender=parse_result.parsed_email.sender.email if parse_result.parsed_email.sender else None,
        source_type=parse_result.parsed_email.source_type,
        verdict=analysis_result.verdict,
        score=analysis_result.score,
        confidence=analysis_result.confidence,
        analyst_note=parse_result.analyst_note,
        parsed_email=parse_result.parsed_email.model_dump(mode="json"),
        extraction_result=extraction_result.model_dump(mode="json"),
        header_analysis_result=header_analysis_result.model_dump(mode="json"),
        analysis_result=analysis_result.model_dump(mode="json"),
        analyst_summary_result=analyst_summary_result.model_dump(mode="json"),
        url_analysis_result=url_analysis_result.model_dump(mode="json"),
        attachment_analysis_result=attachment_analysis_result.model_dump(mode="json"),
        attachment_scan_result=attachment_scan_result.model_dump(mode="json"),
        enrichment_result=enrichment_result.model_dump(mode="json"),
        narrative_report=narrative_report,
        markdown_report=markdown_report,
    )

    return AnalysisBundle(
        parsed_email=parse_result.parsed_email,
        extraction_result=extraction_result,
        header_analysis_result=header_analysis_result,
        analysis_result=analysis_result,
        analyst_summary_result=analyst_summary_result,
        url_analysis_result=url_analysis_result,
        attachment_analysis_result=attachment_analysis_result,
        attachment_scan_result=attachment_scan_result,
        enrichment_result=enrichment_result,
        markdown_report=markdown_report,
        html_report=html_report,
        analyst_note=parse_result.analyst_note,
        narrative_report=narrative_report,
        analysis_id=str(saved.analysis_id),
        warnings=warnings,
    )


def _notify_progress(progress_callback: ProgressCallback | None, stage_id: str) -> None:
    if progress_callback is not None:
        progress_callback(stage_id)


def get_recent_analyses(limit: int = 25) -> list[dict]:
    """Return recent saved analyses for UI display."""
    settings = get_settings()
    initialise_storage(settings)
    records = list_saved_analyses(settings.sqlite_path, limit=limit)
    return [
        {
            "analysis_id": str(record.analysis_id),
            "created_at": record.created_at.isoformat(),
            "subject": record.subject,
            "sender": record.sender,
            "verdict": record.verdict,
            "score": record.score,
        }
        for record in records
    ]


def load_saved_analysis(analysis_id: str) -> AnalysisBundle | None:
    """Load one saved analysis and convert it back into an analysis bundle."""
    settings = get_settings()
    initialise_storage(settings)
    record = get_saved_analysis(settings.sqlite_path, UUID(analysis_id))
    if record is None:
        return None

    return AnalysisBundle(
        analysis_id=str(record.analysis_id),
        parsed_email=ParsedEmail.model_validate(record.parsed_email),
        extraction_result=ExtractionResult.model_validate(record.extraction_result),
        header_analysis_result=HeaderAnalysisResult.model_validate(record.header_analysis_result or {}),
        analysis_result=AnalysisResult.model_validate(record.analysis_result),
        analyst_summary_result=AnalystSummaryResult.model_validate(record.analyst_summary_result or {}),
        url_analysis_result=UrlAnalysisResult.model_validate(record.url_analysis_result or {}),
        attachment_analysis_result=AttachmentAnalysisResult.model_validate(record.attachment_analysis_result or {}),
        attachment_scan_result=AttachmentScanResult.model_validate(record.attachment_scan_result or {}),
        enrichment_result=EnrichmentResult.model_validate(record.enrichment_result or {}),
        markdown_report=record.markdown_report,
        html_report=render_html_report(
            parsed_email=ParsedEmail.model_validate(record.parsed_email),
            extraction_result=ExtractionResult.model_validate(record.extraction_result),
            analyst_summary_result=AnalystSummaryResult.model_validate(record.analyst_summary_result or {}),
            header_analysis_result=HeaderAnalysisResult.model_validate(record.header_analysis_result or {}),
            analysis_result=AnalysisResult.model_validate(record.analysis_result),
            analyst_note=record.analyst_note,
            narrative_report=record.narrative_report,
            url_analysis_result=UrlAnalysisResult.model_validate(record.url_analysis_result or {}),
            attachment_analysis_result=AttachmentAnalysisResult.model_validate(record.attachment_analysis_result or {}),
            attachment_scan_result=AttachmentScanResult.model_validate(record.attachment_scan_result or {}),
            enrichment_result=EnrichmentResult.model_validate(record.enrichment_result or {}),
        ),
        analyst_note=record.analyst_note,
        narrative_report=record.narrative_report,
        warnings=[],
    )


def _parse_input(
    *,
    source_type: str,
    content: bytes | str | None,
    filename: str | None,
    raw_headers: str | None,
    analyst_note: str | None,
):
    if source_type == "msg" and isinstance(content, bytes):
        suffix = Path(filename or "message.msg").suffix or ".msg"
        with NamedTemporaryFile(suffix=suffix, delete=False) as handle:
            handle.write(content)
            temp_path = Path(handle.name)
        try:
            return parse_email_input(
                ParseRequest(
                    source_type="msg",
                    file_path=temp_path,
                    raw_headers=raw_headers,
                    analyst_note=analyst_note,
                )
            )
        finally:
            temp_path.unlink(missing_ok=True)

    return parse_email_input(
        ParseRequest(
            source_type=source_type,
            content=content,
            raw_headers=raw_headers,
            analyst_note=analyst_note,
        )
    )
