"""Markdown report rendering."""

from __future__ import annotations

from sentinel_local.domain.models import (
    AnalysisResult,
    AnalystSummaryResult,
    AttachmentAnalysisResult,
    AttachmentScanResult,
    EnrichmentResult,
    ExtractionResult,
    HeaderAnalysisResult,
    ParsedEmail,
    UrlAnalysisResult,
)


def render_markdown_report(
    *,
    parsed_email: ParsedEmail,
    extraction_result: ExtractionResult,
    analysis_result: AnalysisResult,
    analyst_summary_result: AnalystSummaryResult | None = None,
    header_analysis_result: HeaderAnalysisResult | None = None,
    analyst_note: str | None = None,
    narrative_report: dict | None = None,
    url_analysis_result: UrlAnalysisResult | None = None,
    attachment_analysis_result: AttachmentAnalysisResult | None = None,
    attachment_scan_result: AttachmentScanResult | None = None,
    enrichment_result: EnrichmentResult | None = None,
) -> str:
    """Render a deterministic markdown report."""
    lines: list[str] = []

    lines.append("# Sentinel Local Report")
    lines.append("")
    lines.append("## Summary")
    lines.append(f"- Verdict: `{analysis_result.verdict}`")
    lines.append(f"- Disposition: `{analysis_result.disposition}`")
    lines.append(f"- Score: `{analysis_result.score}`")
    lines.append(f"- Confidence: `{analysis_result.confidence}`")
    lines.append(f"- Subject: {parsed_email.subject or 'N/A'}")
    lines.append(f"- Source Type: `{parsed_email.source_type}`")
    if parsed_email.sender and parsed_email.sender.email:
        lines.append(f"- Sender: {parsed_email.sender.email}")
    if analyst_note:
        lines.append(f"- Analyst Note: {analyst_note}")

    lines.append("")
    lines.append("## Analyst Summary")
    if analyst_summary_result:
        lines.append(analyst_summary_result.summary)
        lines.append("")
        lines.append(f"- Likely Intent: {analyst_summary_result.likely_intent}")
        if analyst_summary_result.evidence_highlights:
            lines.append(f"- Evidence Highlights: {', '.join(analyst_summary_result.evidence_highlights)}")
        if analyst_summary_result.recommended_actions:
            lines.append("- Recommended Actions:")
            for action in analyst_summary_result.recommended_actions:
                lines.append(f"  - {action}")
    else:
        lines.append("No deterministic analyst summary available.")

    if narrative_report:
        lines.append("")
        lines.append("## Narrative")
        lines.append(narrative_report["summary"])
        lines.append("")
        lines.append("### Verdict Rationale")
        lines.append(narrative_report["verdict_rationale"])
        lines.append("")
        lines.append("### Recommended Actions")
        for action in narrative_report.get("recommended_actions", []):
            lines.append(f"- {action}")

    lines.append("")
    lines.append("## Header Analysis")
    if header_analysis_result:
        auth = header_analysis_result.authentication
        lines.append(f"- Message-ID: {header_analysis_result.message_id or 'N/A'}")
        lines.append(f"- Return-Path: {header_analysis_result.return_path or 'N/A'}")
        lines.append(f"- Reply-To: {', '.join(header_analysis_result.reply_to) or 'N/A'}")
        lines.append(
            f"- Authentication: SPF={auth.spf_result or 'unknown'} DKIM={auth.dkim_result or 'unknown'} DMARC={auth.dmarc_result or 'unknown'}"
        )
        lines.append(
            f"- Alignment: SPF={_format_alignment(auth.spf_aligned)} DKIM={_format_alignment(auth.dkim_aligned)} DMARC={_format_alignment(auth.dmarc_aligned)}"
        )
        lines.append(
            f"- Originating IPs: {', '.join(header_analysis_result.originating_ips) or 'None parsed'}"
        )
        if header_analysis_result.findings:
            lines.append(f"- Header findings: {', '.join(header_analysis_result.findings)}")
        if header_analysis_result.mail_flow:
            lines.append("### Mail Flow")
            for hop in header_analysis_result.mail_flow:
                lines.append(
                    f"- Hop {hop.position}: from `{hop.from_host or 'unknown'}` by `{hop.by_host or 'unknown'}` "
                    f"ip `{hop.from_ip or 'n/a'}` at `{hop.timestamp.isoformat() if hop.timestamp else 'unknown'}`"
                )
                if hop.findings:
                    lines.append(f"  Findings: {', '.join(hop.findings)}")
    else:
        lines.append("## Header Analysis")
        lines.append("- No structured header analysis available")

    lines.append("")
    lines.append("## Recipients")
    recipients = [recipient.email or recipient.name or "unknown" for recipient in parsed_email.recipients]
    if recipients:
        lines.extend(f"- {recipient}" for recipient in recipients)
    else:
        lines.append("- None parsed")

    lines.append("")
    lines.append("## Rule Hits")
    if analysis_result.rule_hits:
        for hit in analysis_result.rule_hits:
            lines.append(f"- `{hit.rule_id}` [{hit.severity}] +{hit.score_delta}: {hit.title}")
            if hit.evidence:
                lines.append(f"  Evidence: {', '.join(hit.evidence)}")
    else:
        lines.append("- No deterministic rules fired")

    lines.append("")
    lines.append("## Indicators")
    if extraction_result.indicators:
        for indicator in extraction_result.indicators:
            lines.append(
                f"- `{indicator.type}` from `{indicator.source}`: {indicator.normalized_value}"
            )
    else:
        lines.append("- No indicators extracted")

    lines.append("")
    lines.append("## URL Analysis")
    if url_analysis_result and url_analysis_result.artifacts:
        for artifact in url_analysis_result.artifacts:
            lines.append(f"- URL: `{artifact.original_url}`")
            if artifact.unwrapped_url:
                lines.append(f"  Unwrapped: `{artifact.unwrapped_url}`")
            if artifact.final_url:
                lines.append(f"  Final: `{artifact.final_url}`")
            if artifact.screenshot_url:
                lines.append(f"  Screenshot: `{artifact.screenshot_url}`")
            if artifact.display_text:
                lines.append(f"  Display text: {artifact.display_text}")
            if artifact.findings:
                lines.append(f"  Findings: {', '.join(artifact.findings)}")
        if url_analysis_result.html_artifacts:
            lines.append("  HTML artifacts:")
            for artifact in url_analysis_result.html_artifacts:
                lines.append(f"  - {artifact.artifact_type}: {artifact.summary}")
    else:
        lines.append("- No URL analysis artifacts")

    lines.append("")
    lines.append("## Attachment Analysis")
    if attachment_analysis_result and attachment_analysis_result.artifacts:
        for artifact in attachment_analysis_result.artifacts:
            lines.append(f"- `{artifact.filename}` [{artifact.severity}]")
            if artifact.extension:
                lines.append(f"  Extension: `{artifact.extension}`")
            if artifact.content_type:
                lines.append(f"  MIME: `{artifact.content_type}`")
            if artifact.findings:
                lines.append(f"  Findings: {', '.join(artifact.findings)}")
    else:
        lines.append("- No attachment analysis artifacts")

    lines.append("")
    lines.append("## Local Attachment Scans")
    if attachment_scan_result and attachment_scan_result.artifacts:
        for artifact in attachment_scan_result.artifacts:
            lines.append(f"- `{artifact.filename}`")
            if artifact.sha256:
                lines.append(f"  SHA-256: `{artifact.sha256}`")
            if artifact.findings:
                for finding in artifact.findings:
                    lines.append(
                        f"  - `{finding.scanner}` [{finding.severity}]: {finding.summary}"
                    )
            else:
                lines.append("  - No local scanner findings")
        for warning in attachment_scan_result.warnings:
            lines.append(f"- Warning: {warning}")
    else:
        lines.append("- No local attachment scan results")

    lines.append("")
    lines.append("## Enrichment")
    if enrichment_result and enrichment_result.records:
        for record in enrichment_result.records:
            lines.append(
                f"- `{record.provider}` on `{record.indicator_value}` [{record.severity}]: {record.summary}"
            )
            if record.related_attachment:
                lines.append(f"  Attachment: `{record.related_attachment}`")
    else:
        lines.append("- No enrichment results")

    lines.append("")
    lines.append("## Body Preview")
    lines.append("")
    lines.append("```text")
    lines.append((parsed_email.text_body or parsed_email.html_body or "").strip()[:1500] or "No body parsed")
    lines.append("```")

    return "\n".join(lines)


def _format_alignment(value: bool | None) -> str:
    if value is True:
        return "aligned"
    if value is False:
        return "misaligned"
    return "unknown"
