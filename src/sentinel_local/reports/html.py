"""HTML report rendering."""

from __future__ import annotations

from html import escape

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


def render_html_report(
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
    """Render an analyst-friendly HTML report."""
    body_preview = escape((parsed_email.text_body or parsed_email.html_body or "No body parsed")[:1500])
    recipients = "".join(
        f"<li>{escape(recipient.email or recipient.name or 'unknown')}</li>"
        for recipient in parsed_email.recipients
    ) or "<li>None parsed</li>"
    header_section = "<p>No structured header analysis available</p>"
    if header_analysis_result:
        auth = header_analysis_result.authentication
        mail_flow = "".join(
            (
                f"<li><strong>Hop {hop.position}</strong>: from {escape(hop.from_host or 'unknown')} "
                f"by {escape(hop.by_host or 'unknown')} "
                f"{f'[{escape(hop.from_ip)}]' if hop.from_ip else ''} "
                f"at {escape(hop.timestamp.isoformat() if hop.timestamp else 'unknown')}"
                f"{f'<br>Findings: {escape(', '.join(hop.findings))}' if hop.findings else ''}"
                "</li>"
            )
            for hop in header_analysis_result.mail_flow
        ) or "<li>No mail-flow hops parsed</li>"
        header_section = (
            f"<p><strong>Message-ID:</strong> {escape(header_analysis_result.message_id or 'N/A')}<br>"
            f"<strong>Return-Path:</strong> {escape(header_analysis_result.return_path or 'N/A')}<br>"
            f"<strong>Reply-To:</strong> {escape(', '.join(header_analysis_result.reply_to) or 'N/A')}<br>"
            f"<strong>Authentication:</strong> SPF={escape(auth.spf_result or 'unknown')} "
            f"DKIM={escape(auth.dkim_result or 'unknown')} DMARC={escape(auth.dmarc_result or 'unknown')}<br>"
            f"<strong>Alignment:</strong> SPF={escape(_format_alignment(auth.spf_aligned))} "
            f"DKIM={escape(_format_alignment(auth.dkim_aligned))} "
            f"DMARC={escape(_format_alignment(auth.dmarc_aligned))}<br>"
            f"<strong>Originating IPs:</strong> {escape(', '.join(header_analysis_result.originating_ips) or 'None parsed')}<br>"
            f"<strong>Header Findings:</strong> {escape(', '.join(header_analysis_result.findings) or 'None')}"
            "</p>"
            f"<h3>Mail Flow</h3><ul>{mail_flow}</ul>"
        )
    rule_hits = "".join(
        (
            f"<li><strong>{escape(hit.title)}</strong> "
            f"(<code>{escape(hit.rule_id)}</code>, {escape(hit.severity)}, +{hit.score_delta})"
            f"<br>{escape(hit.description)}"
            f"{'<br><em>Evidence:</em> ' + escape(', '.join(hit.evidence)) if hit.evidence else ''}"
            "</li>"
        )
        for hit in analysis_result.rule_hits
    ) or "<li>No deterministic rules fired</li>"
    indicators = "".join(
        f"<tr><td>{escape(indicator.type)}</td><td>{escape(indicator.normalized_value)}</td><td>{escape(indicator.source)}</td></tr>"
        for indicator in extraction_result.indicators
    ) or "<tr><td colspan='3'>No indicators extracted</td></tr>"
    url_artifacts = "".join(
        (
            f"<li><strong>{escape(artifact.original_url)}</strong>"
            f"{f'<br>Unwrapped: {escape(artifact.unwrapped_url)}' if artifact.unwrapped_url else ''}"
            f"{f'<br>Final: {escape(artifact.final_url)}' if artifact.final_url else ''}"
            f"{f'<br>Screenshot: <a href=\"{escape(artifact.screenshot_url)}\" target=\"_blank\" rel=\"noreferrer\">open</a>' if artifact.screenshot_url else ''}"
            f"{_report_thumbnail_html(artifact.screenshot_url)}"
            f"{f'<br>Display text: {escape(artifact.display_text)}' if artifact.display_text else ''}"
            f"{f'<br>Findings: {escape(', '.join(artifact.findings))}' if artifact.findings else ''}"
            "</li>"
        )
        for artifact in (url_analysis_result.artifacts if url_analysis_result else [])
    ) or "<li>No URL analysis artifacts</li>"
    html_artifacts = "".join(
        f"<li><strong>{escape(item.artifact_type)}</strong>: {escape(item.summary)}</li>"
        for item in (url_analysis_result.html_artifacts if url_analysis_result else [])
    ) or "<li>No suspicious HTML artifacts</li>"
    attachment_artifacts = "".join(
        (
            f"<li><strong>{escape(item.filename)}</strong> [{escape(item.severity)}]"
            f"{f'<br>Extension: {escape(item.extension)}' if item.extension else ''}"
            f"{f'<br>MIME: {escape(item.content_type)}' if item.content_type else ''}"
            f"{f'<br>Findings: {escape(', '.join(item.findings))}' if item.findings else ''}"
            "</li>"
        )
        for item in (attachment_analysis_result.artifacts if attachment_analysis_result else [])
    ) or "<li>No attachment analysis artifacts</li>"
    attachment_scans = "".join(
        (
            f"<li><strong>{escape(item.filename)}</strong>"
            f"{f'<br>SHA-256: <code>{escape(item.sha256)}</code>' if item.sha256 else ''}"
            f"{''.join(f'<br><strong>{escape(finding.scanner)}</strong> [{escape(finding.severity)}]: {escape(finding.summary)}' for finding in item.findings)}"
            f"{'<br>No local scanner findings' if not item.findings else ''}"
            "</li>"
        )
        for item in (attachment_scan_result.artifacts if attachment_scan_result else [])
    ) or "<li>No local attachment scan results</li>"
    attachment_scan_warnings = "".join(
        f"<li>{escape(warning)}</li>" for warning in (attachment_scan_result.warnings if attachment_scan_result else [])
    )
    enrichments = "".join(
        (
            f"<li><strong>{escape(record.provider)}</strong> on {escape(record.indicator_value)}: {escape(record.summary)}"
            f"{f'<br>Attachment: {escape(record.related_attachment)}' if record.related_attachment else ''}</li>"
        )
        for record in (enrichment_result.records if enrichment_result else [])
    ) or "<li>No enrichment results</li>"

    narrative_html = ""
    analyst_summary_html = "<section><h2>Analyst Summary</h2><p>No deterministic analyst summary available.</p></section>"
    if analyst_summary_result:
        summary_actions = "".join(
            f"<li>{escape(action)}</li>" for action in analyst_summary_result.recommended_actions
        ) or "<li>No recommended actions</li>"
        highlights = escape(", ".join(analyst_summary_result.evidence_highlights) or "None")
        analyst_summary_html = (
            "<section><h2>Analyst Summary</h2>"
            f"<p>{escape(analyst_summary_result.summary)}</p>"
            f"<p><strong>Likely Intent:</strong> {escape(analyst_summary_result.likely_intent)}<br>"
            f"<strong>Evidence Highlights:</strong> {highlights}</p>"
            f"<h3>Recommended Actions</h3><ul>{summary_actions}</ul></section>"
        )
    if narrative_report:
        actions = "".join(
            f"<li>{escape(action)}</li>" for action in narrative_report.get("recommended_actions", [])
        ) or "<li>No recommended actions</li>"
        narrative_html = (
            "<section><h2>Narrative</h2>"
            f"<p>{escape(narrative_report['summary'])}</p>"
            "<h3>Verdict Rationale</h3>"
            f"<p>{escape(narrative_report['verdict_rationale'])}</p>"
            "<h3>Recommended Actions</h3>"
            f"<ul>{actions}</ul></section>"
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Sentinel Local Report</title>
  <style>
    :root {{
      --bg: #eef2ee;
      --panel: #fbfcfb;
      --ink: #16212a;
      --accent: #184f43;
      --muted: #5f6973;
      --line: #d7e0d8;
      --soft: #f2f7f3;
    }}
    body {{ margin: 0; font-family: Georgia, 'Times New Roman', serif; background: linear-gradient(180deg, #f7faf7 0%, var(--bg) 42%); color: var(--ink); }}
    main {{ max-width: 1100px; margin: 0 auto; padding: 32px 20px 60px; }}
    header, section {{ background: var(--panel); border: 1px solid var(--line); border-radius: 22px; padding: 22px 24px; margin-bottom: 18px; box-shadow: 0 18px 32px rgba(22, 33, 42, 0.05); }}
    h1, h2, h3 {{ margin-top: 0; letter-spacing: -0.02em; }}
    h1 {{ font-size: 2rem; margin-bottom: 0.9rem; }}
    h2 {{ font-size: 1.2rem; margin-bottom: 0.85rem; }}
    h3 {{ font-size: 0.98rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.06em; }}
    p, li, td, th {{ font-size: 0.98rem; line-height: 1.55; }}
    .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; }}
    .summary-card {{ border: 1px solid var(--line); border-radius: 16px; padding: 13px; background: var(--soft); }}
    .kicker {{ color: var(--muted); text-transform: uppercase; letter-spacing: 0.08em; font-size: 12px; }}
    .value {{ font-size: 24px; font-weight: 700; color: var(--accent); }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ padding: 10px 8px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; }}
    th {{ color: var(--muted); font-size: 0.84rem; text-transform: uppercase; letter-spacing: 0.05em; }}
    code, pre {{ background: #f2f5f2; border-radius: 8px; padding: 2px 6px; }}
    pre {{ padding: 14px; white-space: pre-wrap; }}
    ul {{ margin: 0; padding-left: 1.1rem; }}
    a {{ color: var(--accent); text-decoration: none; }}
    .thumbnail {{ margin-top: 10px; max-width: 100%; border: 1px solid var(--line); border-radius: 14px; overflow: hidden; }}
    .thumbnail img {{ width: 100%; display: block; }}
  </style>
</head>
<body>
  <main>
    <header>
      <h1>Sentinel Local Report</h1>
      <div class="summary-grid">
        <div class="summary-card"><div class="kicker">Verdict</div><div class="value">{escape(analysis_result.verdict.upper())}</div></div>
        <div class="summary-card"><div class="kicker">Disposition</div><div class="value">{escape(analysis_result.disposition.upper())}</div></div>
        <div class="summary-card"><div class="kicker">Score</div><div class="value">{analysis_result.score}</div></div>
        <div class="summary-card"><div class="kicker">Confidence</div><div class="value">{escape(analysis_result.confidence.upper())}</div></div>
        <div class="summary-card"><div class="kicker">Source</div><div class="value">{escape(parsed_email.source_type.upper())}</div></div>
      </div>
      <p><strong>Subject:</strong> {escape(parsed_email.subject or 'N/A')}<br>
      <strong>Sender:</strong> {escape(parsed_email.sender.email if parsed_email.sender and parsed_email.sender.email else 'N/A')}<br>
      {'<strong>Analyst Note:</strong> ' + escape(analyst_note) if analyst_note else ''}</p>
    </header>
    {analyst_summary_html}
    {narrative_html}
    <section><h2>Recipients</h2><ul>{recipients}</ul></section>
    <section><h2>Header Analysis</h2>{header_section}</section>
    <section><h2>Rule Hits</h2><ul>{rule_hits}</ul></section>
    <section><h2>Indicators</h2><table><thead><tr><th>Type</th><th>Normalized Value</th><th>Source</th></tr></thead><tbody>{indicators}</tbody></table></section>
    <section><h2>URL Analysis</h2><ul>{url_artifacts}</ul></section>
    <section><h2>HTML Artifacts</h2><ul>{html_artifacts}</ul></section>
    <section><h2>Attachment Analysis</h2><ul>{attachment_artifacts}</ul></section>
    <section><h2>Local Attachment Scans</h2><ul>{attachment_scans}</ul>{f'<h3>Scanner Warnings</h3><ul>{attachment_scan_warnings}</ul>' if attachment_scan_warnings else ''}</section>
    <section><h2>Enrichment</h2><ul>{enrichments}</ul></section>
    <section><h2>Body Preview</h2><pre>{body_preview}</pre></section>
  </main>
</body>
</html>"""


def _format_alignment(value: bool | None) -> str:
    if value is True:
        return "aligned"
    if value is False:
        return "misaligned"
    return "unknown"


def _report_thumbnail_html(url: str | None) -> str:
    if not url:
        return ""
    lowered = url.lower()
    if not any(ext in lowered for ext in [".png", ".jpg", ".jpeg", ".webp", "image.thum.io"]):
        return ""
    return f'<div class="thumbnail"><img src="{escape(url)}" alt="URL screenshot preview"></div>'
