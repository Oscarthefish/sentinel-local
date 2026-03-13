"""Build concise deterministic analyst summaries from investigation evidence."""

from __future__ import annotations

from sentinel_local.domain.models import (
    AnalysisResult,
    AnalystSummaryResult,
    AttachmentAnalysisResult,
    AttachmentScanResult,
    ExtractionResult,
    HeaderAnalysisResult,
    ParsedEmail,
    UrlAnalysisResult,
)


def build_analyst_summary(
    *,
    parsed_email: ParsedEmail,
    extraction_result: ExtractionResult,
    header_analysis_result: HeaderAnalysisResult,
    analysis_result: AnalysisResult,
    url_analysis_result: UrlAnalysisResult,
    attachment_analysis_result: AttachmentAnalysisResult,
    attachment_scan_result: AttachmentScanResult,
) -> AnalystSummaryResult:
    """Generate a concise deterministic case summary without an LLM."""
    sender = parsed_email.sender.email if parsed_email.sender and parsed_email.sender.email else "unknown sender"
    subject = parsed_email.subject or "no subject"
    intent = _likely_intent(analysis_result.disposition)
    evidence = _evidence_highlights(
        analysis_result=analysis_result,
        header_analysis_result=header_analysis_result,
        extraction_result=extraction_result,
        url_analysis_result=url_analysis_result,
        attachment_analysis_result=attachment_analysis_result,
        attachment_scan_result=attachment_scan_result,
    )
    summary = (
        f"Message '{subject}' from {sender} was classified as {analysis_result.disposition.replace('_', ' ')} "
        f"with a {analysis_result.confidence} confidence deterministic assessment."
    )

    return AnalystSummaryResult(
        summary=summary,
        likely_intent=intent,
        recommended_actions=_recommended_actions(
            disposition=analysis_result.disposition,
            parsed_email=parsed_email,
            extraction_result=extraction_result,
            attachment_scan_result=attachment_scan_result,
        ),
        evidence_highlights=evidence,
    )


def _likely_intent(disposition: str) -> str:
    return {
        "benign": "Routine or low-risk communication with limited suspicious evidence.",
        "spam": "Broad unsolicited outreach or low-quality phishing/spam distribution.",
        "phishing": "Credential theft or user-action deception through links or spoofing.",
        "malware_delivery": "Attachment- or link-led malware delivery or staged execution.",
        "bec": "Payment, account, or trust-abuse fraud targeting business processes.",
        "needs_escalation": "Mixed signals that merit additional analyst review before disposition.",
    }.get(disposition, "Additional analyst review is required.")


def _evidence_highlights(
    *,
    analysis_result: AnalysisResult,
    header_analysis_result: HeaderAnalysisResult,
    extraction_result: ExtractionResult,
    url_analysis_result: UrlAnalysisResult,
    attachment_analysis_result: AttachmentAnalysisResult,
    attachment_scan_result: AttachmentScanResult,
) -> list[str]:
    highlights: list[str] = []
    highlights.extend(hit.title for hit in analysis_result.rule_hits[:4])
    if header_analysis_result.findings:
        highlights.append(f"Header findings: {', '.join(header_analysis_result.findings[:4])}")
    if extraction_result.indicators:
        highlights.append(f"Extracted {len(extraction_result.indicators)} indicators")
    suspicious_urls = [artifact.original_url for artifact in url_analysis_result.artifacts if artifact.findings]
    if suspicious_urls:
        highlights.append(f"URL findings on {min(len(suspicious_urls), 3)} link(s)")
    risky_attachments = [artifact.filename for artifact in attachment_analysis_result.artifacts if artifact.findings]
    if risky_attachments:
        highlights.append(f"Attachment findings on {', '.join(risky_attachments[:2])}")
    scanner_hits = [
        finding.summary
        for artifact in attachment_scan_result.artifacts
        for finding in artifact.findings
    ]
    if scanner_hits:
        highlights.append(scanner_hits[0])
    return list(dict.fromkeys(highlights))


def _recommended_actions(
    *,
    disposition: str,
    parsed_email: ParsedEmail,
    extraction_result: ExtractionResult,
    attachment_scan_result: AttachmentScanResult,
) -> list[str]:
    actions: list[str] = []
    if disposition in {"phishing", "bec", "malware_delivery"}:
        actions.append("Contain the message in the mail platform and prevent further user interaction.")
    if disposition == "phishing":
        actions.append("Block or monitor the extracted URLs and related sender infrastructure.")
    if disposition == "bec":
        actions.append("Validate any payment or account-change request with a trusted out-of-band contact.")
    if disposition == "malware_delivery":
        actions.append("Quarantine the attachment and scan any recipient endpoint that opened or downloaded it.")
    if attachment_scan_result.artifacts and any(artifact.findings for artifact in attachment_scan_result.artifacts):
        actions.append("Retain local scanner evidence and correlate any matching hashes across prior cases.")
    if any(indicator.type == "url" for indicator in extraction_result.indicators):
        actions.append("Review the final URL destinations and block high-risk domains if confirmed malicious.")
    if parsed_email.recipients:
        actions.append("Identify all recipients and determine whether recall, user warning, or mailbox search is required.")
    if not actions:
        actions.append("Document the evidence and retain the message for reference if no further action is required.")
    return actions
