"""Deterministic analysis service."""

from __future__ import annotations

from sentinel_local.analyzers.rules import evaluate_rules
from sentinel_local.domain.models import (
    AnalysisResult,
    AttachmentAnalysisResult,
    ExtractionResult,
    HeaderAnalysisResult,
    ParsedEmail,
)


def analyze_email(
    parsed_email: ParsedEmail,
    extraction_result: ExtractionResult,
    attachment_analysis_result: AttachmentAnalysisResult | None = None,
    header_analysis_result: HeaderAnalysisResult | None = None,
) -> AnalysisResult:
    """Score a parsed email using deterministic rules."""
    rule_hits = evaluate_rules(
        parsed_email,
        extraction_result,
        header_analysis_result=header_analysis_result,
    )
    score = max(0, min(100, sum(hit.score_delta for hit in rule_hits)))
    verdict = _map_verdict(score)
    disposition = _map_disposition(
        parsed_email=parsed_email,
        extraction_result=extraction_result,
        rule_ids={hit.rule_id for hit in rule_hits},
        score=score,
        attachment_analysis_result=attachment_analysis_result,
    )
    confidence = _map_confidence(score, len(rule_hits))

    return AnalysisResult(
        score=score,
        verdict=verdict,
        disposition=disposition,
        confidence=confidence,
        rule_hits=rule_hits,
    )


def _map_verdict(score: int) -> str:
    if score >= 60:
        return "malicious"
    if score >= 20:
        return "suspicious"
    return "benign"


def _map_confidence(score: int, rule_count: int) -> str:
    if score >= 60 or rule_count >= 4:
        return "high"
    if score >= 20 or rule_count >= 2:
        return "medium"
    return "low"


def _map_disposition(
    *,
    parsed_email: ParsedEmail,
    extraction_result: ExtractionResult,
    rule_ids: set[str],
    score: int,
    attachment_analysis_result: AttachmentAnalysisResult | None,
) -> str:
    searchable = " ".join(
        part for part in [parsed_email.subject, parsed_email.text_body, parsed_email.html_body] if part
    ).lower()
    bec_keywords = ("wire transfer", "gift card", "payment", "invoice", "remittance", "bank details")
    has_urls = any(indicator.type == "url" for indicator in extraction_result.indicators)
    risky_attachment = any(
        {
            "risky-extension",
            "macro-capable-document",
            "mime-extension-mismatch",
        }
        & set(artifact.findings)
        or {"archive-file", "lure-filename"} <= set(artifact.findings)
        for artifact in (attachment_analysis_result.artifacts if attachment_analysis_result else [])
    )

    if "suspicious-attachment-type" in rule_ids or risky_attachment:
        return "malware_delivery"
    if any(keyword in searchable for keyword in bec_keywords) and (
        {"reply-to-mismatch", "display-name-impersonation", "return-path-mismatch"} & rule_ids
    ):
        return "bec"
    if rule_ids & {
        "auth-failures",
        "reply-to-mismatch",
        "display-name-impersonation",
        "return-path-mismatch",
        "lure-with-link",
    }:
        return "phishing"
    if "multiple-links" in rule_ids and "high-recipient-count" in rule_ids and score < 40:
        return "spam"
    if score < 20 and not has_urls and not risky_attachment:
        return "benign"
    return "needs_escalation"
