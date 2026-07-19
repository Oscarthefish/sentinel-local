"""Deterministic rules for parsed email analysis."""

from __future__ import annotations

from collections import Counter
from email.utils import getaddresses
import re

from sentinel_local.domain.models import ExtractionResult, HeaderAnalysisResult, ParsedEmail, RuleHit
from sentinel_local.header_analysis import analyze_headers
from sentinel_local.analyzers.secret_scanner import scan_secrets


SUSPICIOUS_ATTACHMENT_EXTENSIONS = {".html", ".htm", ".svg", ".js", ".iso", ".zip", ".exe", ".scr"}
SUSPICIOUS_KEYWORDS = {
    "urgent",
    "suspicious login",
    "wire transfer",
    "password reset",
    "invoice",
    "gift card",
    "crypto",
    "secrecy",
    "verify account",
}


def evaluate_rules(
    parsed_email: ParsedEmail,
    extraction_result: ExtractionResult,
    *,
    header_analysis_result: HeaderAnalysisResult | None = None,
) -> list[RuleHit]:
    """Run the deterministic rule set and return matching rule hits."""
    hits: list[RuleHit] = []
    header_analysis = header_analysis_result or analyze_headers(parsed_email)

    hits.extend(_rule_authentication_failures(header_analysis))
    hits.extend(_rule_authentication_warnings(header_analysis))
    hits.extend(_rule_authentication_alignment(header_analysis))
    hits.extend(_rule_return_path_mismatch(parsed_email))
    hits.extend(_rule_display_name_impersonation(parsed_email))
    hits.extend(_rule_reply_to_mismatch(parsed_email))
    hits.extend(_rule_received_chain_anomalies(header_analysis))
    hits.extend(_rule_received_time_anomalies(header_analysis))
    hits.extend(_rule_suspicious_keywords(parsed_email))
    hits.extend(_rule_lure_with_link(parsed_email, extraction_result))
    hits.extend(_rule_external_link_count(extraction_result))
    hits.extend(_rule_html_attachment(extraction_result))
    hits.extend(_rule_ip_and_hash_present(extraction_result))
    hits.extend(_rule_recipient_volume(parsed_email))
    hits.extend(scan_secrets(parsed_email))

    return hits


def _rule_suspicious_keywords(parsed_email: ParsedEmail) -> list[RuleHit]:
    searchable = " ".join(
        part for part in [parsed_email.subject, parsed_email.text_body, parsed_email.html_body] if part
    ).lower()
    matched = sorted(keyword for keyword in SUSPICIOUS_KEYWORDS if keyword in searchable)

    if not matched:
        return []

    return [
        RuleHit(
            rule_id="suspicious-keywords",
            title="Suspicious phishing language present",
            description="The message contains language commonly seen in phishing or financial fraud lures.",
            severity="medium",
            score_delta=min(20, 5 * len(matched)),
            evidence=matched,
        )
    ]


def _rule_lure_with_link(parsed_email: ParsedEmail, extraction_result: ExtractionResult) -> list[RuleHit]:
    searchable = " ".join(
        part for part in [parsed_email.subject, parsed_email.text_body, parsed_email.html_body] if part
    ).lower()
    matched_keywords = sorted(keyword for keyword in SUSPICIOUS_KEYWORDS if keyword in searchable)
    urls = sorted(
        {
            indicator.normalized_value
            for indicator in extraction_result.indicators
            if indicator.type == "url"
        }
    )

    if not matched_keywords or not urls:
        return []

    return [
        RuleHit(
            rule_id="lure-with-link",
            title="Action-oriented lure paired with a link",
            description="The message combines phishing-style lure language with at least one URL, which increases risk.",
            severity="medium",
            score_delta=15,
            evidence=[*matched_keywords[:3], *urls[:2]],
        )
    ]


def _rule_authentication_failures(header_analysis: HeaderAnalysisResult) -> list[RuleHit]:
    authentication = header_analysis.authentication

    hits: list[RuleHit] = []

    auth_failures = []
    if authentication.spf_result in {"fail", "softfail"}:
        auth_failures.append("spf")
    if authentication.dkim_result == "fail":
        auth_failures.append("dkim")
    if authentication.dmarc_result in {"fail", "quarantine", "reject"}:
        auth_failures.append("dmarc")

    if auth_failures:
        hits.append(
            RuleHit(
                rule_id="auth-failures",
                title="Email authentication failures detected",
                description="One or more email authentication checks indicate failure or enforcement.",
                severity="high",
                score_delta=25,
                evidence=sorted(auth_failures),
            )
        )

    return hits


def _rule_authentication_warnings(header_analysis: HeaderAnalysisResult) -> list[RuleHit]:
    authentication = header_analysis.authentication

    warnings = []
    if authentication.spf_result == "neutral":
        warnings.append("spf-neutral")
    if authentication.dmarc_result == "none":
        warnings.append("dmarc-none")
    if authentication.dkim_result == "none":
        warnings.append("dkim-none")

    if not warnings:
        return []

    return [
        RuleHit(
            rule_id="auth-warnings",
            title="Email authentication results are weak or incomplete",
            description="Authentication checks are not failing outright, but the message shows weak or missing authentication signals.",
            severity="low",
            score_delta=8,
            evidence=warnings,
        )
    ]


def _rule_return_path_mismatch(parsed_email: ParsedEmail) -> list[RuleHit]:
    return_path_header = _get_header(parsed_email, "return-path")
    if not return_path_header or not parsed_email.sender or not parsed_email.sender.email:
        return []

    return_path_addresses = [email for _, email in getaddresses([return_path_header]) if email]
    if not return_path_addresses:
        return []

    sender_domain = _domain_from_email(parsed_email.sender.email)
    return_path_domains = sorted(
        {
            domain
            for domain in (_domain_from_email(address) for address in return_path_addresses)
            if domain
        }
    )
    if not sender_domain or sender_domain in return_path_domains:
        return []

    return [
        RuleHit(
            rule_id="return-path-mismatch",
            title="Return-Path does not align with sender domain",
            description="The envelope sender domain differs from the visible sender domain.",
            severity="medium",
            score_delta=12,
            evidence=[f"return_path={', '.join(return_path_addresses)}", f"from_domain={sender_domain}"],
        )
    ]


def _rule_authentication_alignment(header_analysis: HeaderAnalysisResult) -> list[RuleHit]:
    authentication = header_analysis.authentication
    issues: list[str] = []

    if authentication.spf_result in {"pass", "softfail", "neutral"} and authentication.spf_aligned is False:
        issues.append(f"spf domain {authentication.spf_domain or 'unknown'} misaligned")
    if authentication.dkim_result == "pass" and authentication.dkim_aligned is False:
        issues.append(f"dkim domain {authentication.dkim_domain or 'unknown'} misaligned")
    if authentication.dmarc_result in {"pass", "bestguesspass"} and authentication.dmarc_aligned is False:
        issues.append(f"dmarc header.from {authentication.header_from_domain or 'unknown'} misaligned")

    if not issues:
        return []

    return [
        RuleHit(
            rule_id="auth-alignment-mismatch",
            title="Authentication domains do not align with the visible sender",
            description="Authentication may be present, but the authenticated domains do not align with the visible sender domain.",
            severity="medium",
            score_delta=12,
            evidence=issues,
        )
    ]


def _rule_display_name_impersonation(parsed_email: ParsedEmail) -> list[RuleHit]:
    if not parsed_email.sender or not parsed_email.sender.name or not parsed_email.sender.email:
        return []

    sender_domain = _domain_from_email(parsed_email.sender.email)
    if not sender_domain:
        return []

    sender_name = parsed_email.sender.name.lower()
    recipient_tokens = {
        _organizational_token(recipient.email)
        for recipient in parsed_email.recipients
        if recipient.email
    }
    recipient_tokens.discard("")
    sender_token = _organizational_token(parsed_email.sender.email)

    matched = sorted(token for token in recipient_tokens if token and token in sender_name and token != sender_token)
    if not matched:
        return []

    return [
        RuleHit(
            rule_id="display-name-impersonation",
            title="Sender display name resembles the recipient organization",
            description="The sender display name references the recipient organization while using an unrelated sender domain.",
            severity="medium",
            score_delta=15,
            evidence=[f"display_name={parsed_email.sender.name}", f"matched_tokens={', '.join(matched)}"],
        )
    ]


def _rule_reply_to_mismatch(parsed_email: ParsedEmail) -> list[RuleHit]:
    reply_to_header = _get_header(parsed_email, "reply-to")
    if not reply_to_header or not parsed_email.sender or not parsed_email.sender.email:
        return []

    reply_to_addresses = [email for _, email in getaddresses([reply_to_header]) if email]
    if not reply_to_addresses:
        return []

    sender_domain = _domain_from_email(parsed_email.sender.email)
    mismatched_domains = sorted(
        {
            domain
            for domain in (_domain_from_email(address) for address in reply_to_addresses)
            if domain and domain != sender_domain
        }
    )
    if not mismatched_domains:
        return []

    return [
        RuleHit(
            rule_id="reply-to-mismatch",
            title="Reply-To domain differs from sender domain",
            description="The Reply-To address points to a different domain than the visible sender.",
            severity="medium",
            score_delta=15,
            evidence=[f"reply_to={', '.join(reply_to_addresses)}", f"sender_domain={sender_domain or 'unknown'}"],
        )
    ]


def _rule_received_chain_anomalies(header_analysis: HeaderAnalysisResult) -> list[RuleHit]:
    if not header_analysis.mail_flow:
        return []

    anomalies = sorted(
        {
            finding
            for hop in header_analysis.mail_flow
            for finding in hop.findings
            if finding in {"unknown-host", "private-ip-hop", "helo-only", "multi-hop-chain", "localhost-hop"}
        }
    )

    if not anomalies:
        return []

    return [
        RuleHit(
            rule_id="received-chain-anomaly",
            title="Received chain contains suspicious relay details",
            description="Received headers include private IPs or unknown relay hosts that merit analyst review.",
            severity="low",
            score_delta=10,
            evidence=sorted(anomalies),
        )
    ]


def _rule_received_time_anomalies(header_analysis: HeaderAnalysisResult) -> list[RuleHit]:
    anomalies = [
        f"hop_{hop.position}"
        for hop in header_analysis.mail_flow
        if "received-time-order-anomaly" in hop.findings or "missing-hop-timestamp" in hop.findings
    ]
    if not anomalies:
        return []

    return [
        RuleHit(
            rule_id="received-time-anomaly",
            title="Received chain timestamps are incomplete or out of order",
            description="Relay timestamps should normally progress in a consistent order; missing or reversed times merit review.",
            severity="low",
            score_delta=8,
            evidence=anomalies,
        )
    ]


def _rule_external_link_count(extraction_result: ExtractionResult) -> list[RuleHit]:
    url_indicators = [indicator for indicator in extraction_result.indicators if indicator.type == "url"]
    unique_urls = sorted({indicator.normalized_value for indicator in url_indicators})

    if len(unique_urls) < 2:
        return []

    return [
        RuleHit(
            rule_id="multiple-links",
            title="Multiple links detected",
            description="The message contains more than one distinct URL, which can increase phishing risk.",
            severity="medium",
            score_delta=10,
            evidence=unique_urls[:5],
        )
    ]


def _rule_html_attachment(extraction_result: ExtractionResult) -> list[RuleHit]:
    extensions = [
        indicator.normalized_value
        for indicator in extraction_result.indicators
        if indicator.type == "attachment_ext"
    ]
    matched = sorted({extension for extension in extensions if extension in SUSPICIOUS_ATTACHMENT_EXTENSIONS})

    if not matched:
        return []

    return [
        RuleHit(
            rule_id="suspicious-attachment-type",
            title="Suspicious attachment extension",
            description="The message includes an attachment type frequently used in phishing or malware delivery.",
            severity="high",
            score_delta=30,
            evidence=matched,
        )
    ]


def _rule_ip_and_hash_present(extraction_result: ExtractionResult) -> list[RuleHit]:
    counts = Counter(indicator.type for indicator in extraction_result.indicators)

    if counts["ip"] == 0 and counts["hash"] == 0:
        return []

    evidence = []
    if counts["ip"]:
        evidence.append(f"ips={counts['ip']}")
    if counts["hash"]:
        evidence.append(f"hashes={counts['hash']}")

    return [
        RuleHit(
            rule_id="technical-artifacts",
            title="Technical artifacts embedded in message",
            description="The message includes direct IP or hash indicators, which is unusual for routine business email.",
            severity="low",
            score_delta=10,
            evidence=evidence,
        )
    ]


def _rule_recipient_volume(parsed_email: ParsedEmail) -> list[RuleHit]:
    recipient_count = len(parsed_email.recipients)
    if recipient_count < 4:
        return []

    return [
        RuleHit(
            rule_id="high-recipient-count",
            title="Message sent to many recipients",
            description="The number of recipients is higher than expected for a targeted internal message.",
            severity="low",
            score_delta=5,
            evidence=[f"recipient_count={recipient_count}"],
        )
    ]


def _get_header(parsed_email: ParsedEmail, name: str) -> str | None:
    for key, value in parsed_email.headers.items():
        if key.lower() == name:
            return value
    return None


def _domain_from_email(value: str | None) -> str | None:
    if not value or "@" not in value:
        return None
    return value.split("@", 1)[1].lower()


def _organizational_token(value: str | None) -> str:
    domain = _domain_from_email(value)
    if not domain:
        return ""
    return domain.split(".", 1)[0].lower()
