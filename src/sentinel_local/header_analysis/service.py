"""Structured authentication and mail-flow analysis."""

from __future__ import annotations

import re
from email.utils import getaddresses, parsedate_to_datetime

from sentinel_local.domain.models import (
    AuthenticationEvidence,
    HeaderAnalysisResult,
    MailFlowHop,
    ParsedEmail,
)


def analyze_headers(parsed_email: ParsedEmail) -> HeaderAnalysisResult:
    """Normalize authentication and relay evidence from parsed headers."""
    headers = parsed_email.headers
    auth_blob = _join_header_values(
        headers,
        {"authentication-results", "received-spf", "spf", "dkim-signature"},
    )
    sender_domain = _domain_from_email(parsed_email.sender.email if parsed_email.sender else None)
    authentication = AuthenticationEvidence(
        spf_result=_match_group(auth_blob, r"\bspf\s*=\s*([a-z_]+)\b"),
        spf_domain=_match_group(auth_blob, r"smtp\.mailfrom=([^\s;]+)"),
        dkim_result=_match_group(auth_blob, r"\bdkim\s*=\s*([a-z_]+)\b"),
        dkim_domain=_normalize_domain(_match_group(auth_blob, r"header\.d=([^\s;]+)")),
        dmarc_result=_match_group(auth_blob, r"\bdmarc\s*=\s*([a-z_]+)\b"),
        header_from_domain=_normalize_domain(_match_group(auth_blob, r"header\.from=([^\s;]+)")),
    )
    authentication.spf_domain = _normalize_domain(authentication.spf_domain)
    authentication.spf_aligned = _is_domain_aligned(authentication.spf_domain, sender_domain)
    authentication.dkim_aligned = _is_domain_aligned(authentication.dkim_domain, sender_domain)
    authentication.dmarc_aligned = _is_domain_aligned(authentication.header_from_domain, sender_domain)

    reply_to_header = _get_header(headers, "reply-to")
    return_path_header = _get_header(headers, "return-path")
    mail_flow = _parse_received_chain(_get_header(headers, "received"))
    originating_ips = sorted({hop.from_ip for hop in mail_flow if hop.from_ip})
    findings = _header_findings(authentication, mail_flow)

    return HeaderAnalysisResult(
        authentication=authentication,
        mail_flow=mail_flow,
        message_id=_get_header(headers, "message-id"),
        return_path=_first_address(return_path_header),
        reply_to=[email for _, email in getaddresses([reply_to_header or ""]) if email],
        originating_ips=originating_ips,
        findings=findings,
    )


def _parse_received_chain(received_blob: str | None) -> list[MailFlowHop]:
    if not received_blob:
        return []

    hops: list[MailFlowHop] = []
    for index, raw_line in enumerate([line.strip() for line in received_blob.splitlines() if line.strip()], start=1):
        lowered = raw_line.lower()
        from_host = _match_group(raw_line, r"\bfrom\s+([^\s(;\[]+)")
        by_host = _match_group(raw_line, r"\bby\s+([^\s(;]+)")
        from_ip = _match_group(raw_line, r"\[((?:\d{1,3}\.){3}\d{1,3})\]")
        timestamp = _parse_received_timestamp(raw_line)
        findings: list[str] = []

        if re.search(r"\b(?:unknown|localhost)\b", lowered):
            findings.append("unknown-host")
        if re.search(r"\[(?:10\.|127\.|169\.254\.|172\.(?:1[6-9]|2\d|3[0-1])\.|192\.168\.)", lowered):
            findings.append("private-ip-hop")
        if "helo=" in lowered and "from " not in lowered:
            findings.append("helo-only")
        if re.search(r"\bfrom\s+\[?localhost\]?\b", lowered):
            findings.append("localhost-hop")
        if not timestamp:
            findings.append("missing-hop-timestamp")

        hops.append(
            MailFlowHop(
                position=index,
                from_host=from_host,
                by_host=by_host,
                from_ip=from_ip,
                timestamp=timestamp,
                raw=raw_line,
                findings=findings,
            )
        )

    if len(hops) >= 3:
        hops[0].findings.append("multi-hop-chain")
    _apply_time_consistency_findings(hops)

    return hops


def _parse_received_timestamp(raw_line: str):
    if ";" not in raw_line:
        return None
    _, _, trailing = raw_line.rpartition(";")
    candidate = trailing.strip()
    if not candidate:
        return None
    try:
        return parsedate_to_datetime(candidate)
    except (TypeError, ValueError, IndexError):
        return None


def _header_findings(authentication: AuthenticationEvidence, mail_flow: list[MailFlowHop]) -> list[str]:
    findings: list[str] = []
    if authentication.spf_result in {"fail", "softfail"}:
        findings.append("spf-failed")
    if authentication.dkim_result == "fail":
        findings.append("dkim-failed")
    if authentication.dmarc_result in {"fail", "quarantine", "reject"}:
        findings.append("dmarc-failed")
    if authentication.spf_result in {"neutral", "none"}:
        findings.append("spf-weak")
    if authentication.dkim_result in {"none"}:
        findings.append("dkim-missing")
    if authentication.dmarc_result in {"none"}:
        findings.append("dmarc-missing")
    if authentication.spf_result in {"pass", "softfail", "neutral"} and authentication.spf_aligned is False:
        findings.append("spf-misaligned")
    if authentication.dkim_result == "pass" and authentication.dkim_aligned is False:
        findings.append("dkim-misaligned")
    if authentication.dmarc_result in {"pass", "bestguesspass"} and authentication.dmarc_aligned is False:
        findings.append("dmarc-misaligned")
    for hop in mail_flow:
        findings.extend(hop.findings)
    return list(dict.fromkeys(findings))


def _apply_time_consistency_findings(hops: list[MailFlowHop]) -> None:
    previous_timestamp = None
    for hop in hops:
        if hop.timestamp is None:
            continue
        if previous_timestamp and hop.timestamp > previous_timestamp:
            hop.findings.append("received-time-order-anomaly")
        previous_timestamp = hop.timestamp


def _join_header_values(headers: dict[str, str], names: set[str]) -> str:
    return " ".join(value for key, value in headers.items() if key.lower() in names).lower()


def _get_header(headers: dict[str, str], name: str) -> str | None:
    for key, value in headers.items():
        if key.lower() == name:
            return value
    return None


def _match_group(value: str | None, pattern: str) -> str | None:
    if not value:
        return None
    match = re.search(pattern, value, re.IGNORECASE)
    if not match:
        return None
    return match.group(1).strip().lower()


def _first_address(value: str | None) -> str | None:
    if not value:
        return None
    return next((email for _, email in getaddresses([value]) if email), None)


def _domain_from_email(value: str | None) -> str | None:
    if not value or "@" not in value:
        return None
    return _normalize_domain(value.split("@", 1)[1])


def _normalize_domain(value: str | None) -> str | None:
    if not value:
        return None
    return value.strip().strip("<>").strip(".").lower() or None


def _is_domain_aligned(observed_domain: str | None, sender_domain: str | None) -> bool | None:
    if not observed_domain or not sender_domain:
        return None
    return observed_domain == sender_domain or observed_domain.endswith(f".{sender_domain}")
