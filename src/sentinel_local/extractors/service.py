"""IOC extraction and deduplication service."""

from __future__ import annotations

import ipaddress

from sentinel_local.domain.models import ExtractionResult, Indicator, ParsedEmail
from sentinel_local.extractors.html import extract_links
from sentinel_local.extractors.normalize import (
    attachment_extension,
    normalize_attachment_name,
    normalize_domain,
    normalize_email,
    normalize_hash,
    normalize_ip,
    normalize_url,
    url_to_domain,
)
from sentinel_local.extractors.patterns import DOMAIN_PATTERN, EMAIL_PATTERN, HASH_PATTERN, IPV4_PATTERN, URL_PATTERN


def extract_indicators(parsed_email: ParsedEmail) -> ExtractionResult:
    """Extract normalized indicators from a parsed email."""
    seen: set[tuple[str, str, str]] = set()
    indicators: list[Indicator] = []

    def add_indicator(indicator: Indicator) -> None:
        key = (indicator.type, indicator.normalized_value, indicator.source)
        if key in seen:
            return
        seen.add(key)
        indicators.append(indicator)

    _extract_from_text(parsed_email.text_body, "text_body", add_indicator)
    _extract_from_text(parsed_email.html_body, "html_body", add_indicator)
    _extract_from_html(parsed_email.html_body, add_indicator)
    _extract_from_headers(parsed_email.headers, add_indicator)
    _extract_from_addresses(parsed_email, add_indicator)
    _extract_from_attachments(parsed_email, add_indicator)

    return ExtractionResult(indicators=indicators)


def _extract_from_text(content: str | None, source: str, add_indicator) -> None:
    if not content:
        return

    for raw_url in URL_PATTERN.findall(content):
        normalized = normalize_url(raw_url)
        add_indicator(Indicator(type="url", value=raw_url, normalized_value=normalized, source=source))
        domain = url_to_domain(normalized)
        if domain:
            add_indicator(
                Indicator(
                    type="domain",
                    value=domain,
                    normalized_value=normalize_domain(domain),
                    source=source,
                )
            )

    for raw_email in EMAIL_PATTERN.findall(content):
        normalized = normalize_email(raw_email)
        add_indicator(Indicator(type="email", value=raw_email, normalized_value=normalized, source=source))
        domain = _email_domain(normalized)
        if domain:
            add_indicator(
                Indicator(type="domain", value=domain, normalized_value=normalize_domain(domain), source=source)
            )

    for raw_domain in DOMAIN_PATTERN.findall(content):
        normalized = normalize_domain(raw_domain)
        add_indicator(Indicator(type="domain", value=raw_domain, normalized_value=normalized, source=source))

    for raw_ip in IPV4_PATTERN.findall(content):
        if not _is_valid_ipv4(raw_ip):
            continue
        add_indicator(
            Indicator(type="ip", value=raw_ip, normalized_value=normalize_ip(raw_ip), source=source)
        )

    for raw_hash in HASH_PATTERN.findall(content):
        add_indicator(
            Indicator(type="hash", value=raw_hash, normalized_value=normalize_hash(raw_hash), source=source)
        )


def _extract_from_html(content: str | None, add_indicator) -> None:
    for link in extract_links(content):
        normalized = normalize_url(link)
        add_indicator(Indicator(type="url", value=link, normalized_value=normalized, source="html_body"))
        domain = url_to_domain(normalized)
        if domain:
            add_indicator(
                Indicator(
                    type="domain",
                    value=domain,
                    normalized_value=normalize_domain(domain),
                    source="html_body",
                )
            )


def _extract_from_headers(headers: dict[str, str], add_indicator) -> None:
    for value in headers.values():
        _extract_from_text(value, "headers", add_indicator)


def _extract_from_addresses(parsed_email: ParsedEmail, add_indicator) -> None:
    if parsed_email.sender and parsed_email.sender.email:
        normalized = normalize_email(parsed_email.sender.email)
        add_indicator(
            Indicator(type="email", value=parsed_email.sender.email, normalized_value=normalized, source="sender")
        )
        domain = _email_domain(normalized)
        if domain:
            add_indicator(
                Indicator(type="domain", value=domain, normalized_value=normalize_domain(domain), source="sender")
            )

    for recipient in parsed_email.recipients:
        if not recipient.email:
            continue
        normalized = normalize_email(recipient.email)
        add_indicator(
            Indicator(type="email", value=recipient.email, normalized_value=normalized, source="recipient")
        )
        domain = _email_domain(normalized)
        if domain:
            add_indicator(
                Indicator(
                    type="domain",
                    value=domain,
                    normalized_value=normalize_domain(domain),
                    source="recipient",
                )
            )


def _extract_from_attachments(parsed_email: ParsedEmail, add_indicator) -> None:
    for attachment in parsed_email.attachments:
        normalized_name = normalize_attachment_name(attachment.filename)
        add_indicator(
            Indicator(
                type="attachment_name",
                value=attachment.filename,
                normalized_value=normalized_name,
                source="attachment",
            )
        )

        extension = attachment_extension(attachment.filename)
        if extension:
            add_indicator(
                Indicator(
                    type="attachment_ext",
                    value=extension,
                    normalized_value=extension,
                    source="attachment",
                )
            )


def _is_valid_ipv4(value: str) -> bool:
    try:
        candidate = ipaddress.ip_address(value)
    except ValueError:
        return False
    return candidate.version == 4


def _email_domain(value: str) -> str | None:
    if "@" not in value:
        return None
    local_part, domain = value.split("@", 1)
    if not local_part or not domain:
        return None
    return domain
