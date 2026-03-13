"""Parsers for plaintext and pasted email content."""

from __future__ import annotations

from email import policy
from email.parser import Parser

from sentinel_local.domain.models import ParsedEmail
from sentinel_local.parsers.common import collect_headers, decode_mime_header, parse_addresses, parse_datetime


def parse_txt_bytes(content: bytes) -> ParsedEmail:
    """Parse raw text bytes that may contain headers and body."""
    text = content.decode("utf-8", errors="replace")
    return _parse_text_payload(text, source_type="txt")


def parse_pasted_text(content: str, *, raw_headers: str | None = None) -> ParsedEmail:
    """Parse analyst-pasted email text with optional separately pasted headers."""
    if raw_headers:
        normalized_content = f"{raw_headers.strip()}\n\n{content.strip()}"
        parsed = _parse_text_payload(normalized_content, source_type="pasted")
        if parsed.subject is None:
            fallback = _parse_text_payload(content, source_type="pasted")
            if fallback.subject is not None:
                parsed.subject = fallback.subject
            if parsed.text_body is None and fallback.text_body is not None:
                parsed.text_body = fallback.text_body
        return parsed

    return _parse_text_payload(content, source_type="pasted")


def _parse_text_payload(content: str, *, source_type: str) -> ParsedEmail:
    """Parse header-like plaintext content into ParsedEmail."""
    message = Parser(policy=policy.default).parsestr(content)

    parsed_headers = collect_headers(message.items())
    header_detected = bool(parsed_headers)
    text_body = message.get_body(preferencelist=("plain",))

    sender = next(iter(parse_addresses([message.get("From", "")])), None)

    body = None
    if text_body is not None and text_body.get_content():
        payload = text_body.get_content()
        body = payload.strip() if isinstance(payload, str) and payload.strip() else None
    elif not header_detected:
        body = content.strip() or None
    else:
        raw_body = message.get_payload()
        body = raw_body.strip() if isinstance(raw_body, str) and raw_body.strip() else None

    return ParsedEmail(
        source_type=source_type,  # type: ignore[arg-type]
        subject=decode_mime_header(message.get("Subject")),
        sender=sender,
        to_recipients=parse_addresses(message.get_all("To", [])),
        cc_recipients=parse_addresses(message.get_all("Cc", [])),
        bcc_recipients=parse_addresses(message.get_all("Bcc", [])),
        sent_at=parse_datetime(message.get("Date")),
        text_body=body,
        html_body=None,
        headers=parsed_headers,
        attachments=[],
    )
