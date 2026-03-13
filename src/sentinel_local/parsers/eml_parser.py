"""Parser for RFC822 EML content."""

from __future__ import annotations

from email import policy
from email.parser import BytesParser
from email.utils import collapse_rfc2231_value

from sentinel_local.domain.models import ParsedEmail
from sentinel_local.parsers.common import (
    collect_headers,
    compute_sha256,
    coerce_attachment,
    decode_mime_header,
    parse_addresses,
    parse_datetime,
)


def parse_eml_bytes(content: bytes) -> ParsedEmail:
    """Parse raw EML bytes into the canonical ParsedEmail model."""
    message = BytesParser(policy=policy.default).parsebytes(content)

    text_parts: list[str] = []
    html_parts: list[str] = []
    attachments = []

    for part in message.walk():
        if part.is_multipart():
            continue

        content_disposition = (part.get_content_disposition() or "").lower()
        filename = part.get_filename()
        decoded_filename = collapse_rfc2231_value(filename) if filename else None

        if content_disposition == "attachment" or decoded_filename:
            payload = part.get_payload(decode=True) or b""
            attachment = coerce_attachment(
                decode_mime_header(decoded_filename),
                content_type=part.get_content_type(),
                size=len(payload),
                sha256=compute_sha256(payload),
            )
            if attachment is not None:
                attachments.append(attachment)
            continue

        body = part.get_content()
        if not isinstance(body, str):
            continue

        if part.get_content_type() == "text/plain":
            text_parts.append(body)
        elif part.get_content_type() == "text/html":
            html_parts.append(body)

    sender = next(iter(parse_addresses([message.get("From", "")])), None)

    return ParsedEmail(
        source_type="eml",
        subject=decode_mime_header(message.get("Subject")),
        sender=sender,
        to_recipients=parse_addresses(message.get_all("To", [])),
        cc_recipients=parse_addresses(message.get_all("Cc", [])),
        bcc_recipients=parse_addresses(message.get_all("Bcc", [])),
        sent_at=parse_datetime(message.get("Date")),
        text_body="\n\n".join(part.strip() for part in text_parts if part.strip()) or None,
        html_body="\n\n".join(part.strip() for part in html_parts if part.strip()) or None,
        headers=collect_headers(message.items()),
        attachments=attachments,
    )
