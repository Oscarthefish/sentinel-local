"""Parser for Outlook MSG content."""

from __future__ import annotations

from pathlib import Path

import extract_msg

from sentinel_local.domain.models import ParsedEmail
from sentinel_local.parsers.common import compute_sha256, coerce_attachment, parse_datetime


def parse_msg_file(path: Path) -> ParsedEmail:
    """Parse a local Outlook MSG file into the canonical ParsedEmail model."""
    message = extract_msg.Message(str(path))

    attachments = []
    for attachment in getattr(message, "attachments", []):
        data = getattr(attachment, "data", b"") or b""
        metadata = coerce_attachment(
            getattr(attachment, "longFilename", None) or getattr(attachment, "filename", None),
            content_type=getattr(attachment, "mimetype", None),
            size=len(data),
            sha256=compute_sha256(data),
        )
        if metadata is not None:
            attachments.append(metadata)

    sender_email = getattr(message, "sender", None)
    sender_name = getattr(message, "sender_name", None) or getattr(message, "senderName", None)

    return ParsedEmail(
        source_type="msg",
        subject=getattr(message, "subject", None),
        sender={"name": sender_name, "email": sender_email},
        to_recipients=[{"email": address} for address in _split_msg_addresses(getattr(message, "to", None))],
        cc_recipients=[{"email": address} for address in _split_msg_addresses(getattr(message, "cc", None))],
        bcc_recipients=[{"email": address} for address in _split_msg_addresses(getattr(message, "bcc", None))],
        sent_at=parse_datetime(getattr(message, "date", None)),
        text_body=getattr(message, "body", None),
        html_body=getattr(message, "htmlBody", None),
        headers=_extract_msg_headers(getattr(message, "header", None)),
        attachments=attachments,
    )


def _split_msg_addresses(value: str | None) -> list[str]:
    """Split MSG recipient strings into normalized individual addresses."""
    if not value:
        return []

    normalized = value.replace(";", ",")
    return [part.strip() for part in normalized.split(",") if part.strip()]


def _extract_msg_headers(header_blob: str | None) -> dict[str, str]:
    """Parse message header text emitted by extract-msg if available."""
    if not header_blob:
        return {}

    headers: dict[str, str] = {}
    current_key: str | None = None

    for raw_line in header_blob.splitlines():
        if not raw_line.strip():
            continue

        if raw_line[0].isspace() and current_key:
            headers[current_key] = f"{headers[current_key]} {raw_line.strip()}".strip()
            continue

        if ":" not in raw_line:
            continue

        key, value = raw_line.split(":", 1)
        current_key = key.strip()
        normalized_value = value.strip()
        if current_key in headers and normalized_value:
            headers[current_key] = f"{headers[current_key]}\n{normalized_value}".strip()
        else:
            headers[current_key] = normalized_value

    return headers
