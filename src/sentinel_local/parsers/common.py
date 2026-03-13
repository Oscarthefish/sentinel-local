"""Common helpers used by parser implementations."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime
from email.header import decode_header, make_header
from email.utils import getaddresses, parsedate_to_datetime
from hashlib import sha256

from sentinel_local.domain.models import AttachmentMetadata, EmailAddress


def decode_mime_header(value: str | None) -> str | None:
    """Decode RFC 2047-encoded header values into plain text."""
    if value is None:
        return None

    return str(make_header(decode_header(value))).strip() or None


def parse_addresses(values: Iterable[str]) -> list[EmailAddress]:
    """Parse one or more email address header values into structured entries."""
    parsed = []
    for display_name, email in getaddresses(list(values)):
        parsed.append(
            EmailAddress(
                name=decode_mime_header(display_name),
                email=email or None,
            )
        )
    return parsed


def parse_datetime(value: str | None) -> datetime | None:
    """Parse an email date header if present."""
    if not value:
        return None

    try:
        return parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        return None


def compute_sha256(data: bytes) -> str | None:
    """Return a lowercase SHA-256 hex digest for non-empty attachment bytes."""
    if not data:
        return None

    return sha256(data).hexdigest()


def collect_headers(items: Iterable[tuple[str, str | None]]) -> dict[str, str]:
    """Collect headers while preserving repeated fields as newline-joined values."""
    headers: dict[str, str] = {}
    for key, raw_value in items:
        value = decode_mime_header(raw_value) or ""
        if key in headers and value:
            headers[key] = f"{headers[key]}\n{value}".strip()
        else:
            headers[key] = value
    return headers


def coerce_attachment(
    filename: str | None,
    *,
    content_type: str | None = None,
    size: int | None = None,
    sha256: str | None = None,
) -> AttachmentMetadata | None:
    """Create attachment metadata when a filename is available."""
    if not filename:
        return None

    return AttachmentMetadata(
        filename=filename,
        content_type=content_type,
        size=size,
        sha256=sha256,
    )
