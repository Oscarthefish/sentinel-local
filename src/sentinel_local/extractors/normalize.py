"""Normalization helpers for extracted indicators."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


def normalize_url(value: str) -> str:
    """Normalize a URL for deduplication."""
    trimmed = value.strip().rstrip(".,);]>\"'")
    parts = urlsplit(trimmed)
    scheme = parts.scheme.lower()
    netloc = parts.netloc.lower()
    path = parts.path or "/"
    return urlunsplit((scheme, netloc, path, parts.query, ""))


def url_to_domain(value: str) -> str | None:
    """Extract the hostname from a URL."""
    parts = urlsplit(value)
    return parts.hostname.lower() if parts.hostname else None


def normalize_domain(value: str) -> str:
    """Normalize a domain value."""
    return value.strip().strip(".,);]>\"'").lower()


def normalize_ip(value: str) -> str:
    """Normalize an IPv4 indicator."""
    return value.strip().strip(".,);]>\"'")


def normalize_email(value: str) -> str:
    """Normalize an email address."""
    return value.strip().strip(".,);]>\"'").lower()


def normalize_hash(value: str) -> str:
    """Normalize a hash value."""
    return value.strip().lower()


def normalize_attachment_name(value: str) -> str:
    """Normalize an attachment filename."""
    return Path(value).name.strip().lower()


def attachment_extension(value: str) -> str | None:
    """Return the normalized extension for an attachment filename."""
    suffix = Path(value).suffix.lower()
    return suffix or None
