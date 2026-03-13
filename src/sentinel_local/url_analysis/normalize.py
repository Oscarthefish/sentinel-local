"""Normalization and tracking-link helpers for URL analysis."""

from __future__ import annotations

from urllib.parse import parse_qs, unquote, urlsplit


TRACKING_PARAM_CANDIDATES = (
    "url",
    "u",
    "redirect",
    "redirect_url",
    "dest",
    "destination",
    "target",
    "to",
    "redir",
    "r",
    "redirect_uri",
)
SHORTENER_HOSTS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "buff.ly",
    "lnkd.in",
}
TRACKING_HOST_HINTS = (
    "proofpoint",
    "mimecast",
    "safelinks",
    "urldefense",
    "trendmicro",
    "outlook.com",
)


def unwrap_tracking_url(url: str) -> str | None:
    """Return an embedded destination from a tracking wrapper if present."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    params = parse_qs(parts.query)
    for candidate in TRACKING_PARAM_CANDIDATES:
        if candidate in params and params[candidate]:
            return unquote(params[candidate][0])
    if "urldefense.com" in host and "__" in parts.path:
        try:
            encoded = parts.path.split("__", 1)[1].rsplit("__", 1)[0]
            return unquote(encoded)
        except IndexError:
            return None
    if any(hint in host for hint in TRACKING_HOST_HINTS) and parts.fragment.startswith("url="):
        return unquote(parts.fragment.split("url=", 1)[1])
    return None


def is_shortener(url: str) -> bool:
    """Return whether the URL host is a known shortener."""
    host = urlsplit(url).hostname or ""
    return host.lower() in SHORTENER_HOSTS


def extract_display_domain(text: str | None) -> str | None:
    """Extract a domain-like string from display text when present."""
    if not text:
        return None
    token = text.strip().replace("https://", "").replace("http://", "").split("/", 1)[0]
    if "." in token and " " not in token:
        return token.lower()
    return None
