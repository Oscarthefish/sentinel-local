"""Deterministic and optional network-backed URL analysis."""

from __future__ import annotations

import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlsplit

import httpx

from sentinel_local.domain.models import ExtractionResult, HtmlArtifact, ParsedEmail, UrlAnalysisResult, UrlArtifact
from sentinel_local.url_analysis.html import extract_anchors, extract_html_artifacts
from sentinel_local.url_analysis.normalize import extract_display_domain, is_shortener, unwrap_tracking_url
from sentinel_local.url_analysis.screenshot import capture_screenshot

_MAX_REDIRECT_WORKERS = 6


def analyze_urls(
    *,
    parsed_email: ParsedEmail,
    extraction_result: ExtractionResult,
    resolve_redirects: bool = False,
    enable_screenshots: bool = False,
    screenshot_provider: str = "none",
    screenshot_base_url: str | None = None,
    timeout_seconds: int = 15,
    client: httpx.Client | None = None,
) -> UrlAnalysisResult:
    """Analyze URLs in message content and optionally resolve redirect chains."""
    html_anchor_map = {anchor["href"]: anchor.get("text") or None for anchor in extract_anchors(parsed_email.html_body)}
    html_artifacts = [
        HtmlArtifact(
            artifact_type=item["artifact_type"],  # type: ignore[arg-type]
            summary=item["summary"],
            details={"value": item["details"]},
        )
        for item in extract_html_artifacts(parsed_email.html_body)
    ]

    # Build artifacts deterministically (no network) first
    url_indicators = [indicator for indicator in extraction_result.indicators if indicator.type == "url"]
    seen: set[tuple[str, str]] = set()
    artifacts: list[UrlArtifact] = []
    for indicator in url_indicators:
        key = (indicator.normalized_value, indicator.source)
        if key in seen:
            continue
        seen.add(key)

        display_text = html_anchor_map.get(indicator.normalized_value)
        unwrapped = unwrap_tracking_url(indicator.normalized_value)
        findings = []
        if unwrapped:
            findings.append("tracking-wrapper")
        if is_shortener(indicator.normalized_value):
            findings.append("shortened-url")
        if _has_display_mismatch(display_text, indicator.normalized_value):
            findings.append("display-text-mismatch")

        artifacts.append(UrlArtifact(
            original_url=indicator.normalized_value,
            source=indicator.source,
            unwrapped_url=unwrapped,
            display_text=display_text,
            findings=findings,
        ))

    # Resolve redirects concurrently (network phase, only when requested)
    if resolve_redirects and artifacts:
        _resolve_redirects_parallel(artifacts, timeout_seconds=timeout_seconds)

    if enable_screenshots:
        if screenshot_provider == "playwright":
            _capture_screenshots_parallel(artifacts, timeout_ms=15000)
        else:
            for artifact in artifacts:
                screenshot_target = artifact.final_url or artifact.unwrapped_url or artifact.original_url
                artifact.screenshot_url = _build_screenshot_url(
                    screenshot_target,
                    provider=screenshot_provider,
                    base_url=screenshot_base_url,
                )
                if artifact.screenshot_url:
                    artifact.findings.append("screenshot-available")

    return UrlAnalysisResult(artifacts=artifacts, html_artifacts=html_artifacts)


def _resolve_redirects_parallel(artifacts: list[UrlArtifact], *, timeout_seconds: int) -> None:
    """Resolve redirect chains for all artifacts concurrently, mutating them in place."""
    def _resolve(artifact: UrlArtifact) -> tuple[UrlArtifact, str | None, list[str]]:
        target = artifact.unwrapped_url or artifact.original_url
        final_url, chain = _resolve_redirect_chain(target, timeout_seconds=timeout_seconds)
        return artifact, final_url, chain

    workers = min(_MAX_REDIRECT_WORKERS, len(artifacts))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_resolve, a): a for a in artifacts}
        for future in as_completed(futures):
            try:
                artifact, final_url, chain = future.result()
                artifact.final_url = final_url
                artifact.redirect_chain = chain
                if chain:
                    artifact.findings.append("redirect-resolved")
            except Exception:
                pass


def _has_display_mismatch(display_text: str | None, url: str) -> bool:
    display_domain = extract_display_domain(display_text)
    actual_domain = (urlsplit(url).hostname or "").lower()
    return bool(display_domain and actual_domain and display_domain != actual_domain)


def _capture_screenshots_parallel(artifacts: list[UrlArtifact], *, timeout_ms: int) -> None:
    """Capture screenshots for all safe public artifacts concurrently."""
    def _capture(artifact: UrlArtifact) -> tuple[UrlArtifact, str | None]:
        target = artifact.final_url or artifact.unwrapped_url or artifact.original_url
        if not _is_safe_public_web_target(target):
            return artifact, None
        return artifact, capture_screenshot(target, timeout_ms=timeout_ms)

    workers = min(4, len(artifacts))  # cap browser instances
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_capture, a): a for a in artifacts}
        for future in as_completed(futures):
            try:
                artifact, data_uri = future.result()
                if data_uri:
                    artifact.screenshot_url = data_uri
                    artifact.findings.append("screenshot-available")
            except Exception:
                pass


def _resolve_redirect_chain(
    url: str,
    *,
    timeout_seconds: int,
    client: httpx.Client | None = None,
) -> tuple[str | None, list[str]]:
    if not _is_safe_public_web_target(url):
        return None, []

    close_client = client is None
    client = client or httpx.Client(timeout=timeout_seconds, follow_redirects=True)
    try:
        response = client.get(url)
        chain = [str(item.headers.get("location")) for item in response.history if item.headers.get("location")]
        return str(response.url), chain
    except httpx.HTTPError:
        return None, []
    finally:
        if close_client:
            client.close()


def _build_screenshot_url(url: str, *, provider: str, base_url: str | None) -> str | None:
    if not _is_safe_public_web_target(url):
        return None

    provider = provider.lower()
    if provider == "none":
        return None
    if provider == "custom" and base_url:
        return f"{base_url.rstrip('/')}?url={url}"
    if provider == "thum_io":
        return f"https://image.thum.io/get/width/1200/noanimate/{url}"
    return None


def _is_safe_public_web_target(url: str) -> bool:
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"}:
        return False

    hostname = (parts.hostname or "").strip().lower().rstrip(".")
    if not hostname:
        return False
    if hostname in {"localhost", "localhost.localdomain"}:
        return False
    if hostname.endswith(".local") or hostname.endswith(".internal"):
        return False
    if "." not in hostname:
        return False

    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        return True

    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
        or address.is_unspecified
    )
