"""Local headless screenshot capture using Playwright."""

from __future__ import annotations

import base64
import logging

log = logging.getLogger(__name__)


def capture_screenshot(url: str, *, timeout_ms: int = 15000) -> str | None:
    """Capture a headless screenshot of a URL and return a PNG data URI.

    Returns None on any failure (Playwright not installed, navigation error,
    timeout, etc.) so the rest of the pipeline is unaffected.

    Requires: pip install playwright && playwright install chromium
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        log.warning(
            "playwright is not installed — screenshots disabled. "
            "Run: pip install playwright && playwright install chromium"
        )
        return None

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            try:
                ctx = browser.new_context(
                    viewport={"width": 1280, "height": 800},
                    user_agent=(
                        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/120.0.0.0 Safari/537.36"
                    ),
                    java_script_enabled=True,
                    ignore_https_errors=True,
                )
                page = ctx.new_page()
                page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
                # Brief pause for any JS-driven content to settle
                page.wait_for_timeout(800)
                png_bytes = page.screenshot(full_page=False, type="png")
            finally:
                browser.close()

        b64 = base64.b64encode(png_bytes).decode()
        return f"data:image/png;base64,{b64}"

    except Exception as exc:
        log.debug("Screenshot failed for %s: %s", url, exc)
        return None
