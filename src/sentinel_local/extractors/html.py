"""HTML helpers for IOC extraction."""

from __future__ import annotations

from html.parser import HTMLParser


class _LinkCollector(HTMLParser):
    """Collect href values from basic HTML content."""

    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "a":
            return

        for key, value in attrs:
            if key.lower() == "href" and value:
                self.links.append(value)


def extract_links(html: str | None) -> list[str]:
    """Return href values found in a simple HTML fragment."""
    if not html:
        return []

    parser = _LinkCollector()
    parser.feed(html)
    return parser.links
