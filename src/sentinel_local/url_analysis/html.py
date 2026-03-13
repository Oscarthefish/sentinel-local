"""HTML parsing helpers for URL analysis."""

from __future__ import annotations

from html.parser import HTMLParser


class _AnchorCollector(HTMLParser):
    """Collect href and visible text from anchor tags."""

    def __init__(self) -> None:
        super().__init__()
        self.anchors: list[dict[str, str]] = []
        self._current_href: str | None = None
        self._current_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "a":
            return
        self._current_href = None
        self._current_text = []
        for key, value in attrs:
            if key.lower() == "href" and value:
                self._current_href = value

    def handle_data(self, data: str) -> None:
        if self._current_href is not None:
            self._current_text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() != "a":
            return
        if self._current_href is not None:
            self.anchors.append(
                {
                    "href": self._current_href,
                    "text": " ".join(part.strip() for part in self._current_text if part.strip()),
                }
            )
        self._current_href = None
        self._current_text = []


def extract_anchors(html: str | None) -> list[dict[str, str]]:
    """Return href/text pairs from basic HTML content."""
    if not html:
        return []
    parser = _AnchorCollector()
    parser.feed(html)
    return parser.anchors


class _HtmlArtifactCollector(HTMLParser):
    """Collect HTML artifacts relevant to email analysis."""

    def __init__(self) -> None:
        super().__init__()
        self.artifacts: list[dict[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = {key.lower(): value or "" for key, value in attrs}
        lowered_tag = tag.lower()

        if lowered_tag == "script":
            self.artifacts.append(
                {
                    "artifact_type": "script",
                    "summary": "HTML body contains a script tag",
                    "details": f"tag={lowered_tag}",
                }
            )

        if lowered_tag == "form":
            self.artifacts.append(
                {
                    "artifact_type": "form",
                    "summary": "HTML body contains a form submission element",
                    "details": attrs_dict.get("action", ""),
                }
            )

        if lowered_tag == "a" and attrs_dict.get("href", "").lower().startswith("javascript:"):
            self.artifacts.append(
                {
                    "artifact_type": "javascript-link",
                    "summary": "Anchor href uses javascript:",
                    "details": attrs_dict.get("href", ""),
                }
            )

        style = attrs_dict.get("style", "").lower()
        hidden = attrs_dict.get("hidden", "")
        if hidden or "display:none" in style or "visibility:hidden" in style or attrs_dict.get("aria-hidden", "").lower() == "true":
            self.artifacts.append(
                {
                    "artifact_type": "hidden-element",
                    "summary": "HTML body contains a hidden element",
                    "details": lowered_tag,
                }
            )


def extract_html_artifacts(html: str | None) -> list[dict[str, str]]:
    """Return suspicious non-URL HTML artifacts."""
    if not html:
        return []
    parser = _HtmlArtifactCollector()
    parser.feed(html)
    return parser.artifacts
