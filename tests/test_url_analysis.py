import httpx

from sentinel_local.domain.models import EmailAddress, ExtractionResult, Indicator, ParsedEmail
from sentinel_local.url_analysis import analyze_urls


def test_url_analysis_detects_tracking_wrapper_and_display_mismatch() -> None:
    parsed = ParsedEmail(
        source_type="pasted",
        sender=EmailAddress(email="sender@example.com"),
        html_body='<a href="https://url.example/redirect?url=https%3A%2F%2Fevil.example%2Flogin">https://portal.example.org/login</a>',
    )
    extraction = ExtractionResult(
        indicators=[
            Indicator(
                type="url",
                value="https://url.example/redirect?url=https%3A%2F%2Fevil.example%2Flogin",
                normalized_value="https://url.example/redirect?url=https%3A%2F%2Fevil.example%2Flogin",
                source="html_body",
            )
        ]
    )

    result = analyze_urls(parsed_email=parsed, extraction_result=extraction)

    assert len(result.artifacts) == 1
    artifact = result.artifacts[0]
    assert artifact.unwrapped_url == "https://evil.example/login"
    assert "tracking-wrapper" in artifact.findings
    assert "display-text-mismatch" in artifact.findings


def test_url_analysis_resolves_redirect_chain_when_requested() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url == "https://bit.ly/sample":
            return httpx.Response(
                302,
                headers={"location": "https://final.example/login"},
                request=request,
            )
        return httpx.Response(200, request=request)

    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True)
    parsed = ParsedEmail(source_type="pasted")
    extraction = ExtractionResult(
        indicators=[
            Indicator(
                type="url",
                value="https://bit.ly/sample",
                normalized_value="https://bit.ly/sample",
                source="text_body",
            )
        ]
    )

    result = analyze_urls(
        parsed_email=parsed,
        extraction_result=extraction,
        resolve_redirects=True,
        client=client,
    )

    artifact = result.artifacts[0]
    assert artifact.final_url == "https://final.example/login"
    assert "redirect-resolved" in artifact.findings


def test_url_analysis_detects_hidden_html_forms_and_javascript_links() -> None:
    parsed = ParsedEmail(
        source_type="pasted",
        html_body=(
            '<div style="display:none">hidden</div>'
            '<form action="https://evil.example/post"></form>'
            '<a href="javascript:alert(1)">Open</a>'
            "<script>alert('x')</script>"
        ),
    )
    result = analyze_urls(parsed_email=parsed, extraction_result=ExtractionResult())

    artifact_types = {artifact.artifact_type for artifact in result.html_artifacts}

    assert "hidden-element" in artifact_types
    assert "form" in artifact_types
    assert "javascript-link" in artifact_types
    assert "script" in artifact_types


def test_url_analysis_can_build_screenshot_link() -> None:
    parsed = ParsedEmail(source_type="pasted")
    extraction = ExtractionResult(
        indicators=[
            Indicator(
                type="url",
                value="https://evil.example/login",
                normalized_value="https://evil.example/login",
                source="text_body",
            )
        ]
    )

    result = analyze_urls(
        parsed_email=parsed,
        extraction_result=extraction,
        enable_screenshots=True,
        screenshot_provider="thum_io",
    )

    assert result.artifacts[0].screenshot_url is not None
    assert "image.thum.io" in result.artifacts[0].screenshot_url


def test_url_analysis_skips_private_targets_for_redirects_and_screenshots() -> None:
    parsed = ParsedEmail(source_type="pasted")
    extraction = ExtractionResult(
        indicators=[
            Indicator(
                type="url",
                value="http://192.168.1.25/login",
                normalized_value="http://192.168.1.25/login",
                source="text_body",
            )
        ]
    )

    result = analyze_urls(
        parsed_email=parsed,
        extraction_result=extraction,
        resolve_redirects=True,
        enable_screenshots=True,
        screenshot_provider="thum_io",
    )

    artifact = result.artifacts[0]
    assert artifact.final_url is None
    assert artifact.redirect_chain == []
    assert artifact.screenshot_url is None
