import base64

import httpx

from sentinel_local.core.config import Settings
from sentinel_local.domain.models import AttachmentMetadata, EmailAddress, ExtractionResult, Indicator, ParsedEmail
from sentinel_local.enrichers import enrich_indicators


def test_enrich_indicators_uses_configured_providers() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if "virustotal" in str(request.url):
            if request.url.path.endswith("/domains/evil.example"):
                return httpx.Response(
                    200,
                    json={"data": {"attributes": {"last_analysis_stats": {"malicious": 3, "suspicious": 1}}}},
                )
            if request.url.path.endswith("/ip_addresses/8.8.8.8"):
                return httpx.Response(
                    200,
                    json={"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 0}}}},
                )
        if "abuseipdb" in str(request.url):
            return httpx.Response(
                200,
                json={
                    "data": {
                        "abuseConfidenceScore": 42,
                        "countryCode": "US",
                        "usageType": "Data Center/Web Hosting/Transit",
                        "totalReports": 5,
                    }
                },
            )
        raise AssertionError(f"Unexpected request: {request.url}")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    settings = Settings(
        ENABLE_ENRICHMENT=True,
        VIRUSTOTAL_API_KEY="vt-key",
        ABUSEIPDB_API_KEY="abuse-key",
    )
    extraction = ExtractionResult(
        indicators=[
            Indicator(type="domain", value="evil.example", normalized_value="evil.example", source="text_body"),
            Indicator(type="ip", value="8.8.8.8", normalized_value="8.8.8.8", source="text_body"),
        ]
    )

    result = enrich_indicators(settings=settings, extraction_result=extraction, client=client)

    assert any(record.provider == "VirusTotal" and record.indicator_value == "evil.example" for record in result.records)
    assert any(record.provider == "AbuseIPDB" and record.indicator_value == "8.8.8.8" for record in result.records)


def test_virustotal_url_encoding_path_is_supported() -> None:
    encoded = base64.urlsafe_b64encode("https://evil.example/path".encode()).decode().rstrip("=")
    seen_paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_paths.append(request.url.path)
        return httpx.Response(
            200,
            json={"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 2}}}},
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    settings = Settings(ENABLE_ENRICHMENT=True, VIRUSTOTAL_API_KEY="vt-key")
    extraction = ExtractionResult(
        indicators=[
            Indicator(
                type="url",
                value="https://evil.example/path",
                normalized_value="https://evil.example/path",
                source="text_body",
            )
        ]
    )

    result = enrich_indicators(settings=settings, extraction_result=extraction, client=client)

    assert any(path.endswith(f"/urls/{encoded}") for path in seen_paths)
    assert result.records[0].severity == "medium"


def test_virustotal_404_is_treated_as_no_result() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"error": {"code": "NotFoundError"}})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    settings = Settings(ENABLE_ENRICHMENT=True, VIRUSTOTAL_API_KEY="vt-key")
    extraction = ExtractionResult(
        indicators=[
            Indicator(type="domain", value="missing.example", normalized_value="missing.example", source="text_body")
        ]
    )

    result = enrich_indicators(settings=settings, extraction_result=extraction, client=client)

    assert result.records == []


def test_enrichment_skips_recipient_domains_and_emails() -> None:
    seen_paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_paths.append(request.url.path)
        return httpx.Response(
            200,
            json={"data": {"attributes": {"last_analysis_stats": {"malicious": 1, "suspicious": 0}}}},
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    settings = Settings(enable_enrichment=True, virustotal_api_key="vt-key")
    parsed_email = ParsedEmail(
        source_type="pasted",
        sender=EmailAddress(email="sender@bad.example"),
        to_recipients=[EmailAddress(email="employee@example.org")],
    )
    extraction = ExtractionResult(
        indicators=[
            Indicator(type="domain", value="example.org", normalized_value="example.org", source="recipient"),
            Indicator(type="domain", value="bad.example", normalized_value="bad.example", source="sender"),
        ]
    )

    result = enrich_indicators(
        settings=settings,
        extraction_result=extraction,
        parsed_email=parsed_email,
        client=client,
    )

    assert any(path.endswith("/domains/bad.example") for path in seen_paths)
    assert all(not path.endswith("/domains/example.org") for path in seen_paths)
    assert len(result.records) == 1
    assert result.records[0].indicator_value == "bad.example"


def test_enrichment_uses_attachment_hashes_without_uploading_files() -> None:
    seen_paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_paths.append(request.url.path)
        return httpx.Response(
            200,
            json={"data": {"attributes": {"last_analysis_stats": {"malicious": 5, "suspicious": 0}}}},
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    settings = Settings(enable_enrichment=True, virustotal_api_key="vt-key")
    parsed_email = ParsedEmail(
        source_type="pasted",
        attachments=[
            AttachmentMetadata(
                filename="invoice.zip",
                sha256="a" * 64,
                content_type="application/zip",
            )
        ],
    )

    result = enrich_indicators(
        settings=settings,
        extraction_result=ExtractionResult(),
        parsed_email=parsed_email,
        client=client,
    )

    assert any(path.endswith(f"/files/{'a' * 64}") for path in seen_paths)
    assert len(result.records) == 1
    assert result.records[0].related_attachment == "invoice.zip"
