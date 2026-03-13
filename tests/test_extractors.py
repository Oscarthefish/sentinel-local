from pathlib import Path

from sentinel_local.domain.models import EmailAddress, ParsedEmail
from sentinel_local.extractors import extract_indicators
from sentinel_local.parsers import ParseRequest, parse_email_input


FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_extract_indicators_from_eml_fixture() -> None:
    parsed = parse_email_input(
        ParseRequest(source_type="eml", file_path=FIXTURES_DIR / "sample_email.eml")
    ).parsed_email

    result = extract_indicators(parsed)
    typed_values = {(indicator.type, indicator.normalized_value, indicator.source) for indicator in result.indicators}

    assert ("url", "http://example.com/reset", "text_body") in typed_values
    assert ("domain", "example.com", "text_body") in typed_values
    assert ("email", "alerts@example.com", "sender") in typed_values
    assert ("attachment_name", "evidence.txt", "attachment") in typed_values
    assert ("attachment_ext", ".txt", "attachment") in typed_values


def test_extract_indicators_deduplicates_and_captures_hashes_ips_and_html_links() -> None:
    parsed = parse_email_input(
        ParseRequest(
            source_type="pasted",
            content="\n".join(
                [
                    "Subject: IOC review",
                    "",
                    "Visit https://evil.example/path?x=1 and https://evil.example/path?x=1.",
                    "Contact attacker@evil.example and connect to 8.8.8.8.",
                    "Hash: d41d8cd98f00b204e9800998ecf8427e",
                    '<a href="https://portal.example/login">Login</a>',
                ]
            ),
            raw_headers='From: "Threat Intel" <intel@example.org>\nTo: analyst@example.org',
        )
    ).parsed_email

    result = extract_indicators(parsed)

    urls = [indicator for indicator in result.indicators if indicator.type == "url"]
    domains = [indicator for indicator in result.indicators if indicator.type == "domain"]
    emails = [indicator for indicator in result.indicators if indicator.type == "email"]
    ips = [indicator for indicator in result.indicators if indicator.type == "ip"]
    hashes = [indicator for indicator in result.indicators if indicator.type == "hash"]

    assert any(ind.normalized_value == "https://evil.example/path?x=1" for ind in urls)
    assert sum(1 for ind in urls if ind.normalized_value == "https://evil.example/path?x=1") == 1
    assert any(ind.normalized_value == "portal.example" for ind in domains)
    assert any(ind.normalized_value == "attacker@evil.example" for ind in emails)
    assert any(ind.normalized_value == "8.8.8.8" for ind in ips)
    assert any(ind.normalized_value == "d41d8cd98f00b204e9800998ecf8427e" for ind in hashes)


def test_extract_indicators_ignores_invalid_ipv4_candidates() -> None:
    parsed = parse_email_input(
        ParseRequest(
            source_type="pasted",
            content="Subject: Test\n\nIgnore 999.999.999.999 but keep 1.1.1.1.",
        )
    ).parsed_email

    result = extract_indicators(parsed)
    ips = {indicator.normalized_value for indicator in result.indicators if indicator.type == "ip"}

    assert "1.1.1.1" in ips
    assert "999.999.999.999" not in ips


def test_extract_indicators_tolerate_malformed_email_addresses() -> None:
    parsed = ParsedEmail(
        source_type="pasted",
        sender=EmailAddress(email="alerts@"),
        to_recipients=[EmailAddress(email="@example.org"), EmailAddress(email="valid@example.org")],
        text_body="Contact valid@example.org for review.",
    )

    result = extract_indicators(parsed)
    email_values = {indicator.normalized_value for indicator in result.indicators if indicator.type == "email"}
    domain_values = {indicator.normalized_value for indicator in result.indicators if indicator.type == "domain"}

    assert "valid@example.org" in email_values
    assert "example.org" in domain_values
