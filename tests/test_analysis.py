from pathlib import Path

from sentinel_local.analyzers import analyze_email
from sentinel_local.domain.models import EmailAddress, ParsedEmail
from sentinel_local.extractors import extract_indicators
from sentinel_local.parsers import ParseRequest, parse_email_input


FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_analysis_flags_suspicious_eml_fixture() -> None:
    parsed = parse_email_input(
        ParseRequest(source_type="eml", file_path=FIXTURES_DIR / "sample_email.eml")
    ).parsed_email
    extraction = extract_indicators(parsed)

    result = analyze_email(parsed, extraction)
    rule_ids = {hit.rule_id for hit in result.rule_hits}

    assert result.score >= 20
    assert result.verdict == "suspicious"
    assert result.disposition == "phishing"
    assert "suspicious-keywords" in rule_ids
    assert "lure-with-link" in rule_ids


def test_analysis_escalates_html_attachment_and_multi_signal_message(monkeypatch) -> None:
    class FakeAttachment:
        longFilename = "invoice.html"
        mimetype = "text/html"
        data = b"<html>invoice</html>"

    class FakeMessage:
        subject = "Urgent invoice"
        sender = "billing@vendor-payments.example"
        sender_name = "Billing Team"
        to = "accounts@example.org; analyst@example.org; finance@example.org; manager@example.org"
        cc = "controller@example.org"
        bcc = None
        date = "Fri, 14 Mar 2025 09:00:00 +1300"
        body = (
            "Urgent invoice attached. Complete wire transfer today. "
            "Use https://pay.vendor-payments.example/confirm."
        )
        htmlBody = (
            "<html><body>"
            '<a href="https://pay.vendor-payments.example/confirm">Confirm payment</a>'
            "</body></html>"
        )
        header = "From: Billing Team <billing@vendor-payments.example>\nSubject: Urgent invoice"
        attachments = [FakeAttachment()]

    def fake_message_constructor(path: str) -> FakeMessage:
        assert path.endswith("sample_email.msg")
        return FakeMessage()

    monkeypatch.setattr("sentinel_local.parsers.msg_parser.extract_msg.Message", fake_message_constructor)

    parsed = parse_email_input(
        ParseRequest(source_type="msg", file_path=FIXTURES_DIR / "sample_email.msg")
    ).parsed_email

    extraction = extract_indicators(parsed)
    result = analyze_email(parsed, extraction)

    assert result.score >= 60
    assert result.verdict == "malicious"
    assert result.disposition == "malware_delivery"
    assert any(hit.rule_id == "suspicious-attachment-type" for hit in result.rule_hits)


def test_analysis_keeps_simple_internal_note_low_risk() -> None:
    parsed = parse_email_input(
        ParseRequest(
            source_type="pasted",
            content="\n".join(
                [
                    "From: SOC Team <soc@example.org>",
                    "To: analyst@example.org",
                    "Subject: Daily standup notes",
                    "",
                    "Please review yesterday's queue before the 10am sync.",
                ]
            ),
        )
    ).parsed_email

    extraction = extract_indicators(parsed)
    result = analyze_email(parsed, extraction)

    assert result.score < 20
    assert result.verdict == "benign"
    assert result.disposition == "benign"
    assert result.confidence == "low"


def test_analysis_flags_auth_and_reply_to_header_failures() -> None:
    parsed = ParsedEmail(
        source_type="pasted",
        subject="Security review required",
        sender=EmailAddress(name="Microsoft Security", email="alerts@secure-mailer.example"),
        to_recipients=[EmailAddress(email="analyst@example.org")],
        text_body="Review your account immediately.",
        headers={
            "Authentication-Results": "mx.example.org; spf=fail smtp.mailfrom=secure-mailer.example; dkim=fail header.d=secure-mailer.example; dmarc=fail action=reject header.from=example.org",
            "Reply-To": "credential-harvest@evil-mail.example",
        },
    )

    result = analyze_email(parsed, extract_indicators(parsed))
    rule_ids = {hit.rule_id for hit in result.rule_hits}

    assert "auth-failures" in rule_ids
    assert "reply-to-mismatch" in rule_ids
    assert result.disposition == "phishing"
    assert result.verdict in {"suspicious", "malicious"}


def test_analysis_flags_display_name_impersonation_and_received_anomaly() -> None:
    parsed = ParsedEmail(
        source_type="pasted",
        subject="Shared document",
        sender=EmailAddress(name="Example IT Helpdesk", email="ticket@external-mail.example"),
        to_recipients=[EmailAddress(email="employee@example.org")],
        text_body="Open the attached document to verify access.",
        headers={
            "Received": "from unknown (HELO mx-01) ([10.10.10.50]) by mail.example.org with ESMTP;",
        },
    )

    result = analyze_email(parsed, extract_indicators(parsed))
    rule_ids = {hit.rule_id for hit in result.rule_hits}

    assert "display-name-impersonation" in rule_ids
    assert "received-chain-anomaly" in rule_ids


def test_analysis_flags_return_path_mismatch() -> None:
    parsed = ParsedEmail(
        source_type="pasted",
        subject="Review secure message",
        sender=EmailAddress(email="alerts@trusted.example"),
        to_recipients=[EmailAddress(email="analyst@example.org")],
        text_body="Review the secure message.",
        headers={
            "Return-Path": "<mailer@different-envelope.example>",
        },
    )

    result = analyze_email(parsed, extract_indicators(parsed))
    rule_ids = {hit.rule_id for hit in result.rule_hits}

    assert "return-path-mismatch" in rule_ids


def test_analysis_flags_weak_authentication_without_hard_fail() -> None:
    parsed = ParsedEmail(
        source_type="pasted",
        subject="Quarterly update",
        sender=EmailAddress(email="news@vendor.example"),
        to_recipients=[EmailAddress(email="analyst@example.org")],
        text_body="Quarterly update attached.",
        headers={
            "Authentication-Results": "mx.example.org; spf=neutral smtp.mailfrom=vendor.example; dkim=none; dmarc=none action=none header.from=vendor.example",
        },
    )

    result = analyze_email(parsed, extract_indicators(parsed))
    rule_ids = {hit.rule_id for hit in result.rule_hits}

    assert "auth-warnings" in rule_ids


def test_analysis_flags_auth_alignment_mismatch_and_received_time_issue() -> None:
    parsed = ParsedEmail(
        source_type="pasted",
        sender=EmailAddress(email="ceo@example.org"),
        headers={
            "Authentication-Results": (
                "mx.example.org; spf=pass smtp.mailfrom=mailer.vendor.example; "
                "dkim=pass header.d=mailer.vendor.example; dmarc=pass header.from=vendor.example"
            ),
            "Received": "\n".join(
                [
                    "from edge.vendor.example ([203.0.113.50]) by mx.example.org with ESMTP; Tue, 11 Mar 2025 09:08:00 +1300",
                    "from host.vendor.example ([203.0.113.51]) by edge.vendor.example with ESMTP; Tue, 11 Mar 2025 09:12:00 +1300",
                ]
            ),
        },
    )

    result = analyze_email(parsed, extract_indicators(parsed))
    rule_ids = {hit.rule_id for hit in result.rule_hits}

    assert "auth-alignment-mismatch" in rule_ids
    assert "received-time-anomaly" in rule_ids


def test_analysis_maps_payment_fraud_signals_to_bec() -> None:
    parsed = ParsedEmail(
        source_type="pasted",
        subject="Urgent payment request",
        sender=EmailAddress(name="Example CEO", email="ceo@external-mail.example"),
        to_recipients=[EmailAddress(email="finance@example.org")],
        text_body="Please process this wire transfer immediately and keep it confidential.",
        headers={
            "Reply-To": "accounts-payable@fraud-mail.example",
        },
    )

    result = analyze_email(parsed, extract_indicators(parsed))

    assert result.disposition == "bec"
