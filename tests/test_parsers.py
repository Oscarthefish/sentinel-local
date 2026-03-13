from pathlib import Path
from hashlib import sha256

from sentinel_local.parsers import ParseRequest, parse_email_input


FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_parse_eml_fixture_extracts_headers_bodies_and_attachments() -> None:
    result = parse_email_input(
        ParseRequest(
            source_type="eml",
            file_path=FIXTURES_DIR / "sample_email.eml",
        )
    )

    parsed = result.parsed_email

    assert parsed.source_type == "eml"
    assert parsed.subject == "Suspicious login review"
    assert parsed.sender is not None
    assert parsed.sender.email == "alerts@example.com"
    assert len(parsed.to_recipients) == 1
    assert len(parsed.cc_recipients) == 1
    assert parsed.text_body is not None
    assert "suspicious login" in parsed.text_body
    assert parsed.html_body is not None
    assert parsed.attachments[0].filename == "evidence.txt"
    assert parsed.attachments[0].sha256 == sha256(b"Attachment content here.").hexdigest()


def test_parse_txt_fixture_extracts_header_style_plaintext() -> None:
    result = parse_email_input(
        ParseRequest(
            source_type="txt",
            file_path=FIXTURES_DIR / "sample_email.txt",
        )
    )

    parsed = result.parsed_email

    assert parsed.source_type == "txt"
    assert parsed.subject == "Password reset request"
    assert parsed.sender is not None
    assert parsed.sender.email == "helpdesk@example.com"
    assert parsed.text_body is not None
    assert "123456" in parsed.text_body


def test_parse_pasted_text_supports_separate_headers() -> None:
    pasted_body = (FIXTURES_DIR / "sample_pasted_email.txt").read_text()
    raw_headers = "\n".join(
        [
            'From: "Finance" <finance@example.com>',
            "To: analyst@example.org",
            "Date: Thu, 13 Mar 2025 08:30:00 +1300",
        ]
    )

    result = parse_email_input(
        ParseRequest(
            source_type="pasted",
            content=pasted_body,
            raw_headers=raw_headers,
            analyst_note="Escalated from Slack",
        )
    )

    parsed = result.parsed_email

    assert parsed.source_type == "pasted"
    assert parsed.sender is not None
    assert parsed.sender.email == "finance@example.com"
    assert parsed.subject == "Review payment request"
    assert "wire transfer" in (parsed.text_body or "")
    assert result.analyst_note == "Escalated from Slack"


def test_parse_msg_fixture_uses_outlook_parser(monkeypatch) -> None:
    class FakeAttachment:
        longFilename = "invoice.html"
        mimetype = "text/html"
        data = b"<html>invoice</html>"

    class FakeMessage:
        subject = "Urgent invoice"
        sender = "billing@example.com"
        sender_name = "Billing Team"
        to = "accounts@example.org; analyst@example.org"
        cc = "manager@example.org"
        bcc = None
        date = "Fri, 14 Mar 2025 09:00:00 +1300"
        body = "Please see attached invoice."
        htmlBody = "<html><body>Please see attached invoice.</body></html>"
        header = "From: Billing Team <billing@example.com>\nSubject: Urgent invoice"
        attachments = [FakeAttachment()]

    def fake_message_constructor(path: str) -> FakeMessage:
        assert path.endswith("sample_email.msg")
        return FakeMessage()

    monkeypatch.setattr("sentinel_local.parsers.msg_parser.extract_msg.Message", fake_message_constructor)

    result = parse_email_input(
        ParseRequest(
            source_type="msg",
            file_path=FIXTURES_DIR / "sample_email.msg",
        )
    )

    parsed = result.parsed_email

    assert parsed.source_type == "msg"
    assert parsed.subject == "Urgent invoice"
    assert parsed.sender is not None
    assert parsed.sender.email == "billing@example.com"
    assert len(parsed.to_recipients) == 2
    assert parsed.attachments[0].filename == "invoice.html"
    assert parsed.attachments[0].sha256 == sha256(b"<html>invoice</html>").hexdigest()
