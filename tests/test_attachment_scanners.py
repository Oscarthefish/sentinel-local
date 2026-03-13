from pathlib import Path

from sentinel_local.attachment_scanners import scan_attachments_from_source
from sentinel_local.core.config import Settings


def test_scan_attachments_from_eml_uses_local_yara_rules(monkeypatch, tmp_path) -> None:
    yara_binary = tmp_path / "yara"
    yara_binary.write_text("")
    yara_rules = tmp_path / "rules.yar"
    yara_rules.write_text("rule invoice_lure { condition: true }")

    def fake_run(command, capture_output, text, timeout, check):  # noqa: ANN001
        assert command[0] == str(yara_binary)
        assert command[1] == str(yara_rules)

        class Result:
            returncode = 0
            stdout = f"invoice_lure {command[2]}\n"
            stderr = ""

        return Result()

    monkeypatch.setattr("sentinel_local.attachment_scanners.service.subprocess.run", fake_run)

    settings = Settings(
        enable_attachment_scanning=True,
        yara_binary_path=str(yara_binary),
        yara_rules_path=yara_rules,
    )
    eml_content = b"""From: sender@example.com
To: analyst@example.org
Subject: test
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUNDARY"

--BOUNDARY
Content-Type: text/plain; charset="utf-8"

hello
--BOUNDARY
Content-Type: text/plain; name="invoice.txt"
Content-Disposition: attachment; filename="invoice.txt"

please review attached
--BOUNDARY--
"""

    result = scan_attachments_from_source(settings=settings, source_type="eml", content=eml_content)

    assert len(result.artifacts) == 1
    assert result.artifacts[0].filename == "invoice.txt"
    assert result.artifacts[0].findings[0].scanner == "yara"
    assert "invoice_lure" in result.artifacts[0].findings[0].summary


def test_scan_attachments_warns_when_enabled_without_local_tools() -> None:
    settings = Settings(enable_attachment_scanning=True)

    result = scan_attachments_from_source(
        settings=settings,
        source_type="eml",
        content=b"""From: sender@example.com
To: analyst@example.org
Subject: test
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUNDARY"

--BOUNDARY
Content-Type: text/plain; charset="utf-8"

hello
--BOUNDARY
Content-Type: text/plain; name="invoice.txt"
Content-Disposition: attachment; filename="invoice.txt"

please review attached
--BOUNDARY--
""",
    )

    assert result.artifacts == []
    assert any("no local scanner binaries" in warning.lower() for warning in result.warnings)
