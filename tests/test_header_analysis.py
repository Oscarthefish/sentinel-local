from sentinel_local.domain.models import EmailAddress, ParsedEmail
from sentinel_local.header_analysis import analyze_headers


def test_header_analysis_parses_authentication_and_mail_flow() -> None:
    parsed = ParsedEmail(
        source_type="pasted",
        sender=EmailAddress(email="ceo@example.org"),
        headers={
            "Authentication-Results": (
                "mx.example.org; spf=fail smtp.mailfrom=mailer.bad.example; "
                "dkim=pass header.d=bad.example; dmarc=quarantine header.from=bad.example"
            ),
            "Return-Path": "<bounce@mailer.bad.example>",
            "Reply-To": "payments@fraud.example",
            "Message-ID": "<abc123@bad.example>",
            "Received": "\n".join(
                [
                    "from unknown (HELO mx-01) ([10.10.10.50]) by edge.example.org with ESMTP; Tue, 11 Mar 2025 09:10:00 +1300",
                    "from mail.bad.example ([203.0.113.55]) by mx.example.org with ESMTP; Tue, 11 Mar 2025 09:08:00 +1300",
                ]
            ),
        },
    )

    result = analyze_headers(parsed)

    assert result.authentication.spf_result == "fail"
    assert result.authentication.spf_domain == "mailer.bad.example"
    assert result.authentication.spf_aligned is False
    assert result.authentication.dkim_result == "pass"
    assert result.authentication.dkim_aligned is False
    assert result.authentication.dmarc_result == "quarantine"
    assert result.return_path == "bounce@mailer.bad.example"
    assert result.reply_to == ["payments@fraud.example"]
    assert result.message_id == "<abc123@bad.example>"
    assert result.originating_ips == ["10.10.10.50", "203.0.113.55"]
    assert len(result.mail_flow) == 2
    assert "private-ip-hop" in result.mail_flow[1 - 1].findings
    assert "spf-failed" in result.findings
    assert "dmarc-failed" in result.findings


def test_header_analysis_flags_received_time_order_anomaly() -> None:
    parsed = ParsedEmail(
        source_type="pasted",
        headers={
            "Received": "\n".join(
                [
                    "from edge.bad.example ([203.0.113.55]) by mx.example.org with ESMTP; Tue, 11 Mar 2025 09:08:00 +1300",
                    "from host.internal ([203.0.113.56]) by edge.bad.example with ESMTP; Tue, 11 Mar 2025 09:10:00 +1300",
                ]
            )
        },
    )

    result = analyze_headers(parsed)

    assert "received-time-order-anomaly" in result.mail_flow[1].findings
