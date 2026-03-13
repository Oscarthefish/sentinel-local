from sentinel_local.case_summary import build_analyst_summary
from sentinel_local.domain.models import (
    AnalysisResult,
    AttachmentAnalysisResult,
    AttachmentArtifact,
    AttachmentScanArtifact,
    AttachmentScanFinding,
    AttachmentScanResult,
    ExtractionResult,
    HeaderAnalysisResult,
    Indicator,
    ParsedEmail,
    RuleHit,
    UrlAnalysisResult,
    UrlArtifact,
)


def test_build_analyst_summary_produces_actions_and_highlights() -> None:
    summary = build_analyst_summary(
        parsed_email=ParsedEmail(source_type="pasted", subject="Urgent invoice", sender={"email": "billing@bad.example"}),
        extraction_result=ExtractionResult(
            indicators=[Indicator(type="url", value="https://bad.example", normalized_value="https://bad.example", source="text_body")]
        ),
        header_analysis_result=HeaderAnalysisResult(findings=["spf-failed", "reply-to-mismatch"]),
        analysis_result=AnalysisResult(
            score=72,
            verdict="malicious",
            disposition="malware_delivery",
            confidence="high",
            rule_hits=[
                RuleHit(
                    rule_id="suspicious-attachment-type",
                    title="Suspicious attachment extension",
                    description="Attachment is risky.",
                    severity="high",
                    score_delta=30,
                )
            ],
        ),
        url_analysis_result=UrlAnalysisResult(
            artifacts=[UrlArtifact(original_url="https://bad.example", source="text_body", findings=["redirect-chain"])]
        ),
        attachment_analysis_result=AttachmentAnalysisResult(
            artifacts=[AttachmentArtifact(filename="invoice.html", findings=["risky-extension"], severity="high")]
        ),
        attachment_scan_result=AttachmentScanResult(
            artifacts=[
                AttachmentScanArtifact(
                    filename="invoice.html",
                    findings=[
                        AttachmentScanFinding(
                            scanner="yara",
                            severity="high",
                            summary="YARA matched rule `invoice_lure`.",
                        )
                    ],
                )
            ]
        ),
    )

    assert "classified as malware delivery" in summary.summary
    assert summary.recommended_actions
    assert any("Contain the message" in action for action in summary.recommended_actions)
    assert any("YARA matched rule" in item for item in summary.evidence_highlights)
