from sentinel_local.attachment_analysis import analyze_attachments
from sentinel_local.domain.models import AttachmentMetadata, ParsedEmail


def test_attachment_analysis_flags_risky_extension_and_lure_name() -> None:
    parsed = ParsedEmail(
        source_type="pasted",
        attachments=[
            AttachmentMetadata(filename="invoice.html", content_type="text/html"),
        ],
    )

    result = analyze_attachments(parsed)

    assert len(result.artifacts) == 1
    artifact = result.artifacts[0]
    assert "risky-extension" in artifact.findings
    assert "lure-filename" in artifact.findings
    assert artifact.severity == "high"


def test_attachment_analysis_flags_macro_doc_and_mime_mismatch() -> None:
    parsed = ParsedEmail(
        source_type="pasted",
        attachments=[
            AttachmentMetadata(
                filename="benefits.docm",
                content_type="application/pdf",
                sha256="a" * 64,
            ),
        ],
    )

    result = analyze_attachments(parsed)
    artifact = result.artifacts[0]

    assert "macro-capable-document" in artifact.findings
    assert "mime-extension-mismatch" in artifact.findings
    assert "hash-available" in artifact.findings
    assert artifact.severity == "high"
