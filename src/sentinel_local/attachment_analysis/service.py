"""Deterministic attachment inspection."""

from __future__ import annotations

from pathlib import Path

from sentinel_local.domain.models import AttachmentAnalysisResult, AttachmentArtifact, ParsedEmail


RISKY_EXTENSIONS = {".html", ".htm", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".hta", ".iso", ".img", ".scr", ".exe"}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2"}
MACRO_CAPABLE_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".xls", ".doc"}
LURE_KEYWORDS = {"invoice", "payment", "remittance", "scan", "voicemail", "purchase", "rfq"}
EXPECTED_MIME_BY_EXTENSION = {
    ".pdf": {"application/pdf"},
    ".html": {"text/html"},
    ".htm": {"text/html"},
    ".zip": {"application/zip", "application/x-zip-compressed"},
    ".js": {"application/javascript", "text/javascript"},
    ".docm": {
        "application/vnd.ms-word.document.macroenabled.12",
        "application/octet-stream",
    },
    ".xlsm": {
        "application/vnd.ms-excel.sheet.macroenabled.12",
        "application/octet-stream",
    },
}


def analyze_attachments(parsed_email: ParsedEmail) -> AttachmentAnalysisResult:
    """Analyze attachment metadata for risky characteristics."""
    artifacts = []
    for attachment in parsed_email.attachments:
        path = Path(attachment.filename)
        extension = path.suffix.lower() or None
        filename_lower = attachment.filename.lower()
        findings: list[str] = []

        if extension in RISKY_EXTENSIONS:
            findings.append("risky-extension")
        if extension in ARCHIVE_EXTENSIONS:
            findings.append("archive-file")
        if extension in MACRO_CAPABLE_EXTENSIONS:
            findings.append("macro-capable-document")
        if any(keyword in filename_lower for keyword in LURE_KEYWORDS):
            findings.append("lure-filename")
        if _mime_mismatch(extension, attachment.content_type):
            findings.append("mime-extension-mismatch")
        if attachment.sha256:
            findings.append("hash-available")

        severity = _severity_for_findings(findings)
        artifacts.append(
            AttachmentArtifact(
                filename=attachment.filename,
                extension=extension,
                content_type=attachment.content_type,
                findings=findings,
                severity=severity,
            )
        )

    return AttachmentAnalysisResult(artifacts=artifacts)


def _mime_mismatch(extension: str | None, content_type: str | None) -> bool:
    if not extension or not content_type:
        return False
    expected = EXPECTED_MIME_BY_EXTENSION.get(extension)
    if not expected:
        return False
    return content_type.lower() not in {item.lower() for item in expected}


def _severity_for_findings(findings: list[str]) -> str:
    if "risky-extension" in findings or "mime-extension-mismatch" in findings:
        return "high"
    if "macro-capable-document" in findings or "archive-file" in findings:
        return "medium"
    if findings:
        return "low"
    return "info"
