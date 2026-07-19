"""Baseline Pydantic models for the application."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field


class HealthStatus(BaseModel):
    """Health endpoint response payload."""

    status: str
    environment: str
    version: str


class AttachmentMetadata(BaseModel):
    """Attachment metadata placeholder for later parsing milestones."""

    filename: str
    content_type: str | None = None
    size: int | None = None
    sha256: str | None = None


class EmailAddress(BaseModel):
    """Structured email address details."""

    name: str | None = None
    email: str | None = None


class ParsedEmail(BaseModel):
    """Canonical parsed email structure used by future milestones."""

    source_type: Literal["eml", "msg", "txt", "pasted"]
    subject: str | None = None
    sender: EmailAddress | None = None
    to_recipients: list[EmailAddress] = Field(default_factory=list)
    cc_recipients: list[EmailAddress] = Field(default_factory=list)
    bcc_recipients: list[EmailAddress] = Field(default_factory=list)
    sent_at: datetime | None = None
    text_body: str | None = None
    html_body: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    attachments: list[AttachmentMetadata] = Field(default_factory=list)

    @property
    def recipients(self) -> list[EmailAddress]:
        """Return all parsed recipients as a single list."""
        return [*self.to_recipients, *self.cc_recipients, *self.bcc_recipients]


class Indicator(BaseModel):
    """Normalized indicator extracted from email content."""

    type: Literal["url", "domain", "ip", "email", "hash", "attachment_name", "attachment_ext"]
    value: str
    normalized_value: str
    source: Literal["text_body", "html_body", "headers", "sender", "recipient", "attachment"]


class ExtractionResult(BaseModel):
    """Structured IOC extraction result for a parsed email."""

    indicators: list[Indicator] = Field(default_factory=list)


class RuleHit(BaseModel):
    """One deterministic rule that contributed to the analysis result."""

    rule_id: str
    title: str
    description: str
    severity: Literal["low", "medium", "high"]
    score_delta: int
    evidence: list[str] = Field(default_factory=list)


class AnalysisResult(BaseModel):
    """Deterministic analysis and scoring output."""

    score: int
    verdict: Literal["benign", "suspicious", "malicious"]
    disposition: Literal["benign", "spam", "phishing", "malware_delivery", "bec", "needs_escalation"] = (
        "needs_escalation"
    )
    confidence: Literal["low", "medium", "high"]
    rule_hits: list[RuleHit] = Field(default_factory=list)


class NarrativeReport(BaseModel):
    """LLM-generated narrative derived from deterministic evidence."""

    summary: str
    verdict_rationale: str
    recommended_actions: list[str] = Field(default_factory=list)


class SavedAnalysis(BaseModel):
    """Persisted analysis record stored locally."""

    analysis_id: UUID
    created_at: datetime
    subject: str | None = None
    sender: str | None = None
    source_type: str
    verdict: str
    score: int
    confidence: str
    analyst_note: str | None = None
    parsed_email: dict
    extraction_result: dict
    header_analysis_result: dict | None = None
    analysis_result: dict
    analyst_summary_result: dict | None = None
    url_analysis_result: dict | None = None
    attachment_analysis_result: dict | None = None
    attachment_scan_result: dict | None = None
    enrichment_result: dict | None = None
    narrative_report: dict | None = None
    markdown_report: str


class EnrichmentRecord(BaseModel):
    """One provider response tied to one extracted indicator."""

    provider: str
    indicator_type: str
    indicator_value: str
    summary: str
    severity: Literal["info", "low", "medium", "high"]
    related_attachment: str | None = None
    details: dict = Field(default_factory=dict)


class EnrichmentResult(BaseModel):
    """Optional external enrichment outputs."""

    records: list[EnrichmentRecord] = Field(default_factory=list)


class UrlArtifact(BaseModel):
    """URL-centric finding derived from message content."""

    original_url: str
    source: Literal["text_body", "html_body"]
    unwrapped_url: str | None = None
    final_url: str | None = None
    redirect_chain: list[str] = Field(default_factory=list)
    display_text: str | None = None
    screenshot_url: str | None = None
    findings: list[str] = Field(default_factory=list)


class HtmlArtifact(BaseModel):
    """Non-URL HTML artifact found in the email body."""

    artifact_type: Literal["hidden-element", "form", "script", "javascript-link"]
    summary: str
    details: dict = Field(default_factory=dict)


class UrlAnalysisResult(BaseModel):
    """Structured URL analysis output."""

    artifacts: list[UrlArtifact] = Field(default_factory=list)
    html_artifacts: list[HtmlArtifact] = Field(default_factory=list)


class AuthenticationEvidence(BaseModel):
    """Structured authentication evidence parsed from message headers."""

    spf_result: str | None = None
    spf_domain: str | None = None
    spf_aligned: bool | None = None
    spf_tenants: list[str] = Field(default_factory=list)
    dkim_result: str | None = None
    dkim_domain: str | None = None
    dkim_aligned: bool | None = None
    dmarc_result: str | None = None
    header_from_domain: str | None = None
    dmarc_aligned: bool | None = None


class MailFlowHop(BaseModel):
    """One parsed mail relay hop from a Received chain."""

    position: int
    from_host: str | None = None
    by_host: str | None = None
    from_ip: str | None = None
    timestamp: datetime | None = None
    raw: str
    findings: list[str] = Field(default_factory=list)


class HeaderAnalysisResult(BaseModel):
    """Structured header analysis used for explainable mail-flow review."""

    authentication: AuthenticationEvidence = Field(default_factory=AuthenticationEvidence)
    mail_flow: list[MailFlowHop] = Field(default_factory=list)
    message_id: str | None = None
    return_path: str | None = None
    reply_to: list[str] = Field(default_factory=list)
    originating_ips: list[str] = Field(default_factory=list)
    findings: list[str] = Field(default_factory=list)


class AnalystSummaryResult(BaseModel):
    """Deterministic analyst-facing summary and next actions."""

    summary: str
    likely_intent: str
    recommended_actions: list[str] = Field(default_factory=list)
    evidence_highlights: list[str] = Field(default_factory=list)


class AttachmentArtifact(BaseModel):
    """One deterministic attachment analysis result."""

    filename: str
    extension: str | None = None
    content_type: str | None = None
    findings: list[str] = Field(default_factory=list)
    severity: Literal["info", "low", "medium", "high"]


class AttachmentAnalysisResult(BaseModel):
    """Structured attachment analysis output."""

    artifacts: list[AttachmentArtifact] = Field(default_factory=list)


class AttachmentScanFinding(BaseModel):
    """One scanner result for one attachment."""

    scanner: Literal["yara", "clamav"]
    severity: Literal["info", "low", "medium", "high"]
    summary: str
    details: dict = Field(default_factory=dict)


class AttachmentScanArtifact(BaseModel):
    """Attachment scan output for one extracted attachment."""

    filename: str
    sha256: str | None = None
    findings: list[AttachmentScanFinding] = Field(default_factory=list)


class AttachmentScanResult(BaseModel):
    """Optional local scanner output for attachments."""

    artifacts: list[AttachmentScanArtifact] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
