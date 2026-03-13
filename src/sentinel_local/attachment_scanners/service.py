"""Transient local attachment scanning using optional local tools."""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from email import policy
from email.parser import BytesParser
from email.utils import collapse_rfc2231_value
from pathlib import Path
from tempfile import NamedTemporaryFile

import extract_msg

from sentinel_local.core.config import Settings
from sentinel_local.domain.models import AttachmentScanArtifact, AttachmentScanFinding, AttachmentScanResult
from sentinel_local.parsers.common import compute_sha256, decode_mime_header


@dataclass(slots=True)
class _TransientAttachment:
    filename: str
    data: bytes
    sha256: str | None


def scan_attachments_from_source(
    *,
    settings: Settings,
    source_type: str,
    content: bytes | str | None = None,
    filename: str | None = None,
) -> AttachmentScanResult:
    """Scan extracted attachments with local tools without persisting raw samples."""
    attachments = _extract_transient_attachments(source_type=source_type, content=content, filename=filename)
    if not attachments:
        return AttachmentScanResult()

    warnings: list[str] = []
    artifacts: list[AttachmentScanArtifact] = []
    yara_binary = _resolve_binary(settings.yara_binary_path, "yara")
    clamscan_binary = _resolve_binary(settings.clamscan_binary_path, "clamscan")

    if settings.yara_rules_path and yara_binary is None:
        warnings.append("YARA rules configured, but the `yara` binary was not found.")
    if settings.clamscan_binary_path and clamscan_binary is None:
        warnings.append("ClamAV configured, but the `clamscan` binary was not found.")
    if yara_binary is None and clamscan_binary is None:
        warnings.append("Attachment scanning enabled, but no local scanner binaries are available.")
        return AttachmentScanResult(warnings=warnings)

    for attachment in attachments:
        findings: list[AttachmentScanFinding] = []
        suffix = Path(attachment.filename).suffix or ".bin"
        with NamedTemporaryFile(suffix=suffix, delete=False) as handle:
            handle.write(attachment.data)
            temp_path = Path(handle.name)

        try:
            if yara_binary and settings.yara_rules_path:
                findings.extend(
                    _run_yara(
                        binary=yara_binary,
                        rules_path=settings.yara_rules_path,
                        sample_path=temp_path,
                        timeout_seconds=settings.attachment_scan_timeout_seconds,
                        warnings=warnings,
                    )
                )
            if clamscan_binary:
                findings.extend(
                    _run_clamav(
                        binary=clamscan_binary,
                        sample_path=temp_path,
                        timeout_seconds=settings.attachment_scan_timeout_seconds,
                        warnings=warnings,
                    )
                )
        finally:
            temp_path.unlink(missing_ok=True)

        artifacts.append(
            AttachmentScanArtifact(
                filename=attachment.filename,
                sha256=attachment.sha256,
                findings=findings,
            )
        )

    return AttachmentScanResult(artifacts=artifacts, warnings=_dedupe(warnings))


def _extract_transient_attachments(
    *,
    source_type: str,
    content: bytes | str | None,
    filename: str | None,
) -> list[_TransientAttachment]:
    if source_type == "eml":
        return _extract_eml_attachments(_as_bytes(content))
    if source_type == "msg":
        if not isinstance(content, bytes):
            return []
        return _extract_msg_attachments(content, filename=filename)
    return []


def _extract_eml_attachments(content: bytes) -> list[_TransientAttachment]:
    message = BytesParser(policy=policy.default).parsebytes(content)
    attachments: list[_TransientAttachment] = []

    for part in message.walk():
        if part.is_multipart():
            continue
        content_disposition = (part.get_content_disposition() or "").lower()
        raw_filename = part.get_filename()
        decoded_filename = collapse_rfc2231_value(raw_filename) if raw_filename else None
        if content_disposition != "attachment" and not decoded_filename:
            continue

        payload = part.get_payload(decode=True) or b""
        if not payload:
            continue

        filename_value = decode_mime_header(decoded_filename) or "attachment.bin"
        attachments.append(
            _TransientAttachment(
                filename=filename_value,
                data=payload,
                sha256=compute_sha256(payload),
            )
        )

    return attachments


def _extract_msg_attachments(content: bytes, *, filename: str | None) -> list[_TransientAttachment]:
    suffix = Path(filename or "message.msg").suffix or ".msg"
    attachments: list[_TransientAttachment] = []
    with NamedTemporaryFile(suffix=suffix, delete=False) as handle:
        handle.write(content)
        temp_msg_path = Path(handle.name)

    try:
        message = extract_msg.Message(str(temp_msg_path))
        for attachment in getattr(message, "attachments", []):
            data = getattr(attachment, "data", b"") or b""
            if not data:
                continue
            attachment_name = getattr(attachment, "longFilename", None) or getattr(attachment, "filename", None)
            attachments.append(
                _TransientAttachment(
                    filename=attachment_name or "attachment.bin",
                    data=data,
                    sha256=compute_sha256(data),
                )
            )
    finally:
        temp_msg_path.unlink(missing_ok=True)

    return attachments


def _run_yara(
    *,
    binary: str,
    rules_path: Path,
    sample_path: Path,
    timeout_seconds: int,
    warnings: list[str],
) -> list[AttachmentScanFinding]:
    if not rules_path.exists():
        warnings.append(f"YARA rules path not found: {rules_path}")
        return []

    try:
        result = subprocess.run(
            [binary, str(rules_path), str(sample_path)],
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        warnings.append(f"YARA timed out while scanning `{sample_path.name}`.")
        return []
    except OSError as exc:
        warnings.append(f"YARA execution failed: {exc}")
        return []

    if result.returncode not in {0, 1} and result.stderr.strip():
        warnings.append(f"YARA error for `{sample_path.name}`: {result.stderr.strip()}")
        return []

    findings: list[AttachmentScanFinding] = []
    for line in (result.stdout or "").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        rule_name = stripped.split(maxsplit=1)[0]
        findings.append(
            AttachmentScanFinding(
                scanner="yara",
                severity="high",
                summary=f"YARA matched rule `{rule_name}`.",
                details={"rule": rule_name, "raw_output": stripped},
            )
        )
    return findings


def _run_clamav(
    *,
    binary: str,
    sample_path: Path,
    timeout_seconds: int,
    warnings: list[str],
) -> list[AttachmentScanFinding]:
    try:
        result = subprocess.run(
            [binary, "--no-summary", str(sample_path)],
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        warnings.append(f"ClamAV timed out while scanning `{sample_path.name}`.")
        return []
    except OSError as exc:
        warnings.append(f"ClamAV execution failed: {exc}")
        return []

    if result.returncode > 1:
        error_message = result.stderr.strip() or result.stdout.strip()
        if error_message:
            warnings.append(f"ClamAV error for `{sample_path.name}`: {error_message}")
        return []

    findings: list[AttachmentScanFinding] = []
    for line in (result.stdout or "").splitlines():
        stripped = line.strip()
        if not stripped or stripped.endswith(": OK"):
            continue
        if " FOUND" in stripped:
            _, signature = stripped.rsplit(": ", 1)
            findings.append(
                AttachmentScanFinding(
                    scanner="clamav",
                    severity="high",
                    summary=f"ClamAV matched `{signature.removesuffix(' FOUND')}`.",
                    details={"raw_output": stripped},
                )
            )
    return findings


def _resolve_binary(configured_path: str | None, binary_name: str) -> str | None:
    if configured_path:
        return configured_path if Path(configured_path).exists() else None
    return shutil.which(binary_name)


def _as_bytes(content: bytes | str | None) -> bytes:
    if isinstance(content, bytes):
        return content
    if isinstance(content, str):
        return content.encode("utf-8")
    return b""


def _dedupe(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))
