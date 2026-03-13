"""Optional enrichment orchestration."""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

import httpx

from sentinel_local.core.config import Settings
from sentinel_local.domain.models import EnrichmentRecord, EnrichmentResult, ExtractionResult, ParsedEmail
from sentinel_local.enrichers.providers import lookup_abuseipdb, lookup_virustotal

log = logging.getLogger(__name__)

# Maximum indicators to enrich per analysis run (prevents runaway API consumption)
_MAX_INDICATORS = 30
# Concurrent HTTP workers — enough to saturate a typical API rate limit safely
_MAX_WORKERS = 8


def enrich_indicators(
    *,
    settings: Settings,
    extraction_result: ExtractionResult,
    parsed_email: ParsedEmail | None = None,
    client: httpx.Client | None = None,
) -> EnrichmentResult:
    """Run configured optional enrichments over extracted indicators, concurrently."""
    recipient_emails, recipient_domains = _recipient_identity_sets(parsed_email)

    # Build a deduplicated work list: (indicator_type, value, related_attachment_name)
    work: list[tuple[str, str, str | None]] = []
    seen: set[tuple[str, str]] = set()

    for indicator in extraction_result.indicators:
        key = (indicator.type, indicator.normalized_value)
        if key in seen:
            continue
        seen.add(key)
        if _is_recipient_identity(indicator.type, indicator.normalized_value, recipient_emails, recipient_domains):
            continue
        work.append((indicator.type, indicator.normalized_value, None))

    if settings.virustotal_api_key and parsed_email is not None:
        for attachment in parsed_email.attachments:
            if not attachment.sha256:
                continue
            key = ("hash", attachment.sha256.lower())
            if key in seen:
                continue
            seen.add(key)
            work.append(("hash", attachment.sha256.lower(), attachment.filename))

    work = work[:_MAX_INDICATORS]
    if not work:
        return EnrichmentResult()

    timeout = settings.enrichment_timeout_seconds

    def _lookup(itype: str, ivalue: str, rel_attachment: str | None) -> list[EnrichmentRecord]:
        """Run all provider lookups for one indicator in a dedicated thread-local client."""
        results: list[EnrichmentRecord] = []
        # Each thread owns its client — httpx.Client is not thread-safe to share.
        with httpx.Client(timeout=timeout) as thread_client:
            if settings.virustotal_api_key and itype in {"url", "domain", "ip", "hash"}:
                try:
                    record = lookup_virustotal(
                        indicator_type=itype,
                        indicator_value=ivalue,
                        api_key=settings.virustotal_api_key,
                        timeout_seconds=timeout,
                        related_attachment=rel_attachment,
                        client=thread_client,
                    )
                    if record is not None:
                        results.append(record)
                except Exception:
                    log.debug("VT lookup failed: %s %s", itype, ivalue)

            if settings.abuseipdb_api_key and itype == "ip":
                try:
                    results.append(
                        lookup_abuseipdb(
                            indicator_value=ivalue,
                            api_key=settings.abuseipdb_api_key,
                            timeout_seconds=timeout,
                            client=thread_client,
                        )
                    )
                except Exception:
                    log.debug("AbuseIPDB lookup failed: %s", ivalue)
        return results

    records: list[EnrichmentRecord] = []
    with ThreadPoolExecutor(max_workers=min(_MAX_WORKERS, len(work))) as pool:
        futures = {pool.submit(_lookup, itype, ivalue, rel): (itype, ivalue) for itype, ivalue, rel in work}
        for future in as_completed(futures):
            try:
                records.extend(future.result())
            except Exception:
                pass

    return EnrichmentResult(records=records)


def _recipient_identity_sets(parsed_email: ParsedEmail | None) -> tuple[set[str], set[str]]:
    if parsed_email is None:
        return set(), set()

    recipient_emails = {
        recipient.email.lower()
        for recipient in parsed_email.recipients
        if recipient.email
    }
    recipient_domains = {
        recipient.email.split("@", 1)[1].lower()
        for recipient in parsed_email.recipients
        if recipient.email and "@" in recipient.email
    }
    return recipient_emails, recipient_domains


def _is_recipient_identity(
    indicator_type: str,
    normalized_value: str,
    recipient_emails: set[str],
    recipient_domains: set[str],
) -> bool:
    if indicator_type == "email":
        return normalized_value.lower() in recipient_emails
    if indicator_type == "domain":
        return normalized_value.lower() in recipient_domains
    return False
