"""HTTP-backed enrichment providers."""

from __future__ import annotations

import base64

import httpx

from sentinel_local.domain.models import EnrichmentRecord


def lookup_virustotal(
    *,
    indicator_type: str,
    indicator_value: str,
    api_key: str,
    timeout_seconds: int,
    related_attachment: str | None = None,
    client: httpx.Client | None = None,
) -> EnrichmentRecord | None:
    """Look up a supported indicator in VirusTotal v3."""
    path = _virustotal_path(indicator_type, indicator_value)
    if path is None:
        return None

    close_client = client is None
    client = client or httpx.Client(timeout=timeout_seconds)
    try:
        response = client.get(
            f"https://www.virustotal.com/api/v3/{path}",
            headers={"x-apikey": api_key},
        )
        if response.status_code == 404:
            return None
        response.raise_for_status()
        attributes = response.json()["data"]["attributes"]
        stats = attributes.get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        severity = "high" if malicious else "medium" if suspicious else "info"
        summary = f"VirusTotal malicious={malicious}, suspicious={suspicious}"
        return EnrichmentRecord(
            provider="VirusTotal",
            indicator_type=indicator_type,
            indicator_value=indicator_value,
            summary=summary,
            severity=severity,
            related_attachment=related_attachment,
            details={"last_analysis_stats": stats},
        )
    finally:
        if close_client:
            client.close()


def lookup_abuseipdb(
    *,
    indicator_value: str,
    api_key: str,
    timeout_seconds: int,
    client: httpx.Client | None = None,
) -> EnrichmentRecord:
    """Look up an IPv4 in AbuseIPDB."""
    close_client = client is None
    client = client or httpx.Client(timeout=timeout_seconds)
    try:
        response = client.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": indicator_value, "maxAgeInDays": 90, "verbose": True},
        )
        if response.status_code == 404:
            return EnrichmentRecord(
                provider="AbuseIPDB",
                indicator_type="ip",
                indicator_value=indicator_value,
                summary="No AbuseIPDB result found",
                severity="info",
                details={},
            )
        response.raise_for_status()
        data = response.json()["data"]
        score = int(data.get("abuseConfidenceScore", 0))
        severity = "high" if score >= 75 else "medium" if score >= 25 else "low" if score > 0 else "info"
        summary = f"AbuseIPDB confidence score={score}"
        return EnrichmentRecord(
            provider="AbuseIPDB",
            indicator_type="ip",
            indicator_value=indicator_value,
            summary=summary,
            severity=severity,
            details={
                "abuse_confidence_score": score,
                "country_code": data.get("countryCode"),
                "usage_type": data.get("usageType"),
                "total_reports": data.get("totalReports"),
            },
        )
    finally:
        if close_client:
            client.close()


def _virustotal_path(indicator_type: str, indicator_value: str) -> str | None:
    if indicator_type == "domain":
        return f"domains/{indicator_value}"
    if indicator_type == "ip":
        return f"ip_addresses/{indicator_value}"
    if indicator_type == "hash":
        return f"files/{indicator_value}"
    if indicator_type == "url":
        encoded = base64.urlsafe_b64encode(indicator_value.encode()).decode().rstrip("=")
        return f"urls/{encoded}"
    return None
