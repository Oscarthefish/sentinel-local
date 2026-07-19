"""Secret-pattern scanner for email body content.

Ported from the Claude-OSINT offensive-osint skill secret regex catalog.
Scans subject, text body, and HTML body for leaked credentials or tokens.
"""

from __future__ import annotations

import re

from sentinel_local.domain.models import ParsedEmail, RuleHit

# Severity mapped to Sentinel's 3-tier scale (critical → high)
_H = "high"
_M = "medium"
_L = "low"

# (name, severity, category, pattern) — most-specific first
_PATTERNS: list[tuple[str, str, str, str]] = [
    ("AWS_ACCESS_KEY",      _H, "aws",              r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("AWS_SECRET_TYPED",    _H, "aws",              r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key['\"\s:=]+([A-Za-z0-9/+=]{40})"),
    ("GCP_SERVICE_ACCOUNT", _H, "gcp",              r'"type"\s*:\s*"service_account"'),
    ("GOOGLE_API_KEY",      _H, "gcp",              r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ("GH_PAT_CLASSIC",      _H, "github",           r"\bghp_[A-Za-z0-9]{36}\b"),
    ("GH_PAT_FINEGRAINED",  _H, "github",           r"\bgithub_pat_[A-Za-z0-9_]{82}\b"),
    ("GH_OAUTH",            _H, "github",           r"\bgho_[A-Za-z0-9]{36}\b"),
    ("GH_SERVER_TOKEN",     _H, "github",           r"\bgh[usr]_[A-Za-z0-9]{36,}\b"),
    ("STRIPE_LIVE",         _H, "stripe",           r"\bsk_live_[0-9A-Za-z]{24,}\b"),
    ("STRIPE_TEST",         _L, "stripe",           r"\bsk_test_[0-9A-Za-z]{24,}\b"),
    ("SLACK_TOKEN",         _H, "slack",            r"\bxox[abpors]-[0-9A-Za-z\-]{10,48}\b"),
    ("SLACK_WEBHOOK",       _M, "slack",            r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
    ("SENDGRID",            _H, "email_svc",        r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"),
    ("MAILGUN",             _H, "email_svc",        r"\bkey-[0-9a-zA-Z]{32}\b"),
    ("TWILIO_API",          _H, "twilio",           r"\bSK[0-9a-fA-F]{32}\b"),
    ("JWT",                 _M, "jwt",              r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
    ("BEARER_AUTH",         _M, "bearer",           r"(?i)authorization[\"'=:\s]+bearer\s+[A-Za-z0-9._\-]{20,}"),
    ("BASIC_AUTH_URL",      _M, "basic_auth",       r"https?://[^/\s:@]{3,}:[^/\s:@]{3,}@[^/\s]{4,}"),
    ("RSA_PRIVKEY",         _H, "private_key",      r"-----BEGIN RSA PRIVATE KEY-----"),
    ("EC_PRIVKEY",          _H, "private_key",      r"-----BEGIN EC PRIVATE KEY-----"),
    ("OPENSSH_PRIVKEY",     _H, "private_key",      r"-----BEGIN OPENSSH PRIVATE KEY-----"),
    ("GENERIC_PRIVKEY",     _H, "private_key",      r"-----BEGIN (?:DSA |PGP |)PRIVATE KEY-----"),
    ("GENERIC_API_KEY",     _M, "generic",          r"(?i)(?:api[_\-]?key|apikey|api_secret|access_token|secret[_\-]?token)['\"\s:=]+[\"']([A-Za-z0-9+/=_\-]{24,})[\"']"),
    ("ANTHROPIC_API",       _H, "ai_api",           r"\bsk-ant-(?:api03|admin01)-[A-Za-z0-9_\-]{93,}\b"),
    ("OPENAI_LEGACY",       _H, "ai_api",           r"\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b"),
    ("OPENAI_PROJECT",      _H, "ai_api",           r"\bsk-proj-[A-Za-z0-9_\-]{40,}T3BlbkFJ[A-Za-z0-9_\-]{40,}\b"),
    ("HUGGINGFACE",         _H, "ai_api",           r"\bhf_[A-Za-z0-9]{30,}\b"),
    ("CLOUDFLARE_API",      _H, "infra_api",        r"(?i)cf[_\-]?api[_\-]?key['\"\s:=]+([a-f0-9]{37})"),
    ("DIGITALOCEAN",        _H, "infra_api",        r"\bdop_v1_[a-f0-9]{64}\b"),
    ("NPM_TOKEN",           _H, "package_registry", r"\bnpm_[A-Za-z0-9]{36}\b"),
    ("PYPI_TOKEN",          _H, "package_registry", r"\bpypi-AgENdGV[A-Za-z0-9_\-]+\b"),
    ("DOCKER_HUB_PAT",      _H, "package_registry", r"\bdckr_pat_[A-Za-z0-9_\-]{27,}\b"),
    ("ATLASSIAN_TOKEN",     _H, "saas_api",         r"\bATATT3xFfGF0[A-Za-z0-9_\-]{180,}\b"),
    ("SENTRY_AUTH",         _M, "saas_api",         r"\bsntrys_[A-Za-z0-9_]{40,}\b"),
    ("NGROK_TOKEN",         _M, "tunneling",        r"\bngrok-[A-Za-z0-9_]{35,}\b"),
]

_COMPILED: list[tuple[str, str, str, re.Pattern[str]]] = [
    (name, sev, cat, re.compile(pattern))
    for name, sev, cat, pattern in _PATTERNS
]

_SEV_RANK = {"high": 3, "medium": 2, "low": 1}


def scan_secrets(parsed_email: ParsedEmail) -> list[RuleHit]:
    """Scan subject, text body, and HTML body for leaked credentials or tokens."""
    searchable = "\n".join(
        part for part in [parsed_email.subject, parsed_email.text_body, parsed_email.html_body] if part
    )
    if not searchable:
        return []

    hits_by_category: dict[str, list[str]] = {}
    worst_severity: dict[str, str] = {}

    for name, sev, cat, pattern in _COMPILED:
        if pattern.search(searchable):
            hits_by_category.setdefault(cat, []).append(name)
            if _SEV_RANK.get(sev, 0) > _SEV_RANK.get(worst_severity.get(cat, "low"), 0):
                worst_severity[cat] = sev

    if not hits_by_category:
        return []

    all_pattern_names = sorted(name for names in hits_by_category.values() for name in names)
    overall_severity = max(worst_severity.values(), key=lambda s: _SEV_RANK.get(s, 0))
    score_delta = 35 if overall_severity == "high" else 20 if overall_severity == "medium" else 10

    return [
        RuleHit(
            rule_id="secret-in-body",
            title="Credential or token pattern detected in message content",
            description=(
                "The message body contains patterns matching known credential or API token formats. "
                "This may indicate malware delivery, credential exfiltration, or an insider threat scenario."
            ),
            severity=overall_severity,
            score_delta=score_delta,
            evidence=all_pattern_names[:10],
        )
    ]
