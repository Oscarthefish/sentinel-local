"""Sentinel Local — Documentation page."""

from __future__ import annotations

from sentinel_local.core.config import get_settings
from sentinel_local.ui.components import APP_STYLES

try:
    import streamlit as st
except ModuleNotFoundError as exc:  # pragma: no cover
    raise RuntimeError("Streamlit is not installed.") from exc

settings = get_settings()

st.set_page_config(
    page_title=f"Docs — {settings.app_name}",
    page_icon=":books:",
    layout="wide",
)
st.markdown(APP_STYLES, unsafe_allow_html=True)
st.markdown(
    "<style>.doc-section{margin-bottom:2rem;} h2{letter-spacing:.06em;} "
    "code{background:rgba(0,180,216,.1);border:1px solid rgba(0,180,216,.25);"
    "padding:.1rem .4rem;border-radius:6px;font-size:.85em;color:#00c8ff;}</style>",
    unsafe_allow_html=True,
)

# ── Sidebar ───────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown(
        "<div style='font-family:monospace;font-size:.75rem;color:#00b4d8;"
        "letter-spacing:.18em;text-transform:uppercase;margin-bottom:.4rem'>"
        "Sentinel Local</div>",
        unsafe_allow_html=True,
    )
    st.caption(f"v{settings.app_name} · local-first")
    st.divider()
    st.markdown("**Jump to section**")
    st.markdown(
        "- [What is Sentinel Local](#what-is-sentinel-local)\n"
        "- [Analysis pipeline](#analysis-pipeline)\n"
        "- [Verdict taxonomy](#verdict-taxonomy)\n"
        "- [IOC extraction](#ioc-extraction)\n"
        "- [Header analysis](#header-analysis)\n"
        "- [URL analysis](#url-analysis)\n"
        "- [Attachment analysis](#attachment-analysis)\n"
        "- [Local scanners](#local-scanners-yara-clamav)\n"
        "- [Enrichment](#optional-enrichment)\n"
        "- [LLM narrative](#local-llm-narrative)\n"
        "- [Configuration](#configuration-reference)\n"
        "- [Privacy model](#privacy-model)\n"
        "- [Limitations](#limitations)\n"
        "- [Troubleshooting](#troubleshooting)\n"
    )

# ── Page header ───────────────────────────────────────────────────────────
st.markdown(
    "<div style='font-family:monospace;font-size:.65rem;color:#00b4d8;"
    "letter-spacing:.22em;text-transform:uppercase;margin-bottom:.3rem'>"
    "Sentinel Local / Documentation</div>",
    unsafe_allow_html=True,
)
st.title("Sentinel Local")
st.caption(
    "Local-first email triage and investigation tool for macOS. "
    "Built for SOC analysts who need explainable, evidence-based verdicts without sending data to the cloud."
)
st.divider()

# ──────────────────────────────────────────────────────────────────────────
st.header("What is Sentinel Local")
st.markdown("""
Sentinel Local is a **local-first suspicious email triage tool** designed for SOC analysts and security
practitioners. You provide a raw email (`.eml`, `.msg`, `.txt`, or pasted content); the tool runs a
structured analysis pipeline entirely on your machine and produces an explainable, evidence-backed verdict.

Key design choices:

| Principle | What it means |
|---|---|
| **Local-first** | All core analysis runs on your machine. No cloud calls required. |
| **Deterministic verdicting** | Scores and verdicts come from rules and heuristics, not an LLM. |
| **LLM is narrative-only** | If an LLM is configured, it writes explanations — it never overrides the score or verdict. |
| **Privacy by design** | Recipient emails and recipient domains are never sent to external services. |
| **Fail-open** | If optional stages (enrichment, scanning, LLM) fail, core analysis still completes. |
""")

# ──────────────────────────────────────────────────────────────────────────
st.header("Analysis pipeline")
st.markdown("""
Every submission runs through the same ordered pipeline. Each stage feeds the next.
""")

stages = [
    ("1", "Parse", "Decode the email structure — sender, recipients, subject, date, headers, body (text and HTML), and attachment metadata. Supports `.eml` (RFC 2822), `.msg` (Outlook), `.txt`, and raw pasted content."),
    ("2", "Extract IOCs", "Scan body text, HTML, and headers for URLs, domains, IP addresses, email addresses, and hashes. Attachment names and extensions are also extracted as indicators."),
    ("3", "Header analysis", "Parse `Authentication-Results` for SPF, DKIM, and DMARC results and alignment. Build a mail-flow timeline from `Received:` headers. Extract `Message-ID`, `Return-Path`, `Reply-To`, and originating IPs."),
    ("4", "URL analysis", "Unwrap tracking links, detect URL shorteners, compare anchor text vs. destination, optionally follow redirect chains, and scan HTML for hidden elements, forms, scripts, and `javascript:` links."),
    ("5", "Attachment analysis", "Check each attachment for risky extensions, archive formats, macro-capable file types, lure-style filenames, MIME/extension mismatches, and SHA-256 hashes (computed from raw bytes during parsing)."),
    ("6", "Score", "Run the full deterministic rule set. Each fired rule contributes a score delta. Final score maps to `benign`, `suspicious`, or `malicious` with a confidence level and a disposition label."),
    ("7*", "Attachment scanning (optional)", "If enabled, write attachments to transient temp files and run YARA and/or ClamAV locally. Raw bytes are never stored. Only scanner output is kept."),
    ("8*", "Enrichment (optional)", "Query VirusTotal and/or AbuseIPDB for extracted URLs, domains, IPs, and attachment hashes. Recipient identities are never enriched externally."),
    ("9*", "LLM narrative (optional)", "Send a structured evidence summary (no raw email content) to a local Ollama or LM Studio model. The model writes a human-readable narrative. It has no effect on the score or verdict."),
    ("10", "Analyst summary", "Build a deterministic analyst summary: likely intent, evidence highlights, and recommended next actions. This runs regardless of whether LLM is enabled."),
    ("11", "Reports", "Render markdown, HTML, and JSON exports. Save the full investigation to a local SQLite database."),
]

for num, name, desc in stages:
    optional = "*" in num
    label = f"`{num.replace('*','')}` &nbsp; **{name}**" + (" *(optional)*" if optional else "")
    with st.expander(f"Stage {num.replace('*','')} — {name}" + (" (optional)" if optional else "")):
        st.markdown(f"**{name}**")
        st.write(desc)

# ──────────────────────────────────────────────────────────────────────────
st.header("Verdict taxonomy")
st.markdown("""
Every analysis produces two classification values:

### Verdict
The overall risk signal derived from the total score.

| Verdict | Score range | Meaning |
|---|---|---|
| `benign` | 0 – 29 | No significant risk signals detected. |
| `suspicious` | 30 – 59 | One or more risk signals present; warrants analyst review. |
| `malicious` | 60+ | Multiple high-severity signals; treat as confirmed threat until proven otherwise. |

### Disposition
A more specific category used to guide workflow.

| Disposition | Meaning |
|---|---|
| `benign` | Message appears legitimate. |
| `spam` | Bulk or unsolicited content, low threat. |
| `phishing` | Credential theft or account takeover attempt. |
| `malware_delivery` | Attempting to deliver malicious payloads (attachments, drive-by links). |
| `bec` | Business Email Compromise — impersonation for financial fraud. |
| `needs_escalation` | Insufficient evidence for a confident classification; escalate to tier 2. |

### Confidence
| Level | Meaning |
|---|---|
| `low` | Few rules fired or conflicting signals. Treat result as a starting point. |
| `medium` | Moderate evidence; likely correct but manual review recommended. |
| `high` | Multiple consistent signals; high confidence in verdict. |
""")

# ──────────────────────────────────────────────────────────────────────────
st.header("IOC extraction")
st.markdown("""
Indicators are extracted from all available text surfaces: body (plain text and HTML), headers, sender
fields, and attachment metadata.

| Type | Description |
|---|---|
| `url` | Full URLs found in body text or HTML href attributes. |
| `domain` | Hostnames extracted from URLs and other text patterns. |
| `ip` | IPv4 and IPv6 addresses found in any text surface. |
| `email` | Email addresses found in headers and body content. |
| `hash` | MD5, SHA-1, or SHA-256 strings found in message content. |
| `attachment_name` | Raw filename of each attachment. |
| `attachment_ext` | Extension of each attachment (e.g. `.exe`, `.html`). |

Each indicator carries a `source` tag (`text_body`, `html_body`, `headers`, `sender`, `recipient`, `attachment`)
so you can trace where it was found.

> **Recipient privacy**: Email addresses and domains belonging to recipients are tagged as local-only and
> are never sent to external enrichment services.
""")

# ──────────────────────────────────────────────────────────────────────────
st.header("Header analysis")
st.markdown("""
The header analysis stage parses three areas:

### Authentication
- **SPF** — result (`pass`, `fail`, `softfail`, `neutral`, `none`) and domain alignment vs. `From:` header
- **DKIM** — result and domain alignment
- **DMARC** — result and alignment; reads both `Authentication-Results` and `ARC-Authentication-Results`

### Key header fields
- `Message-ID` — unique message identifier
- `Return-Path` — envelope sender (used for bounce handling, often differs in phishing)
- `Reply-To` — override destination if the user replies (frequently abused in BEC)
- Originating IPs — first external IP from `Received:` chain

### Mail-flow timeline
Each `Received:` header is parsed into a structured hop:

| Field | Description |
|---|---|
| `from_host` | Claimed sending host |
| `by_host` | Receiving MTA |
| `from_ip` | IP of the connecting client |
| `timestamp` | Parsed relay timestamp |
| `findings` | Anomaly flags (private IPs, unknown hosts, time-order violations) |

Repeated `Received:` headers are preserved in order so the full relay chain is visible.
""")

# ──────────────────────────────────────────────────────────────────────────
st.header("URL analysis")
st.markdown("""
URLs extracted from the message body are individually analyzed:

| Check | What it looks for |
|---|---|
| **Tracking wrapper unwrapping** | Strips known email-marketing redirect wrappers to reveal the true URL. |
| **Shortener detection** | Identifies known URL shortener domains (bit.ly, tinyurl, etc.). |
| **Anchor text mismatch** | Compares visible link text to the actual `href` destination. |
| **Redirect resolution** *(optional)* | Follows `Location:` headers up to 10 hops to find the final destination. |
| **HTML artifact detection** | Scans the HTML body for hidden elements, embedded forms, inline scripts, and `javascript:` scheme links. |
| **Screenshot URL generation** *(optional)* | Produces a screenshot URL when a provider is configured. |

URL analysis findings directly influence the deterministic score. A `display-text-mismatch` or `shortened-url`
finding raises the risk level of that link.
""")

# ──────────────────────────────────────────────────────────────────────────
st.header("Attachment analysis")
st.markdown("""
Each attachment is analyzed using its metadata (no file content is executed).

| Check | Detail |
|---|---|
| **Risky extension** | Flags `.exe`, `.scr`, `.js`, `.html`, `.htm`, `.svg`, `.iso`, `.zip`, `.hta`, `.bat`, `.cmd`, `.vbs`, `.ps1` |
| **Archive flag** | `.zip`, `.rar`, `.7z`, `.tar`, `.gz` — often used to bypass gateway scanning |
| **Macro-capable** | `.doc`, `.docm`, `.xls`, `.xlsm`, `.xlam`, `.ppt`, `.pptm` |
| **Lure filename** | Patterns matching common social-engineering lure names (invoice, statement, password, etc.) |
| **MIME mismatch** | Declared MIME type doesn't match the file extension |
| **SHA-256** | Computed from raw attachment bytes during parsing. Used for local scan and reputation lookup. |

Severity (`info`, `low`, `medium`, `high`) is assigned per artifact and displayed in the findings view.
""")

# ──────────────────────────────────────────────────────────────────────────
st.header("Local scanners (YARA / ClamAV)")
st.markdown("""
If enabled via `.env`, Sentinel Local can scan attachment bytes with local tools.

**How it works:**
1. Attachment bytes are written to a transient temporary file.
2. The scanner binary is invoked with a timeout.
3. Results are collected and the temp file is immediately deleted.
4. Raw attachment bytes are never persisted to SQLite.

**Enable in `.env`:**
```bash
SENTINEL_ENABLE_ATTACHMENT_SCANNING=true
SENTINEL_YARA_BINARY_PATH=/opt/homebrew/bin/yara
SENTINEL_YARA_RULES_PATH=./rules/email_triage.yar
SENTINEL_CLAMSCAN_BINARY_PATH=/opt/homebrew/bin/clamscan
SENTINEL_ATTACHMENT_SCAN_TIMEOUT_SECONDS=20
```

**Bundled YARA rules** (`rules/email_triage.yar`) cover:
- HTML credential harvesting patterns
- PowerShell dropper signatures
- Macro-laced Office document indicators
- Suspicious JavaScript in email attachments

If either binary is missing or the scan times out, a warning is appended to the results and analysis
continues normally.
""")

# ──────────────────────────────────────────────────────────────────────────
st.header("Optional enrichment")
st.markdown("""
External reputation lookups are **off by default** and must be explicitly enabled.

| Provider | Indicator types | Notes |
|---|---|---|
| **VirusTotal** | URL, domain, IP, hash | Queries the v3 API. Rate-limited. Attachment hashes use hash-first lookup (no file upload). |
| **AbuseIPDB** | IP | Confidence score and report count for each IP. |

**Enable in `.env`:**
```bash
SENTINEL_ENABLE_ENRICHMENT=true
SENTINEL_VIRUSTOTAL_API_KEY=your_key_here
SENTINEL_ABUSEIPDB_API_KEY=your_key_here
SENTINEL_ENRICHMENT_TIMEOUT_SECONDS=20
```

**Privacy guarantees:**
- Recipient email addresses are never enriched.
- Recipient domains are never enriched.
- Attachment bytes are never uploaded — only the SHA-256 hash is sent.
""")

# ──────────────────────────────────────────────────────────────────────────
st.header("Local LLM narrative")
st.markdown("""
Sentinel Local can optionally generate a human-readable narrative of its findings using a local LLM.

**Supported providers:**
- **Ollama** (`http://127.0.0.1:11434`) — run any GGUF/GGML model locally
- **LM Studio** (`http://127.0.0.1:1234`) — OpenAI-compatible local endpoint

**What the LLM receives:**
A structured text summary of deterministic findings (verdict, score, rule hits, IOC counts, header signals).
**No raw email content, no body text, no attachment bytes are sent to the LLM.**

**What the LLM produces:**
- A plain-English summary of findings
- A rationale for the verdict
- Recommended next actions

The LLM output is **clearly separated** from the deterministic analysis in the UI and reports. It has
no effect on score, verdict, or disposition.

**Enable in `.env`:**
```bash
SENTINEL_ENABLE_LLM=true
SENTINEL_LLM_PROVIDER=ollama          # or: lm_studio
SENTINEL_OLLAMA_MODEL=qwen2.5:7b-instruct
SENTINEL_LLM_TIMEOUT_SECONDS=60
```
""")

# ──────────────────────────────────────────────────────────────────────────
st.header("Configuration reference")
st.markdown("""
All settings are read from the `.env` file in the project root (or environment variables). The prefix
`SENTINEL_` is required for all keys.

```bash
# ── Core ─────────────────────────────────────────────────────
SENTINEL_ENV=development
SENTINEL_APP_NAME=Sentinel Local
SENTINEL_DATABASE_URL=sqlite:///./data/sentinel_local.db

# ── LLM (optional) ────────────────────────────────────────────
SENTINEL_ENABLE_LLM=false
SENTINEL_LLM_PROVIDER=ollama              # ollama | lm_studio
SENTINEL_OLLAMA_MODEL=qwen2.5:7b-instruct
SENTINEL_OLLAMA_BASE_URL=http://127.0.0.1:11434
SENTINEL_LM_STUDIO_BASE_URL=http://127.0.0.1:1234
SENTINEL_LLM_TIMEOUT_SECONDS=60

# ── Enrichment (optional) ──────────────────────────────────────
SENTINEL_ENABLE_ENRICHMENT=false
SENTINEL_VIRUSTOTAL_API_KEY=
SENTINEL_ABUSEIPDB_API_KEY=
SENTINEL_ENRICHMENT_TIMEOUT_SECONDS=20

# ── Local attachment scanners (optional) ───────────────────────
SENTINEL_ENABLE_ATTACHMENT_SCANNING=false
SENTINEL_YARA_BINARY_PATH=/opt/homebrew/bin/yara
SENTINEL_YARA_RULES_PATH=./rules/email_triage.yar
SENTINEL_CLAMSCAN_BINARY_PATH=/opt/homebrew/bin/clamscan
SENTINEL_ATTACHMENT_SCAN_TIMEOUT_SECONDS=20

# ── URL analysis ───────────────────────────────────────────────
SENTINEL_URL_RESOLUTION_TIMEOUT_SECONDS=15
SENTINEL_ENABLE_URL_SCREENSHOTS=false
SENTINEL_SCREENSHOT_PROVIDER=none
SENTINEL_SCREENSHOT_BASE_URL=
```

Copy `.env.example` to `.env` and fill in only the values you need. All optional features default to
**disabled**.
""")

# ──────────────────────────────────────────────────────────────────────────
st.header("Privacy model")
st.markdown("""
Sentinel Local is designed so you stay in control of what leaves your machine.

| Data | Stays local | Sent externally |
|---|---|---|
| Raw email bytes | Always | Never |
| Email body content | Always | Never |
| Attachment bytes | Always (temp files only during scanning) | Never |
| Recipient email addresses | Always | Never |
| Recipient domains | Always | Never |
| Sender email address | Always | When enrichment is enabled |
| Extracted URLs / domains | Always | When enrichment is enabled (opt-in) |
| Extracted IPs | Always | When enrichment is enabled (opt-in) |
| Attachment SHA-256 hashes | Always | When enrichment is enabled (opt-in) |
| LLM prompt (findings summary) | Always | Only if using a remote LLM endpoint |
| Investigation records | SQLite on your machine | Never |

Enrichment and LLM features are **disabled by default** and require explicit configuration.
""")

# ──────────────────────────────────────────────────────────────────────────
st.header("Limitations")
st.markdown("""
Sentinel Local is a triage assistance tool, not an authoritative verdict system.

- **Heuristics are not proof.** A high score means risk signals are present; it does not confirm
  maliciousness with certainty.
- **Auth results depend on what's in the headers.** SPF/DKIM/DMARC are only assessed when the
  corresponding headers are present. Absence of those headers is itself a signal.
- **URL redirect resolution is network-dependent.** Redirects won't resolve if the destination is
  unreachable, rate-limits the resolver, or requires a browser.
- **Attachment analysis is metadata-only by default.** Without YARA/ClamAV enabled, no file-content
  scanning occurs.
- **LLM output is not vetted.** Always verify LLM narrative claims against the deterministic evidence
  section.
- **No detonation.** Sentinel Local does not execute attachments or visit URLs in a sandbox.
""")

# ──────────────────────────────────────────────────────────────────────────
st.header("Troubleshooting")

with st.expander("App won't start — ModuleNotFoundError"):
    st.markdown("""
    The virtual environment is missing or the package isn't installed.
    ```bash
    cd /path/to/sentinel-local
    python3 -m venv .venv
    source .venv/bin/activate
    pip install -e ".[dev]"
    ```
    Then re-run `./start_sentinel.sh`.
    """)

with st.expander("Database not found / permission error"):
    st.markdown("""
    The `data/` directory may not exist. Create it:
    ```bash
    mkdir -p data
    ```
    Or change `SENTINEL_DATABASE_URL` in `.env` to point to a writable location.
    """)

with st.expander("LLM narrative is grayed out"):
    st.markdown("""
    The LLM feature is disabled by default. Enable it in `.env`:
    ```bash
    SENTINEL_ENABLE_LLM=true
    SENTINEL_LLM_PROVIDER=ollama
    SENTINEL_OLLAMA_MODEL=qwen2.5:7b-instruct
    ```
    Also ensure Ollama is running (`ollama serve`) and the model is pulled
    (`ollama pull qwen2.5:7b-instruct`).
    """)

with st.expander("Enrichment buttons are grayed out"):
    st.markdown("""
    Enrichment is disabled by default. Add API keys to `.env`:
    ```bash
    SENTINEL_ENABLE_ENRICHMENT=true
    SENTINEL_VIRUSTOTAL_API_KEY=your_key
    SENTINEL_ABUSEIPDB_API_KEY=your_key
    ```
    """)

with st.expander("YARA / ClamAV scan produces no results"):
    st.markdown("""
    Check that:
    1. `SENTINEL_ENABLE_ATTACHMENT_SCANNING=true` is set in `.env`
    2. The binary paths are correct (`which yara`, `which clamscan`)
    3. The YARA rules file exists at `SENTINEL_YARA_RULES_PATH`
    4. The email actually has attachments

    Scanner warnings are shown in the **Local Scans** tab of the Evidence view.
    """)

with st.expander("Analysis completes but score seems wrong"):
    st.markdown("""
    Open the **Findings** tab and expand each rule group to see exactly which rules fired and their
    score contributions. The **Evidence & Artifacts → Header Analysis** tab shows the raw authentication
    and mail-flow data used as input to the rules.

    If a rule fired incorrectly, please open an issue on the project repository with a redacted sample.
    """)

st.divider()
st.caption(
    f"Sentinel Local · {settings.app_name} · Local-first, analyst-first. "
    "Documentation is auto-generated from the running configuration."
)
