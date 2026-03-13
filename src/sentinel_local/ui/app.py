"""Streamlit UI for Sentinel Local."""

from __future__ import annotations

import json
import re
from collections import Counter
from html import escape

from sentinel_local.app.service import (
    AnalysisBundle,
    build_analysis_stage_plan,
    get_recent_analyses,
    load_saved_analysis,
    run_local_analysis,
)
from sentinel_local.core.config import get_settings
from sentinel_local.ui.components import (
    APP_STYLES,
    artifact_card,
    console_topbar,
    empty_state_card,
    finding_card,
    fish_progress_panel,
    format_alignment,
    risk_dot_html,
    subtle_card,
)

try:
    import streamlit as st
    import streamlit.components.v1 as st_components
except ModuleNotFoundError as exc:  # pragma: no cover
    raise RuntimeError(
        "Streamlit is not installed. Run `pip install -e \".[dev]\"` first."
    ) from exc

settings = get_settings()

st.set_page_config(page_title=settings.app_name, page_icon=":shield:", layout="wide")
st.markdown(APP_STYLES, unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _recent_label(item: dict) -> str:
    return f"{item['created_at'][:19]} | {item['verdict'].upper()} | {item['subject'] or 'No subject'}"


def _capability_dot(enabled: bool) -> str:
    return "🟢" if enabled else "⚪"


def _link_risk_level(findings: list[str]) -> str:
    if not findings:
        return "low"
    if {"display-text-mismatch", "shortened-url", "tracking-wrapper"} & set(findings):
        return "high"
    if {"redirect-resolved", "screenshot-available"} & set(findings):
        return "medium"
    return "low"


def _group_rule_hits(rule_hits: list) -> dict[str, list]:
    grouped: dict[str, list] = {
        "Sender and header signals": [],
        "Link and web signals": [],
        "Attachment and malware signals": [],
        "Content and social engineering signals": [],
        "Other signals": [],
    }
    for hit in rule_hits:
        if hit.rule_id.startswith(("auth-", "reply-to", "return-path", "received-", "display-name")):
            grouped["Sender and header signals"].append(hit)
        elif hit.rule_id in {"multiple-links", "lure-with-link"}:
            grouped["Link and web signals"].append(hit)
        elif "attachment" in hit.rule_id:
            grouped["Attachment and malware signals"].append(hit)
        elif hit.rule_id in {"suspicious-keywords", "high-recipient-count"}:
            grouped["Content and social engineering signals"].append(hit)
        else:
            grouped["Other signals"].append(hit)
    return grouped


def auth_value(value: str | None) -> str:
    return value or "unknown"


def _supports_thumbnail(url: str) -> bool:
    lowered = url.lower()
    # Only direct image files — thum.io requires a paid account so we skip it
    return any(ext in lowered for ext in [".png", ".jpg", ".jpeg", ".webp"])


def _enrichment_risk(records: list) -> str:
    if any(r.severity == "high" for r in records):
        return "high"
    if any(r.severity == "medium" for r in records):
        return "medium"
    return "normal"


def _has_display_mismatch_str(display_text: str, url: str) -> bool:
    from urllib.parse import urlsplit
    from sentinel_local.url_analysis.normalize import extract_display_domain
    display_domain = extract_display_domain(display_text)
    actual_domain = (urlsplit(url).hostname or "").lower()
    return bool(display_domain and actual_domain and display_domain != actual_domain)


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

def _render_sidebar() -> None:
    with st.sidebar:
        st.subheader("Sentinel Local")
        st.caption("Local-first email triage console.")

        st.markdown("**Runtime**")
        st.caption(f"Env: `{settings.environment}`")
        st.caption(
            f"{_capability_dot(settings.enable_llm)} LLM &nbsp; "
            f"{_capability_dot(settings.enable_enrichment)} Enrichment &nbsp; "
            f"{_capability_dot(settings.enable_attachment_scanning)} Local scans"
        )

        st.subheader("Saved cases")
        recent_analyses = get_recent_analyses(limit=10)
        recent_filter = st.text_input(
            "Search saved cases",
            placeholder="Subject, sender, or verdict",
            key="saved_case_filter",
        )
        if recent_filter.strip():
            fv = recent_filter.strip().lower()
            recent_analyses = [
                item for item in recent_analyses
                if fv in (item.get("subject") or "").lower()
                or fv in (item.get("sender") or "").lower()
                or fv in (item.get("verdict") or "").lower()
            ]
        recent_options = {_recent_label(item): item["analysis_id"] for item in recent_analyses}
        selected_recent = st.selectbox(
            "Open saved case",
            options=[""] + list(recent_options.keys()),
            format_func=lambda v: "Choose a saved case" if v == "" else v,
        )
        if selected_recent:
            loaded = load_saved_analysis(recent_options[selected_recent])
            if loaded is not None:
                st.session_state["loaded_bundle"] = loaded.model_dump(mode="json")

        if st.button("Clear current case", use_container_width=True):
            st.session_state.pop("loaded_bundle", None)
            st.session_state.pop("ei_focus", None)

        st.checkbox(
            "Auto-expand high-priority findings",
            key="expand_priority_evidence",
            help="Controls which finding groups expand automatically.",
        )

        with st.expander("Coverage, privacy & limits"):
            st.markdown(
                "**Coverage:** headers, SPF/DKIM/DMARC, mail flow, "
                "links, attachments, and extracted indicators.\n\n"
                "**Privacy:** no files sent to public scanners, no internal "
                "domains or recipient addresses sent externally by default.\n\n"
                "**Limits:** scores are evidence-based heuristics, not proof."
            )

        with st.expander("Runtime details"):
            st.write(f"Database: `{settings.database_url}`")
            st.write(f"Ollama: `{settings.ollama_base_url}`")
            st.write(f"LM Studio: `{settings.lm_studio_base_url or 'disabled'}`")
            st.write(f"LLM provider: `{settings.llm_provider}`")


# ---------------------------------------------------------------------------
# Intake form
# ---------------------------------------------------------------------------

def _render_intake() -> AnalysisBundle | None:
    if st.session_state.get("loaded_bundle"):
        if st.button("← New investigation", help="Clear current case and start a new one"):
            st.session_state.pop("loaded_bundle", None)
            st.session_state.pop("ei_focus", None)
            st.rerun()
        return None

    st.markdown('<div class="section-card">', unsafe_allow_html=True)
    st.markdown('<div class="section-heading">Start investigation</div>', unsafe_allow_html=True)
    st.markdown(
        '<p class="section-copy">Load an email file or paste message content. '
        "Analysis runs locally. Optional external enrichment only runs when you enable it.</p>",
        unsafe_allow_html=True,
    )

    tab_upload, tab_paste = st.tabs(["Load file", "Paste content"])
    bundle = None

    with tab_upload:
        main_col, options_col = st.columns([1.5, 1], gap="large")
        with main_col:
            uploaded = st.file_uploader(
                "Email file",
                type=["eml", "msg", "txt"],
                help="Supported formats: .eml, .msg, and plain text exports.",
            )
            upload_note = st.text_input(
                "Analyst note",
                key="upload_note",
                placeholder="Optional context, ticket reference, or note",
            )
        with options_col:
            st.markdown('<div class="section-card compact">', unsafe_allow_html=True)
            st.markdown('<div class="section-heading">Analysis options</div>', unsafe_allow_html=True)
            upload_narrative = st.checkbox(
                "Generate local narrative",
                key="upload_narrative",
                disabled=not settings.enable_llm,
                help="Local LLM explanatory narrative. Requires local LLM configured.",
            )
            upload_enrichment = st.checkbox(
                "Run external enrichment",
                key="upload_enrichment",
                disabled=not settings.enable_enrichment,
                help="Optional external lookups. Requires enrichment configured.",
            )
            upload_scans = st.checkbox(
                "Run local attachment scanners",
                key="upload_scans",
                disabled=not settings.enable_attachment_scanning,
                help="Uses local YARA or ClamAV when configured.",
            )
            upload_resolve = st.checkbox(
                "Resolve redirects",
                key="upload_resolve",
                help="Follows URL redirect chains to show the final destination.",
            )
            upload_screenshots = st.checkbox(
                "Capture URL screenshots",
                key="upload_screenshots",
                disabled=not settings.enable_url_screenshots,
                help="Local Playwright screenshot capture when configured.",
            )
            st.markdown("</div>", unsafe_allow_html=True)

        analyze_upload = st.button("Analyze file", type="primary", use_container_width=True)

        if analyze_upload:
            if uploaded is None:
                st.error("Choose a file to review first.")
            else:
                source_type = uploaded.name.rsplit(".", 1)[-1].lower()
                processing_banner = st.empty()
                stage_plan = build_analysis_stage_plan(
                    generate_narrative=upload_narrative and settings.enable_llm,
                    run_enrichment=upload_enrichment and settings.enable_enrichment,
                    run_attachment_scans=upload_scans and settings.enable_attachment_scanning,
                    resolve_urls=upload_resolve,
                    capture_screenshots=upload_screenshots and settings.enable_url_screenshots,
                )

                def update_progress(stage_id: str) -> None:
                    processing_banner.markdown(
                        fish_progress_panel(
                            "ANALYSIS IN PROGRESS",
                            "Running investigation stages.",
                            stage_plan,
                            stage_id,
                        ),
                        unsafe_allow_html=True,
                    )

                try:
                    update_progress(stage_plan[0][0])
                    bundle = run_local_analysis(
                        source_type=source_type,
                        content=uploaded.getvalue(),
                        filename=uploaded.name,
                        analyst_note=upload_note or None,
                        generate_narrative=upload_narrative,
                        run_enrichment=upload_enrichment,
                        run_attachment_scans=upload_scans,
                        resolve_urls=upload_resolve,
                        capture_screenshots=upload_screenshots,
                        progress_callback=update_progress,
                    )
                    st.session_state["loaded_bundle"] = bundle.model_dump(mode="json")
                except Exception as exc:
                    st.error(f"Review failed: {exc}")
                finally:
                    processing_banner.empty()

    with tab_paste:
        main_col, options_col = st.columns([1.5, 1], gap="large")
        with main_col:
            pasted_headers = st.text_area(
                "Raw headers",
                height=160,
                placeholder="Optional: paste full raw headers here.",
            )
            pasted_content = st.text_area(
                "Message content",
                height=240,
                placeholder="Paste the email body or raw email text here.",
            )
            pasted_note = st.text_input(
                "Analyst note",
                key="pasted_note",
                placeholder="Optional context, source, or analyst note",
            )
        with options_col:
            st.markdown('<div class="section-card compact">', unsafe_allow_html=True)
            st.markdown('<div class="section-heading">Analysis options</div>', unsafe_allow_html=True)
            pasted_narrative = st.checkbox(
                "Generate local narrative",
                key="pasted_narrative",
                disabled=not settings.enable_llm,
            )
            pasted_enrichment = st.checkbox(
                "Run external enrichment",
                key="pasted_enrichment",
                disabled=not settings.enable_enrichment,
            )
            pasted_scans = st.checkbox(
                "Run local attachment scanners",
                key="pasted_scans",
                disabled=not settings.enable_attachment_scanning,
            )
            pasted_resolve = st.checkbox("Resolve redirects", key="pasted_resolve")
            pasted_screenshots = st.checkbox(
                "Capture URL screenshots",
                key="pasted_screenshots",
                disabled=not settings.enable_url_screenshots,
            )
            st.markdown("</div>", unsafe_allow_html=True)

        analyze_pasted = st.button("Analyze pasted content", use_container_width=True)

        if analyze_pasted:
            if not pasted_content.strip():
                st.error("Paste message content before starting.")
            else:
                processing_banner = st.empty()
                stage_plan = build_analysis_stage_plan(
                    generate_narrative=pasted_narrative and settings.enable_llm,
                    run_enrichment=pasted_enrichment and settings.enable_enrichment,
                    run_attachment_scans=pasted_scans and settings.enable_attachment_scanning,
                    resolve_urls=pasted_resolve,
                    capture_screenshots=pasted_screenshots and settings.enable_url_screenshots,
                )

                def update_progress(stage_id: str) -> None:
                    processing_banner.markdown(
                        fish_progress_panel(
                            "ANALYSIS IN PROGRESS",
                            "Running investigation stages.",
                            stage_plan,
                            stage_id,
                        ),
                        unsafe_allow_html=True,
                    )

                try:
                    update_progress(stage_plan[0][0])
                    bundle = run_local_analysis(
                        source_type="pasted",
                        content=pasted_content,
                        raw_headers=pasted_headers or None,
                        analyst_note=pasted_note or None,
                        generate_narrative=pasted_narrative,
                        run_enrichment=pasted_enrichment,
                        run_attachment_scans=pasted_scans,
                        resolve_urls=pasted_resolve,
                        capture_screenshots=pasted_screenshots,
                        progress_callback=update_progress,
                    )
                    st.session_state["loaded_bundle"] = bundle.model_dump(mode="json")
                except Exception as exc:
                    st.error(f"Review failed: {exc}")
                finally:
                    processing_banner.empty()

    st.markdown("</div>", unsafe_allow_html=True)
    return bundle


# ---------------------------------------------------------------------------
# Verdict bar (top strip)
# ---------------------------------------------------------------------------

def _render_verdict_bar(bundle: AnalysisBundle) -> None:
    analysis = bundle.analysis_result
    parsed = bundle.parsed_email
    analyst_summary = bundle.analyst_summary_result
    verdict = analysis.verdict

    score_chip_cls = "danger" if analysis.score >= 70 else "warn" if analysis.score >= 35 else "ok"
    verdict_chip_cls = {"malicious": "danger", "suspicious": "warn", "benign": "ok"}.get(verdict, "accent")

    sender = parsed.sender.email if parsed.sender else "unknown"
    to_str = ", ".join(r.email for r in parsed.recipients[:2] if r.email) or "—"
    subj = parsed.subject or "No subject"

    chips_html = "".join(
        f"<span class='vbar-chip {cls}'>{lbl}</span>"
        for lbl, cls in [
            (f"Score {analysis.score}", score_chip_cls),
            (analysis.disposition.replace("_", " ").upper(), verdict_chip_cls),
            (analysis.confidence.upper() + " CONFIDENCE", "accent"),
            (f"{len(analysis.rule_hits)} findings", "accent"),
        ]
    )

    st.markdown(
        f"""<div class="vbar">
          <div class="vbar-accent {verdict}"></div>
          <div class="vbar-body">
            <div>
              <div class="vbar-label">Assessment</div>
              <div class="vbar-verdict {verdict}">{verdict.upper()}</div>
              <div class="vbar-subject">{escape(subj)}</div>
              <div class="vbar-meta">{escape(sender)} → {escape(to_str)}</div>
            </div>
            <div class="vbar-chips">{chips_html}</div>
            <div class="vbar-summary">{escape(analyst_summary.summary)}</div>
          </div>
        </div>""",
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Left analysis tabs
# ---------------------------------------------------------------------------

def _render_tab_details(bundle: AnalysisBundle) -> None:
    parsed = bundle.parsed_email
    header_analysis = bundle.header_analysis_result
    analysis = bundle.analysis_result

    # Sender
    _ei_section("Envelope")
    sender_email = parsed.sender.email if parsed.sender else None
    sender_name = parsed.sender.name if parsed.sender else None
    sender_display = (
        f"{sender_name} <{sender_email}>" if sender_name and sender_email
        else (sender_email or "Not parsed")
    )
    sender_rule_ids = {
        "display-name-impersonation", "return-path-mismatch", "reply-to-mismatch",
        "auth-failure", "auth-warning", "auth-alignment",
    }
    sender_hits = [h for h in analysis.rule_hits if h.rule_id in sender_rule_ids]
    sender_risk = (
        "high" if any(h.severity == "high" for h in sender_hits)
        else "medium" if sender_hits else "normal"
    )

    if sender_email:
        _ei_inspect_row("From", sender_display, sender_risk, ("sender", sender_email), section="details")
    else:
        _ei_field("From", sender_display, sender_risk)

    if header_analysis.reply_to:
        for rt in header_analysis.reply_to[:2]:
            _ei_inspect_row("Reply-To", rt, "medium", ("reply_to", rt), section="details")

    if header_analysis.return_path:
        rp = header_analysis.return_path
        rp_domain = rp.split("@")[-1].rstrip(">") if "@" in rp else ""
        sender_domain = sender_email.split("@")[-1] if sender_email and "@" in sender_email else ""
        rp_risk = "high" if rp_domain and sender_domain and rp_domain.lower() != sender_domain.lower() else "normal"
        _ei_inspect_row("Return-Path", rp, rp_risk, ("return_path", rp), section="details")

    if parsed.recipients:
        _ei_field("To", ", ".join(r.email or r.name or "" for r in parsed.recipients[:3]))

    _ei_field("Subject", parsed.subject or "N/A")
    _ei_field("Date", parsed.sent_at.strftime("%Y-%m-%d  %H:%M UTC") if parsed.sent_at else "N/A")
    _ei_field("Source", parsed.source_type.upper())

    if header_analysis.message_id:
        _ei_field("Message-ID", header_analysis.message_id)

    if parsed.attachments:
        _ei_field("Attachments", str(len(parsed.attachments)))

    if bundle.analysis_id:
        _ei_field("Case ID", bundle.analysis_id)


def _render_tab_auth(bundle: AnalysisBundle) -> None:
    header_analysis = bundle.header_analysis_result
    auth = header_analysis.authentication

    def _result_label(result: str | None) -> str:
        sym = "✓" if result in {"pass", "softpass"} else "✗" if result in {"fail", "none", "reject", "hardfail"} else "~"
        return f"{sym} {(result or 'unknown').upper()}"

    _ei_section("Authentication results — click any result to learn more")

    spf_col, dkim_col, dmarc_col = st.columns(3, gap="small")

    with spf_col:
        with st.popover(_result_label(auth.spf_result) + "  SPF", use_container_width=True):
            st.markdown("### SPF — Sender Policy Framework")
            st.markdown(
                "SPF lets a domain owner publish a list of mail servers that are **authorised to send email** "
                "on their behalf. When a receiving server gets a message, it looks up the sender's domain in "
                "DNS and checks whether the sending IP is on that list.\n\n"
                "| Result | Meaning |\n"
                "|--------|----------|\n"
                "| **pass** | Sending server is authorised — expected and healthy |\n"
                "| **fail** | Sending server is NOT authorised — strong spoofing signal |\n"
                "| **softfail** | Not authorised but the domain hasn't enforced a hard policy |\n"
                "| **none** | No SPF record published — cannot verify |\n"
                "| **neutral** | Domain explicitly declines to assert |\n\n"
                "**Alignment** means the SPF-authenticated domain matches the visible From address domain. "
                "A pass without alignment can still be exploited."
            )
            st.divider()
            spf_risk = "normal" if auth.spf_result == "pass" else "high" if auth.spf_result in {"fail", "none", "hardfail"} else "medium"
            _ei_field("Result", auth.spf_result or "unknown", spf_risk)
            _ei_field("Domain", auth.spf_domain or "N/A")
            _ei_field("Alignment", format_alignment(auth.spf_aligned))

    with dkim_col:
        with st.popover(_result_label(auth.dkim_result) + "  DKIM", use_container_width=True):
            st.markdown("### DKIM — DomainKeys Identified Mail")
            st.markdown(
                "DKIM adds a **cryptographic signature** to the email headers. The sending mail server signs "
                "outgoing messages with a private key; the public key is published in DNS. Receiving servers "
                "verify the signature to confirm the email is genuinely from the stated domain and hasn't "
                "been tampered with in transit.\n\n"
                "| Result | Meaning |\n"
                "|--------|----------|\n"
                "| **pass** | Signature verified — email is authentic and untampered |\n"
                "| **fail** | Signature invalid — email may have been modified or spoofed |\n"
                "| **none** | No DKIM signature present — common but weakens trust |\n"
                "| **permerror** | Permanent error in the DKIM record |\n\n"
                "**Alignment** means the DKIM signing domain (`d=` tag) matches the From header domain. "
                "Misalignment can indicate a third-party sender or spoofing attempt."
            )
            st.divider()
            dkim_risk = "normal" if auth.dkim_result == "pass" else "high" if auth.dkim_result in {"fail", "none"} else "medium"
            _ei_field("Result", auth.dkim_result or "unknown", dkim_risk)
            _ei_field("Domain", auth.dkim_domain or "N/A")
            _ei_field("Alignment", format_alignment(auth.dkim_aligned))

    with dmarc_col:
        with st.popover(_result_label(auth.dmarc_result) + "  DMARC", use_container_width=True):
            st.markdown("### DMARC — Domain-based Message Authentication, Reporting & Conformance")
            st.markdown(
                "DMARC builds on SPF and DKIM. It lets domain owners specify a **policy** for what "
                "receiving servers should do with mail that fails both checks — and crucially, it requires "
                "SPF or DKIM to *align* with the visible From address. This closes the gap that allows "
                "header spoofing even when SPF passes.\n\n"
                "| Result | Meaning |\n"
                "|--------|----------|\n"
                "| **pass** | At least one of SPF or DKIM passed with From-domain alignment |\n"
                "| **fail** | Neither SPF nor DKIM passed with alignment — high spoofing risk |\n"
                "| **none** | No DMARC record published — policy not enforced |\n\n"
                "**DMARC policy levels:** `none` (report only) → `quarantine` (spam folder) → `reject` "
                "(block outright). A domain with `p=reject` and DMARC pass is very hard to spoof convincingly."
            )
            st.divider()
            dmarc_risk = "normal" if auth.dmarc_result == "pass" else "high" if auth.dmarc_result in {"fail", "none", "reject"} else "medium"
            _ei_field("Result", auth.dmarc_result or "unknown", dmarc_risk)
            _ei_field("From domain", auth.header_from_domain or "N/A")
            _ei_field("Alignment", format_alignment(auth.dmarc_aligned))

    if header_analysis.findings:
        _ei_section("Header findings")
        for finding in header_analysis.findings:
            _ei_field("Finding", finding, "medium")


def _render_tab_urls(bundle: AnalysisBundle) -> None:
    url_artifacts = bundle.url_analysis_result.artifacts

    if not url_artifacts:
        st.info("No URLs were found in this message.")
        return

    _ei_section(f"URLs ({len(url_artifacts)})")
    for artifact in url_artifacts:
        risk = _link_risk_level(artifact.findings)
        display_url = (artifact.original_url[:72] + "…") if len(artifact.original_url) > 72 else artifact.original_url
        _ei_inspect_row("URL", display_url, risk, ("url", artifact.original_url), section="urls")

    # HTML artifacts
    html_artifacts = bundle.url_analysis_result.html_artifacts
    if html_artifacts:
        _ei_section(f"HTML artifacts ({len(html_artifacts)})")
        for art in html_artifacts[:8]:
            _ei_field(art.artifact_type, art.summary, "medium")


def _render_tab_attachments(bundle: AnalysisBundle) -> None:
    attachments = bundle.parsed_email.attachments
    att_analysis_map = {a.filename: a for a in bundle.attachment_analysis_result.artifacts}

    if not attachments:
        st.info("No attachments were found in this message.")
        return

    _ei_section(f"Attachments ({len(attachments)})")
    for att in attachments:
        att_artifact = att_analysis_map.get(att.filename)
        risk = att_artifact.severity if att_artifact else "normal"
        size_str = f"{att.size:,} bytes" if att.size else "unknown size"
        _ei_inspect_row(
            "Attachment",
            f"{att.filename} ({size_str})",
            risk,
            ("attachment", att.filename),
            section="attachments",
        )


def _render_tab_transmission(bundle: AnalysisBundle) -> None:
    header_analysis = bundle.header_analysis_result

    if header_analysis.originating_ips:
        _ei_section(f"Originating IPs ({len(header_analysis.originating_ips)})")
        for ip in header_analysis.originating_ips[:6]:
            ip_recs = [r for r in bundle.enrichment_result.records if r.indicator_value == ip]
            ip_risk = _enrichment_risk(ip_recs) if ip_recs else "normal"
            _ei_inspect_row("IP", ip, ip_risk, ("server_ip", ip), section="transmission")

    if header_analysis.mail_flow:
        _ei_section(f"Mail flow ({len(header_analysis.mail_flow)} hops)")
        for hop in header_analysis.mail_flow:
            hop_val = f"{hop.from_host or hop.from_ip or '?'} → {hop.by_host or '?'}"
            hop_risk = "medium" if hop.findings else "normal"
            if hop.from_ip:
                _ei_inspect_row(f"Hop {hop.position}", hop_val, hop_risk, ("server_ip", hop.from_ip), section="transmission")
            else:
                _ei_field(f"Hop {hop.position}", hop_val, hop_risk)
    else:
        if not header_analysis.originating_ips:
            st.info("No transmission data was parsed from this message.")


def _render_tab_xheaders(bundle: AnalysisBundle) -> None:
    parsed = bundle.parsed_email
    if parsed.headers:
        st.dataframe(
            [{"Header": k, "Value": v} for k, v in parsed.headers.items()],
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No headers were parsed from this message.")


def _render_tab_findings(bundle: AnalysisBundle) -> None:
    analysis = bundle.analysis_result
    analyst_summary = bundle.analyst_summary_result

    # AI/LLM narrative (if available)
    if bundle.narrative_report:
        st.markdown("**AI narrative**")
        st.write(bundle.narrative_report.get("summary", ""))
        rationale = bundle.narrative_report.get("verdict_rationale", "")
        if rationale:
            st.caption(rationale)
        actions = bundle.narrative_report.get("recommended_actions", [])
        if actions:
            st.markdown("*Recommended:*")
            for action in actions:
                st.markdown(f"- {action}")
        st.divider()

    # Analyst summary
    st.markdown("**Summary**")
    st.write(analyst_summary.summary)
    if analyst_summary.likely_intent:
        st.caption(f"Likely intent: {analyst_summary.likely_intent}")

    if analyst_summary.evidence_highlights or analyst_summary.recommended_actions:
        hl_col, action_col = st.columns(2, gap="medium")
        with hl_col:
            if analyst_summary.evidence_highlights:
                st.markdown("**Evidence highlights**")
                for item in analyst_summary.evidence_highlights[:5]:
                    st.markdown(f"- {item}")
        with action_col:
            if analyst_summary.recommended_actions:
                st.markdown("**Recommended actions**")
                for action in analyst_summary.recommended_actions[:4]:
                    st.markdown(f"- {action}")

    st.divider()
    st.markdown("**Deterministic findings**")

    if analysis.rule_hits:
        severity_counts = Counter(hit.severity for hit in analysis.rule_hits)
        st.markdown(
            "<div class='subtle-grid'>"
            + subtle_card("High", str(severity_counts.get("high", 0)))
            + subtle_card("Medium", str(severity_counts.get("medium", 0)))
            + subtle_card("Low", str(severity_counts.get("low", 0)))
            + subtle_card("Score impact", f"+{sum(h.score_delta for h in analysis.rule_hits)}")
            + "</div>",
            unsafe_allow_html=True,
        )
        preferred_open = st.session_state.get("expand_priority_evidence", True)
        for group_label, hits in _group_rule_hits(analysis.rule_hits).items():
            if not hits:
                continue
            expanded = preferred_open and group_label in {
                "Sender and header signals",
                "Link and web signals",
                "Attachment and malware signals",
            }
            with st.expander(f"{group_label} ({len(hits)})", expanded=expanded):
                for hit in hits:
                    st.markdown(
                        finding_card(hit.title, hit.severity, hit.rule_id, hit.score_delta, hit.description),
                        unsafe_allow_html=True,
                    )
                    if hit.evidence:
                        st.code("\n".join(hit.evidence), language="text")
    else:
        st.info("No deterministic rules fired.")


def _render_tab_reports(bundle: AnalysisBundle) -> None:
    parsed = bundle.parsed_email

    st.caption("Export analyst-ready reports or inspect the full JSON bundle.")
    preview_expanded = st.toggle("Show report preview", value=False, key="report_preview_toggle")
    if preview_expanded:
        st.markdown(bundle.markdown_report)

    dl1, dl2, dl3 = st.columns(3)
    with dl1:
        st.download_button(
            "Markdown report",
            data=bundle.markdown_report,
            file_name="sentinel-report.md",
            mime="text/markdown",
            use_container_width=True,
        )
    with dl2:
        st.download_button(
            "HTML report",
            data=bundle.html_report,
            file_name="sentinel-report.html",
            mime="text/html",
            use_container_width=True,
        )
    with dl3:
        st.download_button(
            "Parsed JSON",
            data=json.dumps(parsed.model_dump(mode="json"), indent=2),
            file_name="sentinel-parsed.json",
            mime="application/json",
            use_container_width=True,
        )

    with st.expander("Full JSON bundle"):
        st.json({
            "parsed_email": parsed.model_dump(mode="json"),
            "extraction_result": bundle.extraction_result.model_dump(mode="json"),
            "header_analysis_result": bundle.header_analysis_result.model_dump(mode="json"),
            "analysis_result": bundle.analysis_result.model_dump(mode="json"),
            "analyst_summary_result": bundle.analyst_summary_result.model_dump(mode="json"),
            "url_analysis_result": bundle.url_analysis_result.model_dump(mode="json"),
            "attachment_analysis_result": bundle.attachment_analysis_result.model_dump(mode="json"),
            "enrichment_result": bundle.enrichment_result.model_dump(mode="json"),
            "narrative_report": bundle.narrative_report,
        })


def _render_left_panel(bundle: AnalysisBundle) -> None:
    (
        tab_details, tab_auth, tab_urls,
        tab_attachments, tab_transmission, tab_xheaders,
        tab_findings, tab_reports,
    ) = st.tabs([
        "Details", "Authentication", "URLs",
        "Attachments", "Transmission", "X-Headers",
        "Findings", "Reports",
    ])

    with tab_details:
        _render_tab_details(bundle)
    with tab_auth:
        _render_tab_auth(bundle)
    with tab_urls:
        _render_tab_urls(bundle)
    with tab_attachments:
        _render_tab_attachments(bundle)
    with tab_transmission:
        _render_tab_transmission(bundle)
    with tab_xheaders:
        _render_tab_xheaders(bundle)
    with tab_findings:
        _render_tab_findings(bundle)
    with tab_reports:
        _render_tab_reports(bundle)


# ---------------------------------------------------------------------------
# Right email viewer
# ---------------------------------------------------------------------------

def _sanitize_email_html(html_body: str, url_findings: dict) -> str:
    """Return a safe self-contained HTML document for iframe rendering.

    All external resources are neutralised, scripts removed, and links are
    intercepted so clicking them shows a detail overlay within the iframe.
    """
    # Strip scripts (with content)
    html = re.sub(r"<script[^>]*>.*?</script>", "", html_body, flags=re.DOTALL | re.IGNORECASE)
    # Strip on* event attributes
    html = re.sub(r'\s+on\w+=["\'][^"\']*["\']', "", html, flags=re.IGNORECASE)
    # Strip external stylesheet links
    html = re.sub(r'<link[^>]+rel=["\']stylesheet["\'][^>]*/?>', "", html, flags=re.IGNORECASE)
    # Neutralise tracking pixels and external images
    html = re.sub(
        r'(<img[^>]*)\ssrc=["\']https?://[^"\']+["\']',
        r'\1 src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"',
        html,
        flags=re.IGNORECASE,
    )
    # Neutralise external iframes
    html = re.sub(r"<iframe[^>]*>.*?</iframe>", "", html, flags=re.DOTALL | re.IGNORECASE)

    url_data_json = json.dumps(url_findings)

    # Rewrite anchor tags — intercept clicks and show detail panel within the iframe
    def _rewrite_anchor(m: re.Match) -> str:
        tag_content = m.group(1) or ""
        href_m = re.search(r'href=["\']([^"\']{1,2000})["\']', tag_content, re.IGNORECASE)
        if not href_m:
            return m.group(0)
        url = href_m.group(1)
        if url.startswith(("javascript:", "data:", "#")):
            return f"<a href='#' data-url='{escape(url)}'"
        info = url_findings.get(url, {})
        findings = info.get("findings", [])
        risk = (
            "high" if any(f in findings for f in ("display-text-mismatch", "shortened-url")) else
            "medium" if findings else
            "low"
        )
        border_color = "#ef4444" if risk == "high" else "#f59e0b" if risk == "medium" else "#3b82f6"
        safe_url = url.replace("\\", "").replace("'", "\\'").replace('"', "&quot;")
        return (
            f"<a href='#' "
            f"data-url='{escape(url)}' "
            f"style='color:{border_color};font-weight:600;text-decoration:underline;"
            f"background:rgba(59,130,246,.07);border-radius:3px;padding:0 2px;cursor:pointer' "
            f"onclick=\"showDetail('{safe_url}');return false;\""
        )

    html = re.sub(r"<a(\s[^>]*)?>", _rewrite_anchor, html, flags=re.IGNORECASE)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width">
<style>
  * {{ box-sizing: border-box; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    margin: 0;
    padding: 12px;
    background: #fff;
    color: #1e293b;
    font-size: 14px;
    line-height: 1.6;
  }}
  a {{ cursor: pointer; }}
  img {{ max-width: 100%; height: auto; }}
  table {{ max-width: 100%; border-collapse: collapse; }}

  /* Detail overlay panel */
  #detail-panel {{
    display: none;
    position: fixed;
    bottom: 0; left: 0; right: 0;
    background: #1e293b;
    color: #f1f5f9;
    padding: 12px 16px 14px;
    font-family: "SFMono-Regular", "Menlo", monospace;
    font-size: 12px;
    z-index: 99999;
    border-top: 3px solid #3b82f6;
    box-shadow: 0 -4px 24px rgba(0,0,0,.35);
    max-height: 200px;
    overflow-y: auto;
  }}
  #detail-panel-header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 8px;
  }}
  #detail-panel-title {{
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: .14em;
    color: #93c5fd;
    font-weight: 700;
  }}
  #detail-close {{
    cursor: pointer;
    color: #94a3b8;
    font-size: 18px;
    line-height: 1;
    background: none;
    border: none;
    padding: 0 2px;
  }}
  #detail-url {{ color: #fbbf24; word-break: break-all; margin-bottom: 6px; font-size: 12px; }}
  #detail-final {{ color: #94a3b8; margin-top: 4px; font-size: 11px; }}
  #detail-final span {{ color: #fbbf24; }}
  .d-finding {{ color: #f87171; margin-top: 3px; font-size: 11px; }}
  .d-clean {{ color: #34d399; margin-top: 3px; font-size: 11px; }}
  .d-badge {{
    display: inline-block;
    padding: 1px 7px;
    border-radius: 999px;
    font-size: 10px;
    font-weight: 700;
    margin-right: 4px;
    letter-spacing: .06em;
  }}
  .d-badge-high   {{ background: rgba(239,68,68,.2);  color: #f87171; border: 1px solid rgba(239,68,68,.3); }}
  .d-badge-medium {{ background: rgba(245,158,11,.2); color: #fbbf24; border: 1px solid rgba(245,158,11,.3); }}
  .d-badge-low    {{ background: rgba(59,130,246,.2); color: #93c5fd; border: 1px solid rgba(59,130,246,.3); }}
</style>
</head>
<body>
{html}

<div id="detail-panel">
  <div id="detail-panel-header">
    <span id="detail-panel-title">URL Detail</span>
    <button id="detail-close" onclick="closeDetail()">×</button>
  </div>
  <div id="detail-url"></div>
  <div id="detail-findings"></div>
  <div id="detail-final"></div>
</div>

<script>
var urlData = {url_data_json};

function showDetail(url) {{
  var info = urlData[url] || {{}};
  var findings = info.findings || [];
  var risk = findings.length === 0 ? "low"
    : (findings.indexOf("display-text-mismatch") >= 0 || findings.indexOf("shortened-url") >= 0) ? "high"
    : "medium";

  document.getElementById("detail-url").textContent = url;

  var fEl = document.getElementById("detail-findings");
  if (findings.length) {{
    var badgeCls = "d-badge d-badge-" + risk;
    fEl.innerHTML = '<span class="' + badgeCls + '">' + risk.toUpperCase() + '</span>'
      + '<span class="d-finding">⚠ ' + findings.join(", ") + '</span>';
  }} else {{
    fEl.innerHTML = '<span class="d-clean">✓ No suspicious findings detected</span>';
  }}

  var fEl2 = document.getElementById("detail-final");
  if (info.final_url && info.final_url !== url) {{
    fEl2.innerHTML = "Final destination: <span>" + info.final_url + "</span>";
  }} else if (info.unwrapped && info.unwrapped !== url) {{
    fEl2.innerHTML = "Unwrapped: <span>" + info.unwrapped + "</span>";
  }} else {{
    fEl2.innerHTML = "";
  }}

  document.getElementById("detail-panel").style.display = "block";
}}

function closeDetail() {{
  document.getElementById("detail-panel").style.display = "none";
}}
</script>
</body>
</html>"""


def _render_email_rendered(bundle: AnalysisBundle) -> None:
    html_body = bundle.parsed_email.html_body
    if not html_body:
        if bundle.parsed_email.text_body:
            st.code(bundle.parsed_email.text_body, language="text")
        else:
            st.info("No email body available.")
        return

    url_findings: dict = {}
    for artifact in bundle.url_analysis_result.artifacts:
        url_findings[artifact.original_url] = {
            "findings": artifact.findings,
            "final_url": artifact.final_url,
            "unwrapped": artifact.unwrapped_url,
        }

    sanitized = _sanitize_email_html(html_body, url_findings)
    st_components.html(sanitized, height=580, scrolling=True)

    if url_findings:
        risk_counts = {"high": 0, "medium": 0, "low": 0}
        for info in url_findings.values():
            risk_counts[_link_risk_level(info.get("findings", []))] += 1
        parts = []
        if risk_counts["high"]:
            parts.append(f"🔴 {risk_counts['high']} high-risk")
        if risk_counts["medium"]:
            parts.append(f"🟡 {risk_counts['medium']} medium-risk")
        if risk_counts["low"]:
            parts.append(f"🔵 {risk_counts['low']} clean")
        st.caption(f"Links: {' · '.join(parts)} — click any link in the email to inspect it.")


def _render_email_html(bundle: AnalysisBundle) -> None:
    html_body = bundle.parsed_email.html_body
    if html_body:
        st.code(html_body, language="html")
    else:
        st.info("No HTML body available.")


def _render_email_source(bundle: AnalysisBundle) -> None:
    parsed = bundle.parsed_email
    if parsed.headers:
        raw_headers = "\n".join(f"{k}: {v}" for k, v in parsed.headers.items())
        st.code(raw_headers, language="text")
    else:
        st.info("No raw headers were parsed.")


def _render_screenshot(screenshot_url: str, label: str) -> None:
    if screenshot_url.startswith("data:image/"):
        st.markdown(
            f'<img src="{screenshot_url}" alt="Screenshot: {escape(label)}" '
            f'style="width:100%;border-radius:6px;border:1px solid #e2e8f0;margin-top:.35rem">',
            unsafe_allow_html=True,
        )
    elif "thum.io" in screenshot_url.lower():
        st.caption("Screenshot unavailable — thum.io requires a paid account. Enable Playwright for local screenshots.")
    elif _supports_thumbnail(screenshot_url):
        st.image(screenshot_url, caption=f"Preview: {label}", use_container_width=True)
    else:
        st.caption("Screenshot URL available but cannot be previewed inline.")


def _render_right_panel(bundle: AnalysisBundle) -> None:
    focus = st.session_state.get("ei_focus")

    if focus:
        if st.button("← Back to email", key="close_detail_right"):
            st.session_state.pop("ei_focus", None)
            st.rerun()
        with st.container(border=True):
            _render_inspector_right(focus, bundle)
    else:
        tab_rendered, tab_html, tab_source = st.tabs(["Rendered", "HTML", "Source"])
        with tab_rendered:
            _render_email_rendered(bundle)
        with tab_html:
            _render_email_html(bundle)
        with tab_source:
            _render_email_source(bundle)

        # Screenshots from URL analysis
        screenshots = [a for a in bundle.url_analysis_result.artifacts if a.screenshot_url]
        if screenshots:
            with st.expander(f"URL screenshots ({len(screenshots)})", expanded=False):
                for artifact in screenshots:
                    st.caption(artifact.original_url[:80])
                    _render_screenshot(artifact.screenshot_url, artifact.original_url)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Top-level result layout
# ---------------------------------------------------------------------------

def _render_results(bundle: AnalysisBundle) -> None:
    _render_verdict_bar(bundle)

    left_col, right_col = st.columns([1, 1.45], gap="large")
    with left_col:
        _render_left_panel(bundle)
    with right_col:
        _render_right_panel(bundle)


# ---------------------------------------------------------------------------
# Inspector field helpers (used in detail panel)
# ---------------------------------------------------------------------------

def _ei_section(title: str) -> None:
    st.markdown(
        f"<div class='ei-section'>{escape(title)}</div>",
        unsafe_allow_html=True,
    )


def _ei_field(label: str, value: str, risk: str = "normal") -> None:
    risk_cls = risk if risk in {"high", "medium", "low"} else "normal"
    st.markdown(
        f"<div class='ei-field'>"
        f"<div class='ei-field-label'>{escape(label)}</div>"
        f"<div class='ei-field-value risk-{risk_cls}'>{escape(value)}</div>"
        f"</div>",
        unsafe_allow_html=True,
    )


def _ei_inspect_row(label: str, value: str, risk: str, focus_key: tuple, *, section: str = "") -> None:
    _ei_field(label, value, risk)
    key = f"ei_{abs(hash((focus_key[0], str(focus_key[1]), label, section)))}"
    if st.button(f"Inspect  ›  {label}", key=key, use_container_width=True):
        st.session_state["ei_focus"] = focus_key
        st.rerun()


# ---------------------------------------------------------------------------
# Inspector detail panel (right side when item is selected)
# ---------------------------------------------------------------------------

def _render_inspector_right(focus: tuple, bundle: AnalysisBundle) -> None:
    focus_type, focus_value = focus
    dispatch = {
        "sender":      _ei_detail_sender,
        "reply_to":    _ei_detail_reply_to,
        "return_path": _ei_detail_return_path,
        "server_ip":   _ei_detail_server_ip,
        "url":         _ei_detail_url,
        "attachment":  _ei_detail_attachment,
    }
    handler = dispatch.get(focus_type)
    if handler:
        handler(focus_value, bundle)
    else:
        st.info(f"No detail view for: {focus_type}")


def _ei_detail_sender(sender_email: str, bundle: AnalysisBundle) -> None:
    parsed = bundle.parsed_email
    header_analysis = bundle.header_analysis_result
    auth = header_analysis.authentication
    analysis = bundle.analysis_result

    st.subheader("Sender detail")
    sender_name = parsed.sender.name if parsed.sender else None
    _ei_field("Email", sender_email)
    if sender_name:
        _ei_field("Display name", sender_name)
    domain = sender_email.split("@")[-1] if "@" in sender_email else ""
    if domain:
        _ei_field("Domain", domain)

    _ei_section("Authentication")
    spf_risk = "normal" if auth.spf_result == "pass" else "high" if auth.spf_result in {"fail","none","hardfail"} else "medium"
    dkim_risk = "normal" if auth.dkim_result == "pass" else "high" if auth.dkim_result in {"fail","none"} else "medium"
    dmarc_risk = "normal" if auth.dmarc_result == "pass" else "high" if auth.dmarc_result in {"fail","none","reject"} else "medium"
    _ei_field("SPF", f"{auth.spf_result or 'unknown'} · alignment: {format_alignment(auth.spf_aligned)}", spf_risk)
    _ei_field("DKIM", f"{auth.dkim_result or 'unknown'} · alignment: {format_alignment(auth.dkim_aligned)}", dkim_risk)
    _ei_field("DMARC", f"{auth.dmarc_result or 'unknown'} · alignment: {format_alignment(auth.dmarc_aligned)}", dmarc_risk)

    if header_analysis.reply_to:
        rt = header_analysis.reply_to[0]
        rt_domain = rt.split("@")[-1] if "@" in rt else ""
        rt_match = rt_domain.lower() == domain.lower() if domain else True
        _ei_field("Reply-To", rt, "normal" if rt_match else "medium")

    if header_analysis.return_path:
        rp = header_analysis.return_path
        rp_domain = rp.split("@")[-1].rstrip(">") if "@" in rp else ""
        rp_match = rp_domain.lower() == domain.lower() if domain else True
        _ei_field("Return-Path", rp, "normal" if rp_match else "high")

    sender_rule_ids = {
        "display-name-impersonation", "return-path-mismatch", "reply-to-mismatch",
        "auth-failure", "auth-warning", "auth-alignment",
    }
    hits = [h for h in analysis.rule_hits if h.rule_id in sender_rule_ids]
    if hits:
        _ei_section("Rule findings")
        for hit in hits:
            st.markdown(finding_card(hit.title, hit.severity, hit.rule_id, hit.score_delta, hit.description), unsafe_allow_html=True)

    domain_recs = [r for r in bundle.enrichment_result.records if r.indicator_type == "domain" and r.indicator_value == domain]
    if domain_recs:
        _ei_section("Domain enrichment")
        for rec in domain_recs:
            _ei_field(rec.provider, rec.summary, rec.severity)


def _ei_detail_reply_to(rt: str, bundle: AnalysisBundle) -> None:
    parsed = bundle.parsed_email

    st.subheader("Reply-To detail")
    sender_email = parsed.sender.email if parsed.sender else None
    sender_domain = sender_email.split("@")[-1] if sender_email and "@" in sender_email else ""
    rt_domain = rt.split("@")[-1] if "@" in rt else ""

    _ei_field("Reply-To address", rt)
    _ei_field("Sender address", sender_email or "N/A")
    if rt_domain and sender_domain:
        match = rt_domain.lower() == sender_domain.lower()
        _ei_field(
            "Domain comparison",
            "Same domain — consistent" if match else f"DIFFERENT ({rt_domain} vs {sender_domain})",
            "normal" if match else "medium",
        )

    _ei_section("What this means")
    st.markdown(
        "A Reply-To address that differs from From means any reply goes to a different mailbox. "
        "This is a classic BEC and phishing technique — the attacker intercepts your response "
        "without needing to control the spoofed sender's domain."
    )

    rt_recs = [r for r in bundle.enrichment_result.records if r.indicator_type == "domain" and r.indicator_value == rt_domain]
    if rt_recs:
        _ei_section("Domain enrichment")
        for rec in rt_recs:
            _ei_field(rec.provider, rec.summary, rec.severity)


def _ei_detail_return_path(rp: str, bundle: AnalysisBundle) -> None:
    parsed = bundle.parsed_email

    st.subheader("Return-Path detail")
    sender_email = parsed.sender.email if parsed.sender else None
    sender_domain = sender_email.split("@")[-1] if sender_email and "@" in sender_email else ""
    rp_domain = rp.split("@")[-1].rstrip(">") if "@" in rp else ""

    _ei_field("Return-Path", rp)
    _ei_field("Sender domain", sender_domain or "N/A")
    if rp_domain and sender_domain:
        match = rp_domain.lower() == sender_domain.lower()
        _ei_field(
            "Domain comparison",
            "Same domain — consistent" if match else f"MISMATCH ({rp_domain} vs {sender_domain})",
            "normal" if match else "high",
        )

    _ei_section("What this means")
    st.markdown(
        "The Return-Path is where bounce messages are delivered. A Return-Path domain that differs "
        "from the From domain indicates the sending infrastructure doesn't control the displayed "
        "sender domain — a common indicator of spoofing or third-party sending abuse."
    )


def _ei_detail_server_ip(ip: str, bundle: AnalysisBundle) -> None:
    header_analysis = bundle.header_analysis_result

    st.subheader("Sending server")
    _ei_field("IP address", ip)

    for hop in header_analysis.mail_flow:
        if hop.from_ip == ip:
            _ei_section("Mail flow context")
            _ei_field("Hop", str(hop.position))
            if hop.from_host:
                _ei_field("From host", hop.from_host)
            if hop.by_host:
                _ei_field("Received by", hop.by_host)
            if hop.timestamp:
                _ei_field("Timestamp", hop.timestamp.isoformat())
            if hop.findings:
                for f in hop.findings:
                    _ei_field("Finding", f, "medium")
            break

    ip_recs = [r for r in bundle.enrichment_result.records if r.indicator_value == ip]
    if ip_recs:
        _ei_section("Reputation")
        for rec in ip_recs:
            _ei_field(rec.provider, rec.summary, rec.severity)
            details = rec.details or {}
            if "abuse_confidence_score" in details:
                score = details["abuse_confidence_score"]
                _ei_field("Abuse confidence", str(score), "high" if score >= 75 else "medium" if score >= 25 else "normal")
            if details.get("country_code"):
                _ei_field("Country", details["country_code"])
            if "total_reports" in details:
                _ei_field("Total abuse reports", str(details["total_reports"]))
            if details.get("last_analysis_stats"):
                stats = details["last_analysis_stats"]
                _ei_field("VT malicious", str(stats.get("malicious", 0)), "high" if stats.get("malicious", 0) > 0 else "normal")
    else:
        st.info("No enrichment data for this IP. Enable external enrichment and re-run to check reputation.")


_URL_FINDING_DETAILS: dict[str, dict] = {
    "tracking-wrapper": {
        "label": "⚠ Tracking wrapper",
        "risk": "medium",
        "title": "Tracking / Redirect Wrapper",
        "body": (
            "The URL is wrapped by a **tracking or redirect service** — typically an email marketing "
            "platform (e.g. Mailchimp, Sendgrid, Salesforce) or a corporate click-tracking proxy.\n\n"
            "When you click the link, the tracking service logs the click (recipient, timestamp, device) "
            "before forwarding you to the real destination. The unwrapped URL shown above is the actual "
            "target after the wrapper is removed.\n\n"
            "**Why it matters in phishing:**\n"
            "- Attackers use legitimate tracking services to make URLs appear trustworthy\n"
            "- The tracking domain passes reputation checks even if the final destination is malicious\n"
            "- Always inspect the *unwrapped* destination, not the wrapper domain"
        ),
    },
    "shortened-url": {
        "label": "⚠ Shortened URL",
        "risk": "medium",
        "title": "URL Shortener Detected",
        "body": (
            "The link uses a **URL shortening service** (e.g. bit.ly, tinyurl.com, t.co, ow.ly). "
            "These services map a short alias to a real destination that is hidden from view.\n\n"
            "URL shorteners are widely abused in phishing and malware campaigns because:\n"
            "- The true destination is invisible without clicking or resolving\n"
            "- Shortened URLs bypass many URL reputation filters\n"
            "- They can be re-targeted — the same short link can point to different destinations over time\n\n"
            "**Recommended action:** enable redirect resolution and re-run to see the final destination "
            "before clicking."
        ),
    },
    "display-text-mismatch": {
        "label": "🔴 Display text mismatch",
        "risk": "high",
        "title": "Display Text Does Not Match the Link",
        "body": (
            "The **visible text** of the link in the email does not match the domain the link actually "
            "goes to. This is one of the clearest indicators of a phishing attempt.\n\n"
            "**Example:**\n"
            "- Display text shown to the reader: `www.paypal.com/signin`\n"
            "- Actual URL the link goes to: `http://evil-site.ru/steal`\n\n"
            "Legitimate senders almost never need to show one domain while linking to another. "
            "This technique exploits the fact that most people read the displayed text rather than "
            "hovering over or inspecting the underlying href.\n\n"
            "**Treat this as high risk.** Do not click — inspect the final destination carefully."
        ),
    },
    "redirect-resolved": {
        "label": "↪ Redirects detected",
        "risk": "medium",
        "title": "URL Redirects to a Different Destination",
        "body": (
            "Following this URL revealed one or more **HTTP redirects** before reaching the final page. "
            "The redirect chain is shown above.\n\n"
            "Redirects are normal in many legitimate contexts (CDNs, login flows, link tracking). "
            "However, multi-hop redirect chains are also commonly used to:\n"
            "- Evade URL reputation filters (the first hop looks clean)\n"
            "- Route through legitimate domains before landing on a malicious page\n"
            "- Serve different content to security scanners vs real users (cloaking)\n\n"
            "**Check the final destination** in the redirect chain — that is the page the user will "
            "actually land on. A clean-looking initial URL is not a guarantee of a safe destination."
        ),
    },
    "screenshot-available": {
        "label": "📸 Screenshot captured",
        "risk": "low",
        "title": "Destination Screenshot",
        "body": (
            "A **headless browser screenshot** of the destination page was captured during analysis. "
            "Screenshots are taken using a local Playwright instance — the page is loaded in an "
            "isolated browser with no cookies or session data.\n\n"
            "Screenshots help identify:\n"
            "- Credential harvesting pages impersonating known brands\n"
            "- Fake login forms, CAPTCHA bypass lures, or tech support scams\n"
            "- Pages that appear blank to scanners but render content in a real browser\n\n"
            "The screenshot is shown in the panel above."
        ),
    },
}


def _render_url_finding_popovers(findings: list[str]) -> None:
    """Render each URL finding as a clickable popover button with a full explanation."""
    for finding_key in findings:
        detail = _URL_FINDING_DETAILS.get(finding_key)
        if detail:
            with st.popover(detail["label"], use_container_width=True):
                st.markdown(f"### {detail['title']}")
                st.markdown(detail["body"])
        else:
            # Unknown finding — plain field fallback
            _ei_field(finding_key, finding_key, "medium")


def _ei_detail_url(url: str, bundle: AnalysisBundle) -> None:
    st.subheader("URL detail")

    artifact = next((a for a in bundle.url_analysis_result.artifacts if a.original_url == url), None)

    _ei_field("Original URL", url)
    if artifact:
        if artifact.unwrapped_url:
            _ei_field("Unwrapped (tracking removed)", artifact.unwrapped_url, "medium")
        if artifact.final_url and artifact.final_url != url:
            _ei_field("Final destination", artifact.final_url, "medium")
        if artifact.display_text:
            dt_risk = "high" if _has_display_mismatch_str(artifact.display_text, url) else "normal"
            _ei_field("Display text", artifact.display_text, dt_risk)

        if artifact.redirect_chain:
            _ei_section(f"Redirect chain ({len(artifact.redirect_chain)} hops)")
            for i, hop in enumerate(artifact.redirect_chain[:8], 1):
                _ei_field(f"Hop {i}", hop)

        if artifact.findings:
            _ei_section("Findings — click any to learn more")
            _render_url_finding_popovers(artifact.findings)

        if artifact.screenshot_url:
            _ei_section("Screenshot")
            _render_screenshot(artifact.screenshot_url, url)

    url_recs = [r for r in bundle.enrichment_result.records if r.indicator_value == url]
    if url_recs:
        _ei_section("Reputation")
        for rec in url_recs:
            _ei_field(rec.provider, rec.summary, rec.severity)
            if rec.details.get("last_analysis_stats"):
                stats = rec.details["last_analysis_stats"]
                _ei_field("Malicious detections", str(stats.get("malicious", 0)), "high" if stats.get("malicious", 0) > 0 else "normal")
    else:
        st.info("No enrichment data for this URL. Enable external enrichment and re-run for VirusTotal results.")


def _ei_detail_attachment(filename: str, bundle: AnalysisBundle) -> None:
    st.subheader("Attachment detail")

    att = next((a for a in bundle.parsed_email.attachments if a.filename == filename), None)
    att_artifact = next((a for a in bundle.attachment_analysis_result.artifacts if a.filename == filename), None)

    _ei_field("Filename", filename)
    if att:
        if att.content_type:
            _ei_field("Content type", att.content_type)
        if att.size:
            _ei_field("Size", f"{att.size:,} bytes")
        if att.sha256:
            _ei_field("SHA-256", att.sha256)

    if att_artifact:
        _ei_section("Analysis")
        _ei_field("Severity", att_artifact.severity.upper(), att_artifact.severity)
        if att_artifact.extension:
            _ei_field("Extension", att_artifact.extension)
        if att_artifact.findings:
            for f in att_artifact.findings:
                _ei_field("Finding", f, "medium")
        else:
            st.info("No suspicious findings for this attachment.")

    att_scan = next((a for a in bundle.attachment_scan_result.artifacts if a.filename == filename), None)
    if att_scan and att_scan.findings:
        _ei_section("Local scanner results")
        for finding in att_scan.findings:
            _ei_field(finding.scanner, finding.summary, finding.severity)

    hash_val = att.sha256.lower() if att and att.sha256 else None
    hash_recs = [
        r for r in bundle.enrichment_result.records
        if r.indicator_type == "hash" and (not hash_val or r.indicator_value == hash_val)
    ]
    if hash_recs:
        _ei_section("Hash reputation")
        for rec in hash_recs:
            _ei_field(rec.provider, rec.summary, rec.severity)
    elif hash_val:
        st.info("No hash reputation data. Enable external enrichment and re-run for VirusTotal results.")


# ---------------------------------------------------------------------------
# Main entrypoint
# ---------------------------------------------------------------------------

_render_sidebar()
st.markdown(console_topbar(settings.app_name, settings.environment), unsafe_allow_html=True)

bundle = None
loaded_bundle = st.session_state.get("loaded_bundle")
if loaded_bundle:
    bundle = AnalysisBundle.model_validate(loaded_bundle)

fresh_bundle = _render_intake()
if fresh_bundle is not None:
    bundle = fresh_bundle

if bundle is None:
    st.markdown(
        empty_state_card(
            "No active investigation",
            "Load an email file or paste message content above to begin local analysis.",
        ),
        unsafe_allow_html=True,
    )
else:
    if bundle.warnings:
        for warning in bundle.warnings:
            st.warning(warning)
    _render_results(bundle)
