"""Reusable UI helpers for the Streamlit app."""

from __future__ import annotations

from html import escape


# ---------------------------------------------------------------------------
# CSS — clean light professional theme
# ---------------------------------------------------------------------------

APP_STYLES = """
<style>
  :root {
    --bg:            #f1f5f9;
    --panel:         #ffffff;
    --panel-2:       #f8fafc;
    --panel-muted:   #f1f5f9;
    --ink:           #1e293b;
    --muted:         #64748b;
    --line:          #e2e8f0;
    --line-strong:   #94a3b8;
    --accent:        #3b82f6;
    --accent-soft:   rgba(59,130,246,.1);
    --accent-2:      #10b981;
    --accent-2-soft: rgba(16,185,129,.1);
    --warn:          #f59e0b;
    --warn-soft:     rgba(245,158,11,.1);
    --danger:        #ef4444;
    --danger-soft:   rgba(239,68,68,.1);
    --ok:            #10b981;
    --ok-soft:       rgba(16,185,129,.1);
    --shadow:        0 1px 4px rgba(0,0,0,.07), 0 4px 16px rgba(0,0,0,.05);
    --shadow-sm:     0 1px 3px rgba(0,0,0,.06);
    --mono:          "SFMono-Regular","JetBrains Mono","Menlo","Consolas",monospace;
    --sans:          "Inter","Segoe UI","Helvetica Neue",sans-serif;
    --r:             8px;
    --r-lg:          12px;
    --r-pill:        999px;
  }

  html, body, [class*="css"] { font-family: var(--mono); }

  /* ── App shell ──────────────────────────────────────────────── */
  .stApp {
    background: var(--bg);
    color: var(--ink);
  }
  [data-testid="stAppViewContainer"] > .main { background: transparent; }

  [data-testid="stHeader"] {
    background: rgba(255,255,255,.95);
    border-bottom: 1px solid var(--line);
    backdrop-filter: blur(8px);
  }

  [data-testid="stSidebar"] {
    background: var(--panel);
    border-right: 1px solid var(--line);
  }
  [data-testid="stSidebar"] .stMarkdown { color: var(--ink); }

  .block-container {
    max-width: 1360px;
    padding-top: 1rem;
    padding-bottom: 3rem;
  }

  /* ── Topbar ─────────────────────────────────────────────────── */
  .console-topbar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 1rem;
    margin-bottom: 1rem;
    padding: 0.5rem 0;
    border-bottom: 1px solid var(--line);
  }
  .console-brand { display: flex; align-items: center; gap: 0.7rem; }
  .console-mark {
    width: 8px; height: 8px;
    border-radius: 50%;
    background: var(--accent);
    box-shadow: 0 0 0 3px rgba(59,130,246,.2);
    flex-shrink: 0;
    animation: pulse-dot 2.4s ease-in-out infinite;
  }
  @keyframes pulse-dot {
    0%,100% { box-shadow: 0 0 0 3px rgba(59,130,246,.2); }
    50%      { box-shadow: 0 0 0 5px rgba(59,130,246,.1); }
  }
  .console-eyebrow {
    font-size: 0.58rem;
    text-transform: uppercase;
    letter-spacing: 0.22em;
    color: var(--accent);
    font-family: var(--mono);
    margin-bottom: 0.08rem;
  }
  .console-title {
    color: var(--ink);
    font-size: 0.92rem;
    font-weight: 700;
    letter-spacing: 0.02em;
    font-family: var(--mono);
  }
  .console-runtime {
    border: 1px solid var(--line);
    background: var(--panel);
    border-radius: var(--r-pill);
    padding: 0.22rem 0.65rem;
    color: var(--muted);
    font-size: 0.68rem;
    font-family: var(--mono);
    font-weight: 600;
    letter-spacing: 0.06em;
  }

  /* ── Hero ────────────────────────────────────────────────────── */
  .hero {
    border: 1px solid var(--line);
    border-radius: var(--r-lg);
    padding: 1.1rem 1.25rem;
    background: var(--panel);
    box-shadow: var(--shadow);
    margin-bottom: 1rem;
  }
  .hero-kicker {
    font-size: 0.6rem;
    text-transform: uppercase;
    letter-spacing: 0.22em;
    color: var(--accent);
    font-family: var(--mono);
    margin-bottom: 0.25rem;
  }
  .hero-title {
    font-size: 1.15rem;
    font-weight: 700;
    color: var(--ink);
    margin: 0 0 0.35rem;
    max-width: 36ch;
    line-height: 1.3;
    font-family: var(--mono);
  }
  .hero-copy {
    color: var(--muted);
    max-width: 54rem;
    margin: 0;
    font-size: 0.85rem;
    line-height: 1.6;
  }
  .hero-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 0.7rem;
    margin-top: 0.8rem;
  }
  .panel {
    border: 1px solid var(--line);
    border-radius: var(--r);
    background: var(--panel-muted);
    padding: 0.7rem 0.85rem;
  }
  .panel-title {
    font-size: 0.62rem;
    text-transform: uppercase;
    letter-spacing: 0.16em;
    color: var(--accent);
    margin-bottom: 0.38rem;
    font-family: var(--mono);
    font-weight: 600;
  }
  .list-plain {
    margin: 0;
    padding-left: 1rem;
    color: var(--muted);
    line-height: 1.65;
    font-size: 0.85rem;
  }

  /* ── Section cards ──────────────────────────────────────────── */
  .section-card {
    border: 1px solid var(--line);
    border-radius: var(--r-lg);
    background: var(--panel);
    padding: 1rem 1.1rem;
    box-shadow: var(--shadow);
    margin-bottom: 1rem;
  }
  .section-card.compact { padding: 0.8rem 1rem; }
  .section-heading {
    font-size: 0.82rem;
    font-weight: 700;
    color: var(--ink);
    margin: 0 0 0.15rem;
    letter-spacing: 0.03em;
    font-family: var(--mono);
    text-transform: uppercase;
  }
  .section-copy {
    color: var(--muted);
    margin: 0 0 0.85rem;
    font-size: 0.84rem;
    line-height: 1.55;
  }
  .option-stack { display: grid; gap: 0.3rem; padding-top: 0.1rem; }
  .stack { display: grid; gap: 0.75rem; }

  /* ── Assessment / verdict block ─────────────────────────────── */
  .assessment {
    border: 1px solid var(--line);
    border-left: 4px solid var(--line-strong);
    border-radius: var(--r-lg);
    padding: 1rem 1.2rem;
    background: var(--panel);
    margin: 0 0 1rem;
    box-shadow: var(--shadow);
  }
  .assessment.verdict-benign   { border-left-color: var(--ok); }
  .assessment.verdict-suspicious { border-left-color: var(--warn); }
  .assessment.verdict-malicious  { border-left-color: var(--danger); }
  .assessment-label {
    font-size: 0.58rem;
    text-transform: uppercase;
    letter-spacing: 0.2em;
    color: var(--muted);
    font-family: var(--mono);
    margin-bottom: 0.28rem;
  }
  .assessment-title {
    font-size: 1.75rem;
    font-weight: 800;
    margin: 0.12rem 0 0.4rem;
    letter-spacing: 0.04em;
    line-height: 1;
    font-family: var(--mono);
  }
  .assessment-title.benign    { color: var(--ok); }
  .assessment-title.suspicious { color: var(--warn); }
  .assessment-title.malicious  { color: var(--danger); }
  .status-row {
    display: flex;
    flex-wrap: wrap;
    gap: 0.45rem;
    margin-bottom: 0.65rem;
  }
  .status-chip {
    display: inline-flex;
    align-items: center;
    gap: 0.3rem;
    padding: 0.24rem 0.58rem;
    border-radius: var(--r-pill);
    border: 1px solid var(--line);
    font-size: 0.68rem;
    color: var(--muted);
    background: var(--panel-muted);
    font-family: var(--mono);
    font-weight: 600;
    letter-spacing: 0.04em;
  }
  .status-chip .icon { color: var(--accent); font-size: 0.68rem; }
  .assessment-meta { color: var(--muted); line-height: 1.6; font-size: 0.85rem; }
  .assessment-meta strong { color: var(--ink); }
  .mini-note {
    border-left: 2px solid var(--accent);
    padding-left: 0.65rem;
    color: var(--muted);
    margin: 0.55rem 0 0;
    font-size: 0.85rem;
    line-height: 1.6;
  }

  /* ── Metric grid ─────────────────────────────────────────────── */
  .metric-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(145px, 1fr));
    gap: 0.6rem;
    margin-top: 0.85rem;
  }
  .metric-card {
    border: 1px solid var(--line);
    border-radius: var(--r);
    padding: 0.8rem 0.9rem;
    background: var(--panel-muted);
  }
  .metric-label {
    color: var(--muted);
    font-size: 0.6rem;
    text-transform: uppercase;
    letter-spacing: 0.16em;
    font-family: var(--mono);
    font-weight: 600;
  }
  .metric-value {
    color: var(--ink);
    font-size: 1.35rem;
    font-weight: 700;
    margin-top: 0.18rem;
    letter-spacing: 0.02em;
    font-family: var(--mono);
  }
  .metric-note { color: var(--muted); font-size: 0.75rem; margin-top: 0.22rem; line-height: 1.45; }

  /* ── Subtle grid / cards ─────────────────────────────────────── */
  .subtle-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 0.55rem;
    margin-bottom: 0.8rem;
  }
  .subtle-card {
    border: 1px solid var(--line);
    border-radius: var(--r);
    background: var(--panel-muted);
    padding: 0.72rem 0.85rem;
  }
  .subtle-label {
    color: var(--muted);
    font-size: 0.58rem;
    text-transform: uppercase;
    letter-spacing: 0.16em;
    margin-bottom: 0.22rem;
    font-family: var(--mono);
    font-weight: 600;
  }
  .subtle-value {
    color: var(--ink);
    font-size: 0.85rem;
    font-weight: 600;
    word-break: break-all;
    font-family: var(--mono);
  }

  /* ── Evidence / finding cards ────────────────────────────────── */
  .reference-shell { display: grid; gap: 0.75rem; margin-top: 0.3rem; }
  .evidence-card {
    border: 1px solid var(--line);
    border-left: 3px solid var(--line-strong);
    border-radius: var(--r);
    background: var(--panel);
    padding: 0.8rem 0.9rem;
  }
  .evidence-card.severity-high   { border-left-color: var(--danger); background: rgba(239,68,68,.03); }
  .evidence-card.severity-medium { border-left-color: var(--warn);   background: rgba(245,158,11,.03); }
  .evidence-card.severity-low, .evidence-card.severity-info { border-left-color: var(--accent-2); }
  .evidence-topline {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 0.65rem;
    margin-bottom: 0.35rem;
  }
  .evidence-title {
    font-weight: 700;
    color: var(--ink);
    font-size: 0.85rem;
    line-height: 1.35;
    font-family: var(--mono);
  }
  .evidence-meta  { color: var(--muted); font-size: 0.78rem; margin-bottom: 0.22rem; line-height: 1.45; }
  .evidence-desc  { color: var(--ink); font-size: 0.82rem; line-height: 1.55; }

  /* ── Badges ──────────────────────────────────────────────────── */
  .badge {
    display: inline-block;
    border-radius: var(--r-pill);
    padding: 0.18rem 0.48rem;
    font-size: 0.62rem;
    font-weight: 700;
    letter-spacing: 0.07em;
    border: 1px solid transparent;
    font-family: var(--mono);
    white-space: nowrap;
    flex-shrink: 0;
  }
  .badge-high   { color: var(--danger); background: var(--danger-soft); border-color: rgba(239,68,68,.3); }
  .badge-medium { color: #b45309;       background: var(--warn-soft);   border-color: rgba(245,158,11,.3); }
  .badge-low, .badge-info { color: var(--ok); background: var(--ok-soft); border-color: rgba(16,185,129,.3); }

  /* ── Chips / pills ───────────────────────────────────────────── */
  .chip-row { display: flex; gap: 0.4rem; flex-wrap: wrap; margin-top: 0.55rem; }
  .chip {
    display: inline-flex;
    align-items: center;
    border: 1px solid var(--line);
    border-radius: var(--r-pill);
    padding: 0.22rem 0.55rem;
    font-size: 0.7rem;
    color: var(--muted);
    background: var(--panel-muted);
    font-family: var(--mono);
  }
  .chip-local   { background: var(--accent-soft); border-color: rgba(59,130,246,.3); color: var(--accent); }
  .recipient-pill {
    display: inline-block;
    padding: 0.1rem 0.4rem;
    border-radius: var(--r-pill);
    border: 1px solid rgba(59,130,246,.3);
    background: var(--accent-soft);
    color: var(--accent);
    font-size: 0.68rem;
    margin-left: 0.35rem;
    font-family: var(--mono);
  }

  /* ── Risk dot ────────────────────────────────────────────────── */
  .risk-dot {
    display: inline-block;
    width: 0.5rem; height: 0.5rem;
    border-radius: 50%;
    margin-right: 0.35rem;
    vertical-align: middle;
    flex-shrink: 0;
  }
  .risk-dot.red   { background: var(--danger); }
  .risk-dot.amber { background: var(--warn); }
  .risk-dot.green { background: var(--ok); }

  /* ── Toolbar ─────────────────────────────────────────────────── */
  .toolbar { display: flex; justify-content: space-between; align-items: center; gap: 1rem; flex-wrap: wrap; }
  .toolbar-copy { color: var(--muted); font-size: 0.84rem; line-height: 1.5; }
  .toolbar-meta { display: flex; gap: 0.35rem; flex-wrap: wrap; }
  .meta-pill {
    display: inline-flex;
    align-items: center;
    padding: 0.2rem 0.5rem;
    border-radius: var(--r-pill);
    background: var(--panel-muted);
    border: 1px solid var(--line);
    color: var(--muted);
    font-size: 0.66rem;
    font-family: var(--mono);
    font-weight: 600;
    letter-spacing: 0.05em;
  }

  /* ── Trust banner ────────────────────────────────────────────── */
  .trust-banner {
    border: 1px solid rgba(16,185,129,.25);
    border-radius: var(--r);
    background: rgba(16,185,129,.06);
    padding: 0.72rem 0.9rem;
    color: var(--ink);
    font-size: 0.84rem;
    line-height: 1.6;
  }
  .trust-banner strong { color: var(--ok); }

  /* ── Empty state ─────────────────────────────────────────────── */
  .empty-state {
    border: 1px dashed var(--line-strong);
    border-radius: var(--r-lg);
    padding: 2rem 1.5rem;
    background: var(--panel);
    text-align: center;
  }
  .empty-title { color: var(--ink); font-size: 1rem; font-weight: 700; margin-bottom: 0.4rem; font-family: var(--mono); letter-spacing: 0.03em; }
  .empty-copy  { color: var(--muted); line-height: 1.6; font-size: 0.86rem; max-width: 52rem; margin: 0 auto; }

  /* ── Tabs ────────────────────────────────────────────────────── */
  .stTabs [data-baseweb="tab-list"] {
    gap: 0.2rem;
    background: transparent;
    padding: 0 0 0.4rem;
    margin-bottom: 0.75rem;
    border-bottom: 1px solid var(--line);
  }
  .stTabs [data-baseweb="tab-highlight"] { display: none !important; }
  .stTabs [data-baseweb="tab"] {
    height: auto;
    background: transparent;
    border: 1px solid transparent;
    border-radius: var(--r-pill);
    color: var(--muted);
    padding: 0.32rem 0.75rem;
    font-size: 0.8rem;
    font-weight: 500;
    font-family: var(--mono);
    letter-spacing: 0.03em;
  }
  .stTabs [aria-selected="true"] {
    background: var(--accent-soft);
    border-color: rgba(59,130,246,.3);
    color: var(--accent);
    font-weight: 700;
  }
  .stTabs [data-baseweb="tab"]:hover:not([aria-selected="true"]) {
    background: var(--panel-muted);
    color: var(--ink);
    border-color: var(--line);
  }

  /* ── Buttons ─────────────────────────────────────────────────── */
  .stButton button, .stDownloadButton button {
    border-radius: var(--r) !important;
    border: 1px solid var(--line) !important;
    background: var(--panel) !important;
    color: var(--ink) !important;
    font-weight: 600 !important;
    font-family: var(--mono) !important;
    font-size: 0.82rem !important;
    letter-spacing: 0.02em !important;
    transition: all 0.12s ease !important;
    box-shadow: var(--shadow-sm) !important;
  }
  .stButton button[kind="primary"] {
    background: var(--accent) !important;
    border-color: var(--accent) !important;
    color: #fff !important;
    box-shadow: 0 2px 8px rgba(59,130,246,.25) !important;
  }
  .stButton button:hover, .stDownloadButton button:hover {
    background: var(--panel-muted) !important;
    border-color: var(--line-strong) !important;
  }
  .stButton button[kind="primary"]:hover {
    background: #2563eb !important;
    box-shadow: 0 3px 12px rgba(59,130,246,.35) !important;
  }

  /* ── Form elements ───────────────────────────────────────────── */
  .stTextInput input,
  .stTextArea textarea,
  .stSelectbox div[data-baseweb="select"] > div,
  .stFileUploader section {
    background: var(--panel) !important;
    color: var(--ink) !important;
    border: 1px solid var(--line) !important;
    border-radius: var(--r) !important;
    font-family: var(--mono) !important;
  }
  .stTextInput input:focus,
  .stTextArea textarea:focus {
    border-color: var(--accent) !important;
    box-shadow: 0 0 0 2px rgba(59,130,246,.15) !important;
  }
  .stTextInput input::placeholder,
  .stTextArea textarea::placeholder { color: var(--muted) !important; opacity: 1 !important; }

  /* ── Data frames ─────────────────────────────────────────────── */
  [data-testid="stDataFrame"], .stDataFrame, [data-testid="stJson"] {
    border: 1px solid var(--line);
    border-radius: var(--r);
    overflow: hidden;
  }
  .stAlert {
    border-radius: var(--r) !important;
    border: 1px solid var(--line) !important;
  }

  /* ── Verdict bar (Phishtool-style) ───────────────────────────── */
  .vbar {
    display: flex;
    align-items: stretch;
    border: 1px solid var(--line);
    border-radius: var(--r-lg);
    background: var(--panel);
    box-shadow: var(--shadow);
    margin-bottom: 1rem;
    overflow: hidden;
  }
  .vbar-accent {
    width: 5px;
    flex-shrink: 0;
    border-radius: var(--r-lg) 0 0 var(--r-lg);
  }
  .vbar-accent.benign    { background: var(--ok); }
  .vbar-accent.suspicious { background: var(--warn); }
  .vbar-accent.malicious  { background: var(--danger); }
  .vbar-body {
    flex: 1;
    padding: 0.85rem 1.1rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 0.75rem;
  }
  .vbar-verdict {
    font-size: 1.5rem;
    font-weight: 800;
    font-family: var(--mono);
    letter-spacing: 0.04em;
    line-height: 1;
  }
  .vbar-verdict.benign    { color: var(--ok); }
  .vbar-verdict.suspicious { color: var(--warn); }
  .vbar-verdict.malicious  { color: var(--danger); }
  .vbar-label {
    font-size: 0.56rem;
    text-transform: uppercase;
    letter-spacing: 0.2em;
    color: var(--muted);
    font-family: var(--mono);
    margin-bottom: 0.2rem;
  }
  .vbar-subject {
    font-weight: 600;
    color: var(--ink);
    font-family: var(--mono);
    font-size: 0.88rem;
    margin-top: 0.2rem;
  }
  .vbar-meta {
    color: var(--muted);
    font-size: 0.76rem;
    font-family: var(--mono);
    margin-top: 0.06rem;
  }
  .vbar-summary {
    color: var(--muted);
    font-size: 0.82rem;
    line-height: 1.55;
    margin-top: 0.5rem;
    padding-top: 0.5rem;
    border-top: 1px solid var(--line);
    flex-basis: 100%;
  }
  .vbar-chips {
    display: flex;
    flex-wrap: wrap;
    gap: 0.35rem;
    align-items: flex-start;
  }
  .vbar-chip {
    padding: 0.2rem 0.55rem;
    border-radius: var(--r-pill);
    border: 1px solid var(--line);
    font-family: var(--mono);
    font-size: 0.66rem;
    font-weight: 600;
    letter-spacing: 0.04em;
    background: var(--panel-muted);
    color: var(--muted);
    white-space: nowrap;
  }
  .vbar-chip.danger  { background: var(--danger-soft); border-color: rgba(239,68,68,.3);  color: var(--danger); }
  .vbar-chip.warn    { background: var(--warn-soft);   border-color: rgba(245,158,11,.3); color: #b45309; }
  .vbar-chip.ok      { background: var(--ok-soft);     border-color: rgba(16,185,129,.3); color: var(--ok); }
  .vbar-chip.accent  { background: var(--accent-soft); border-color: rgba(59,130,246,.3); color: var(--accent); }

  /* ── Inspector field rows ────────────────────────────────────── */
  .ei-section {
    font-size: 0.6rem;
    text-transform: uppercase;
    letter-spacing: 0.18em;
    color: var(--accent);
    font-family: var(--mono);
    margin: 0.9rem 0 0.35rem;
    border-bottom: 1px solid var(--line);
    padding-bottom: 0.22rem;
  }
  .ei-field {
    margin-bottom: 0.5rem;
  }
  .ei-field-label {
    color: var(--muted);
    font-size: 0.62rem;
    font-family: var(--mono);
    text-transform: uppercase;
    letter-spacing: 0.1em;
    margin-bottom: 0.12rem;
  }
  .ei-field-value {
    font-family: var(--mono);
    font-size: 0.82rem;
    word-break: break-all;
    line-height: 1.45;
  }
  .ei-field-value.risk-high   { color: var(--danger); }
  .ei-field-value.risk-medium { color: #b45309; }
  .ei-field-value.risk-low    { color: var(--ok); }
  .ei-field-value.risk-normal { color: var(--ink); }

  /* ── Auth badge row ──────────────────────────────────────────── */
  .auth-row { display: flex; gap: 0.6rem; flex-wrap: wrap; margin: 0.3rem 0 0.6rem; }
  .auth-badge {
    display: inline-flex;
    align-items: center;
    gap: 0.28rem;
    padding: 0.28rem 0.65rem;
    border-radius: var(--r-pill);
    font-family: var(--mono);
    font-size: 0.72rem;
    font-weight: 700;
    border: 1px solid transparent;
  }
  .auth-badge.pass   { background: var(--ok-soft);     border-color: rgba(16,185,129,.3);  color: var(--ok); }
  .auth-badge.fail   { background: var(--danger-soft); border-color: rgba(239,68,68,.3);   color: var(--danger); }
  .auth-badge.warn   { background: var(--warn-soft);   border-color: rgba(245,158,11,.3);  color: #b45309; }
  .auth-badge.unknown{ background: var(--panel-muted); border-color: var(--line);           color: var(--muted); }

  /* ── Responsive ──────────────────────────────────────────────── */
  @media (max-width: 980px) {
    .hero-grid, .metric-grid { grid-template-columns: 1fr 1fr; }
    .vbar-body { flex-direction: column; align-items: flex-start; }
  }
  @media (max-width: 680px) {
    .hero, .section-card, .assessment { padding: 0.8rem; border-radius: var(--r); }
    .hero-title { font-size: 1rem; }
    .hero-grid, .metric-grid, .subtle-grid { grid-template-columns: 1fr; }
  }
</style>
<div style="display:none" class="sentinel-shell"></div>
"""


# ---------------------------------------------------------------------------
# CSS fish animation — ocean progress panel (pure CSS, no JS required)
# ---------------------------------------------------------------------------
# Uses __TITLE__, __STEP__, __STAGE__, __PCT__ as substitution placeholders.
# Deliberately keeps its own dark ocean look — it's a loading overlay.

_FISH_HTML = """
<div class="fo-wrap">
  <div class="fo-hdr">
    <span class="fo-title">__TITLE__</span>
    <span class="fo-step">__STEP__</span>
  </div>
  <div class="fo-ocean">
    <div class="fo-floor"></div>
    <div class="fo-sw" style="--d:0s;--x:6%">🌿</div>
    <div class="fo-sw" style="--d:.5s;--x:16%">🌿</div>
    <div class="fo-sw" style="--d:.9s;--x:27%">🌿</div>
    <div class="fo-sw" style="--d:.3s;--x:39%">🌿</div>
    <div class="fo-sw" style="--d:1.2s;--x:52%">🌿</div>
    <div class="fo-sw" style="--d:.7s;--x:64%">🌿</div>
    <div class="fo-sw" style="--d:1.5s;--x:76%">🌿</div>
    <div class="fo-sw" style="--d:.2s;--x:88%">🌿</div>
    <div class="fo-sw" style="--d:1.0s;--x:96%">🌿</div>
    <div class="fo-bub" style="--d:0s;--x:10%"></div>
    <div class="fo-bub" style="--d:1.1s;--x:24%"></div>
    <div class="fo-bub" style="--d:2.3s;--x:37%"></div>
    <div class="fo-bub" style="--d:.6s;--x:51%"></div>
    <div class="fo-bub" style="--d:1.8s;--x:67%"></div>
    <div class="fo-bub" style="--d:3.1s;--x:80%"></div>
    <div class="fo-bub" style="--d:.4s;--x:91%"></div>
    <div class="fo-fish">🐠</div>
  </div>
  <div class="fo-stage">&gt;&nbsp;__STAGE__</div>
  <div class="fo-bar-bg"><div class="fo-bar" style="width:max(__PCT__%, 2%)"></div></div>
</div>

<style>
  .fo-wrap {
    border: 1px solid #1a4060;
    border-radius: 14px;
    background: #040c14;
    padding: 0.7rem 0.9rem 0.55rem;
    margin: 0.5rem 0 1rem;
    overflow: hidden;
  }
  .fo-hdr {
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    margin-bottom: 0.35rem;
  }
  .fo-title {
    font-family: monospace;
    font-size: 0.78rem;
    font-weight: 700;
    color: #00c8ff;
    letter-spacing: 0.08em;
    text-transform: uppercase;
  }
  .fo-step {
    font-family: monospace;
    font-size: 0.68rem;
    color: #3a7090;
    letter-spacing: 0.06em;
  }
  .fo-ocean {
    position: relative;
    height: 90px;
    overflow: hidden;
    background: linear-gradient(180deg, #020810 0%, #030d1a 100%);
    border-radius: 8px;
    border: 1px solid #0a1f35;
  }
  .fo-floor {
    position: absolute;
    bottom: 0; left: 0; right: 0;
    height: 13px;
    background: linear-gradient(#081828, #030c18);
    border-top: 1px solid #0d2540;
  }
  .fo-sw {
    position: absolute;
    bottom: 11px;
    left: var(--x, 10%);
    font-size: 1.05rem;
    line-height: 1;
    transform-origin: bottom center;
    filter: hue-rotate(15deg) saturate(0.75) brightness(0.65);
    animation: fo-sway 11s ease-in-out var(--d, 0s) infinite;
  }
  @keyframes fo-sway {
    0%, 100% { transform: rotate(-13deg) scaleX(0.88); }
    50%       { transform: rotate(13deg) scaleX(1.12); }
  }
  .fo-bub {
    position: absolute;
    bottom: 13px;
    left: var(--x, 20%);
    width: 5px;
    height: 5px;
    border-radius: 50%;
    border: 1px solid rgba(80,200,255,0.45);
    animation: fo-rise 16s linear var(--d, 0s) infinite;
  }
  @keyframes fo-rise {
    0%   { bottom: 13px; opacity: 0.7; transform: translateX(0); }
    40%  { transform: translateX(3px); }
    80%  { transform: translateX(-2px); }
    100% { bottom: 90px; opacity: 0; transform: translateX(1px); }
  }
  .fo-fish {
    position: absolute;
    top: 50%;
    font-size: 1.6rem;
    line-height: 1;
    transform: translateY(-55%) scaleX(-1);
    filter: drop-shadow(0 0 5px rgba(0,180,255,0.35));
    animation: fo-swim 19s linear infinite, fo-bob 7s ease-in-out infinite;
  }
  @keyframes fo-swim {
    0%   { left: -8%; }
    100% { left: 108%; }
  }
  @keyframes fo-bob {
    0%, 100% { margin-top: 0px; }
    50%       { margin-top: -7px; }
  }
  .fo-stage {
    font-family: monospace;
    font-size: 0.73rem;
    color: #00d68f;
    margin-top: 0.35rem;
    letter-spacing: 0.06em;
  }
  .fo-bar-bg {
    height: 4px;
    background: rgba(0,40,70,0.7);
    border-radius: 2px;
    margin-top: 0.42rem;
    overflow: hidden;
  }
  .fo-bar {
    height: 4px;
    background: linear-gradient(90deg, #0070b0, #00a8d0, #00d090);
    border-radius: 2px;
    box-shadow: 0 0 8px rgba(0,200,180,0.5);
    transition: width 0.4s ease;
  }
</style>
"""


def fish_progress_panel(
    title: str,
    subtitle: str,
    stages: list[tuple[str, str]],
    current_stage: str | None,
) -> str:
    """Return the ocean animation HTML for the progress panel."""
    stage_ids = [s[0] for s in stages]
    ci = stage_ids.index(current_stage) if current_stage in stage_ids else 0
    label = next((lbl for sid, lbl in stages if sid == current_stage), "Initializing...")
    pct = int((ci / max(len(stages), 1)) * 100)
    step = f"Step {ci + 1} of {len(stages)}"

    return (
        _FISH_HTML
        .replace("__TITLE__", escape(title))
        .replace("__STEP__", escape(step))
        .replace("__STAGE__", escape(label))
        .replace("__PCT__", str(pct))
    )


# ---------------------------------------------------------------------------
# Component helpers
# ---------------------------------------------------------------------------

def format_alignment(value: bool | None) -> str:
    if value is True:
        return "aligned"
    if value is False:
        return "misaligned"
    return "unknown"


def badge_class(value: str) -> str:
    normalized = value.lower().replace(" ", "_")
    if normalized in {"high", "malicious"}:
        return "badge badge-high"
    if normalized in {"medium", "suspicious"}:
        return "badge badge-medium"
    return "badge badge-low"


def subtle_card(label: str, value: str) -> str:
    return (
        "<div class='subtle-card'>"
        f"<div class='subtle-label'>{escape(label)}</div>"
        f"<div class='subtle-value'>{escape(value)}</div>"
        "</div>"
    )


def console_topbar(app_name: str, environment: str) -> str:
    return (
        "<div class='console-topbar'>"
        "<div class='console-brand'>"
        "<span class='console-mark'></span>"
        "<div>"
        "<div class='console-eyebrow'>Local Investigation Console</div>"
        f"<div class='console-title'>{escape(app_name)}</div>"
        "</div>"
        "</div>"
        f"<div class='console-runtime'>{escape(environment.upper())} &nbsp;&middot;&nbsp; LOCAL-FIRST</div>"
        "</div>"
    )


def empty_state_card(title: str, copy: str) -> str:
    return (
        "<div class='empty-state'>"
        f"<div class='empty-title'>{escape(title)}</div>"
        f"<div class='empty-copy'>{escape(copy)}</div>"
        "</div>"
    )


def risk_dot_html(level: str) -> str:
    normalized = level.lower()
    if normalized in {"high", "red", "danger"}:
        css_class = "red"
    elif normalized in {"medium", "amber", "warning"}:
        css_class = "amber"
    else:
        css_class = "green"
    return f"<span class='risk-dot {css_class}'></span>"


def finding_card(title: str, severity: str, rule_id: str, score_delta: int, description: str) -> str:
    sev_class = severity.lower()
    return (
        f"<div class='evidence-card severity-{sev_class}'>"
        "<div class='evidence-topline'>"
        f"<div class='evidence-title'>{escape(title)}</div>"
        f"<span class='{badge_class(severity)}'>{severity.upper()}</span>"
        "</div>"
        f"<div class='evidence-meta'>{escape(rule_id)} &nbsp;&middot;&nbsp; score +{score_delta}</div>"
        f"<div class='evidence-desc'>{escape(description)}</div>"
        "</div>"
    )


def artifact_card(title: str, severity: str, rows: list[tuple[str, str]]) -> str:
    sev_class = severity.lower()
    body = "".join(
        f"<div class='evidence-meta'><strong>{escape(label)}:</strong> {escape(value)}</div>"
        for label, value in rows
    )
    return (
        f"<div class='evidence-card severity-{sev_class}'>"
        "<div class='evidence-topline'>"
        f"<div class='evidence-title'>{escape(title)}</div>"
        f"<span class='{badge_class(severity)}'>{severity.upper()}</span>"
        "</div>"
        f"{body}"
        "</div>"
    )


def progress_panel(
    title: str,
    subtitle: str,
    stages: list[tuple[str, str]],
    current_stage: str | None,
) -> str:
    """Legacy text progress panel — kept for compatibility, delegates to fish animation."""
    return fish_progress_panel(title, subtitle, stages, current_stage)


def verdict_icon(verdict: str) -> str:
    normalized = verdict.lower()
    if normalized == "malicious":
        return "&#x26A0;"
    if normalized == "suspicious":
        return "&#x2753;"
    return "&#x2713;"


def disposition_icon(disposition: str) -> str:
    normalized = disposition.lower()
    mapping = {
        "benign": "&#x2713;",
        "spam": "SP",
        "phishing": "PH",
        "malware_delivery": "MW",
        "bec": "BC",
        "needs_escalation": "&#x25B2;",
    }
    return mapping.get(normalized, "&middot;")
