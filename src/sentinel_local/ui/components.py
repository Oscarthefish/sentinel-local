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
    --panel-muted:   #f8fafc;
    --ink:           #0f172a;
    --muted:         #64748b;
    --muted-2:       #94a3b8;
    --line:          #e2e8f0;
    --line-strong:   #cbd5e1;
    --accent:        #2563eb;
    --accent-soft:   rgba(37,99,235,.08);
    --accent-2:      #10b981;
    --accent-2-soft: rgba(16,185,129,.1);
    --warn:          #d97706;
    --warn-soft:     rgba(217,119,6,.08);
    --danger:        #dc2626;
    --danger-soft:   rgba(220,38,38,.08);
    --ok:            #059669;
    --ok-soft:       rgba(5,150,105,.08);
    --shadow:        0 1px 3px rgba(0,0,0,.07), 0 4px 16px rgba(0,0,0,.06);
    --shadow-sm:     0 1px 2px rgba(0,0,0,.05);
    --shadow-lg:     0 4px 24px rgba(0,0,0,.12), 0 1px 3px rgba(0,0,0,.06);
    --mono:          "SFMono-Regular","JetBrains Mono","Menlo","Consolas",monospace;
    --sans:          -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
    --r:             8px;
    --r-lg:          12px;
    --r-pill:        999px;
  }

  /* Sans-serif for everything — mono reserved for data values */
  html, body, [class*="css"] { font-family: var(--sans); }

  /* ── App shell ──────────────────────────────────────────────── */
  .stApp { background: var(--bg); color: var(--ink); }
  [data-testid="stAppViewContainer"] > .main { background: transparent; }
  [data-testid="stHeader"] { display: none !important; }

  /* ── Sidebar — dark ─────────────────────────────────────────── */
  [data-testid="stSidebar"] { background: #0f172a !important; border-right: 1px solid rgba(255,255,255,.06) !important; }
  [data-testid="stSidebar"] > div { background: #0f172a !important; }

  [data-testid="stSidebar"] p,
  [data-testid="stSidebar"] .stMarkdown,
  [data-testid="stSidebar"] label,
  [data-testid="stSidebar"] .stCaption,
  [data-testid="stSidebar"] small { color: #64748b !important; }
  [data-testid="stSidebar"] h1,
  [data-testid="stSidebar"] h2,
  [data-testid="stSidebar"] h3,
  [data-testid="stSidebar"] strong,
  [data-testid="stSidebar"] b { color: #e2e8f0 !important; }

  [data-testid="stSidebar"] input,
  [data-testid="stSidebar"] textarea {
    background: rgba(255,255,255,.06) !important;
    border: 1px solid rgba(255,255,255,.1) !important;
    color: #e2e8f0 !important;
  }
  [data-testid="stSidebar"] [data-baseweb="select"] > div:first-child {
    background: rgba(255,255,255,.06) !important;
    border: 1px solid rgba(255,255,255,.1) !important;
    color: #e2e8f0 !important;
  }
  [data-testid="stSidebar"] .stButton button {
    background: rgba(255,255,255,.07) !important;
    border: 1px solid rgba(255,255,255,.1) !important;
    color: #cbd5e1 !important;
    box-shadow: none !important;
    font-family: var(--sans) !important;
  }
  [data-testid="stSidebar"] .stButton button:hover {
    background: rgba(255,255,255,.12) !important;
    border-color: rgba(255,255,255,.18) !important;
  }
  [data-testid="stSidebar"] details,
  [data-testid="stSidebar"] [data-testid="stExpander"] {
    border: 1px solid rgba(255,255,255,.07) !important;
    border-radius: var(--r) !important;
    background: rgba(255,255,255,.02) !important;
  }
  [data-testid="stSidebar"] summary { color: #94a3b8 !important; }
  [data-testid="stSidebar"] hr { border-color: rgba(255,255,255,.07) !important; }

  .block-container {
    max-width: 1440px;
    padding-top: 0 !important;
    padding-bottom: 3rem;
  }

  /* ── App header ─────────────────────────────────────────────── */
  .app-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    background: #0f172a;
    border-radius: var(--r-lg);
    padding: 0.85rem 1.25rem;
    margin-bottom: 1.5rem;
    border: 1px solid rgba(255,255,255,.06);
    box-shadow: var(--shadow-lg);
  }
  .app-header-left { display: flex; align-items: center; gap: 0.9rem; }
  .app-header-mark {
    width: 34px; height: 34px;
    border-radius: var(--r);
    background: var(--accent);
    display: flex; align-items: center; justify-content: center;
    font-family: var(--mono);
    font-weight: 800;
    font-size: 0.68rem;
    color: #fff;
    letter-spacing: -0.03em;
    flex-shrink: 0;
  }
  .app-header-name {
    font-size: 0.94rem;
    font-weight: 700;
    color: #f1f5f9;
    letter-spacing: 0.01em;
    line-height: 1.2;
  }
  .app-header-tagline {
    font-size: 0.7rem;
    color: #475569;
    margin-top: 0.1rem;
    letter-spacing: 0.01em;
  }
  .app-header-right { display: flex; align-items: center; gap: 0.6rem; }
  .app-env-badge {
    display: inline-block;
    background: rgba(37,99,235,.15);
    color: #93c5fd;
    border: 1px solid rgba(37,99,235,.25);
    border-radius: var(--r);
    padding: 0.2rem 0.6rem;
    font-family: var(--mono);
    font-size: 0.63rem;
    font-weight: 700;
    letter-spacing: 0.1em;
  }
  .app-header-sep { width: 1px; height: 16px; background: rgba(255,255,255,.1); }
  .app-local-tag {
    color: #334155;
    font-size: 0.63rem;
    font-family: var(--mono);
    font-weight: 600;
    letter-spacing: 0.1em;
  }

  /* ── Section cards ──────────────────────────────────────────── */
  .section-card {
    border: 1px solid var(--line);
    border-radius: var(--r-lg);
    background: var(--panel);
    padding: 1.25rem 1.4rem;
    box-shadow: var(--shadow);
    margin-bottom: 1rem;
  }
  .section-card.compact { padding: 1rem 1.2rem; }
  .section-heading {
    font-size: 0.8rem;
    font-weight: 700;
    color: var(--ink);
    margin: 0 0 0.25rem;
    letter-spacing: 0.02em;
    text-transform: uppercase;
  }
  .section-copy {
    color: var(--muted);
    margin: 0 0 1rem;
    font-size: 0.875rem;
    line-height: 1.6;
  }
  .option-stack { display: grid; gap: 0.35rem; padding-top: 0.1rem; }
  .stack { display: grid; gap: 0.75rem; }

  /* ── Subtle grid / cards ─────────────────────────────────────── */
  .subtle-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 0.65rem;
    margin-bottom: 1rem;
  }
  .subtle-card {
    border: 1px solid var(--line);
    border-radius: var(--r);
    background: var(--panel-muted);
    padding: 0.85rem 1rem;
  }
  .subtle-label {
    color: var(--muted);
    font-size: 0.65rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-bottom: 0.28rem;
    font-weight: 600;
  }
  .subtle-value {
    color: var(--ink);
    font-size: 1rem;
    font-weight: 700;
    font-family: var(--mono);
  }

  /* ── Evidence / finding cards ────────────────────────────────── */
  .reference-shell { display: grid; gap: 0.75rem; margin-top: 0.3rem; }
  .evidence-card {
    border: 1px solid var(--line);
    border-left: 3px solid var(--line-strong);
    border-radius: var(--r);
    background: var(--panel);
    padding: 0.9rem 1rem;
  }
  .evidence-card.severity-high   { border-left-color: var(--danger); background: rgba(220,38,38,.02); }
  .evidence-card.severity-medium { border-left-color: var(--warn);   background: rgba(217,119,6,.02); }
  .evidence-card.severity-low, .evidence-card.severity-info { border-left-color: var(--accent-2); }
  .evidence-topline {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 0.65rem;
    margin-bottom: 0.4rem;
  }
  .evidence-title {
    font-weight: 700;
    color: var(--ink);
    font-size: 0.875rem;
    line-height: 1.35;
  }
  .evidence-meta  { color: var(--muted); font-size: 0.75rem; margin-bottom: 0.25rem; line-height: 1.4; font-family: var(--mono); }
  .evidence-desc  { color: var(--muted); font-size: 0.84rem; line-height: 1.6; }

  /* ── Badges ──────────────────────────────────────────────────── */
  .badge {
    display: inline-block;
    border-radius: 4px;
    padding: 0.2rem 0.5rem;
    font-size: 0.62rem;
    font-weight: 700;
    letter-spacing: 0.08em;
    border: 1px solid transparent;
    font-family: var(--mono);
    white-space: nowrap;
    flex-shrink: 0;
  }
  .badge-high   { color: var(--danger); background: var(--danger-soft); border-color: rgba(220,38,38,.25); }
  .badge-medium { color: #92400e;       background: var(--warn-soft);   border-color: rgba(217,119,6,.25); }
  .badge-low, .badge-info { color: var(--ok); background: var(--ok-soft); border-color: rgba(5,150,105,.25); }

  /* ── Risk dot ────────────────────────────────────────────────── */
  .risk-dot {
    display: inline-block;
    width: 6px; height: 6px;
    border-radius: 50%;
    margin-right: 0.35rem;
    vertical-align: middle;
    flex-shrink: 0;
  }
  .risk-dot.red   { background: var(--danger); }
  .risk-dot.amber { background: var(--warn); }
  .risk-dot.green { background: var(--ok); }

  /* ── Empty state ─────────────────────────────────────────────── */
  .empty-state {
    border: 2px dashed var(--line);
    border-radius: var(--r-lg);
    padding: 4rem 2rem;
    background: var(--panel);
    text-align: center;
  }
  .empty-icon { font-size: 1.75rem; margin-bottom: 1rem; opacity: 0.35; display: block; }
  .empty-title { color: var(--ink); font-size: 1.05rem; font-weight: 700; margin-bottom: 0.5rem; letter-spacing: 0.01em; }
  .empty-copy  { color: var(--muted); line-height: 1.65; font-size: 0.875rem; max-width: 40ch; margin: 0 auto; }

  /* ── Tabs ────────────────────────────────────────────────────── */
  .stTabs [data-baseweb="tab-list"] {
    gap: 0;
    background: transparent;
    padding: 0;
    margin-bottom: 1rem;
    border-bottom: 2px solid var(--line);
  }
  .stTabs [data-baseweb="tab-highlight"] { display: none !important; }
  .stTabs [data-baseweb="tab"] {
    height: auto;
    background: transparent;
    border: none;
    border-bottom: 2px solid transparent;
    margin-bottom: -2px;
    border-radius: 0;
    color: var(--muted);
    padding: 0.5rem 0.9rem;
    font-size: 0.82rem;
    font-weight: 500;
    font-family: var(--sans);
    letter-spacing: 0.01em;
  }
  .stTabs [aria-selected="true"] {
    color: var(--accent);
    border-bottom-color: var(--accent);
    color: var(--accent);
    font-weight: 700;
  }
  .stTabs [data-baseweb="tab"]:hover:not([aria-selected="true"]) {
    color: var(--ink);
    background: transparent;
  }

  /* ── Buttons ─────────────────────────────────────────────────── */
  .stButton button, .stDownloadButton button {
    border-radius: var(--r) !important;
    border: 1px solid var(--line) !important;
    background: var(--panel) !important;
    color: var(--ink) !important;
    font-weight: 600 !important;
    font-family: var(--sans) !important;
    font-size: 0.84rem !important;
    letter-spacing: 0.01em !important;
    transition: all 0.12s ease !important;
    box-shadow: var(--shadow-sm) !important;
  }
  .stButton button[kind="primary"] {
    background: var(--accent) !important;
    border-color: var(--accent) !important;
    color: #fff !important;
    box-shadow: 0 2px 8px rgba(37,99,235,.3) !important;
  }
  .stButton button:hover, .stDownloadButton button:hover {
    background: var(--panel-muted) !important;
    border-color: var(--line-strong) !important;
  }
  .stButton button[kind="primary"]:hover {
    background: #1d4ed8 !important;
    box-shadow: 0 3px 12px rgba(37,99,235,.4) !important;
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
    font-family: var(--sans) !important;
  }
  .stTextInput input:focus,
  .stTextArea textarea:focus {
    border-color: var(--accent) !important;
    box-shadow: 0 0 0 3px rgba(37,99,235,.1) !important;
  }
  .stTextInput input::placeholder,
  .stTextArea textarea::placeholder { color: var(--muted-2) !important; opacity: 1 !important; }

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

  /* ── Verdict bar ────────────────────────────────────────────── */
  .vbar {
    display: flex;
    align-items: stretch;
    border: 1px solid var(--line);
    border-radius: var(--r-lg);
    background: var(--panel);
    box-shadow: var(--shadow-lg);
    margin-bottom: 1.25rem;
    overflow: hidden;
  }
  .vbar-accent {
    width: 6px;
    flex-shrink: 0;
  }
  .vbar-accent.benign    { background: var(--ok); }
  .vbar-accent.suspicious { background: var(--warn); }
  .vbar-accent.malicious  { background: var(--danger); }
  .vbar-body {
    flex: 1;
    padding: 1rem 1.35rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 0.75rem;
  }
  .vbar-verdict {
    font-size: 1.75rem;
    font-weight: 800;
    font-family: var(--mono);
    letter-spacing: 0.05em;
    line-height: 1;
  }
  .vbar-verdict.benign    { color: var(--ok); }
  .vbar-verdict.suspicious { color: var(--warn); }
  .vbar-verdict.malicious  { color: var(--danger); }
  .vbar-label {
    font-size: 0.6rem;
    text-transform: uppercase;
    letter-spacing: 0.16em;
    color: var(--muted);
    font-weight: 600;
    margin-bottom: 0.22rem;
  }
  .vbar-subject {
    font-weight: 600;
    color: var(--ink);
    font-size: 0.9rem;
    margin-top: 0.22rem;
  }
  .vbar-meta {
    color: var(--muted);
    font-size: 0.78rem;
    font-family: var(--mono);
    margin-top: 0.08rem;
  }
  .vbar-summary {
    color: var(--muted);
    font-size: 0.85rem;
    line-height: 1.65;
    margin-top: 0.6rem;
    padding-top: 0.7rem;
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
    padding: 0.22rem 0.6rem;
    border-radius: 4px;
    border: 1px solid var(--line);
    font-family: var(--mono);
    font-size: 0.64rem;
    font-weight: 700;
    letter-spacing: 0.05em;
    background: var(--panel-muted);
    color: var(--muted);
    white-space: nowrap;
  }
  .vbar-chip.danger  { background: var(--danger-soft); border-color: rgba(220,38,38,.25);  color: var(--danger); }
  .vbar-chip.warn    { background: var(--warn-soft);   border-color: rgba(217,119,6,.25);  color: var(--warn); }
  .vbar-chip.ok      { background: var(--ok-soft);     border-color: rgba(5,150,105,.25);  color: var(--ok); }
  .vbar-chip.accent  { background: var(--accent-soft); border-color: rgba(37,99,235,.25);  color: var(--accent); }

  /* ── Inspector field rows ────────────────────────────────────── */
  .ei-section {
    font-size: 0.62rem;
    text-transform: uppercase;
    letter-spacing: 0.12em;
    color: var(--muted);
    font-weight: 700;
    margin: 1rem 0 0.4rem;
    border-bottom: 1px solid var(--line);
    padding-bottom: 0.22rem;
  }
  .ei-field {
    margin-bottom: 0.5rem;
  }
  .ei-field-label {
    color: var(--muted);
    font-size: 0.65rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    font-weight: 600;
    margin-bottom: 0.14rem;
  }
  .ei-field-value {
    font-family: var(--mono);
    font-size: 0.82rem;
    word-break: break-all;
    line-height: 1.5;
  }
  .ei-field-value.risk-high   { color: var(--danger); }
  .ei-field-value.risk-medium { color: var(--warn); }
  .ei-field-value.risk-low    { color: var(--ok); }
  .ei-field-value.risk-normal { color: var(--ink); }

  /* ── Responsive ──────────────────────────────────────────────── */
  @media (max-width: 980px) {
    .vbar-body { flex-direction: column; align-items: flex-start; }
    .app-header { padding: 0.75rem 1rem; }
  }
  @media (max-width: 680px) {
    .section-card { padding: 1rem; border-radius: var(--r); }
    .subtle-grid { grid-template-columns: 1fr; }
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
        "<div class='app-header'>"
        "<div class='app-header-left'>"
        "<div class='app-header-mark'>SL</div>"
        "<div>"
        f"<div class='app-header-name'>{escape(app_name)}</div>"
        "<div class='app-header-tagline'>Email triage console</div>"
        "</div>"
        "</div>"
        "<div class='app-header-right'>"
        f"<span class='app-env-badge'>{escape(environment.upper())}</span>"
        "<span class='app-header-sep'></span>"
        "<span class='app-local-tag'>LOCAL&#x2011;FIRST</span>"
        "</div>"
        "</div>"
    )


def empty_state_card(title: str, copy: str) -> str:
    return (
        "<div class='empty-state'>"
        "<span class='empty-icon'>&#9903;</span>"
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
