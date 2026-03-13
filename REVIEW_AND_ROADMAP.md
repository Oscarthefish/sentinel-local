# Sentinel Local Review And Roadmap

## What The Project Currently Does

Sentinel Local is already a working local-first suspicious email triage tool rather than a blank scaffold.

Current implemented capabilities:

- Input handling
  - `.eml`
  - `.msg`
  - `.txt`
  - pasted raw content
- Parsing
  - sender
  - recipients
  - subject
  - dates
  - headers
  - body text / HTML
  - attachment metadata
- IOC extraction
  - URLs
  - domains
  - IPs
  - email addresses
  - hashes already present in content
  - attachment names / extensions
- Deterministic analysis
  - SPF / DKIM / DMARC fail and weak-auth checks if present in headers
  - Reply-To mismatch
  - Return-Path mismatch
  - display-name impersonation
  - suspicious `Received` chain signals
  - phishing lure language
  - lure-plus-link scoring
  - risky attachment extension scoring
- URL analysis
  - tracking-wrapper unwrapping
  - shortener identification
  - anchor-text vs destination mismatch
  - optional redirect resolution
  - HTML artifact detection for hidden elements, forms, scripts, and `javascript:` links
  - optional screenshot URL generation
- Attachment analysis
  - risky extension detection
  - archive flags
  - macro-capable file flags
  - lure-style filenames
  - MIME / extension mismatch detection
  - hash-available flag
- Enrichment
  - VirusTotal for URL / domain / IP / hash
  - AbuseIPDB for IP
  - privacy guard: recipient emails and recipient domains are not externally enriched
  - attachment hash enrichment when SHA-256 is available
- Local LLM support
  - Ollama or LM Studio compatible
  - limited to summary / rationale / recommendations
  - does not replace deterministic verdicting
- Reports and workflow
  - Streamlit analyst UI
  - SQLite-backed saved cases
  - markdown and HTML reports
  - JSON export

## What Is Good

- The architecture is modular enough to extend without rewriting.
- Deterministic logic is correctly treated as the source of truth.
- Optional features fail open instead of breaking core analysis.
- Privacy direction is mostly right for a solo SOC analyst.
- The project already supports real analyst tasks, not just a toy demo.
- Tests are broad and currently passing.

## What Is Weak Or Missing

- README is out of date and understates what the tool can do.
- Attachment hashing is not consistently computed during parsing yet.
- Header analysis is useful but still not full mail-flow analysis.
- No local AV / YARA scanning yet.
- No timeline / structured chronology view yet.
- No explicit disposition taxonomy beyond benign / suspicious / malicious.
- URL screenshot support is only URL generation today, not stored capture results.
- No safe local redirect/body-fetch caching.
- No message-id, originating IP, or mail path normalization layer exposed as first-class objects.
- Case management is still basic: no tagging, state, or filtering.

## What Is Overly Complex Right Now

- The Streamlit UI carries a lot of orchestration detail directly in one file.
- There are several parallel analysis result types, but the current project still lacks a single normalized “investigation findings” layer for cross-cutting reporting.
- Some optional stages are beginning to overlap conceptually:
  - URL analysis
  - enrichment
  - screenshot generation

These should stay separate, but they may need a more explicit investigation pipeline abstraction later.

## What Should Not Be Changed Yet

- Do not replace Streamlit yet.
- Do not move verdicting to the LLM.
- Do not add automatic file submission to public services.
- Do not jump into expensive sandboxing or detonation first.
- Do not rebuild the data model from scratch.

## Recommended Real-World SOC Analyst Workflow

1. Validate source and context
   - Why did the user receive it
   - Expected sender or not
   - Internal thread or external unsolicited message

2. Parse and normalize the message
   - sender
   - recipients
   - subject
   - headers
   - body
   - attachments

3. Analyze sender authenticity and mail flow
   - From / Reply-To / Return-Path alignment
   - SPF / DKIM / DMARC if present
   - display-name deception
   - Received chain anomalies
   - Message-ID and relay context

4. Inspect URLs and HTML
   - extract all URLs
   - unwrap tracking links
   - resolve shorteners and redirects when safe
   - compare visible destination vs actual href
   - detect forms, scripts, hidden elements, JavaScript links

5. Inspect attachments
   - metadata
   - hash
   - risky extension / MIME mismatch
   - lure naming
   - local AV / YARA if available

6. Extract IOCs
   - domains
   - URLs
   - IPs
   - hashes
   - email addresses

7. Assess social-engineering theme and likely objective
   - credential theft
   - payment fraud / BEC
   - malware delivery
   - spam / bulk lure
   - MFA fatigue / login prompt lure

8. Determine disposition
   - benign
   - spam
   - phishing
   - malware delivery
   - BEC
   - needs escalation

9. Produce concise analyst output
   - evidence
   - verdict / confidence
   - recommended next actions
   - reusable case notes

## Automation Matrix

| Task | Why it matters | Normal analyst method | Automatable? | Cheap/free implementation | Confidence / limitations |
|---|---|---|---|---|---|
| Parse email and headers | Foundation for everything else | Manual header reading + mail client | Yes | Python email libs + extract-msg | High |
| SPF / DKIM / DMARC review if present | Sender trust signal | Read `Authentication-Results` manually | Yes | Deterministic header parsing | Medium: depends on header presence / correctness |
| From / Reply-To / Return-Path alignment | Common phishing / BEC clue | Manual comparison | Yes | Deterministic header checks | High |
| Display-name deception | Frequent lure pattern | Manual visual inspection | Partly | Local heuristics | Medium |
| URL extraction and unwrap | High-value phishing evidence | Copy URLs into tools | Yes | Local regex + URL parsing | High |
| Redirect-chain resolution | Reveals true destination | Browser / curl | Yes, optionally | `httpx` with safe limits | Medium: network-dependent |
| Hidden HTML / forms / JS | Credential theft clue | View source manually | Yes | HTML parser heuristics | High |
| Attachment metadata and hashing | Malware triage | Manual hash and file review | Yes | Local hashing + metadata parsing | High |
| Attachment local scan | Malware triage | AV/YARA manually | Yes | ClamAV + YARA | High once integrated |
| IOC extraction | Case enrichment and blocking | Manual copy/paste | Yes | Local extractor pipeline | High |
| Reputation lookup | Speeds prioritization | Browser / VT / AbuseIPDB | Yes, optionally | VT / AbuseIPDB APIs | Medium: external, rate-limited |
| LLM summary | Faster note writing | Manual case notes | Yes, optionally | Ollama / LM Studio | Medium: must remain evidence-bounded |
| Report export | Case closure and repeatability | Manual writeup | Yes | Local markdown / HTML | High |

## Gap Analysis Against A Strong SOC Workflow

Implemented well:

- ingestion
- parsing
- IOC extraction
- basic header/auth analysis
- URL inspection
- attachment metadata inspection
- risk scoring
- local reporting

Still missing or weak:

- first-class message-id / originating-IP / mail-path view
- local AV / YARA scan stage
- consistent attachment hashing from parser bytes
- stronger BEC-specific heuristics
- explicit disposition taxonomy beyond benign / suspicious / malicious
- timeline / structured chronology
- attachment-content analysis beyond metadata
- screenshot capture persistence rather than screenshot URL generation

## Prioritized Roadmap

### Quick Wins

- Compute attachment hashes during parsing where bytes are available
- Update README and operator docs
- Expose message-id, originating IPs, and Return-Path more clearly in the UI/report
- Add explicit disposition mapping layer:
  - benign
  - spam
  - phishing
  - malware delivery
  - BEC
  - needs escalation

### Medium-Value Improvements

- Local AV / YARA attachment scan stage
- better BEC heuristics
  - payment fraud cues
  - executive impersonation cues
  - vendor / invoice fraud cues
- header timeline / mail-flow view
- case filtering, status, and tags

### Advanced Future Enhancements

- persistent screenshot capture and thumbnail preview
- private sandbox integration hooks
- richer domain intelligence using passive DNS / WHOIS age when privacy permits
- analyst feedback loop for tuning heuristics

## Recommended Next Safe Improvement

Completed since the initial review:

- consistent attachment SHA-256 hashing from parser bytes
- optional local YARA / ClamAV attachment scanning with transient temp files only
- preserved repeated `Received` headers during parsing
- structured authentication and mail-flow analysis
- deterministic analyst summary and recommended next actions even when the LLM is off

Best next phase:

- expand sender/auth alignment modeling and organizational impersonation logic
- grow the bundled local YARA ruleset for phishing HTML, credential harvesting, and script droppers
- add deterministic user-impact guidance:
  - likely recipient exposure
  - likely credential risk
  - recommended containment workflow

## Notes On Product Direction

- Keep deterministic evidence, heuristics, and LLM narrative visibly separate.
- Keep optional networked steps off by default or clearly marked.
- Prefer metadata-only enrichment over file submission.
- Build toward analyst trust, not flashy automation.
