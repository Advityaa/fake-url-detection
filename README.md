# Evidence-Grounded Fake URL / Phishing Website Detection using LLMs and RAG

A **defensive research prototype** for a college project. The system lets a user
enter a suspicious URL and returns an **evidence-grounded** classification
(*Likely Benign / Suspicious / Likely Phishing*), a transparent 0–100 risk score
with a **per-category breakdown**, the supporting evidence, retrieved security
knowledge (RAG), external **threat-** and **domain-intelligence** signals, and a
readable explanation.

> ⚠️ **This is a defensive research prototype, not a production security tool.**
> Classification comes from a **transparent rule-based engine, not a trained
> ML/LLM model**. Treat results as decision support, not a definitive verdict.
> Bundled demo data uses only fictional brands and domains.

---

## Status (feature by feature)

Status is tracked by capability below rather than as one headline number — a
single percentage would hide what actually runs **by default** vs. what is
**available but disabled**. By count, roughly **19 of ~24 planned capabilities are
implemented (~79%)**: 11 run by default, 8 are implemented but disabled in the
default config, and ~5 remain as genuine future work.

### 1. Implemented — ON by default

1. URL input/validation and **HTTPS-first** lexical analysis: length, subdomains,
   IP/`@`/punycode, link shorteners, hostname entropy, **suspicious TLDs**,
   host-vs-path keyword weighting, **brand impersonation in the URL**
   (`paypal.secure-login.example.net`), and **lookalike/typosquat** detection
   (leetspeak `paypa1`→paypal, plus edit-distance typos).
2. **Safe crawler** — GET-only, bounded timeout/redirects, capped response size,
   non-HTML skipped, no JavaScript execution, no form submission (httpx
   "requests" backend), plus an offline sample-page mode.
3. **HTML / visible-text analysis** — forms, password fields, credential-request
   language, external links/scripts, brand-like words; brand-vs-domain matching.
4. **Prompt-injection detection** over visible *and* hidden content, with severity.
5. **TF-IDF RAG retrieval** over a local 22-entry knowledge base (evidence-
   conditioned: retrieved knowledge adds risk only when a matching indicator was
   actually observed).
6. **Threat intelligence — OpenPhish feed** (downloaded, cached with a TTL,
   offline-safe; matched by URL / host / registered domain).
7. **Domain intelligence — WHOIS** (age, registrar, registrant), **DNS** (A/MX),
   **TLS** (issuer/org/validity/self-signed), plus a **cross-signal conflict
   layer** that tallies contradictions across these signals.
8. **Transparent rule-based risk engine** (0–100) with centralized weights, an
   **11-category per-category score breakdown**, evidence-conditioning, and a
   local **trusted-domain allowlist** mitigation (suppressed for severe risks).
9. **Evidence-grounded explanation** (deterministic; cites the factors used).
10. **Two front-ends over one shared pipeline** (`src/pipeline.py`): a Streamlit
    app and a React ("Sentinel") + FastAPI app; JSON/Markdown report export.
11. **Test suite** (175 passing / 4 skipped) and a **reproducible evaluation
    harness** (`evaluation/`).

### 2. Implemented — available but DISABLED in the default config

Built and tested, but **off by default** so the core runs offline with no heavy or
system dependencies. Each notes why it is off / how to enable it:

- **LLM explanation** — `USE_LLM=false`. Wording-only: it rephrases the
  explanation and **never changes the score or verdict** (those stay with the rule
  engine). Needs a provider API key + SDK (`anthropic`/`openai`).
- **Embedding RAG** (sentence-transformers + Chroma) — `RETRIEVER_BACKEND=tfidf`;
  optional heavy deps; **auto-falls-back to TF-IDF** if unavailable.
- **Playwright render backend** (headless Chromium) — `RENDER_BACKEND=requests`;
  needs `pip install playwright && playwright install chromium`.
- **Multimodal (screenshot + OCR)** — `USE_MULTIMODAL=false`; needs Playwright and
  the Tesseract binary.
- **Dynamic-analysis** (post-interaction cloaking diff) — runs only with the
  Playwright backend, so off by default.
- **Login-click during dynamic analysis** — `CLICK_LOGIN_BUTTON=false`.
- **Geo/ASN conflict type** — needs `GEOIP_DB_PATH` + `geoip2`. **Inactive in the
  default setup, so this specific conflict never fires by default** (the other
  conflict types — brand-vs-domain, free-email registrant, free-email+new-domain,
  impersonation-with-weak-cert — do run).
- **PhishTank feed** — needs an API key; **OpenPhish is the feed that actually
  runs** by default.

### False-positive calibration (added after an `amazon.com` test)

The risk engine was tuned so that legitimate popular sites are not flagged just
for having login/payment words, many scripts/links, or semantically similar RAG
hits:

- **HTTPS-first**: a bare domain (`amazon.com`) is checked over HTTPS first and
  the *final* URL scheme is used for scoring, so no spurious "no HTTPS" penalty.
- **Evidence-conditioned RAG**: retrieved knowledge only adds risk when a
  matching indicator was actually observed (e.g. HTTP-risk knowledge adds
  nothing if the final URL is HTTPS; prompt-injection knowledge adds nothing if
  no injection was detected).
- **Common e-commerce terms** (sign in, payment, account, ...) only add
  meaningful risk when combined with other suspicious signals, and are
  suppressed for trusted domains / brand-domain matches.
- **Many links/scripts** is a weak signal (+3) and never pushes a site into
  "Needs Caution" on its own; it is ignored for trusted domains.
- **Classification bands**: 0–29 Likely Safe · 30–59 Needs Caution · 60–100 High Risk.

### 3. Genuine future work (not yet built)

- A **trained ML / deep-learning** classifier (the current classifier is the
  transparent rule engine, by design).
- **LLM-backed classification** (today the LLM is wording-only, not a classifier).
- **Large-scale labelled evaluation** with published metrics / error analysis (the
  harness exists and runs, but on small samples).
- **Browser-extension** front-end and deployment.
- Multi-agent LLM debate.

### Scoping facts (stated plainly)

- The classifier is a **transparent rule engine, not a trained ML/LLM model**.
- **RAG is real** (TF-IDF by default; embeddings optional).
- **No accuracy is claimed in the app itself.** The `evaluation/` harness measures
  it separately and honestly. On a seeded 300 + 300 Tranco-vs-OpenPhish sample,
  URL/HTML/domain signals **alone** (threat-intel disabled to prevent label
  leakage) are high-precision but **low-recall** (≈0.92 precision / 0.25 recall /
  0.40 F1); with the threat-intel feed enabled, ≈0.97 / 0.89 / 0.93. The low
  URL-only recall is a real limitation, stated rather than hidden.
- Bundled data is **demo data, not mock**: `data/sample_html/*`, `sample_urls.csv`,
  `trusted_domains.json` (small local allowlist), and `knowledge_base.json` (22
  curated RAG entries). Live modes use real network sources.

---

## Installation

Requires **Python 3.10+** (developed/tested on 3.12).

```bash
# from the project root
python -m venv .venv
# Windows (PowerShell)
.venv\Scripts\Activate.ps1
# macOS / Linux
source .venv/bin/activate

pip install -r requirements.txt
```

(Optional) configure the LLM/crawler settings:

```bash
cp .env.example .env   # then edit values; LLM is OFF by default
```

---

## How to run

There are two interchangeable front-ends; both call the same analysis pipeline
in `src/pipeline.py`, so results are identical.

### Option A — Streamlit (single process, Python only)

```bash
streamlit run app.py
```

Then open the local URL Streamlit prints (usually http://localhost:8501).

### Option B — React "Sentinel" UI + FastAPI backend

Run the API and the React dev server in two terminals:

```bash
# Terminal 1 — FastAPI backend (http://localhost:8000)
uvicorn api:app --port 8000

# Terminal 2 — React frontend (http://localhost:5173)
cd frontend
npm install      # first time only
npm run dev
```

Open the URL Vite prints (usually http://localhost:5173). The frontend calls
`POST http://localhost:8000/api/analyze`. The React UI shows an animated risk
gauge, a per-category score breakdown, URL anatomy, retrieved knowledge, the
hidden-instruction check, and the explanation.

## How to run tests

```bash
pytest
# or, more verbose:
pytest -v
```

---

## Optional: JS-rendering crawl backend (Playwright)

By default the crawler fetches pages with a single bounded GET request (httpx).
For sites that build their content with JavaScript, an **optional** headless
Chromium backend can render the page first:

```bash
pip install playwright
playwright install chromium     # required: downloads the browser
```

Then set in `.env`:

```bash
RENDER_BACKEND=playwright       # default is "requests"
RENDER_TIMEOUT_SECONDS=8
```

Safety is preserved: navigation only (no form submission), downloads blocked,
popups closed rather than followed, a hard timeout, and the browser context is
always torn down. If Playwright or the Chromium binary is missing, the crawler
logs a warning and **falls back to the requests backend automatically**, so the
pipeline always runs end-to-end.

### Dynamic-cloaking detection (piggybacks on the Playwright backend)

When `RENDER_BACKEND=playwright`, live pages also get a **dynamic-analysis** pass
that catches content revealed only *after* rendering/interaction — e.g. a login
form or password field injected by JavaScript on scroll, a timer, or a click, so
the initial HTML looks harmless. It snapshots credential-relevant DOM counts,
does a minimal safe interaction (scroll in steps), snapshots again, and flags a
material increase (the key case: a password field going 0 → 1).

- **Clicking is off by default.** Set `CLICK_LOGIN_BUTTON=true` to also click a
  control whose visible text tightly matches "log in / sign in"; cross-origin
  navigations are reverted, never followed. Arbitrary buttons are never clicked.
- Hard-timeout wrapped, browser always closed, and skipped gracefully if the
  browser is unavailable. Its risk contribution is conservative — a cloaking
  signal alone cannot reach *High Risk*, and it is suppressed for trusted domains.

---

## Optional: multimodal (screenshot + OCR) analysis

An **optional, off-by-default** stage renders the page in a headless browser,
OCRs the screenshot, and surfaces two signals the HTML-only path can miss:

1. **Visible-vs-DOM text divergence** — text OCR sees rendered but that is weakly
   present in the HTML (a hidden-text / cloaking indicator).
2. **Brand-name-in-image** — a known brand shown in the screenshot while the
   domain doesn't belong to that brand (logo/brand impersonation shipped as an
   image to evade HTML brand analysis).

All OCR text is treated as **untrusted** — it is scanned by the prompt-injection
detector and never obeyed (attackers hide instructions as low-contrast/tiny image
text specifically to hit the OCR channel). Rendering is GET-only navigation with a
hard timeout, no downloads, and no form interaction.

**This stage is disabled by default and requires extra dependencies** — both pip
packages *and* system binaries:

```bash
pip install playwright pytesseract Pillow
playwright install chromium          # downloads the headless browser
# Tesseract OCR engine (system package):
#   macOS:         brew install tesseract
#   Debian/Ubuntu: sudo apt-get install tesseract-ocr
```

Then enable it in `.env`:

```bash
USE_MULTIMODAL=true
```

If any of these are missing, the stage logs a warning and is skipped — the
pipeline still runs end-to-end. It only runs in **live** mode (it needs a real URL
to render), and its risk contributions are **conservative**: no single visual
signal alone can push a site to *High Risk*, and all visual signals are suppressed
for trusted-allowlist domains.

---

## Demo flow (for the progress review)

1. Launch the app: `streamlit run app.py`.
2. Choose an **Analysis mode**:
   - *Live website check* → type `amazon.com` → expect **Likely Safe** (low score,
     brand match + trusted-domain mitigation, HTTPS).
   - *Sample safe page* → expect **Likely Safe**.
   - *Sample phishing page* → expect **High Risk** (password field + brand mismatch
     + suspicious URL).
   - *Sample prompt-injection page* → expect **High Risk** with a *hidden
     instruction* warning.
3. Review the plain-English result, recommended action, the "Why did we give this
   result?" reasons, retrieved security knowledge, and the explanation.
4. Open **Advanced technical details** for raw JSON if needed.
5. Use the buttons to **download JSON / Markdown** reports or **save both** to
   `outputs/`.

---

## Folder structure

```
.
├── app.py                      # Streamlit UI (calls src/pipeline.py)
├── api.py                      # FastAPI backend (calls src/pipeline.py)
├── frontend/                   # React (Vite) "Sentinel" UI
│   ├── index.html
│   ├── package.json
│   └── src/
│       ├── App.jsx             # full results UI (gauge, breakdown, anatomy, …)
│       ├── index.css
│       └── main.jsx
├── requirements.txt
├── README.md
├── progress_report.md
├── .env.example
├── conftest.py                 # makes `src` importable for pytest
│
├── data/
│   ├── knowledge_base.json     # 22 local security knowledge entries (RAG)
│   ├── trusted_domains.json    # local MVP allowlist (demo trust signal only)
│   ├── sample_urls.csv         # fictional demo URLs (feature extraction)
│   └── sample_html/
│       ├── benign_example.html
│       ├── phishing_example.html
│       └── prompt_injection_example.html
│
├── outputs/                    # saved JSON / Markdown reports (.gitkeep)
│
├── src/
│   ├── __init__.py
│   ├── config.py               # settings + shared vocab, known brands, TLDs
│   ├── pipeline.py             # shared analysis pipeline (used by app.py & api.py)
│   ├── schemas.py              # dataclasses for all result objects
│   ├── url_features.py         # incl. brand-impersonation / lookalike detection
│   ├── crawler.py
│   ├── html_analyzer.py
│   ├── prompt_injection_detector.py
│   ├── rag_retriever.py
│   ├── risk_engine.py          # centralized weights + per-category breakdown
│   ├── llm_explainer.py
│   ├── report_generator.py
│   └── utils.py
│
└── tests/
    ├── test_url_features.py
    ├── test_prompt_injection_detector.py
    ├── test_rag_retriever.py
    ├── test_risk_engine.py
    ├── test_brand_domain.py        # brand-domain matching
    ├── test_trusted_domains.py     # allowlist mitigation + amazon scenario
    └── test_calibration.py         # conditional RAG, HTTPS, e-commerce terms
```

---

## Safety notes

- **Defensive only.** The project classifies pages for safety; it never attacks,
  submits forms, collects credentials, or bypasses security systems.
- **Untrusted content.** Webpage text is treated strictly as untrusted evidence.
  Prompt-injection text found in pages is reported but **never executed or obeyed**.
- **Safe crawler.** GET-only, bounded timeout and redirect count, capped response
  size, non-HTML responses skipped, no JavaScript execution.
- **No real malicious URLs** are bundled. Samples use fictional brands/domains.
- **No secrets in code.** API keys (if used later) come from `.env`, never source.
- This tool should **not** be used as the only security control.

---

## Future work

See **"Status → 3. Genuine future work"** above for the authoritative list. In
short: a trained ML classifier, LLM-backed *classification* (not just wording),
large-scale labelled evaluation, a browser-extension front-end, and multi-agent
LLM debate. The threat-intelligence, WHOIS/DNS/TLS, screenshot/OCR, and
LLM-explanation items from earlier drafts of this README are **now implemented**
(the last three are available but disabled in the default config).
