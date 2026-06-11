# Evidence-Grounded Fake URL / Phishing Website Detection using LLMs and RAG

A **50% MVP research prototype** for a college progress report. The system lets a
user enter a suspicious URL and returns an **evidence-grounded** classification
(*Likely Benign / Suspicious / Likely Phishing*), a 0–100 risk score, the
supporting evidence, retrieved security knowledge (lightweight RAG), and a
readable explanation.

> ⚠️ **This is a defensive research prototype, not a production security tool.**
> It uses weak lexical/structural signals and a transparent rule-based score.
> Treat results as decision support, not a definitive verdict. Sample data uses
> only fictional brands and domains.

---

## Current MVP Scope (≈ 50%)

This prototype implements the first half of the project: URL feature
extraction, a safe crawler, HTML analysis, prompt-injection detection, a local
TF-IDF RAG retriever, a rule-based risk engine, an explainer with a
deterministic fallback, a Streamlit UI, and report export.

### Features implemented

1. URL input and validation
2. **HTTPS-first** URL normalization and lexical feature extraction
3. Safe webpage crawler (GET-only, bounded, no form submission, HTTP fallback)
4. HTML / visible-text extraction and analysis
5. Form and password-field detection
6. Prompt-injection ("hidden instruction") detection over visible **and hidden** content
7. **Brand-domain matching** (match reduces risk, mismatch increases it)
8. **Brand impersonation in the URL itself** (e.g. `paypal.secure-login.example.net`,
   `paypalsecure.com`) — detected even when the page does not load
9. **Lookalike / typosquat detection** (leetspeak `paypa1`→paypal, `g00gle`→google,
   plus edit-distance typos) and **suspicious-TLD** scoring (`.tk`, `.xyz`, `.zip`, …)
10. **Local trusted-domain allowlist** (MVP demo signal, not a guarantee)
11. Lightweight local RAG using a JSON knowledge base + TF-IDF similarity
12. Transparent rule-based risk scoring (0–100) with **evidence-conditioned RAG**,
    centralized weights, and a per-category **score breakdown**
13. Optional LLM explanation module with a deterministic, non-technical fallback
14. **Two front-ends over one shared pipeline** (`src/pipeline.py`): a Streamlit
    app and a React (Sentinel) + FastAPI app
15. JSON / Markdown analysis report export
16. Unit tests for the core modules
17. This README and `progress_report.md`

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

### Features intentionally NOT implemented yet (next 50%)

- Multimodal screenshot analysis and OCR (only placeholder notes exist)
- Real-time external threat-intelligence APIs (PhishTank / OpenPhish, etc.)
- Automatic crawling of known-malicious sites
- WHOIS / DNS / TLS / certificate intelligence
- Browser-extension deployment
- Multi-agent LLM debate
- Trained deep-learning models / GPU dependencies
- Large-scale labelled evaluation with reported accuracy/metrics

No final accuracy or research results are claimed.

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

## Future work (planned for the remaining 50%)

- Screenshot capture + OCR (multimodal evidence).
- Live threat-intelligence / blocklist lookups.
- WHOIS / DNS / TLS certificate signals (e.g. domain age).
- Stronger prompt-injection defenses and input sanitisation for the LLM path.
- A labelled evaluation set with proper metrics and error analysis.
- A real LLM-backed explanation (Anthropic Claude / OpenAI) behind `USE_LLM=true`.
- Optional browser-extension front-end and deployment.
