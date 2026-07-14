# Evaluation harness

A reproducible, honest evaluation of the phishing-detection pipeline
(`src/pipeline.py` → `analyze_url`, scored by `src/risk_engine.py`).
It measures how well the system separates real phishing URLs from real
legitimate domains — and reports its own blind spots.

## How labels are obtained (no synthesized labels)

| Class | Source | Assumption |
|---|---|---|
| **Benign** | [Tranco](https://tranco-list.eu) top-sites list — a seeded random sample (default 300) from the top 10,000 ranks | Popular domains are treated as benign. **Not manually verified** — popular ≠ guaranteed safe. |
| **Phishing** | OpenPhish public feed, read from this project's own cache (`data/threat_cache/`) | Feed entries are treated as phishing. **Not manually verified** — feeds contain occasional false positives and dead pages. |

The exact sampled items, sources, seed, and timestamps are written to
`evaluation/data/dataset_<timestamp>.json` so any run can be reproduced and
audited later, even after the live feeds change.

## Leakage control (the important part)

The phishing labels come from the OpenPhish feed — the **same feed the
pipeline's threat-intel module checks**. Evaluating with that lookup enabled
would be circular: the system would "detect" phishing by looking up the answer
key.

Therefore:

- The **headline configuration** runs the pipeline with
  `enable_threat_intel=False` (a flag added to `analyze_url` for exactly this
  purpose). The feed is never consulted; the score reflects URL, page-content,
  brand, hidden-instruction, and domain-reputation signals only.
- The **with-threat-intel configuration** is computed by re-running the pure
  `assess_risk()` function on the *identical* collected evidence plus a
  cache-only feed check — exactly what the production pipeline produces, with
  no second crawl. Both are reported side by side so the feed's contribution
  is visible instead of hidden inside the headline number.

## How to run

```bash
# 1. Build a dataset snapshot (downloads the Tranco list; reads the cached feed)
python -m evaluation.build_dataset --benign-n 300 --phish-n 300 --seed 42

# 2. Run the evaluation (live crawls; ~20-40 min at default settings)
python -m evaluation.run_evaluation --workers 6

# Quick smoke run:
python -m evaluation.run_evaluation --limit 10 --workers 4 --no-domain-intel
```

Outputs land in `evaluation/results/`: a JSON with every per-URL record, a
Markdown report, a confusion-matrix figure, and a score-distribution figure.

## Metrics reported

- Positive class = phishing. Reported under **two** definitions of a positive
  prediction: *High Risk only* (score ≥ 60) and *High Risk + Needs Caution*
  (score ≥ 30).
- Precision, recall, F1, accuracy, and false-positive rate for **both**
  configurations.
- Confusion matrices, score distributions, and top-10 worst false positives /
  false negatives with their per-category score breakdowns for error analysis.
- Coverage table: how many URLs were skipped (no DNS resolution), how many
  errored, and WHOIS/DNS/TLS availability rates.

## Safety posture

GET-only crawling with the project's bounded crawler (timeouts, no form
submission, no JS execution, capped response size). Dataset snapshots and
results are **git-ignored** because they contain live phishing URLs — nothing
malicious is committed to the repository. Re-create them with the commands
above.

## Known limitations (read before quoting numbers)

1. **Small samples** (default 300 + 300) → wide confidence intervals. Treat
   results as indicative, not definitive.
2. **Live feeds change daily.** Phishing URLs die within hours; a snapshot
   evaluated tomorrow will have more dead pages than one evaluated today.
3. **Labels are not manually verified** in either direction: Tranco domains
   can be compromised or unsavory; feed entries can be mislabeled.
4. **Dead URLs are skipped** (no DNS resolution). This excludes exactly the
   pages where only URL-lexical signals would apply, so it changes the mix of
   evidence available to the system. Skip counts are reported.
5. **The benign class is "easy."** Popular top-sites are not hard negatives;
   a benign set of obscure-but-legitimate small sites would produce more false
   positives than reported here.
6. **WHOIS throttles at scale**, so domain-age availability may be low across
   a large run; availability percentages are reported alongside the metrics.
7. **One moment in time, one geography.** Results depend on the day's feed,
   the network, and where the crawler runs.
8. No comparison against external baselines or state-of-the-art systems is
   made or implied.
