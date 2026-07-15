"""Run the evaluation over a dataset snapshot and produce honest metrics.

Two configurations are reported from ONE network pass:

  * **without threat intel** (headline): the pipeline runs with
    ``enable_threat_intel=False`` — the OpenPhish feed that supplied the
    phishing labels is NEVER consulted, so it cannot leak into the score.
  * **with threat intel**: the pure ``assess_risk`` function is re-run on the
    SAME collected evidence plus a cache-only feed check, which is exactly what
    the production pipeline would have produced. This shows the feed's
    contribution without a second crawl.

Coverage honesty: URLs whose hostname does not resolve are skipped and counted;
per-URL analysis errors are counted; WHOIS/DNS/TLS availability rates are
reported (WHOIS throttles at scale).

Usage:
    python -m evaluation.run_evaluation [--dataset PATH] [--limit N]
        [--workers 6] [--no-domain-intel] [--crawl-timeout 8]
"""

from __future__ import annotations

import argparse
import json
import sys
import traceback
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evaluation.llm_baseline import (  # noqa: E402
    PROMPT_VERSION,
    SYSTEM_INSTRUCTION,
    VARIANT_URL_AND_TEXT,
    VARIANT_URL_ONLY,
    NaiveLLMBaseline,
    baseline_available,
    build_comparison,
    build_prompt,
    find_disagreements,
)
from evaluation.metrics import (  # noqa: E402
    BAND_PHISHING,
    BAND_SUSPICIOUS,
    summarize_bands,
)
from src.config import load_trusted_domains, settings  # noqa: E402
from src.domain_intel import DomainIntelClient  # noqa: E402
from src.pipeline import analyze_url  # noqa: E402
from src.rag_retriever import RAGRetriever, build_query  # noqa: E402
from src.risk_engine import assess_risk  # noqa: E402
from src.threat_intel import ThreatIntelClient  # noqa: E402

EVAL_DIR = Path(__file__).resolve().parent
RESULTS_DIR = EVAL_DIR / "results"

# Palette (validated with the dataviz six-checks script, light surface):
# benign = categorical slot 1, phishing = categorical slot 6.
COLOR_BENIGN = "#2a78d6"
COLOR_PHISHING = "#e34948"
INK = "#333333"
INK_MUTED = "#767676"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _hostname(url: str) -> str:
    if "://" not in url:
        url = "https://" + url
    return urlparse(url).hostname or ""


def resolves(url: str, timeout: float = 3.0) -> bool:
    """True if the URL's hostname has an A record (short-timeout DNS check)."""
    import dns.resolver

    host = _hostname(url)
    if not host:
        return False
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout
    try:
        return len(resolver.resolve(host, "A")) > 0
    except Exception:  # noqa: BLE001 - any failure counts as "did not resolve"
        return False


def analyze_one(
    url: str,
    label: int,
    retriever: RAGRetriever,
    trusted: List[str],
    domain_client: Optional[DomainIntelClient],
    ti_client: ThreatIntelClient,
    capture_text: bool = False,
) -> Dict:
    """Analyze one URL; return a record with both configs' scores/bands.

    When ``capture_text`` is True, a bounded excerpt of the fetched visible page
    text is stored so the raw-LLM baseline's url_and_text variant can reuse it
    without a second fetch.
    """
    record: Dict = {"url": url, "label": label}
    try:
        result = analyze_url(
            url,
            "live",
            retriever=retriever,
            trusted_domains=trusted,
            domain_client=domain_client,
            enable_threat_intel=False,  # leakage control (headline config)
        )
        if result is None:
            record["error"] = "invalid URL"
            return record

        ra = result.risk_assessment
        record.update(
            {
                "final_url": result.crawl.final_url,
                "crawl_ok": result.crawl.success,
                "score_no_ti": result.risk_score,
                "band_no_ti": result.classification,
                "breakdown_no_ti": ra.score_breakdown,
                "risk_factors": ra.risk_factors[:6],
                # Injection flag: used by the baseline's disagreement analysis to
                # surface the cloaking/injection cases the raw LLM cannot see.
                "injection_detected": bool(result.prompt_injection.injection_detected),
                "whois_available": bool(result.domain_intel and result.domain_intel.whois_available),
                "dns_available": bool(result.domain_intel and result.domain_intel.dns_available),
                "tls_available": bool(result.domain_intel and result.domain_intel.tls_available),
            }
        )
        if capture_text:
            record["visible_text_excerpt"] = (result.crawl.visible_text or "")[:2000]

        # --- With-threat-intel config: cache-only feed check + pure re-score.
        uf, ha, pi = result.url_features, result.html_analysis, result.prompt_injection
        ti = ti_client.check(result.crawl.final_url or url, uf.registered_domain)
        query = build_query(
            uf.evidence_messages,
            ha.evidence_messages,
            pi.evidence_messages,
            extra_terms=uf.suspicious_keywords_found
            + ha.credential_patterns_found
            + ti.evidence_messages
            + (result.domain_intel.evidence_messages if result.domain_intel else []),
        )
        risk_ti = assess_risk(
            uf,
            ha,
            pi,
            retriever.retrieve(query),
            brand_check=result.brand_check,
            is_trusted_domain=result.is_trusted_domain,
            redirect_count=len(result.crawl.redirect_chain),
            threat_intel=ti,
            domain_intel=result.domain_intel,
        )
        record.update(
            {
                "ti_listed": ti.listed,
                "score_with_ti": risk_ti.score,
                "band_with_ti": risk_ti.classification,
            }
        )
    except Exception as exc:  # noqa: BLE001 - one bad URL must not kill the run
        record["error"] = f"{type(exc).__name__}: {exc}"
        record["traceback"] = traceback.format_exc(limit=2)
    return record


# ---------------------------------------------------------------------------
# Plots (matplotlib, light surface; palette validated — see module constants)
# ---------------------------------------------------------------------------
def plot_confusion_matrices(cm_no_ti: Dict, cm_with_ti: Dict, out_path: Path) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, axes = plt.subplots(1, 2, figsize=(9, 4.2))
    for ax, (title, cm) in zip(
        axes,
        [("Without threat intel", cm_no_ti), ("With threat intel", cm_with_ti)],
    ):
        grid = [[cm["tp"], cm["fn"]], [cm["fp"], cm["tn"]]]
        vmax = max(1, max(max(row) for row in grid))
        ax.imshow(grid, cmap="Blues", vmin=0, vmax=vmax)  # sequential single hue
        for i in range(2):
            for j in range(2):
                value = grid[i][j]
                ink = "#ffffff" if value > 0.6 * vmax else INK
                ax.text(j, i, f"{value:,}", ha="center", va="center",
                        fontsize=15, fontweight="bold", color=ink)
        ax.set_xticks([0, 1], ["Phishing", "Benign"], color=INK)
        ax.set_yticks([0, 1], ["Phishing", "Benign"], color=INK)
        ax.set_xlabel("Predicted", color=INK_MUTED)
        ax.set_ylabel("Actual", color=INK_MUTED)
        ax.set_title(title, color=INK, fontsize=11)
        for spine in ax.spines.values():
            spine.set_visible(False)
    fig.suptitle("Confusion matrices — positive prediction = High Risk band",
                 color=INK, fontsize=12)
    fig.tight_layout()
    fig.savefig(out_path, dpi=160, facecolor="white", bbox_inches="tight")
    plt.close(fig)


def plot_score_distribution(records: List[Dict], out_path: Path) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    benign = [r["score_no_ti"] for r in records if r["label"] == 0 and "score_no_ti" in r]
    phish = [r["score_no_ti"] for r in records if r["label"] == 1 and "score_no_ti" in r]

    fig, ax = plt.subplots(figsize=(9, 4.2))
    bins = list(range(0, 105, 5))
    ax.hist(benign, bins=bins, alpha=0.75, label=f"Benign (n={len(benign)})",
            color=COLOR_BENIGN, edgecolor="white", linewidth=0.5)
    ax.hist(phish, bins=bins, alpha=0.75, label=f"Phishing (n={len(phish)})",
            color=COLOR_PHISHING, edgecolor="white", linewidth=0.5)
    for x, name in [(30, "Needs Caution ≥30"), (60, "High Risk ≥60")]:
        ax.axvline(x, color=INK_MUTED, linestyle="--", linewidth=1)
        ax.text(x + 1, ax.get_ylim()[1] * 0.95, name, color=INK_MUTED,
                fontsize=8, va="top")
    ax.set_xlabel("Risk score (0–100, threat intel disabled)", color=INK)
    ax.set_ylabel("URLs", color=INK)
    ax.set_title("Score distribution by true class — without threat intel",
                 color=INK, fontsize=12)
    ax.legend(frameon=False)
    ax.grid(axis="y", color="#e6e6e6", linewidth=0.6)
    ax.set_axisbelow(True)
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    fig.tight_layout()
    fig.savefig(out_path, dpi=160, facecolor="white", bbox_inches="tight")
    plt.close(fig)


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
def _fmt_metrics_table(metrics_by_config: Dict) -> str:
    lines = [
        "| Config | Positive = | Precision | Recall | F1 | Accuracy | FPR |",
        "|---|---|---|---|---|---|---|",
    ]
    pretty = {
        "high_risk_positive": "High Risk only",
        "caution_or_high_positive": "High Risk + Needs Caution",
    }
    for config, defs in metrics_by_config.items():
        cfg_name = "without threat intel" if config == "no_threat_intel" else "WITH threat intel"
        for def_key, m in defs.items():
            lines.append(
                f"| {cfg_name} | {pretty[def_key]} | {m['precision']:.3f} | "
                f"{m['recall']:.3f} | {m['f1']:.3f} | {m['accuracy']:.3f} | "
                f"{m['false_positive_rate']:.3f} |"
            )
    return "\n".join(lines)


def _fmt_error_table(rows: List[Dict], score_key: str) -> str:
    if not rows:
        return "_None._"
    lines = ["| URL | Score | Band | Top factors / breakdown |", "|---|---|---|---|"]
    for r in rows:
        factors = "; ".join(r.get("risk_factors", [])[:3]) or "—"
        nonzero = {k: v for k, v in r.get("breakdown_no_ti", {}).items() if v}
        url_short = (r["url"][:70] + "…") if len(r["url"]) > 70 else r["url"]
        lines.append(
            f"| `{url_short}` | {r.get(score_key, '?')} | {r.get('band_no_ti', '?')} "
            f"| {factors} `{nonzero}` |"
        )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Raw-LLM baseline ("why not just ask an LLM?")
# ---------------------------------------------------------------------------
def _pipeline_pred(record: Dict, band_key: str) -> int:
    """Binary phishing prediction from a pipeline band (positive = High Risk)."""
    return 1 if record.get(band_key) == BAND_PHISHING else 0


def _select_baseline_targets(ok: List[Dict], limit: int) -> List[Dict]:
    """Pick the URLs to send to the baseline (balanced per class when capped)."""
    if not limit or limit <= 0:
        return ok
    per_class = max(1, limit // 2)
    benign = [r for r in ok if r["label"] == 0][:per_class]
    phish = [r for r in ok if r["label"] == 1][:per_class]
    return benign + phish


def _run_baseline_variant(
    variant: str, targets: List[Dict], model: str, min_interval: float
) -> Dict:
    """Run one baseline variant over the target URLs; return a report block."""
    urls = [r["url"] for r in targets]
    page_texts = None
    if variant == VARIANT_URL_AND_TEXT:
        page_texts = [r.get("visible_text_excerpt") or None for r in targets]

    baseline = NaiveLLMBaseline(model=model, min_interval=min_interval)
    print(f"  baseline [{variant}]: {len(urls)} URLs "
          f"(min interval {min_interval:.1f}s; cached responses reused)")

    def _progress(done: int, total: int) -> None:
        print(f"    baseline {variant}: {done}/{total} "
              f"(api calls {baseline.calls_made}, cache hits {baseline.cache_hits})")

    results = baseline.run(urls, page_texts=page_texts, progress=_progress)
    by_url = {res.url: res for res in results}

    common_rows: List[Dict] = []       # predictions for metrics (identical set)
    disagreement_rows: List[Dict] = []  # for the disagreement table
    n_errors = 0
    for r in targets:
        res = by_url.get(r["url"])
        if res is None or res.is_phishing is None:
            n_errors += 1
            continue
        base_pred = 1 if res.is_phishing else 0
        pipe_pred = _pipeline_pred(r, "band_no_ti")
        common_rows.append({
            "label": r["label"],
            "base_pred": base_pred,
            "pipe_no_ti_pred": pipe_pred,
            "pipe_with_ti_pred": _pipeline_pred(r, "band_with_ti"),
        })
        disagreement_rows.append({
            "url": r["url"], "label": r["label"],
            "base_pred": base_pred, "base_reason": res.reason,
            "pipe_pred": pipe_pred, "pipe_band": r.get("band_no_ti", "?"),
            "pipe_score": r.get("score_no_ti", "?"),
            "injection_detected": bool(r.get("injection_detected")),
        })

    disagreements = find_disagreements(disagreement_rows)
    return {
        "variant": variant,
        "n_targets": len(targets),
        "n_predicted": len(common_rows),
        "n_errors": n_errors,
        "calls_made": baseline.calls_made,
        "cache_hits": baseline.cache_hits,
        "comparison": build_comparison(common_rows) if common_rows else None,
        "n_disagreements": len(disagreements),
        "disagreements": disagreements[:25],
    }


def run_llm_baseline(ok: List[Dict], args: argparse.Namespace) -> Optional[Dict]:
    """Run the raw-LLM baseline if requested; return a report block or None.

    Never raises for a missing key: it reports a clean "skipped" block instead.
    """
    if not args.llm_baseline:
        return None
    if not baseline_available():
        print("LLM baseline requested but no API key configured -> skipping cleanly.")
        return {"status": "skipped_no_key", "note": "baseline not run (no API key)"}
    if not ok:
        return {"status": "skipped_no_data", "note": "baseline not run (no analyzed URLs)"}

    targets = _select_baseline_targets(ok, args.llm_baseline_limit)
    variants = (
        [VARIANT_URL_ONLY, VARIANT_URL_AND_TEXT]
        if args.llm_baseline_variant == "both"
        else [args.llm_baseline_variant]
    )
    print(f"\n=== Raw-LLM baseline (model {args.llm_model}) ===")
    variant_blocks = [
        _run_baseline_variant(v, targets, args.llm_model, args.llm_min_interval)
        for v in variants
    ]
    from evaluation.llm_baseline import DEFAULT_CACHE_PATH
    return {
        "status": "ok",
        "model": args.llm_model,
        "prompt_version": PROMPT_VERSION,
        "system_instruction": SYSTEM_INSTRUCTION,
        "prompt_example_url_only": build_prompt("http://example-login.example.net/verify"),
        "min_interval_seconds": args.llm_min_interval,
        "cache_path": str(DEFAULT_CACHE_PATH),
        "variants": variant_blocks,
    }


def _fmt_comparison_table(comp: Dict) -> str:
    order = [
        ("raw_llm_baseline", "Raw-LLM baseline"),
        ("pipeline_no_threat_intel", "Full pipeline (no threat intel)"),
        ("pipeline_with_threat_intel", "Full pipeline (with threat intel)"),
    ]
    lines = [
        "| Approach | Precision | Recall | F1 | Accuracy | FPR | n |",
        "|---|---|---|---|---|---|---|",
    ]
    for key, name in order:
        m = comp[key]
        lines.append(
            f"| {name} | {m['precision']:.3f} | {m['recall']:.3f} | {m['f1']:.3f} "
            f"| {m['accuracy']:.3f} | {m['false_positive_rate']:.3f} | {comp['n']} |"
        )
    return "\n".join(lines)


def _fmt_disagreement_table(rows: List[Dict]) -> str:
    if not rows:
        return "_No disagreements._"
    lines = [
        "| URL | True | Baseline | Pipeline (no-TI) | Injection flagged |",
        "|---|---|---|---|---|",
    ]
    lab = {0: "benign", 1: "phishing"}
    pred = {0: "legit", 1: "phishing"}
    for r in rows:
        url_short = (r["url"][:60] + "…") if len(r["url"]) > 60 else r["url"]
        reason = (r.get("base_reason") or "").replace("|", "/").replace("\n", " ")[:80]
        lines.append(
            f"| `{url_short}` | {lab[r['label']]} | {pred[r['base_pred']]} ({reason}) "
            f"| {r['pipe_band']} ({r['pipe_score']}) "
            f"| {'yes' if r['injection_detected'] else 'no'} |"
        )
    return "\n".join(lines)


def _fmt_baseline_section(block: Optional[Dict]) -> List[str]:
    if block is None:
        return []  # baseline not requested -> no section at all
    md = ['## Raw-LLM baseline — "why not just ask an LLM?"', ""]
    if block.get("status") != "ok":
        return md + [f"_{block.get('note', 'baseline not run')}._", ""]
    md += [
        f"Naive baseline: for each URL, ask **{block['model']}** for a JSON phishing "
        "verdict using the same fair, minimal prompt a non-expert user would type "
        "(documented in `evaluation/README.md`). Run on the SAME analyzed URLs as the "
        "pipeline; responses are cached and rate-limited so re-runs don't re-spend quota.",
        "",
    ]
    for vb in block["variants"]:
        title = "URL only" if vb["variant"] == VARIANT_URL_ONLY else "URL + fetched page text"
        md += [f"### Variant: {title}", ""]
        if not vb.get("comparison"):
            md += [f"_No parseable predictions (targets {vb['n_targets']}, "
                   f"errors {vb['n_errors']})._", ""]
            continue
        md += [
            f"Compared on **{vb['comparison']['n']}** URLs (targets {vb['n_targets']}, "
            f"baseline errors/unparseable {vb['n_errors']}, API calls {vb['calls_made']}, "
            f"cache hits {vb['cache_hits']}).",
            "",
            _fmt_comparison_table(vb["comparison"]),
            "",
            f"**Baseline vs no-TI pipeline disagreements: {vb['n_disagreements']}** "
            f"(showing up to {min(25, vb['n_disagreements'])}, injection-flagged first):",
            "",
            _fmt_disagreement_table(vb["disagreements"]),
            "",
        ]
    md += [
        "_Honesty note: numbers are reported exactly as measured, including any case "
        "where the raw LLM beats the pipeline. The prompt is a fair naive prompt, not "
        "tuned to make the baseline look bad. Caveats (single model, free-tier limits, "
        "live URLs that may have died between snapshot and run) are in the README._",
        "",
    ]
    return md


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", default=str(EVAL_DIR / "data" / "dataset_latest.json"))
    parser.add_argument("--limit", type=int, default=0, help="cap per class (0 = all)")
    parser.add_argument("--workers", type=int, default=6)
    parser.add_argument("--no-domain-intel", action="store_true",
                        help="skip WHOIS/DNS/TLS lookups (much faster)")
    parser.add_argument("--crawl-timeout", type=int, default=0,
                        help="override crawler timeout seconds")
    # --- Raw-LLM baseline ("why not just ask an LLM?") ---
    parser.add_argument("--llm-baseline", action="store_true",
                        help="also run the naive raw-LLM baseline on the SAME URLs")
    parser.add_argument("--llm-baseline-variant", default=VARIANT_URL_ONLY,
                        choices=[VARIANT_URL_ONLY, VARIANT_URL_AND_TEXT, "both"],
                        help="baseline input: URL only (default), URL+page text, or both")
    parser.add_argument("--llm-model", default=settings.gemini_model,
                        help="Gemini model id for the baseline")
    parser.add_argument("--llm-min-interval", type=float, default=4.2,
                        help="min seconds between baseline API calls (free-tier friendly)")
    parser.add_argument("--llm-baseline-limit", type=int, default=0,
                        help="cap baseline calls to N URLs (balanced per class; 0 = all analyzed)")
    args = parser.parse_args()

    if args.crawl_timeout > 0:
        settings.crawler_timeout_seconds = args.crawl_timeout

    snapshot = json.loads(Path(args.dataset).read_text(encoding="utf-8"))
    benign_urls = [it["url"] for it in snapshot["benign"]["items"]]
    phish_urls = [it["url"] for it in snapshot["phishing"]["items"]]
    if args.limit:
        benign_urls = benign_urls[: args.limit]
        phish_urls = phish_urls[: args.limit]

    print(f"Dataset: {args.dataset} (created {snapshot['created_utc']})")
    print(f"Candidates: {len(benign_urls)} benign, {len(phish_urls)} phishing")

    # --- Resolution pre-check (skip dead URLs; count honestly) --------------
    candidates = [(u, 0) for u in benign_urls] + [(u, 1) for u in phish_urls]
    with ThreadPoolExecutor(max_workers=max(8, args.workers)) as pool:
        resolved_flags = list(pool.map(lambda t: resolves(t[0]), candidates))
    todo = [c for c, ok in zip(candidates, resolved_flags) if ok]
    skipped = {
        "benign": sum(1 for (u, lb), ok in zip(candidates, resolved_flags) if lb == 0 and not ok),
        "phishing": sum(1 for (u, lb), ok in zip(candidates, resolved_flags) if lb == 1 and not ok),
    }
    print(f"Resolution: skipped {skipped['benign']} benign, {skipped['phishing']} phishing (no DNS)")

    # --- Shared clients ------------------------------------------------------
    retriever = RAGRetriever()
    trusted = load_trusted_domains()
    domain_client = DomainIntelClient(enabled=not args.no_domain_intel)
    # Huge TTL: reuse the SAME cached feed the labels came from; never refresh
    # mid-run (a refresh would silently change the with-TI hit rate).
    ti_client = ThreatIntelClient(ttl_seconds=10**9)
    ti_client.check("https://example.com/", "example.com")  # warm the feed once

    # --- Analyze -------------------------------------------------------------
    # Stash page-text excerpts only if the baseline's text variant will need them.
    capture_text = args.llm_baseline and args.llm_baseline_variant in (
        VARIANT_URL_AND_TEXT, "both",
    )
    records: List[Dict] = []
    done = 0
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [
            pool.submit(analyze_one, u, lb, retriever, trusted, domain_client, ti_client, capture_text)
            for u, lb in todo
        ]
        for fut in futures:
            records.append(fut.result())
            done += 1
            if done % 25 == 0 or done == len(futures):
                print(f"  analyzed {done}/{len(futures)}")

    ok = [r for r in records if "error" not in r]
    errors = [r for r in records if "error" in r]
    coverage = {
        "benign": {
            "sampled": len(benign_urls),
            "skipped_unresolved": skipped["benign"],
            "errors": sum(1 for r in errors if r["label"] == 0),
            "analyzed": sum(1 for r in ok if r["label"] == 0),
        },
        "phishing": {
            "sampled": len(phish_urls),
            "skipped_unresolved": skipped["phishing"],
            "errors": sum(1 for r in errors if r["label"] == 1),
            "analyzed": sum(1 for r in ok if r["label"] == 1),
        },
    }

    # --- Metrics (both configs, both positive definitions) ------------------
    y_true = [r["label"] for r in ok]
    metrics_by_config = {
        "no_threat_intel": summarize_bands(y_true, [r["band_no_ti"] for r in ok]),
        "with_threat_intel": summarize_bands(y_true, [r["band_with_ti"] for r in ok]),
    }
    n_analyzed = len(ok)
    availability = {
        "whois_pct": round(100 * sum(r["whois_available"] for r in ok) / n_analyzed, 1) if n_analyzed else 0,
        "dns_pct": round(100 * sum(r["dns_available"] for r in ok) / n_analyzed, 1) if n_analyzed else 0,
        "tls_pct": round(100 * sum(r["tls_available"] for r in ok) / n_analyzed, 1) if n_analyzed else 0,
        "ti_feed_hit_rate_phishing_pct": round(
            100 * sum(r["ti_listed"] for r in ok if r["label"] == 1)
            / max(1, sum(1 for r in ok if r["label"] == 1)), 1),
    }

    # --- Error analysis ------------------------------------------------------
    positive = {BAND_PHISHING}
    fps = sorted(
        (r for r in ok if r["label"] == 0 and r["band_no_ti"] in positive),
        key=lambda r: -r["score_no_ti"],
    )[:10]
    fns = sorted(
        (r for r in ok if r["label"] == 1 and r["band_no_ti"] not in positive),
        key=lambda r: r["score_no_ti"],
    )[:10]
    rescued_by_ti = sum(
        1 for r in ok
        if r["label"] == 1 and r["band_no_ti"] not in positive and r["band_with_ti"] in positive
    )

    # --- Raw-LLM baseline (opt-in; same URLs; clean skip if no key) ----------
    baseline_block = run_llm_baseline(ok, args)

    # --- Write outputs -------------------------------------------------------
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    run_meta = {
        "run_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "dataset": {"path": str(args.dataset), "created_utc": snapshot["created_utc"],
                    "seed": snapshot["seed"]},
        "config": {
            "limit_per_class": args.limit or None,
            "workers": args.workers,
            "domain_intel_enabled": not args.no_domain_intel,
            "crawler_timeout_seconds": settings.crawler_timeout_seconds,
            "threat_intel_in_pipeline": False,
            "with_ti_config": "assess_risk re-scored on identical evidence + cache-only feed check",
        },
        "coverage": coverage,
        "availability": availability,
        "metrics": metrics_by_config,
        "phishing_missed_without_ti_but_caught_with_ti": rescued_by_ti,
        "worst_false_positives": fps,
        "worst_false_negatives": fns,
        "per_url": records,
    }
    if baseline_block is not None:
        run_meta["llm_baseline"] = baseline_block
    json_path = RESULTS_DIR / f"results_{stamp}.json"
    json_path.write_text(json.dumps(run_meta, indent=2, default=str), encoding="utf-8")

    cm_path = RESULTS_DIR / f"confusion_matrices_{stamp}.png"
    dist_path = RESULTS_DIR / f"score_distribution_{stamp}.png"
    plot_confusion_matrices(
        metrics_by_config["no_threat_intel"]["high_risk_positive"]["confusion"],
        metrics_by_config["with_threat_intel"]["high_risk_positive"]["confusion"],
        cm_path,
    )
    plot_score_distribution(ok, dist_path)

    md = [
        "# Evaluation report",
        "",
        f"- Run: {run_meta['run_utc']}  ·  Dataset: `{Path(args.dataset).name}` "
        f"(created {snapshot['created_utc']}, seed {snapshot['seed']})",
        f"- Benign source: {snapshot['benign']['source']}",
        f"- Phishing source: {snapshot['phishing']['source']} "
        f"(feed cached {snapshot['phishing'].get('feed_cached_at_utc')})",
        "- **Leakage control:** the headline config runs the pipeline with threat-intel "
        "lookups DISABLED, because the phishing labels come from that same feed. "
        "The with-TI config re-scores identical evidence plus a cache-only feed check.",
        "",
        "## Coverage (honesty first)",
        "",
        f"| Class | Sampled | Skipped (no DNS) | Errors | Analyzed |",
        f"|---|---|---|---|---|",
        f"| Benign | {coverage['benign']['sampled']} | {coverage['benign']['skipped_unresolved']} "
        f"| {coverage['benign']['errors']} | {coverage['benign']['analyzed']} |",
        f"| Phishing | {coverage['phishing']['sampled']} | {coverage['phishing']['skipped_unresolved']} "
        f"| {coverage['phishing']['errors']} | {coverage['phishing']['analyzed']} |",
        "",
        f"Signal availability on analyzed URLs: WHOIS {availability['whois_pct']}%, "
        f"DNS {availability['dns_pct']}%, TLS {availability['tls_pct']}%. ",
        f"Of analyzed phishing URLs, {availability['ti_feed_hit_rate_phishing_pct']}% were "
        "(still) present in the cached feed at scoring time.",
        "",
        "## Metrics",
        "",
        _fmt_metrics_table(metrics_by_config),
        "",
        f"Phishing URLs missed without threat intel but caught with it: **{rescued_by_ti}**.",
        "",
        f"![Confusion matrices]({cm_path.name})",
        f"![Score distribution]({dist_path.name})",
        "",
        "## Worst false positives (benign flagged High Risk, no-TI config)",
        "",
        _fmt_error_table(fps, "score_no_ti"),
        "",
        "## Worst false negatives (phishing NOT flagged High Risk, no-TI config)",
        "",
        _fmt_error_table(fns, "score_no_ti"),
        "",
        *_fmt_baseline_section(baseline_block),
        "## Limitations",
        "",
        "See `evaluation/README.md` — small sample, live feeds change daily, labels are "
        "not manually verified, non-resolving URLs are excluded from metrics, and the "
        "benign class (popular sites) is easier than hard negatives would be.",
        "",
    ]
    md_path = RESULTS_DIR / f"report_{stamp}.md"
    md_path.write_text("\n".join(md), encoding="utf-8")

    print("\n=== Results ===")
    for config, defs in metrics_by_config.items():
        m = defs["high_risk_positive"]
        print(f"{config:>18} (High Risk +): precision {m['precision']:.3f}  "
              f"recall {m['recall']:.3f}  F1 {m['f1']:.3f}  acc {m['accuracy']:.3f}")
    if baseline_block and baseline_block.get("status") == "ok":
        for vb in baseline_block["variants"]:
            comp = vb.get("comparison")
            if comp:
                m = comp["raw_llm_baseline"]
                print(f"{'raw-LLM ' + vb['variant']:>18} (n={comp['n']}): precision "
                      f"{m['precision']:.3f}  recall {m['recall']:.3f}  F1 {m['f1']:.3f}  "
                      f"acc {m['accuracy']:.3f}  (disagreements {vb['n_disagreements']})")
    elif baseline_block:
        print(f"{'raw-LLM baseline':>18}: {baseline_block.get('note')}")
    print(f"Saved: {json_path}\n       {md_path}\n       {cm_path}\n       {dist_path}")


if __name__ == "__main__":
    main()
