"""Build a reproducible evaluation dataset snapshot (real labels only).

Ground truth:
  * **Benign**: a seeded random sample from the top of the Tranco top-sites
    list (https://tranco-list.eu) — a research-oriented ranking of popular
    domains. Popularity is used as a proxy for legitimacy (see README for the
    limits of that assumption).
  * **Phishing**: a seeded random sample of URLs from the OpenPhish public feed,
    via the project's own threat-intel cache (``src/threat_intel.py``).

No labels are synthesized. The exact sampled items, sources, seed, and
timestamps are written to a snapshot JSON so a run can be reproduced and
audited. Snapshots are git-ignored because they contain live phishing URLs.

Usage:
    python -m evaluation.build_dataset [--benign-n 300] [--phish-n 300]
                                       [--benign-pool 10000] [--seed 42]
"""

from __future__ import annotations

import argparse
import io
import json
import random
import sys
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path

# Allow running as a script from the repo root.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.config import settings  # noqa: E402
from src.threat_intel import ThreatIntelClient  # noqa: E402

EVAL_DATA_DIR = Path(__file__).resolve().parent / "data"
CACHE_DIR = EVAL_DATA_DIR / "cache"
TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
TRANCO_CSV = CACHE_DIR / "tranco_top1m.csv"
TRANCO_META = CACHE_DIR / "tranco_meta.json"
TRANCO_TTL_SECONDS = 7 * 24 * 3600  # weekly list; refresh at most weekly


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def download_tranco() -> tuple[Path, str]:
    """Download (or reuse a cached copy of) the Tranco top-1m list.

    Returns ``(csv_path, provenance_note)``. GET-only, bounded; falls back to a
    stale cache when the network is unavailable.
    """
    fresh = False
    try:
        meta = json.loads(TRANCO_META.read_text(encoding="utf-8"))
        fresh = (time.time() - float(meta.get("fetched_at", 0))) < TRANCO_TTL_SECONDS
    except (OSError, ValueError):
        pass

    if fresh and TRANCO_CSV.exists():
        return TRANCO_CSV, "cached copy (fresh)"

    try:
        import httpx

        print(f"Downloading Tranco list from {TRANCO_URL} ...")
        resp = httpx.get(
            TRANCO_URL,
            timeout=120,
            follow_redirects=True,
            headers={"User-Agent": settings.crawler_user_agent},
        )
        resp.raise_for_status()
        with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
            csv_name = next(n for n in zf.namelist() if n.endswith(".csv"))
            CACHE_DIR.mkdir(parents=True, exist_ok=True)
            TRANCO_CSV.write_bytes(zf.read(csv_name))
        TRANCO_META.write_text(
            json.dumps({"fetched_at": time.time(), "source_url": TRANCO_URL}),
            encoding="utf-8",
        )
        return TRANCO_CSV, "downloaded fresh"
    except Exception as exc:  # noqa: BLE001 - fall back to stale cache
        if TRANCO_CSV.exists():
            print(f"WARNING: Tranco download failed ({exc}); using stale cached copy.")
            return TRANCO_CSV, f"stale cache (download failed: {exc})"
        raise SystemExit(
            f"ERROR: Tranco download failed and no cached copy exists: {exc}"
        ) from exc


def load_top_domains(csv_path: Path, pool_size: int) -> list[tuple[int, str]]:
    """Read the first ``pool_size`` (rank, domain) rows of the Tranco CSV."""
    rows: list[tuple[int, str]] = []
    with csv_path.open(encoding="utf-8") as fh:
        for line in fh:
            rank_str, _, domain = line.strip().partition(",")
            if not domain:
                continue
            rows.append((int(rank_str), domain.lower()))
            if len(rows) >= pool_size:
                break
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benign-n", type=int, default=300, help="benign sample size")
    parser.add_argument("--phish-n", type=int, default=300, help="phishing sample size")
    parser.add_argument(
        "--benign-pool", type=int, default=10_000,
        help="sample benign domains from the top-N of the Tranco list",
    )
    parser.add_argument("--seed", type=int, default=42, help="sampling seed")
    args = parser.parse_args()

    rng = random.Random(args.seed)
    EVAL_DATA_DIR.mkdir(parents=True, exist_ok=True)

    # --- Benign: Tranco ---
    csv_path, tranco_note = download_tranco()
    pool = load_top_domains(csv_path, args.benign_pool)
    if len(pool) < args.benign_n:
        raise SystemExit(f"Tranco pool too small: {len(pool)} < {args.benign_n}")
    benign_sample = sorted(rng.sample(pool, args.benign_n), key=lambda r: r[0])

    # --- Phishing: OpenPhish feed via the project's threat-intel cache ---
    ti = ThreatIntelClient()
    feed = ti.feed_urls()
    if not feed:
        raise SystemExit(
            "ERROR: OpenPhish feed unavailable (offline and no cache). "
            "Run once with network access to populate data/threat_cache/."
        )
    phish_sample = rng.sample(feed, min(args.phish_n, len(feed)))
    fetched_at = ti.cache_fetched_at()
    feed_cached_iso = (
        datetime.fromtimestamp(fetched_at, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        if fetched_at
        else None
    )

    snapshot = {
        "created_utc": _now_iso(),
        "seed": args.seed,
        "benign": {
            "source": f"Tranco top-sites list ({TRANCO_URL})",
            "provenance": tranco_note,
            "sampling": f"seeded random sample of {args.benign_n} from the top {args.benign_pool} ranks",
            "label_assumption": "popular domains are treated as benign (NOT manually verified)",
            "count": len(benign_sample),
            "items": [
                {"rank": rank, "domain": domain, "url": f"https://{domain}/"}
                for rank, domain in benign_sample
            ],
        },
        "phishing": {
            "source": "OpenPhish public feed (via data/threat_cache/)",
            "feed_cached_at_utc": feed_cached_iso,
            "feed_size_at_build": len(feed),
            "sampling": f"seeded random sample of {min(args.phish_n, len(feed))} of {len(feed)} feed URLs",
            "label_assumption": "feed entries are treated as phishing (NOT manually verified)",
            "count": len(phish_sample),
            "items": [{"url": u} for u in phish_sample],
        },
    }

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_path = EVAL_DATA_DIR / f"dataset_{stamp}.json"
    out_path.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
    latest = EVAL_DATA_DIR / "dataset_latest.json"
    latest.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")

    print(f"Benign : {len(benign_sample)} domains ({tranco_note})")
    print(f"Phish  : {len(phish_sample)} URLs (feed size {len(feed)}, cached {feed_cached_iso})")
    print(f"Saved  : {out_path}")
    print(f"         {latest} (copy)")


if __name__ == "__main__":
    main()
