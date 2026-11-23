"""Trainer for the domain character n-gram language model (heuristics.ml_classifier).

Pure Python, single source of the training logic — used by the offline script and by
the LIVE on-device auto-retrainer. It learns from REAL (benign) domain names what a
"natural" name looks like; a name whose character sequences are far less likely than
normal is flagged as gibberish. The global blocklist is NOT needed to train it (the
model describes normal names, not bad ones).

A retrain only replaces the live model if its gate passes: well-known sites must stay
"natural" (no false positives) and obvious random strings must be flagged (it works).
Nothing leaves the device.
"""

from __future__ import annotations

import json
import math
import os
import random
import sqlite3
import time
from pathlib import Path

from .ml_classifier import (
    domain_core, char_ngrams, MODEL_FILENAME, MODEL_KIND, NGRAM_VERSION, N,
)

BENIGN_SEED = Path(__file__).parent / "ml_benign_seed.txt"

# Real names/brands that MUST stay "natural" after any retrain (no false positives).
GATE_NATURAL = [
    "amazon.de", "otto.de", "ebay.de", "google.com", "microsoft.com", "cloudflare.com",
    "github.com", "wikipedia.org", "apple.com", "paypal.com", "netflix.com",
    "sparkasse.de", "claude.ai", "chatgpt.com", "yandex.ru", "tagesschau.de",
    "adidas.de", "spotify.com", "telegram.org", "booking.com",
]
# Obvious machine-generated cores that SHOULD be flagged (proves the model works).
GATE_GIBBERISH = [
    "x8k9m2z1q", "qwxkjhgfdsa", "kjqwehrlksjdf", "a1b2c3d4e5f6g7",
    "zxcvbnmqwert", "pwqkxznvbmrt", "f7g2h9k1m4",
]


def load_lines(path) -> list[str]:
    out = []
    try:
        with open(path, encoding="utf-8") as f:
            for ln in f:
                ln = ln.strip().lower()
                if ln and not ln.startswith("#"):
                    out.append(ln.split()[-1])
    except FileNotFoundError:
        pass
    return out


def train(benign_domains, *, k: float = 0.5, low_percentile: float = 3.0) -> dict | None:
    """Build the n-gram log-prob table from benign domains, calibrate the gibberish
    threshold, and gate it. Returns a model dict, or None if the gate fails."""
    cores = [c for c in (domain_core(d) for d in benign_domains) if len(c) >= 3]
    cores = list(dict.fromkeys(cores))
    if len(cores) < 100:
        return None

    counts: dict[str, int] = {}
    total = 0
    for c in cores:
        for g in char_ngrams(c, N):
            counts[g] = counts.get(g, 0) + 1
            total += 1
    if total == 0:
        return None
    V = len(counts)
    logp = {g: math.log((cnt + k) / (total + k * V)) for g, cnt in counts.items()}
    default = math.log(k / (total + k * V))

    def avg_logp(core: str):
        grams = char_ngrams(core, N)
        if not grams:
            return None
        return sum(logp.get(g, default) for g in grams) / len(grams)

    benign_logps = sorted(x for x in (avg_logp(c) for c in cores) if x is not None)
    benign_mean = sum(benign_logps) / len(benign_logps)
    idx = max(0, int(len(benign_logps) * low_percentile / 100.0) - 1)
    threshold_logp = benign_logps[idx]
    if threshold_logp >= benign_mean:
        threshold_logp = benign_mean - 0.1

    def gscore(core: str) -> float:
        a = avg_logp(core)
        if a is None or a >= benign_mean:
            return 0.0
        if a <= threshold_logp or benign_mean <= threshold_logp:
            return 1.0
        return (benign_mean - a) / (benign_mean - threshold_logp)

    # ---- gate ----
    # real sites must look clearly natural (no false positives), or reject the model
    for d in GATE_NATURAL:
        if gscore(domain_core(d)) >= 0.3:
            return None
    # and obvious random strings must be flagged, or the model is useless -> reject
    caught = sum(1 for g in GATE_GIBBERISH if gscore(g) >= 0.8)
    if caught < len(GATE_GIBBERISH) - 1:
        return None

    return {
        "kind": MODEL_KIND, "ngram_version": NGRAM_VERSION, "n": N,
        "logp": logp, "default": default,
        "benign_mean": benign_mean, "threshold_logp": threshold_logp,
        "trained_at": time.time(), "n_benign": len(cores),
        "gibberish_caught": caught, "gibberish_total": len(GATE_GIBBERISH),
    }


def _flow_log_allowed(data_dir) -> list[str]:
    db = Path(data_dir) / "flow_log.db"
    if not db.exists():
        return []
    try:
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=4)
        try:
            return [r[0].strip().lower() for r in con.execute(
                "SELECT DISTINCT domain FROM flow_log WHERE status NOT IN ('blocked')") if r[0]]
        finally:
            con.close()
    except Exception:
        return []


def train_on_device(data_dir) -> dict:
    """Retrain the language model on this box: benign seed + the domains THIS network
    actually visited. Atomically replaces the model only if the gate passes."""
    data_dir = Path(data_dir)
    # Corpus of REAL registered names (the LM models name-shape, not good/bad):
    # bundled seed + this network's own visited domains + a sample of the blocklist
    # (also real registered names — gives the vocabulary volume). DGA/random names
    # are the rare outliers the model will then score as gibberish.
    real = load_lines(BENIGN_SEED) + _flow_log_allowed(data_dir)
    bl = data_dir / "effective_blocklist.txt"
    if bl.exists():
        names = load_lines(bl)
        if len(names) > 8000:
            names = random.Random(42).sample(names, 8000)
        real += names
    model = train(real)
    if not model:
        return {"success": False, "error": "gate failed or too little data; kept previous model"}
    out = data_dir / MODEL_FILENAME
    tmp = out.with_name(out.name + ".tmp")
    tmp.write_text(json.dumps(model), encoding="utf-8")
    os.replace(tmp, out)
    return {"success": True, "n_benign": model["n_benign"],
            "gibberish_caught": "%d/%d" % (model["gibberish_caught"], model["gibberish_total"])}


def _random_core(rng: random.Random) -> str:
    """A machine-generated-looking label (what a DGA / junk domain looks like)."""
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(rng.choice(alphabet) for _ in range(rng.randint(8, 15)))


def evaluate(data_dir, *, benign_sample: int = 2000, gibberish_n: int = 300) -> dict:
    """Score the LIVE model's quality on this box. Two honest, plain-language numbers:

    * how often it leaves the REAL domains this network actually visits alone
      (no false alarms), and
    * how often it flags obvious machine-generated / DGA gibberish (it works).

    Read-only: loads the current model and scores samples in memory. No training,
    no writes, nothing leaves the device.
    """
    from .ml_classifier import CharNGramModel

    model = CharNGramModel(data_dir)
    if not model.available:
        return {"available": False}
    rng = random.Random(1234)

    # Real domains this network visited (deduped). Falls back to known brands when
    # the box has barely any traffic yet, so the number is never empty/misleading.
    benign = list(dict.fromkeys(d for d in _flow_log_allowed(data_dir) if domain_core(d)))
    if len(benign) > benign_sample:
        benign = rng.sample(benign, benign_sample)
    used_real_traffic = len(benign) >= 20
    if not used_real_traffic:
        benign = list(GATE_NATURAL)
    b_tested = len(benign)
    b_flagged = sum(1 for d in benign if model.is_gibberish(d))

    # Obvious gibberish that SHOULD be caught: the fixed gate set + fresh random labels.
    gib = list(GATE_GIBBERISH) + [_random_core(rng) for _ in range(gibberish_n)]
    g_tested = len(gib)
    g_caught = sum(1 for g in gib if model.is_gibberish(g))

    return {
        "available": True,
        "benign_tested": b_tested,
        "benign_flagged": b_flagged,
        "benign_from_traffic": used_real_traffic,
        "clean_pass_rate": round(100.0 * (b_tested - b_flagged) / b_tested, 1) if b_tested else None,
        "false_positive_rate": round(100.0 * b_flagged / b_tested, 2) if b_tested else None,
        "gibberish_tested": g_tested,
        "gibberish_caught": g_caught,
        "detection_rate": round(100.0 * g_caught / g_tested, 1) if g_tested else None,
    }
