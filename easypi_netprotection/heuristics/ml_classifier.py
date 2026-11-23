"""Character n-gram language model of domain names — the engine's learned brain for
"does this name look like real language / a brand, or like machine-generated
gibberish?".

This is a genuine (character-level) language model: it is TRAINED on real domain
names and learns the probability of character sequences. A name the model finds very
unlikely scores high on `gibberish`. It powers DGA / gibberish detection, replacing
the old hand-coded list of "common bigrams" + a fixed entropy cut-off. It is the one
place that does learned sequence modelling — it does not re-compute the entropy /
length / keyword features the other detectors already produce.

Runtime inference is pure stdlib: average log-probability of the name's n-grams.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

MODEL_FILENAME = "ml_domain_model.json"
MODEL_KIND = "char_ngram_lm"  # guards against loading an old (different) model file
NGRAM_VERSION = 1
N = 3
_PAD = "^"
_END = "$"


def domain_core(domain: str) -> str:
    """The label we model — the registrable label (e.g. 'amazon' from 'm.amazon.de')."""
    d = (domain or "").lower().strip().rstrip(".")
    if not d:
        return ""
    labels = d.split(".")
    return labels[-2] if len(labels) >= 2 else labels[0]


def char_ngrams(text: str, n: int = N) -> list[str]:
    if not text:
        return []
    s = _PAD * (n - 1) + text + _END
    return [s[i:i + n] for i in range(len(s) - n + 1)]


class CharNGramModel:
    """Loads the trained n-gram log-prob table; pure-stdlib scoring. Auto-reloads."""

    def __init__(self, data_dir: str | Path):
        self._path = Path(data_dir) / MODEL_FILENAME
        self._m: dict | None = None
        self._mtime_ns: int | None = None
        self._reload()

    def _reload(self) -> None:
        try:
            st = self._path.stat()
        except FileNotFoundError:
            self._m = None
            self._mtime_ns = None
            return
        if self._mtime_ns == st.st_mtime_ns:
            return
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            if data.get("kind") == MODEL_KIND and data.get("ngram_version") == NGRAM_VERSION:
                self._m = data
                self._mtime_ns = st.st_mtime_ns
        except Exception:
            pass

    @property
    def available(self) -> bool:
        self._reload()
        return self._m is not None

    def avg_logprob(self, domain: str) -> float | None:
        self._reload()
        m = self._m
        if not m:
            return None
        grams = char_ngrams(domain_core(domain), m.get("n", N))
        if not grams:
            return None
        logp = m["logp"]
        default = m["default"]
        return sum(logp.get(g, default) for g in grams) / len(grams)

    def gibberish_score(self, domain: str) -> float:
        """0.0 = looks like real language; 1.0 = looks machine-generated."""
        m = self._m
        a = self.avg_logprob(domain)
        if m is None or a is None:
            return 0.0
        hi = m["benign_mean"]          # typical real-domain likelihood
        lo = m["threshold_logp"]       # below this we call it gibberish
        if a >= hi:
            return 0.0
        if a <= lo:
            return 1.0
        return round((hi - a) / (hi - lo), 4) if hi > lo else 0.0

    def is_gibberish(self, domain: str) -> bool:
        m = self._m
        a = self.avg_logprob(domain)
        return bool(m) and a is not None and a < m["threshold_logp"]


_model: CharNGramModel | None = None
_lock = threading.Lock()


def get_domain_ml_model(data_dir: str | Path) -> CharNGramModel:
    global _model
    if _model is None:
        with _lock:
            if _model is None:
                _model = CharNGramModel(data_dir)
    return _model
