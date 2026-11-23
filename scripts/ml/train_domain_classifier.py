#!/usr/bin/env python3
"""Offline trainer for the domain character n-gram LANGUAGE MODEL.

Thin wrapper around easypi_netprotection.heuristics.ml_trainer.train (the single
source of training logic, also used by the live on-device auto-retrainer). Learns
'what a natural domain name looks like' from benign domains and writes
data/ml_train/ml_domain_model.json. Pure Python; no numpy/sklearn.
"""
import json
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, ROOT)
from easypi_netprotection.heuristics.ml_trainer import train, load_lines, BENIGN_SEED  # noqa: E402
from easypi_netprotection.heuristics.ml_classifier import (  # noqa: E402
    CharNGramModel, MODEL_FILENAME,
)

NEG_FILE = os.path.join(ROOT, "data", "ml_train", "negatives_server.txt")
POS_FILE = os.path.join(ROOT, "data", "ml_train", "positives_server.txt")  # blocklist sample = real names too
OUT_DIR = os.path.join(ROOT, "data", "ml_train")


def main():
    corpus = load_lines(POS_FILE) + load_lines(NEG_FILE) + load_lines(BENIGN_SEED)
    print("real-name training corpus: %d" % len(corpus))
    model = train(corpus)
    if model is None:
        print("GATE_FAILED — model NOT written")
        return 1
    with open(os.path.join(OUT_DIR, MODEL_FILENAME), "w", encoding="utf-8") as f:
        json.dump(model, f)
    print("wrote model: n_benign=%d  gibberish_caught=%d/%d  threshold_logp=%.3f  benign_mean=%.3f"
          % (model["n_benign"], model["gibberish_caught"], model["gibberish_total"],
             model["threshold_logp"], model["benign_mean"]))

    # quick demo of the trained language model
    m = CharNGramModel(OUT_DIR)
    print("-- gibberish score (0 natural .. 1 gibberish) --")
    for d in ["amazon.de", "otto.de", "google.com", "sparkasse.de", "tagesschau.de",
              "x8k9m2z1q.cn", "kjqwehrlksjdf.com", "a1b2c3d4e5f6.net", "pwqkxznvbmrt.xyz"]:
        print("   %-24s %.2f" % (d, m.gibberish_score(d)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
