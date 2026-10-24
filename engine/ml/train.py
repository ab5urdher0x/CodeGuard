"""Train the lightweight multi-label classifier (Phase 4).

Features = symbolic engine features (engine.features) ⊕ TF-IDF char n-grams of the code.
Model    = OneVsRestClassifier(LogisticRegression) over the 9 official categories.
Trains ONLY on data/synthetic/train.jsonl. Never touches dev / validation / challenge.

Run: python engine/ml/train.py
"""
import json
import os
import sys

import joblib
import numpy as np
from scipy.sparse import hstack, csr_matrix
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.multiclass import OneVsRestClassifier
from sklearn.preprocessing import StandardScaler

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

from engine.facts import CATEGORIES  # noqa: E402
from engine.features import FEATURE_NAMES, symbolic_features, vectorize  # noqa: E402
from engine.pipeline import analyze  # noqa: E402

ARTIFACTS = os.path.join(ROOT, "engine", "ml", "artifacts")
TRAIN = os.path.join(ROOT, "data", "synthetic", "train.jsonl")


def featurize(codes):
    """Return (dense symbolic matrix, list of code strings)."""
    sym = []
    for code in codes:
        a = analyze(code)
        sym.append(vectorize(symbolic_features(a, code), FEATURE_NAMES))
    return np.array(sym, dtype=np.float32)


def main():
    rows = [json.loads(l) for l in open(TRAIN) if l.strip()]
    codes = [r["code"] for r in rows]
    Y = np.array([r["labels"] for r in rows], dtype=np.int8)
    print(f"training rows: {len(rows)}  (ONLY {os.path.relpath(TRAIN, ROOT)})")

    sym = featurize(codes)
    scaler = StandardScaler().fit(sym)
    sym_s = scaler.transform(sym)

    tfidf = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=2, max_features=3000)
    tf = tfidf.fit_transform(codes)

    X = hstack([csr_matrix(sym_s), tf]).tocsr()
    clf = OneVsRestClassifier(
        LogisticRegression(max_iter=2000, C=1.0, class_weight="balanced"), n_jobs=-1
    ).fit(X, Y)

    os.makedirs(ARTIFACTS, exist_ok=True)
    joblib.dump(
        {"clf": clf, "scaler": scaler, "tfidf": tfidf, "feature_names": FEATURE_NAMES,
         "categories": list(CATEGORIES), "version": "lr-tfidf-1"},
        os.path.join(ARTIFACTS, "head.joblib"),
    )
    size = os.path.getsize(os.path.join(ARTIFACTS, "head.joblib")) / 1024
    print(f"saved head.joblib ({size:.0f} KB)  features: {sym.shape[1]} symbolic + {tf.shape[1]} tfidf")

    # quick training-fit sanity (NOT a generalization metric)
    P = clf.predict(X)
    exact = (P == Y).all(axis=1).mean()
    print(f"train exact-match (fit sanity, not generalization): {exact:.3f}")


if __name__ == "__main__":
    main()
