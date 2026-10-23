"""Shadow-mode ML evaluation (Phase 4).

Runs the ML head ALONGSIDE the rules without letting it change the live verdict, and
compares A (rules only) vs B (rules+ML fused) on every dataset. The live /evaluate is
untouched. Reports whether ML catches rule-missed risks and whether it adds FPs.
"""
import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from engine import aggregator  # noqa: E402
from engine.features import symbolic_features  # noqa: E402
from engine.ml.fusion import FusionModel  # noqa: E402
from engine.pipeline import analyze  # noqa: E402

SETS = {
    "dev(42)": "data/dev/codeguard_dev.jsonl",
    "val(581)": "data/synthetic/validation.jsonl",
    "challenge(25)": "data/challenge/challenge.jsonl",
    "holdout2(30)*": "data/challenge/holdout2.jsonl",  # independent, never tuned on
}


def truth(row):
    if "label" in row and isinstance(row.get("category"), str):
        cats = set() if row["category"] == "benign" else {c.strip() for c in row["category"].split(",")}
        return int(row["label"]), cats
    return int(row.get("label", 0)), set(row.get("categories", []))


def verdict_of(resp):
    return 1 if resp["verdict"] == "block" else 0


def score(rows, use_ml):
    model = FusionModel.get() if use_ml else None
    tp = fp = tn = fn = 0
    ml_saved, ml_added = [], []  # rule miss that ML catches / benign that ML newly blocks
    lat = []
    for r in rows:
        y, _ = truth(r)
        t0 = time.perf_counter()
        a = analyze(r["code"])
        probs = None
        if model is not None:
            sym_risk = aggregator.overall_risk(aggregator.category_scores(a.findings))
            lo, hi = aggregator.AMBIGUOUS_BAND
            if lo <= sym_risk <= hi:
                probs = model.predict(r["code"], a.language, symbolic_features(a, r["code"]))
        resp = aggregator.build_response(a, probs)
        lat.append((time.perf_counter() - t0) * 1000)
        p = verdict_of(resp)
        # compare to rules-only verdict to spot ML-driven changes
        if model is not None:
            rules_p = verdict_of(aggregator.build_response(a, None))
            if p == 1 and rules_p == 0 and y == 1:
                ml_saved.append(r.get("id"))
            if p == 1 and rules_p == 0 and y == 0:
                ml_added.append(r.get("id"))
        if p and y:
            tp += 1
        elif p and not y:
            fp += 1
        elif not p and not y:
            tn += 1
        else:
            fn += 1
    n = len(rows)
    prec = tp / (tp + fp) if tp + fp else 1.0
    rec = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    lat.sort()
    p95 = lat[int(len(lat) * 0.95)] if lat else 0
    return dict(n=n, tp=tp, fp=fp, tn=tn, fn=fn, prec=prec, rec=rec, f1=f1, fpr=fpr,
               p95=p95, ml_saved=ml_saved, ml_added=ml_added)


def main():
    print(f"ML head: {'loaded' if FusionModel.get() else 'MISSING'}  (* = independent, never tuned on)\n")
    header = f"{'dataset':15} {'mode':10} {'P':>5} {'R':>5} {'F1':>5} {'FPR':>6} {'FP':>3} {'FN':>3} {'p95ms':>6}"
    print(header); print("-" * len(header))
    for name, path in SETS.items():
        rows = [json.loads(l) for l in open(os.path.join(ROOT, path)) if l.strip()]
        for mode, use_ml in (("rules", False), ("rules+ML", True)):
            s = score(rows, use_ml)
            print(f"{name:15} {mode:10} {s['prec']:5.3f} {s['rec']:5.3f} {s['f1']:5.3f} "
                  f"{s['fpr']:6.3f} {s['fp']:3d} {s['fn']:3d} {s['p95']:6.2f}")
            if use_ml and (s["ml_saved"] or s["ml_added"]):
                print(f"{'':15}  -> ML changed verdict: caught {len(s['ml_saved'])} rule-missed, "
                      f"added {len(s['ml_added'])} new FPs {s['ml_added'] or ''}")
        print()


if __name__ == "__main__":
    main()
