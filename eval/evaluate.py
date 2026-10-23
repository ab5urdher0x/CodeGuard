#!/usr/bin/env python
"""CodeGuard evaluation: verdict + multi-label category metrics. Stdlib only.

Snippets are only ever passed as strings to the analyzer (or POSTed); never executed.
"""
import argparse
import json
import os
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

CATEGORIES = (
    "secret_access", "data_exfiltration", "destructive_command", "persistence_or_privesc",
    "obfuscated_execution", "dependency_risk", "resource_exhaustion", "ssrf_network_exfil",
    "ai_targeted_instructions",
)


def _categories():
    try:
        from engine.facts import CATEGORIES as C
        return tuple(C)
    except Exception:
        return CATEGORIES


# ---------------------------------------------------------------- ground truth
def normalize_row(row, cats=None):
    """Return (is_positive, set_of_categories) for either supported row format."""
    cats = cats or _categories()
    positive = bool(int(row.get("label", 0)))
    found = set()
    labels = row.get("labels")
    if isinstance(labels, (list, tuple)) and len(labels) == len(cats):
        found = {c for c, v in zip(cats, labels) if v}
    elif isinstance(row.get("categories"), (list, tuple)):
        found = {str(c).strip() for c in row["categories"] if str(c).strip()}
    elif isinstance(row.get("category"), str):
        found = {c.strip() for c in row["category"].split(",") if c.strip()}
    found.discard("benign")
    if not positive:
        found = set()
    return positive, found


def load_rows(path):
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


# ---------------------------------------------------------------- validation
def validate_response(r):
    """Return list of schema problems (empty = valid)."""
    errs = []
    if not isinstance(r, dict):
        return ["response is not an object"]
    if r.get("verdict") not in ("allow", "block"):
        errs.append("verdict not in {allow, block}")
    rs = r.get("risk_score")
    if isinstance(rs, bool) or not isinstance(rs, (int, float)) or not 0.0 <= rs <= 1.0:
        errs.append("risk_score not a number in [0,1]")
    c = r.get("categories")
    if not isinstance(c, list) or not all(isinstance(x, str) for x in c):
        errs.append("categories not list[str]")
    if not isinstance(r.get("code_language"), str):
        errs.append("code_language not str")
    if "reason" in r and r["reason"] is not None and not isinstance(r["reason"], str):
        errs.append("reason not str")
    vl = r.get("vulnerable_lines")
    if vl is not None and (not isinstance(vl, list)
                           or not all(isinstance(x, int) and not isinstance(x, bool) for x in vl)):
        errs.append("vulnerable_lines not list[int]")
    return errs


# ---------------------------------------------------------------- metrics
def _div(a, b):
    return a / b if b else 0.0


def prf(tp, fp, fn):
    p, r = _div(tp, tp + fp), _div(tp, tp + fn)
    return p, r, _div(2 * p * r, p + r)


def verdict_counts(items):
    tp = sum(1 for i in items if i["truth_pos"] and i["pred_pos"])
    fp = sum(1 for i in items if not i["truth_pos"] and i["pred_pos"])
    tn = sum(1 for i in items if not i["truth_pos"] and not i["pred_pos"])
    fn = sum(1 for i in items if i["truth_pos"] and not i["pred_pos"])
    p, r, f1 = prf(tp, fp, fn)
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "precision": p, "recall": r, "f1": f1,
            "fpr": _div(fp, fp + tn), "accuracy": _div(tp + tn, len(items)), "n": len(items)}


def category_metrics(items, cats):
    out = {}
    for c in cats:
        tp = sum(1 for i in items if c in i["truth_cats"] and c in i["pred_cats"])
        fp = sum(1 for i in items if c not in i["truth_cats"] and c in i["pred_cats"])
        fn = sum(1 for i in items if c in i["truth_cats"] and c not in i["pred_cats"])
        p, r, f1 = prf(tp, fp, fn)
        out[c] = {"tp": tp, "fp": fp, "fn": fn, "precision": p, "recall": r, "f1": f1,
                  "support": tp + fn}
    return out


def exact_match_rate(items):
    pos = [i for i in items if i["truth_pos"]]
    return _div(sum(1 for i in pos if i["truth_cats"] == i["pred_cats"]), len(pos)), len(pos)


def percentile(vals, q):
    if not vals:
        return 0.0
    s = sorted(vals)
    k = (len(s) - 1) * q
    lo = int(k)
    hi = min(lo + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


def latency_stats(vals):
    return {"p50": percentile(vals, 0.5), "p95": percentile(vals, 0.95), "max": max(vals) if vals else 0.0}


# ---------------------------------------------------------------- running
def make_local():
    from engine.pipeline import evaluate
    return evaluate


def make_remote(url):
    endpoint = url.rstrip("/")
    if not endpoint.endswith("/evaluate"):
        endpoint += "/evaluate"

    def call(code):
        req = urllib.request.Request(endpoint, data=json.dumps({"code": code}).encode(),
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read().decode())
    return call


def run(rows, call, cats=None):
    cats = cats or _categories()
    items, schema_failures = [], []
    for idx, row in enumerate(rows):
        truth_pos, truth_cats = normalize_row(row, cats)
        t0 = time.perf_counter()
        try:
            resp = call(row.get("code", ""))
            err = validate_response(resp)
        except Exception as e:  # network / engine crash
            resp, err = {}, ["request failed: %s" % e]
        wall = (time.perf_counter() - t0) * 1000
        rid = row.get("id", "row%d" % idx)
        if err:
            schema_failures.append((rid, err))
        ok = isinstance(resp, dict)
        lat = resp.get("latency_ms") if ok else None
        if isinstance(lat, bool) or not isinstance(lat, (int, float)):
            lat = wall
        # an invalid/missing verdict counts as allow so it can never inflate precision
        pred_pos = ok and resp.get("verdict") == "block"
        pc = resp.get("categories") if ok else None
        pred_cats = {c for c in pc if isinstance(c, str)} if isinstance(pc, list) else set()
        lang = row.get("language") or (resp.get("code_language") if ok else None) or "unknown"
        items.append({
            "id": rid, "language": str(lang),
            "truth_pos": truth_pos, "truth_cats": truth_cats, "pred_pos": pred_pos, "pred_cats": pred_cats,
            "risk": resp.get("risk_score") if ok else None,
            "reason": resp.get("reason") if ok else "", "latency": float(lat),
        })
    return items, schema_failures


def compute(items, cats=None):
    cats = cats or _categories()
    langs = {}
    for i in items:
        langs.setdefault(i["language"], []).append(i)
    em, npos = exact_match_rate(items)
    return {
        "verdict": verdict_counts(items), "categories": category_metrics(items, cats),
        "exact": em, "n_pos": npos,
        "languages": {k: verdict_counts(v) for k, v in sorted(langs.items())},
        "latency": latency_stats([i["latency"] for i in items]),
    }


def misses(items):
    out = []
    for i in items:
        if i["truth_pos"] and not i["pred_pos"]:
            kind = "FN"
        elif not i["truth_pos"] and i["pred_pos"]:
            kind = "FP"
        elif i["truth_pos"] and i["truth_cats"] != i["pred_cats"]:
            kind = "CAT"
        else:
            continue
        out.append((kind, i))
    return out


# ---------------------------------------------------------------- rendering
def _f(x):
    return "%.3f" % x


def _cell(s):
    return str(s).replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def render_markdown(m, schema_failures, items, title="CodeGuard evaluation"):
    v = m["verdict"]
    L = ["# %s" % title, ""]
    if schema_failures:
        L += ["## SCHEMA FAILURES: %d" % len(schema_failures), ""]
        L += ["- `%s`: %s" % (rid, "; ".join(e)) for rid, e in schema_failures[:50]] + [""]
    else:
        L += ["Schema failures: 0", ""]
    L += ["## Verdict (n=%d)" % v["n"], "",
          "| TP | FP | TN | FN | precision | recall | F1 | FPR | accuracy |",
          "|---|---|---|---|---|---|---|---|---|",
          "| %d | %d | %d | %d | %s | %s | %s | %s | %s |" % (
              v["tp"], v["fp"], v["tn"], v["fn"], _f(v["precision"]), _f(v["recall"]), _f(v["f1"]),
              _f(v["fpr"]), _f(v["accuracy"])), ""]
    L += ["## Per-category", "",
          "| category | support | TP | FP | FN | precision | recall | F1 |", "|---|---|---|---|---|---|---|---|"]
    for c, x in m["categories"].items():
        L.append("| %s | %d | %d | %d | %d | %s | %s | %s |" % (
            c, x["support"], x["tp"], x["fp"], x["fn"], _f(x["precision"]), _f(x["recall"]), _f(x["f1"])))
    L += ["", "Exact category-set match on positive rows: %s (%d rows)" % (_f(m["exact"]), m["n_pos"]), ""]
    L += ["## Per-language", "",
          "| language | n | TP | FP | TN | FN | precision | recall | F1 | accuracy |",
          "|---|---|---|---|---|---|---|---|---|---|"]
    for k, x in m["languages"].items():
        L.append("| %s | %d | %d | %d | %d | %d | %s | %s | %s | %s |" % (
            k, x["n"], x["tp"], x["fp"], x["tn"], x["fn"], _f(x["precision"]), _f(x["recall"]),
            _f(x["f1"]), _f(x["accuracy"])))
    t = m["latency"]
    L += ["", "## Latency (ms)", "", "p50 %.2f | p95 %.2f | max %.2f" % (t["p50"], t["p95"], t["max"]), ""]
    L += render_misses(items)
    return "\n".join(L) + "\n"


def render_misses(items):
    ms = misses(items)
    L = ["## Misses (%d)" % len(ms), "",
         "| kind | id | language | truth | predicted | categories | risk | reason |",
         "|---|---|---|---|---|---|---|---|"]
    for kind, i in ms:
        risk = "%.2f" % i["risk"] if isinstance(i["risk"], (int, float)) else "-"
        L.append("| %s | %s | %s | %s | %s | %s | %s | %s |" % (
            kind, _cell(i["id"]), _cell(i["language"]),
            _cell(",".join(sorted(i["truth_cats"])) or "benign"),
            "block" if i["pred_pos"] else "allow", _cell(",".join(sorted(i["pred_cats"])) or "-"),
            risk, _cell((i["reason"] or "")[:100])))
    return L + [""]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data", default="data/dev/codeguard_dev.jsonl")
    ap.add_argument("--url", help="base URL of a running server (POSTs to /evaluate)")
    ap.add_argument("--out", default="eval/results.md")
    ap.add_argument("--show-misses", action="store_true")
    a = ap.parse_args(argv)

    data = a.data if os.path.isabs(a.data) or os.path.exists(a.data) else os.path.join(ROOT, a.data)
    rows = load_rows(data)
    call = make_remote(a.url) if a.url else make_local()
    items, fails = run(rows, call)
    m = compute(items)
    md = render_markdown(m, fails, items, "CodeGuard evaluation (%s)" % os.path.basename(a.data))
    if fails:
        print("!" * 60 + "\n!! SCHEMA FAILURES: %d of %d responses" % (len(fails), len(items)))
        for rid, e in fails[:20]:
            print("!!  %s: %s" % (rid, "; ".join(e)))
        print("!" * 60)
    print(md if a.show_misses else md.split("## Misses")[0])
    out = a.out if os.path.isabs(a.out) else os.path.join(os.getcwd(), a.out)
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        f.write(md)
    print("wrote %s" % a.out)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
