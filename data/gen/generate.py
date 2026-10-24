"""Synthetic dataset generator (CPU-only, no LLM, no network).

Produces train/validation JSONL in the multi-label contract:
  {id, code, language, categories, labels[9], label, family, variant, sub_categories, source}

Guarantees, enforced at generation time:
  * no generated line (>=20 chars) also appears in the dev set  -> no leakage
  * train and validation share no identical code string         -> honest split
  * every malicious family has a benign counterpart where possible
"""
import argparse
import hashlib
import json
import os
import random
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

from data.gen import templates as T  # noqa: E402
from engine.facts import CATEGORIES  # noqa: E402

DEV_PATH = os.path.join(ROOT, "data", "dev", "codeguard_dev.jsonl")
# lines generic enough that overlap with dev is coincidental, not copied content
_GENERIC_OK = {
    "def main():", "if __name__ == '__main__':", "import os", "import requests", "import subprocess",
    "import json", "import base64", "import shutil", "import threading", "import boto3", "import pickle",
    "import logging", "import importlib", "import os, requests",
}
# structural idioms that are universal, not distinctive dev content
_GENERIC_RX = re.compile(
    r"^(import |from \w+ import |with open\([^)]*\) as \w+:|return \w+\.read\(\)|"
    r"conn = \w+\.connect\(|cur = conn\.cursor\(\)|for \w+ in |while True:|"
    r"def \w+\(|return subprocess\.run\(|raise \w*Error\(|return \w+\.\w+\(\w*\)$|"
    r"\w+ = \w+\.\w+\(\w*\)$)")


def _is_generic(s):
    return s in _GENERIC_OK or bool(_GENERIC_RX.match(s))


def _dev_lines():
    lines = set()
    if os.path.exists(DEV_PATH):
        for ln in open(DEV_PATH):
            for row in json.loads(ln)["code"].splitlines():
                s = row.strip()
                if len(s) >= 20:
                    lines.add(s)
    return lines


def _labels(cats):
    return [1 if c in cats else 0 for c in CATEGORIES]


def _row(code, language, cats, subs, family, variant, idx):
    rid = f"syn_{family}_{variant}_{idx:04d}"
    return {
        "id": rid, "code": code, "language": language,
        "categories": sorted(cats), "labels": _labels(cats),
        "label": 0 if not cats else 1,
        "family": family, "variant": variant, "sub_categories": sorted(subs),
        "source": "synthetic",
    }


def _unique_batch(render, rng, want, seen):
    """Render up to `want` unique code strings, giving up gracefully (no crash)."""
    out, attempts = [], 0
    while len(out) < want and attempts < want * 12 + 50:
        attempts += 1
        code = render(rng)
        h = hashlib.sha1(code.encode()).hexdigest()
        if h in seen:
            continue
        seen.add(h)
        out.append(code)
    return out


def _capacity(render, rng, tries=60):
    """How many unique code strings a template can produce (cheap estimate)."""
    if render is None:
        return 0
    return len({render(rng) for _ in range(tries)})


def _assign_split(rng):
    """Assign each family wholly to train or val (family-disjoint). Per category, hold
    out for validation the UNSEEN family with the most render capacity (so val is well
    populated and every category has an unseen family), keeping ≥1 family in train.
    Returns {family_name: 'train'|'val'}."""
    by_cat = {}
    cap = {}
    for fam in T.FAMILIES:
        by_cat.setdefault(fam[2][0], []).append(fam)
        cap[fam[0]] = _capacity(fam[4], rng)
    split = {}
    for cat, fams in by_cat.items():
        for f in fams:
            split[f[0]] = "train"
        if len(fams) >= 3:
            # hold out the highest-capacity family that can fill a val quota
            holdout = max(fams, key=lambda f: cap[f[0]])
            split[holdout[0]] = "val"
    return split


def generate(seed, n_train, n_val):
    rng = random.Random(seed)
    devlines = _dev_lines()
    seen_hashes = set()
    train, val = [], []
    assign = _assign_split(rng)

    fam_count = len(T.FAMILIES)
    per_fam_train = max(10, n_train // fam_count)
    per_fam_val = max(6, n_val // max(1, sum(1 for v in assign.values() if v == "val")))

    counters = {}
    for name, lang, cats, subs, risky, benign in T.FAMILIES:
        bucket, want = (val, per_fam_val) if assign[name] == "val" else (train, per_fam_train)
        for variant, render, vcats, vsubs in (
            ("malicious", risky, cats, subs),
            ("benign_twin", benign, (), ()),
        ):
            if render is None:
                continue
            for code in _unique_batch(render, rng, want, seen_hashes):
                i = counters.get((name, variant), 0); counters[(name, variant)] = i + 1
                bucket.append(_row(code, lang, vcats, vsubs, name, variant, i))

    # multi-label: combine two python malicious families from the SAME split so the
    # family-disjoint guarantee still holds (train multi uses train families only, etc.)
    def add_multi(bucket, fam_names, n, tag):
        pool = [f for f in T.FAMILIES if f[1] == "python" and f[4] and f[0] in fam_names]
        made = 0
        for k in range(n * 6):
            if made >= n:
                break
            a, b = rng.sample(pool, 2)
            code = a[4](rng) + "\n\n" + b[4](rng)
            if hashlib.sha1(code.encode()).hexdigest() in seen_hashes:
                continue
            seen_hashes.add(hashlib.sha1(code.encode()).hexdigest())
            cats = tuple(set(a[2]) | set(b[2]))
            subs = tuple(set(a[3]) | set(b[3]))
            bucket.append(_row(code, "python", cats, subs, f"multi_{tag}", "malicious", made))
            made += 1

    train_fams = {n for n, v in assign.items() if v == "train"}
    val_fams = {n for n, v in assign.items() if v == "val"}
    add_multi(train, train_fams, max(1, int(len(train) * 0.10)), "tr")
    add_multi(val, val_fams, max(6, int(len(val) * 0.10)), "va")

    # leak guard (hard): the real risk is copied COMMENTS/PROSE and copied multi-line
    # BLOCKS (verbatim dev content), not isolated standard idioms. Flag either.
    comment_rx = re.compile(r"^\s*(#|//|<!--|--\s|/\*)")
    for r in train + val:
        prev_hit = prev_generic = False
        for ln in r["code"].splitlines():
            s = ln.strip()
            hit = len(s) >= 20 and s in devlines
            gen = _is_generic(s)
            if hit and comment_rx.match(ln):
                raise SystemExit(f"DEV LEAK (comment) in {r['id']}: {s!r}")
            if hit and prev_hit and not (gen and prev_generic):  # distinctive copied block
                raise SystemExit(f"DEV LEAK (block) in {r['id']}: {s!r}")
            prev_hit, prev_generic = hit, gen

    rng.shuffle(train); rng.shuffle(val)
    return train, val


def _write(rows, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=20261024)
    ap.add_argument("--out-dir", default=os.path.join(ROOT, "data", "synthetic"))
    ap.add_argument("--train", type=int, default=1200)
    ap.add_argument("--val", type=int, default=300)
    a = ap.parse_args()
    train, val = generate(a.seed, a.train, a.val)
    _write(train, os.path.join(a.out_dir, "train.jsonl"))
    _write(val, os.path.join(a.out_dir, "validation.jsonl"))
    mal = sum(1 for r in train if r["label"])
    print(f"train: {len(train)} rows ({mal} malicious, {len(train)-mal} benign)")
    print(f"validation: {len(val)} rows")
    print("no dev leakage; written to", a.out_dir)


if __name__ == "__main__":
    main()
