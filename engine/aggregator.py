"""Combine findings (+ optional neural probabilities) into the response schema."""
import os
from collections import defaultdict

from engine.facts import CATEGORIES, Analysis, Finding

BLOCK_THRESHOLD = float(os.getenv("CODEGUARD_BLOCK_THRESHOLD", "0.6"))
REPORT_THRESHOLD = 0.5     # a category is reported only with its own evidence above this
LINE_THRESHOLD = 0.4
AMBIGUOUS_BAND = (0.25, 0.75)  # neural head runs only inside this band (locked decision)


def category_scores(findings: list[Finding]) -> dict[str, float]:
    """Noisy-OR per category, de-duplicating the same rule firing on the same line."""
    seen, per_cat = set(), defaultdict(list)
    for f in findings:
        key = (f.rule, f.line)
        if key in seen:
            continue
        seen.add(key)
        per_cat[f.category].append(f.score)
    out = {}
    for cat in CATEGORIES:
        p = 1.0
        for s in per_cat.get(cat, []):
            p *= 1.0 - s
        out[cat] = 1.0 - p
    return out


def overall_risk(cat: dict[str, float]) -> float:
    ranked = sorted(cat.values(), reverse=True)
    if not ranked or ranked[0] == 0:
        return 0.0
    rest = 1.0
    for s in ranked[1:]:
        rest *= 1.0 - 0.25 * s
    return 1.0 - (1.0 - ranked[0]) * rest


def fuse(sym: dict[str, float], probs: dict[str, float]) -> dict[str, float]:
    """Neural refinement. Strong neural evidence can raise a category; weak evidence damps it."""
    out = {}
    for c in CATEGORIES:
        s, p = sym.get(c, 0.0), probs.get(c, 0.0)
        out[c] = max(s, 0.5 * s + 0.5 * p + 0.1) if p >= 0.5 else s * (0.7 + 0.6 * p)
    return out


def build_response(analysis: Analysis, probs: dict[str, float] | None = None) -> dict:
    sym_cat = category_scores(analysis.findings)
    sym_risk = overall_risk(sym_cat)
    # Neuro-symbolic guardrail: the symbolic layer owns the allow/block decision; the ML
    # head only REFINES already-blocked cases (raises confidence, adds corroborated
    # categories). It never flips a benign symbolic result to block, so it cannot
    # introduce false positives, and never lowers a block, so it cannot hide a threat.
    if probs is not None and sym_risk >= BLOCK_THRESHOLD:
        cat = fuse(sym_cat, probs)
    else:
        cat = sym_cat
    risk = round(min(1.0, overall_risk(cat)), 4)
    verdict = "block" if sym_risk >= BLOCK_THRESHOLD else "allow"

    categories = []
    if verdict == "block":
        categories = [c for c in CATEGORIES if cat[c] >= REPORT_THRESHOLD]
        if not categories:
            categories = [max(cat, key=cat.get)]

    reported = set(categories)
    top = sorted((f for f in analysis.findings if f.category in reported), key=lambda f: -f.score)
    lines = sorted({f.line for f in top if f.line and f.score >= LINE_THRESHOLD})

    if verdict == "block":
        parts = [f"[{f.category}] line {f.line}: {f.message}" if f.line else f"[{f.category}] {f.message}" for f in top[:3]]
        reason = f"Blocked (risk {risk:.2f}): " + "; ".join(parts)
    else:
        weak = sorted(analysis.findings, key=lambda f: -f.score)[:1]
        reason = f"Allowed (risk {risk:.2f}): no high-risk behavior detected" + (
            f"; low-confidence signal: {weak[0].message}" if weak and weak[0].score >= 0.2 else "")

    subs = sorted({f.sub_category for f in top if f.sub_category}) if verdict == "block" else []
    return {
        "verdict": verdict,
        "risk_score": risk,
        "categories": categories,
        "code_language": analysis.language,
        "reason": reason,
        "vulnerable_lines": lines,
        "sub_categories": subs,
        "findings": [
            {"category": f.category, "score": round(f.score, 3), "line": f.line, "rule": f.rule,
             "message": f.message, **({"sub_category": f.sub_category} if f.sub_category else {}),
             **({"intel": f.intel} if f.intel else {})}
            for f in sorted(analysis.findings, key=lambda f: -f.score)[:20]
        ],
    }
