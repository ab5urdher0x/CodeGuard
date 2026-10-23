"""Single entry point used by the API, the batch endpoint, the eval script and @guard.

Static only: submitted code is parsed, never executed, imported or written to disk.
"""
import logging
import os
import time

from engine import aggregator
from engine.analyzers import javascript, python_ast, shell, sql, structured, universal
from engine.detector import detect_language
from engine.facts import OBFUSCATED_EXECUTION, Analysis, Finding
from engine.features import symbolic_features
from engine.ml.fusion import FusionModel

log = logging.getLogger("codeguard")
MAX_CODE_CHARS = 256_000

_LANG_ANALYZERS = {
    "python": [python_ast.analyze],
    "bash": [shell.analyze],
    "javascript": [javascript.analyze],
    "sql": [sql.analyze],
    "yaml": [structured.analyze],
    "markdown": [structured.analyze],
}


def analyze(code: str) -> Analysis:
    language, conf = detect_language(code)
    analysis = Analysis(language=language, language_confidence=conf)
    failures = 0
    analyzers = [universal.analyze] + _LANG_ANALYZERS.get(language, [])
    for fn in analyzers:
        try:
            fn(code, analysis)
        except RecursionError:
            failures += 1
            analysis.parse_ok = False
            analysis.findings.append(Finding(OBFUSCATED_EXECUTION, 0.5, None, "meta.recursion",
                                             "pathologically nested code (possible parser-evasion attempt)"))
        except Exception:
            failures += 1
            analysis.parse_ok = False
            log.exception("analyzer %s failed", getattr(fn, "__module__", fn))
    if failures == len(analyzers):  # fail closed
        analysis.findings.append(Finding(OBFUSCATED_EXECUTION, 0.65, None, "meta.analysis_failed",
                                         "code could not be analyzed; blocked by fail-closed policy"))
    return analysis


def evaluate(code: str) -> dict:
    t0 = time.perf_counter()
    raw = code or ""
    if len(raw) > MAX_CODE_CHARS:
        # Fail closed against pad-and-append evasion: analyze BOTH the head and the tail
        # (a payload hidden after huge padding must still be seen), and flag the oversize.
        code = raw[:MAX_CODE_CHARS]
        analysis = analyze(code)
        tail = raw[-(MAX_CODE_CHARS // 2):]
        nl = tail.find("\n")
        tail = tail[nl + 1:] if nl != -1 else tail
        try:
            analysis.findings.extend(analyze(tail).findings)
        except Exception:
            log.exception("tail analysis failed")
        analysis.findings.append(Finding(OBFUSCATED_EXECUTION, 0.35, None, "meta.oversized",
                                         "input exceeds the size cap; analyzed head+tail only "
                                         "(oversized input is a common evasion)"))
    else:
        code = raw
        analysis = analyze(code)

    probs = None
    # Production is rules-only (Phase-4 experiment showed ML is redundant: it repeats
    # the rules' errors on unseen data). ML is opt-in via CODEGUARD_USE_ML=1 for research.
    sym_risk = aggregator.overall_risk(aggregator.category_scores(analysis.findings))
    lo, hi = aggregator.AMBIGUOUS_BAND
    model = FusionModel.get() if os.getenv("CODEGUARD_USE_ML") == "1" else None
    if model is not None and lo <= sym_risk <= hi:
        try:
            probs = model.predict(code, analysis.language, symbolic_features(analysis, code))
        except Exception:
            log.exception("fusion model failed; continuing symbolic-only")

    resp = aggregator.build_response(analysis, probs)
    resp["latency_ms"] = round((time.perf_counter() - t0) * 1000, 2)
    resp["neural_used"] = probs is not None
    return resp
