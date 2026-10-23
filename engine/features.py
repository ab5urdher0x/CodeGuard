"""Symbolic feature vector for the neural fusion head (CONTRACT between A and B).

Rules:
- The vector is built *by name*. The trained model stores its FEATURE_NAMES and
  `vectorize` aligns by name, so adding a feature never breaks an old model
  (missing -> 0.0); it just needs a retrain to be used.
- Person A adds new signal names to SIGNALS (append only) and sets them in
  Analysis.signals. Person B never hand-edits this list.
"""
import math

from engine.detector import LANGUAGES
from engine.facts import CATEGORIES, SUB_CATEGORIES, Analysis

# Named taint/structure signals emitted by analyzers (value 0..1 or small counts).
SIGNALS = [
    "taint.decoded_to_exec", "taint.remote_to_exec", "taint.input_to_exec", "taint.secret_to_network",
    "taint.file_to_network", "taint.input_to_shell", "taint.input_to_sql", "taint.input_to_path_delete",
    "taint.secret_read", "taint.env_bulk_read", "sink.exec_const", "sink.dynamic_import", "sink.deserialize",
    "sink.shell_string", "sink.network", "sink.file_write", "sink.file_delete", "net.internal_host",
    "net.metadata_host", "net.exfil_dest", "net.lookalike_domain", "loop.unbounded", "loop.spawn",
    "alloc.huge", "dep.install", "dep.typosquat", "persist.path_write", "persist.startup_hook",
    "prompt.injection_phrase", "prompt.ai_addressee", "secret.hardcoded", "sql.no_where", "sql.formatted",
    "safe.literal_eval", "safe.parameterized_sql", "safe.allowlist_check", "safe.readonly_cmd",
]

FEATURE_NAMES = (
    [f"cat_max.{c}" for c in CATEGORIES]
    + [f"cat_count.{c}" for c in CATEGORIES]
    + [f"sub.{s}" for s in SUB_CATEGORIES]
    + [f"lang.{l}" for l in LANGUAGES]
    + ["meta.parse_ok", "meta.lang_conf", "meta.log_lines", "meta.n_findings", "meta.intel_hit"]
    + [f"sig.{s}" for s in SIGNALS]
)


def symbolic_features(analysis: Analysis, code: str) -> dict[str, float]:
    f = dict.fromkeys(FEATURE_NAMES, 0.0)
    for fd in analysis.findings:
        f[f"cat_max.{fd.category}"] = max(f[f"cat_max.{fd.category}"], fd.score)
        f[f"cat_count.{fd.category}"] = min(f[f"cat_count.{fd.category}"] + 1, 5)
        if fd.sub_category:
            f[f"sub.{fd.sub_category}"] = max(f[f"sub.{fd.sub_category}"], fd.score)
        if fd.intel:
            f["meta.intel_hit"] = 1.0
    if f"lang.{analysis.language}" in f:
        f[f"lang.{analysis.language}"] = 1.0
    f["meta.parse_ok"] = float(analysis.parse_ok)
    f["meta.lang_conf"] = analysis.language_confidence
    f["meta.log_lines"] = math.log1p(code.count("\n") + 1)
    f["meta.n_findings"] = min(len(analysis.findings), 20)
    for name, val in analysis.signals.items():
        key = f"sig.{name}"
        if key in f:
            f[key] = float(val)
    return f


def vectorize(features: dict[str, float], names: list[str]) -> list[float]:
    return [float(features.get(n, 0.0)) for n in names]
