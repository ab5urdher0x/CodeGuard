# ML experiment & efficiency note (Phase 4)

## Model
- **Type:** OneVsRest LogisticRegression (9 categories, multi-label), CPU-only.
- **Features:** 68 symbolic engine features (`engine/features.py`) ⊕ 3,000 TF-IDF char n-grams (3–5).
- **Trained on:** `data/synthetic/train.jsonl` **only** (1,194 rows). Never dev / validation / challenge / holdout2.
- **Size:** 334 KB (`engine/ml/artifacts/head.joblib`). **No torch / transformers / onnxruntime** (not installable on this Python 3.14 env; LR was the requested CPU-efficient choice).
- **Note:** the CodeBERT-embedding path from the plan is documented but not used — unavailable here, and unnecessary given the result below.

## A (rules) vs B (rules+ML) — shadow mode (`eval/shadow_ml.py`)

| dataset | mode | P | R | F1 | FPR | FP | FN | p95 ms |
|---|---|---|---|---|---|---|---|---|
| dev (42) | rules | 1.000 | 1.000 | 1.000 | 0.000 | 0 | 0 | 1.84 |
| dev (42) | rules+ML | 1.000 | 1.000 | 1.000 | 0.000 | 0 | 0 | 1.85 |
| val (581) | rules | 1.000 | 1.000 | 1.000 | 0.000 | 0 | 0 | 0.70 |
| val (581) | rules+ML | 1.000 | 1.000 | 1.000 | 0.000 | 0 | 0 | 1.71 |
| challenge (25) | rules | 1.000 | 1.000 | 1.000 | 0.000 | 0 | 0 | 0.64 |
| challenge (25) | rules+ML | 1.000 | 1.000 | 1.000 | 0.000 | 0 | 0 | 0.46 |
| **holdout2 (30)\*** | **rules** | **0.857** | **0.800** | **0.828** | **0.133** | **2** | **3** | 0.99 |
| **holdout2 (30)\*** | **rules+ML** | **0.857** | **0.800** | **0.828** | **0.133** | **2** | **3** | 1.72 |

\* holdout2 = independently written scenarios with new template families; **never used for tuning or training**. It is the honest generalization estimate.

## Verdict: ML provides no measurable improvement → not integrated

- On every set, rules+ML equals rules. On the independent holdout2, **ML changed 0 verdicts**.
- On the 3 rule-missed FNs, the ML head's own probability is **0.00** — it misses them too.
- On the 2 FPs, the ML head also predicts **block** (0.99, 0.82) — it repeats the same mistakes.
- **Why:** the model was trained on synthetic data generated from the same template families the rules were designed around, so it learned the same decision surface and inherits the same blind spots. Combining two correlated detectors did not help.
- ML also roughly **doubles p95 latency** when active, for no accuracy gain.

**Decision:** production stays **rules-only** (the `symbolic-v1` engine). ML is kept in the repo, **off by default**, enabled only with `CODEGUARD_USE_ML=1` for research. `/evaluate` remains static-only; schema, batch endpoint and interception demo unchanged.

## Honest generalization & known limitations (from holdout2 — NOT tuned against)
The independent set shows the real engine sits around **P 0.86 / R 0.80**, not 1.00. Rule gaps it exposed (left as documented limitations, not patched against the holdout):
- SSRF where the host is a *fully* dynamic f-string variable (no constant prefix to classify).
- Overwriting a system binary via `open('/bin/ls','w')` (not in persistence path set).
- Prompt-injection verb "email the secrets" (verb list gap).
- A parameterized `DELETE ... WHERE id = %s` flagged (benign `%s` placeholder treated as format string) — a precision bug worth a general fix.
- `compile(tree,'<s>','exec')` for linting flagged (compile→exec is genuinely dual-use).
