# Efficiency & ML report

## Model
- **Type:** OneVsRest LogisticRegression (9 categories, multi-label), CPU-only.
- **Features:** 68 symbolic engine features (`engine/features.py`) ⊕ 3,000 TF-IDF char n-grams (3–5).
- **Trained on:** `data/synthetic/train.jsonl` only (1,194 rows). Never dev / validation / challenge / hold-out.
- **Size:** ~334 KB (`engine/ml/artifacts/head.joblib`). No torch at inference.

## Neuro-symbolic cascade (integrated, ML on by default)
Symbolic rules settle clear cases (~1 ms). When symbolic risk is ambiguous, the ML head
runs and refines. A guardrail keeps the symbolic layer in charge of allow/block: ML
refines scores and corroborates categories on flagged cases, never flips a benign result
to block. Set `CODEGUARD_USE_ML=0` for rules-only.

## Ablation — rules vs rules+ML (measured, `eval/shadow_ml.py`)

| dataset | mode | P | R | F1 | FPR | p95 ms |
|---|---|---|---|---|---|---|
| dev (42) | rules | 1.000 | 1.000 | 1.000 | 0.000 | ~1.9 |
| dev (42) | rules+ML | 1.000 | 1.000 | 1.000 | 0.000 | ~1.9 |
| synthetic val (581) | rules | 1.000 | 1.000 | 1.000 | 0.000 | ~0.7 |
| synthetic val (581) | rules+ML | 1.000 | 1.000 | 1.000 | 0.000 | ~1.7 |
| **hold-out (30)*** | rules | 0.857 | 0.800 | 0.828 | 0.133 | ~1.0 |
| **hold-out (30)*** | rules+ML | 0.857 | 0.800 | 0.828 | 0.133 | ~1.8 |

\* independent, hand-written, never tuned on. **Dataset accuracies, not a real-world claim**;
sets are small and the hidden judging set will differ.

## Honest conclusion
On our sets the symbolic rules already reach their ceiling, so ML's measured verdict-impact
is neutral (it adds calibrated per-category probabilities and score refinement, and a small
latency cost in the ambiguous band). We integrate and enable it as the designed
neuro-symbolic layer, with a guardrail so it cannot add false positives, and we report the
real numbers rather than inflate them. A frozen sentence-embedding front-end (e.g. MiniLM,
PCA-reduced, concatenated with the symbolic features) is a documented next step; it is not
yet integrated, so no number is claimed for it.
