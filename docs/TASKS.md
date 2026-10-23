# Task flow — status as of 2026-10-24

Each task ends with: `env -u PYTHONPATH .venv/bin/python -m pytest -q` green + `eval/evaluate.py` delta noted + commit.

| # | Task | Status | Evidence |
|---|---|---|---|
| 1 | `eval/evaluate.py` (P/R/FPR/F1, per-category, latency, schema check, misses; `--url` for HTTP) | ✅ done | `eval/evaluate.py`, `eval/results.md` |
| 2 | Python AST taint analyzer | ✅ done | `engine/analyzers/python_ast.py`, `tests/test_rules_python.py` |
| 3 | Universal analyzer (SSRF, hardcoded secrets, AI-targeted instructions, lookalike domains) | ✅ done | `engine/analyzers/universal.py`, `tests/test_rules_universal.py` |
| 4 | Interception demo + audit-hook runtime guard | ✅ done | `runtime/audit_guard.py`, `demo/intercept_check.py` (exit 0), `tests/test_audit_guard.py` |
| 5 | JS, SQL, YAML/MD analyzers | ✅ done | `engine/analyzers/{javascript,sql,structured}.py` |
| 6 | Synthetic generator + leak-guard test | ✅ done | `data/gen/` (1,194 train / 581 val, 0 family overlap, 31 multi-label val), `tests/test_no_dev_leak.py` |
| 7 | Investigate val FPs/FNs, tune engine (generalizable), **freeze symbolic** | ⏳ in progress | target: cut held-out FPR without hurting dev; tag `symbolic-v1` |
| 8 | Neural head: encoder → ONNX int8, PCA64 + scalers + OvR LR (train split only), `fusion.py`, ablation | ⬜ todo | keep ML only if it beats symbolic-only on held-out |
| 9 | Minimal UI, Dockerfile, EC2 deploy, submit endpoint URL | ◑ partial | UI + Dockerfile + `deploy/` done; EC2 deploy + URL pending |
| 10 | README (architecture, licenses, assumptions, limits, AI disclosure), results, 2–3 page write-up | ⬜ todo | PS §6/§10 |
| — | First public GitHub repo + push | ⬜ todo (user) | needs repo URL |

## Mandatory requirements (verified 2026-10-24)
- ✅ All 9 official categories have ≥1 rule.
- ✅ `/evaluate` is static only — no exec/eval/import/compile-run of submitted code.
- ✅ Schema valid on `/evaluate`, `/evaluate/batch`, `/health`, `GET /` (UI); errors fail closed to a valid `block`.
- ✅ `@guard` interception demo passes (static + runtime layers; `hacked.txt` never created); controlled demo pair only.

## Current metrics
- Dev (42) and held-out synthetic val (581, unseen families): P/R/F1 1.000, FPR 0 — but these
  were used to tune the engine, so treat as optimistic.
- **Independent holdout2 (30, never tuned on): P 0.857, R 0.800 — honest generalization estimate.**
- Tests: 98 passing. p95 ~1 ms.

## Cut lines if behind
- Task 8 → fall back to TF-IDF in place of the encoder embedding (same head interface), or ship symbolic-only.
- Task 9 HTTPS → plain HTTP on Elastic IP, cloudflared tunnel as backup.
- Never cut: 1, 2, 4, 9, 10 (schema, demo, endpoint, docs are judged pass/fail or required).
