# CodeGuard — rules for every agent working in this repo

Read `docs/PLAN.md` (architecture, locked decisions) and `docs/TASKS.md` (sequential task flow) before changing anything.

## Hard rules (hackathon pass/fail floors — never break these)
1. `/evaluate` is **static only**. Never `exec`, `eval`, `import`, `compile`-and-run, or write to disk any submitted/test snippet. The only code that ever runs is the demo pair in `demo/`.
2. **No external LLM API** anywhere — inference, training, data generation, tests. No OpenAI/Anthropic/etc. clients, no keys.
3. **The dev set (`data/dev/codeguard_dev.jsonl`) is evaluation-only.** Never train on it, never copy its text, ids or distinctive strings into rules, templates or tests. Fix failures by generalising a rule.
4. Response always has `verdict`, `risk_score` (0..1), `categories`, `code_language`, `reason`, `vulnerable_lines`. Errors must still return a valid response (fail closed → block).
5. Fake secrets (`AKIAEXAMPLE...`) and placeholder domains (`*.example`) only.
6. CPU only. No GPU code paths.

## Contracts (change only with both teammates agreeing)
- `engine/facts.py` — `Finding`, `Analysis`, category names.
- Analyzer signature: `analyze(code: str, analysis: Analysis) -> None`.
- `engine/features.py` — `SIGNALS` is **append-only**; features are aligned by name.
- `engine/ml/fusion.py` — `FusionModel.get()` / `.predict(code, language, sym_features) -> {category: prob}`.
- `app/schemas.py` — API schema.
- Dataset rows: `{"id","code","language","categories","labels"(9, CATEGORIES order),"label","family","variant","sub_categories","source"}`.

## Conventions
- Rule ids: `<lang>.<family>.<detail>` (e.g. `py.exec.decoded`, `sh.rm.root`).
- Every new rule gets a positive and a benign-twin test in `tests/` (synthetic text, not dev text).
- Before pushing: `env -u PYTHONPATH .venv/bin/python -m pytest -q` (ROS on PYTHONPATH breaks pytest) and `.venv/bin/python eval/evaluate.py` (report the delta in the PR).
- Commit messages: imperative, small PRs to `main` from `a/*` or `b/*` branches.
