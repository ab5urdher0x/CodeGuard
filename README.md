# CodeGuard

**A real-time, pre-execution safety layer for LLM-generated code.**

AI agents write and run code, shell commands, and SQL on their own. CodeGuard sits
*inline, before execution*, and returns an allow/block verdict in ~1 ms — no LLM call,
CPU-only. If the verdict is **block**, the code never runs.

```json
POST /evaluate   {"code": "..."}
→ {"verdict": "block", "risk_score": 0.72, "categories": ["data_exfiltration"],
   "code_language": "python", "reason": "...", "vulnerable_lines": [3]}
```

## How it works

```
  code ──POST──►  /evaluate
     │
     ▼
  1. Language detector        python | bash | javascript | sql | yaml | markdown
  2. Layered static analysis  (NEVER executes the code)
       ├─ Universal pass  :  secrets, SSRF, prompt-injection   (any language)
       ├─ Python AST      :  taint tracking  (source ──► sink)
       └─ Shell / SQL / JS / YAML rules
  3. Findings ──► risk score (noisy-OR) ──► verdict  (block if ≥ 0.60)

  Same engine also powers:   @guard (demo, blocks a real call)   +   minimal web UI
```

**The core idea — meaning, not keywords.** `os` and `subprocess` aren't bad by
themselves. CodeGuard follows *data flow*: does a value from a secret file or user input
reach a dangerous call (`eval`, `os.system`, `requests.post`, `cursor.execute`)? A
constant reaching a sink is safe; a *tainted* one is not. That's why it allows
`ast.literal_eval`, parameterised SQL, `crontab -l`, and reading `~/.config`, while
blocking their malicious look-alikes.

## Detection categories (9)

`secret_access` · `data_exfiltration` · `destructive_command` · `persistence_or_privesc` ·
`obfuscated_execution` · `dependency_risk` · `resource_exhaustion` · `ssrf_network_exfil` ·
`ai_targeted_instructions`

Plus a **Black October** threat-intel feed (the Oct 2026 LiteLLM supply-chain attack):
`.pth`/`sitecustomize` startup-hook persistence, look-alike domains, AI-key harvesting,
compromised versions, slopsquatting.

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

uvicorn app.main:app --port 8000      # open http://127.0.0.1:8000/   (web UI)
python demo/intercept_check.py        # interception proof (exit 0 = blocked code never ran)
pytest -q                             # 98 tests
```

## Interception proof

`demo/intercept_check.py` wraps real functions with `@guard`. A malicious "setup helper"
(a LiteLLM-style startup-hook planter) is **blocked statically** and never runs; an
obfuscated variant that slips past static analysis is caught by a `sys.addaudithook`
runtime tripwire — proven by a marker file (`hacked.txt`) that never appears.

## Repository guide

| Folder | Purpose |
|---|---|
| `engine/` | The detector. `pipeline.py` orchestrates; `analyzers/` hold per-language logic; `knowledge.py` is shared security knowledge; `aggregator.py` scores. |
| `app/` | FastAPI service (`/evaluate`, `/evaluate/batch`, `/health`) + minimal web UI. |
| `runtime/` | `@guard` decorator + audit-hook tripwire (used only by the demo). |
| `demo/` | The interception proof. |
| `tests/` | 98 tests — every rule has a malicious case and a benign twin. |
| `eval/` | Evaluation harness + results. Metrics are measured, not claimed. |
| `data/gen/` | Synthetic **training**-data generator (template-based, no LLM). |
| `engine/ml/` | Optional ML experiment — **off by default** (see "ML", below). |
| `deploy/` | Docker + AWS/tunnel deployment notes. |

## Honest metrics

These are **dataset accuracies, not a real-world accuracy claim** — our test sets are
small and the hidden judging set will differ.

| Dataset | Precision | Recall | FPR | Notes |
|---|---|---|---|---|
| Dev (42) & synthetic val (581) | 1.00 | 1.00 | 0.00 | the engine was **tuned on these**, so treat as optimistic, not real-world |
| Independent hold-out (30) | 0.86 | 0.80 | 0.13 | a **small, limited** set we never tuned on — our best (still rough) generalization estimate |

Latency: p95 ~1 ms — this is **local, in-process analysis latency** (no network), measured
on a laptop. We lead with the hold-out number because the tuned sets over-state performance.

## ML: tried, measured, not shipped

We trained a logistic-regression classifier (symbolic features + TF-IDF) on synthetic
data only. In shadow mode it **repeated the rules' errors** on unseen data and added
latency, so production is **rules-only**. The experiment stays in the repo
(`CODEGUARD_USE_ML=1` to enable) and is written up in `eval/efficiency.md`. We did not
ship ML just to claim it.

## Constraints honored

No external LLM call for the verdict · CPU-only · `/evaluate` never executes submitted
code · fake secrets / placeholder domains only · fails closed (errors → valid `block`).

## Open-source components

These are the licenses of the libraries we build on (credited per hackathon rules).
CodeGuard itself has **not adopted a license yet** — no `LICENSE` file is included.

| Component | Use | License |
|---|---|---|
| FastAPI / Starlette / Uvicorn | HTTP service | MIT / BSD-3 |
| Pydantic | schema validation | MIT |
| Python stdlib `ast`, `tokenize`, `shlex`, `ipaddress` | static analysis | PSF |
| scikit-learn | optional ML experiment | BSD-3 |

Detection logic, rules, taint tracking, and datasets are our own work. Threat-intel IOCs
come from public incident reports (cited in `engine/intel/black_october.json`).

**AI assistance:** developed with an AI coding assistant (disclosed per hackathon rules);
`CLAUDE.md` records the repo rules we worked under.

## Notes

The organizer dev dataset (`data/dev/`) and our internal challenge sets (`data/challenge/`)
are kept local-only (git-ignored) — place the dev `.jsonl` in `data/dev/` to run
`eval/evaluate.py`.
