# CodeGuard

A real-time, pre-execution safety layer for LLM-generated code.

Autonomous AI agents increasingly generate and execute their own code, shell commands,
and SQL. That code can leak credentials, exfiltrate data, run destructive commands,
escalate privileges, hide its intent through obfuscation, install malicious packages,
exhaust resources, reach internal network endpoints, or carry instructions aimed at a
downstream AI. CodeGuard inspects a snippet **before it runs** and returns an
allow/block decision in about a millisecond — CPU-only, with no call to an external LLM.

```http
POST /evaluate      {"code": "..."}

{
  "verdict": "block",
  "risk_score": 0.72,
  "categories": ["data_exfiltration"],
  "code_language": "python",
  "reason": "Blocked (risk 0.72): [data_exfiltration] line 3: ...",
  "vulnerable_lines": [3]
}
```

## Architecture

CodeGuard is a **symbolic-first, neuro-symbolic cascade**. Fast deterministic analysis
decides clear-cut cases; a trained classifier refines the ambiguous ones.

```
  code ──► POST /evaluate
     │
     ▼
  1. Language detection         python | bash | javascript | sql | yaml | markdown
  2. Static analysis            (the code is never executed)
       • Universal pass         secrets, SSRF, prompt-injection — language-agnostic
       • Python AST + taint      data-flow from sources (secrets, input, decoded bytes)
                                 to sinks (eval, os.system, requests, cursor.execute)
       • Shell / SQL / JS / YAML statement- and command-level rules
  3. Symbolic scoring           findings ──► per-category noisy-OR ──► risk
  4. ML fusion (ambiguous only) logistic-regression head over symbolic features + TF-IDF
                                refines the score; a guardrail keeps the symbolic layer
                                in charge of the allow/block decision
  5. Verdict                    block if risk ≥ 0.60, else allow
```

The same engine backs the HTTP API, a `@guard` decorator used in the interception demo,
and a minimal web UI.

**Detection is semantic, not keyword-based.** `os` and `subprocess` are not treated as
dangerous in themselves; the engine tracks whether untrusted or sensitive data reaches a
dangerous call. This is why it allows `ast.literal_eval`, parameterised SQL, `crontab -l`,
and reading a user config file, while blocking their malicious look-alikes.

## Detection categories

Nine categories, multi-label:

`secret_access` · `data_exfiltration` · `destructive_command` · `persistence_or_privesc` ·
`obfuscated_execution` · `dependency_risk` · `resource_exhaustion` · `ssrf_network_exfil` ·
`ai_targeted_instructions`

An updatable threat-intelligence feed (`engine/intel/`) generalises the October 2026
LiteLLM supply-chain attack: Python startup-hook persistence (`.pth` / `sitecustomize`),
look-alike domains, AI-provider key harvesting, compromised package versions, and
typo/slop-squatting.

## Machine learning

The ML component is a trained, integrated part of the system (not a stub):

- **Model:** one-vs-rest logistic regression over 68 symbolic engine features concatenated
  with 3,000 TF-IDF character n-grams. ~334 KB, CPU-only, no `torch` at inference.
- **Training:** `engine/ml/train.py`, on `data/synthetic/train.jsonl` only (never the dev,
  validation, or hold-out sets).
- **Integration:** enabled by default; runs on cases whose symbolic risk is ambiguous.
  A guardrail lets it refine scores and corroborate categories on flagged code but never
  flip a benign result to block, so it cannot introduce false positives. Set
  `CODEGUARD_USE_ML=0` for rules-only.

Measured honestly, the symbolic rules already reach their ceiling on our test sets, so the
ML head's effect on the verdict is currently neutral; it contributes calibrated
per-category probabilities and score refinement. See `eval/efficiency.md` for the full
ablation. We report measured numbers only.

## Results

These are dataset accuracies, **not a real-world accuracy claim** — the sets are small and
the hidden judging set will differ.

| Dataset | Precision | Recall | F1 | FPR | Notes |
|---|---|---|---|---|---|
| Dev (42) and synthetic validation (581) | 1.00 | 1.00 | 1.00 | 0.00 | the engine was tuned on these — optimistic |
| Independent hold-out (30) | 0.86 | 0.80 | 0.83 | 0.13 | small, never tuned on — our best generalisation estimate |

Latency: p95 ≈ 1 ms, measured locally and in-process.

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

uvicorn app.main:app --port 8000      # web UI and API at http://127.0.0.1:8000/
python demo/intercept_check.py        # interception proof (exit 0)
pytest -q                             # test suite
```

Endpoints: `POST /evaluate`, `POST /evaluate/batch`, `GET /health`, `GET /` (UI).

## Interception proof

`demo/intercept_check.py` guards real function calls. A malicious "setup helper" that
plants a LiteLLM-style startup hook is blocked by static analysis and never runs; an
obfuscated variant that evades static analysis is stopped by a `sys.addaudithook` runtime
tripwire. Both are proven by a marker file that is never created. `/evaluate` itself never
executes submitted code — only this controlled demo pair runs.

## Repository layout

| Path | Contents |
|---|---|
| `engine/` | Detection engine: `pipeline` (orchestration), `analyzers/` (per-language), `knowledge` (shared security data), `aggregator` (scoring), `ml/` (fusion head) |
| `app/` | FastAPI service and minimal web UI |
| `runtime/` | `@guard` decorator and audit-hook tripwire (demo only) |
| `demo/` | Interception proof |
| `eval/` | Evaluation harness, results, efficiency report |
| `data/gen/` | Template-based synthetic data generator (no LLM) |
| `tests/` | Test suite — each rule has a malicious case and a benign twin |
| `deploy/` | Container and deployment notes |

## Design constraints

No external LLM call for the verdict · CPU-only, no GPU · `/evaluate` never executes
submitted code · fails closed (any internal error returns a valid `block`) · only fake
secrets and placeholder domains in all fixtures and tests.

## License and credits

Released under the MIT License (see `LICENSE`).

| Component | Role | License |
|---|---|---|
| FastAPI, Starlette, Uvicorn | HTTP service | MIT, BSD-3 |
| Pydantic | request/response validation | MIT |
| scikit-learn | ML classifier | BSD-3 |
| Python standard library (`ast`, `tokenize`, `shlex`, `ipaddress`) | static analysis | PSF |

Detection logic, taint tracking, rules, and datasets are the team's own work;
threat-intelligence indicators are drawn from public incident reports.

Parts of this project were developed with the help of an AI coding assistant, disclosed
per the hackathon rules. All design decisions, detection logic, and review are the
team's own.

## Notes

The organizer dev dataset and the internal challenge/hold-out sets are kept local-only
(git-ignored). Place the dev `.jsonl` in `data/dev/` to run `eval/evaluate.py`; without
it, the dataset-dependent test is skipped.
