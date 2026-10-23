# CodeGuard — Final Plan

A real-time, pre-execution safety layer for LLM-generated code. It runs on CPU only and never asks an LLM to judge code.

## 1. Approach

1. **Meaning over keywords.** About 30% of the dev set is benign code that looks dangerous (`crontab -l`, `ast.literal_eval`, SQL with bound parameters, `password = 'hunter2'` inside a docstring). We track data flow (what reaches what) and resolve constants. Keyword matching alone would fail on these.
2. **Shared fact model.** Every analyzer (Python AST, shell, JS, SQL, YAML/Markdown) emits `Finding(category, score, line, rule, message)`. Only the aggregator decides the verdict, so adding a language means adding an analyzer and nothing else.
3. **Neuro-symbolic cascade (LOCKED).** The symbolic layer (rules + AST taint) decides clear cases and is the only source of `reason` and `vulnerable_lines`. When the symbolic risk falls in [0.25, 0.75], a frozen code encoder (ONNX int8) runs. Its embedding is PCA-reduced to 64 dims, both blocks are standardized, it's concatenated with the symbolic feature vector, and a multi-label LogisticRegression head (9 outputs) refines risk and categories. For Bash/SQL/YAML/Markdown we lean on the symbolic features (the encoder was not pretrained on them). Fallback if the encoder isn't ready: TF-IDF in place of the embedding block, same head interface.
4. **Static analysis only in the service.** `/evaluate` never runs anything it receives. Runtime detection (the audit hook) exists only inside the controlled demo pair.
5. **Honest metrics.** The dev set is held-out evaluation and is never used for training. Training data comes from our own synthetic generator, which pairs every malicious example with a benign near-twin.
6. **Fail closed.** If a parser breaks, the remaining layers still run. If everything fails, the response is still a valid schema with `block`.
7. **Differentiator: Black October intel (Oct 2026).** Behavioral rules generalize the LiteLLM 1.107.0 attack: `.pth`/`sitecustomize.py` startup hooks, lookalike domains, AI provider key harvesting and slopsquatting. Known-bad specifics live in an updatable intel feed.

## 2. Architecture

```
            POST /evaluate {"code"}            POST /evaluate/batch [{"code"},...]
                          │
            ┌─────────────▼──────────────┐
            │  Guardrails: size cap, timeouts, never execute, error → valid block
            └─────────────┬──────────────┘
   L0 LanguageDetector    │  shebang → parser confirmation → weighted cues
                          │  python | bash | javascript | sql | yaml | markdown
   L1 Universal pass      │  ~1 ms, any language: SSRF hosts/IP encodings/schemes,
                          │  hardcoded credential formats + entropy, prompt injection
                          │  in comments/strings/docs, lookalike domains
   L2 Semantic pass       │  Python: ast + taint (sources → sinks), alias resolution,
                          │          constant folding ('sub'+'process'), return-value taint
                          │  Shell:  pipeline/segment parser (also fed command strings
                          │          pulled out of subprocess/os.system/child_process)
                          │  SQL:    statement rules (DROP/TRUNCATE, DELETE/UPDATE w/o WHERE)
                          │  JS:     structural regex + light taint
                          │  YAML/MD: universal + shell analysis of `run:` and code fences
                          ▼
                  Findings[] (category, score, line, rule, CWE/ATT&CK, intel)
   L3 Neural (ambiguous)  │  only if symbolic risk ∈ [0.25, 0.75]:
                          │  frozen code encoder (CodeBERT-class, ONNX int8) → mean-pool 768
                          │  → PCA 64 ─┐
                          │  symbolic feature vector (engine/features.py) ─┴→ standardize
                          │  → concat → One-vs-Rest LogisticRegression (calibrated), 9 labels
                          ▼
   Aggregator             │  per-category noisy-OR → risk_score (calibrated)
                          │  verdict = block if risk ≥ 0.6; categories only with own evidence
                          ▼
   {"verdict","risk_score","categories","code_language","reason","vulnerable_lines",
    + optional "sub_categories","findings","latency_ms"}

   runtime/audit_guard.py  @guard = static engine check → if allowed, run under
                           sys.addaudithook tripwire (demo pair only)
```

## 3. Tech stack (each component credited with its license in the README)

| Layer | Choice | License |
|---|---|---|
| Language | Python 3.12 (Docker image), runs on 3.10+ | PSF |
| API | FastAPI + Pydantic v2 + Uvicorn | MIT / MIT / BSD-3 |
| Static analysis | stdlib `ast`, `tokenize`, `shlex`, `ipaddress`, `re` (our own rules) | PSF |
| ML | scikit-learn (LogisticRegression, TF-IDF, calibration), joblib | BSD-3 |
| SLM (stretch) | onnxruntime + optimum (int8); encoder candidates: `Salesforce/codet5p-110m-embedding` or `jinaai/jina-embeddings-v2-base-code`. Verify the license on the model card before use. | MIT / Apache-2.0 / per model card |
| UI | One static HTML page served by FastAPI (no framework) | — |
| Tests/eval | pytest, httpx | MIT / BSD-3 |
| Deploy | Docker on AWS EC2 (t3.medium, Elastic IP), cloudflared tunnel from the laptop as fallback | Apache-2.0 |

There is no external LLM API anywhere: not at inference, not in training, and no key in `.env.example`.

## 4. Categories (9 required + 2 extra)

| Category | Main signals |
|---|---|
| secret_access | reads credential paths (~/.ssh, ~/.aws, .env, docker config, kube), bulk/secret env reads, hardcoded keys (AKIA…, xox[bp]-, ghp_, sk-…, PEM) |
| data_exfiltration | taint flow from secret/file data into network sinks (requests/urllib/socket/smtp/ping -p/DNS); SQL injection on SELECT |
| destructive_command | rm -rf on critical or variable paths, rmtree, dd/mkfs, DROP/TRUNCATE, DELETE/UPDATE without WHERE, shell/SQL injection on destructive verbs |
| persistence_or_privesc | crontab edits (not -l), systemd units, rc files, sudoers/NOPASSWD, setuid, authorized_keys, **.pth / sitecustomize (Black October)** |
| obfuscated_execution | decoded/remote data into eval/exec/compile, dynamic `__import__`/importlib, curl\|sh, base64\|sh, insecure deserialization |
| dependency_risk | typosquats/slopsquats (offline edit distance vs popular packages), known malicious names, compromised versions (intel), VCS/URL installs, custom indexes |
| resource_exhaustion | fork bombs, `while True` with no exit or blocking call, unbounded thread/process/socket spawning, huge allocations, dd from /dev/zero |
| ssrf_network_exfil | metadata IPs/hosts, loopback/private/link-local (including decimal/hex/IPv6-mapped encodings), gopher/dict/file schemes, host sweeps |
| ai_targeted_instructions | comments/strings/docs addressing an AI reader with override verbs ("ignore previous instructions", "approve regardless", "reveal system prompt") |
| **code_injection** (extra) | untrusted input into SQL strings or shell commands; reported in `sub_categories` and mapped to the official parent category |
| **insecure_deserialization** (extra) | pickle/shelve/marshal/yaml.load/dill on untrusted data; reported in `sub_categories` and mapped to obfuscated_execution |

Tagging policy: a category is reported only when it has its own evidence. The dev set tags narrowly; for example, an IAM credential fetch from the metadata endpoint is labeled ssrf only.

## 5. Interception proof (`demo/intercept_check.py`)

- **The pair is ours and harmless.** The only side effect is a marker file in a temp directory. Fake secrets, `*.example` domains, and no network.
  - **SAFE:** a normal agent helper that writes `safe_marker.txt`. Expected: `allow`, it runs, and the marker exists.
  - **UNSAFE:** an "agent-generated setup helper" that tries to plant a LiteLLM-style startup hook. Its real effect is only writing `hacked.txt`. Expected: `block`, it never runs, and `hacked.txt` does not exist.
  - **Bonus, defense in depth:** an obfuscated UNSAFE variant written to pass the static check on purpose. The `sys.addaudithook` tripwire raises on `open(...,'w')` to the marker or hook path before the write happens.
- `@guard` uses `inspect.getsource` on the wrapped function, calls the same `engine.evaluate()` as the API, and raises `BlockedByCodeGuard` *before* calling the function.
- The script asserts the marker state, prints the verdicts and latency, exits non-zero on any failure, and cleans up. `--safe/--unsafe` accept other files.

## 6. Accuracy plan

1. Run `eval/evaluate.py` against `data/dev/codeguard_dev.jsonl` from hour 1 to get a baseline. It reports precision, recall, FPR, F1, per-category P/R and p50/p95 latency.
2. Fix failures by **generalizing a rule** (a new source/sink or folding case), never by matching a dev row. Every fix gets a synthetic regression test that does not use dev text.
3. Run `data/gen_synthetic.py` to produce 600–1000 snippets: Python-heavy, all 9 categories plus multi-label cases, a benign twin for every malicious pattern, and randomized identifiers and structure.
4. Train the ML layer on synthetic data only and calibrate it. Report dev metrics before and after adding ML, and before and after int8 quantization.
5. Report counts: the number of findings and `vulnerable_lines` for each snippet.

## 7. Service hardening (security developer view)

- Max code size of 256 KB. Regexes are written to avoid ReDoS. `ast.parse` recursion errors are caught. Each request has a time budget.
- Submitted code is never `exec`'d, `import`ed or written to disk. Logs store a sha256 of the code, not the content.
- Internal errors still return a valid schema (fail closed → block). `GET /health` exists for monitoring.
- The environment variable `CODEGUARD_STRICT_SCHEMA=1` removes the optional extra fields if the judge's validator is strict.

## 8. Schedule (two people: A = engine, B = data/ML/delivery)

| Phase | A | B |
|---|---|---|
| P1 (now) | Python AST taint engine, universal rules, aggregator | API + batch + schemas, `eval/evaluate.py` baseline |
| P2 | JS/SQL/YAML analyzers, fix dev failures by generalizing | Synthetic generator + benign twins + regression tests |
| P3 | ML integration in the cascade | ML training/calibration; SLM experiment (keep only if it beats LR) |
| P4 | Demo + audit-hook runtime guard | UI page, Docker, EC2 deploy, endpoint URL to organizers |
| P5 (freeze) | Write-up (2–3 pages) | README (architecture, licenses, assumptions, limitations, AI-assistant disclosure), final metrics |

At the start of P4, anything unfinished, including the SLM, is cut.

## 9. Problem statement traceability (each clause → how it's met)

| PS clause | How it's met |
|---|---|
| "intercepts LLM-generated code or commands before they execute, and returns a verdict" | `engine.evaluate()` is called by the API and by `@guard` before execution |
| "Called synchronously, in the hot path" / "too slow… CLI subprocess per check" | In-process Python with models loaded once; target p95 < 50 ms on rules+AST and < 150 ms with ML; latency reported |
| "A 'block' verdict must actually prevent execution" | `@guard` raises before calling the function; the demo asserts the marker file is absent |
| "No LLM-as-judge… rules, AST-aware static analysis, classical ML/SLMs or a cascade" | L1 rules → L2 AST → L3 sklearn/SLM only in the ambiguous band; no LLM calls anywhere |
| "Proof of real interception… decorator/wrapper… marker file" | `demo/intercept_check.py` with SAFE/UNSAFE pair, marker assertions, audit-hook bonus |
| "Name each [pretrained/OSS component] and its license in the README" / "thin wrapper… will score low" | License table in the README; detection logic is our own, OSS used only as building blocks |
| Nine categories | All 9 covered (section 4), plus 2 extras in `sub_categories` |
| Schema: accept `{"code"}`; return verdict, risk_score 0-1, categories, code_language (+ reason, vulnerable_lines) | Strict Pydantic models; all six fields always present; extras can be switched off |
| "organizer calls your team's own endpoint… once per snippet" | Public HTTPS endpoint on AWS EC2 plus a fallback tunnel; URL submitted before the window |
| 4.1 "Python 3.10+, Git, FastAPI… onnxruntime, optimum, scikit-learn… Static analysis libraries" | Same stack (section 3) |
| 4.1 "minimal UI or script for the live demo (input code, verdict, risk score, categories, reason, latency)" | `GET /` page with exactly those fields, plus highlighted vulnerable lines |
| 4.1 "no GPU" / 5 "Solutions that need a GPU" (out) | CPU only; ONNX int8 for any encoder |
| 4.2 "No external LLM API key… for any part of the system" | No such key or client in code, `.env.example` or training |
| 5 "single interface… covering all nine categories" | `POST /evaluate` (plus the same function for CLI/decorator use) |
| 5 "layered, CPU-first detector… keyword blocklist alone is not enough" | Cascade with taint/data-flow; the benign look-alikes prove it isn't a blocklist |
| 5 "Training or fine-tuning your own SLM/ML model… encouraged" | Our own LR trained on our own synthetic set; frozen-encoder SLM head as a stretch goal |
| 5 "A batch evaluation endpoint… per-sample response as per the given schema" | `POST /evaluate/batch` returns a list of schema responses in order |
| 5 out: "Training large foundation models from scratch" | No; only a small LR head |
| 5 out: "Executing attacker-style or test code outside the one controlled… pair" | `/evaluate` is purely static; only the demo pair ever runs |
| 5 out: "Use fake secrets and placeholder domains only" | Demo, synthetic data and tests use `AKIAEXAMPLE…`, `*.example` |
| 5 out: "Full integration into an agent framework" | Not done; the decorator is enough |
| 5 out: "polished, production-grade UI" | One static page |
| 5 out: "Hard-coding answers or patterns copied verbatim from public datasets" | Dev set is eval-only; rules are behavioral and written by us; intel IOCs come from incident reports, not datasets |
| 6 "public GitHub repository" | Yes |
| 6 "runnable service… Submit your endpoint URL… in advance" | Docker + EC2; submit the URL in P4 |
| 6 "demo/intercept_check.py" | Exact path |
| 6 "Evaluation results on the public dev sample (precision, recall, false positives)" | `eval/evaluate.py` → `eval/results.md` |
| 6 "efficiency note (model size(s), latency, accuracy before/after any optimization)" | Table: rules-only vs +LR vs +SLM fp32 vs int8 (size, p50/p95, P/R) |
| 6 "README with architecture, every pretrained component and its license, assumptions, and known limitations" | README sections exactly as named |
| 6 "short write-up (2–3 pages)" | `docs/WRITEUP.md` → PDF |
| 7 floor "Valid response schema" | Pydantic + error path still returns valid schema + schema tests |
| 7 floor "interception-proof demo genuinely works, verified live" | Script exits non-zero on failure; rehearsed |
| 7 floor "No execution of code outside the one controlled demo pair" | Enforced by design (no exec/import of input) |
| 7 floor "No hard-coded answers to the public dev sample" | No dev IDs/text in code; grep check in CI |
| 8 "CWE… MITRE ATT&CK" | Each rule carries a CWE/ATT&CK id shown in `reason` |
| 8 "Teams can expand on the shared dev sample" | Synthetic generator (expansion without copying) |
| 9 "No pre-built solution" / "Both members contribute" / "AI coding assistants allowed if disclosed" | All work inside the window; A/B split; disclosure in README |
| 9 "No attempting to… reconstruct the hidden test set" | None |
| 10 "code, run instructions, .env.example (no real secrets, no LLM key), evaluation script, README" | All present |
| 10 "live, in-person demo on the team's own laptop… interception-proof script… minimal UI" | Laptop runs the demo and UI; the API is also on EC2 |

## 10. Locked ML decisions

- Encoder: frozen; candidates `microsoft/codebert-base` vs `Salesforce/codet5p-110m-embedding`, picked by dev ablation. The license is verified on the model card before use. Exported to ONNX, int8 dynamic quantization (optimum/onnxruntime). Inference uses `onnxruntime` + `tokenizers` only (no torch at runtime). Max 512 tokens; longer code uses head+tail chunks, mean-pooled.
- Fusion: `StandardScaler(PCA64(emb)) ⊕ StandardScaler(symbolic_features)` → OneVsRest LogisticRegression (C tuned), calibrated probabilities.
- Targets: 9-length binary vector in fixed `engine.facts.CATEGORIES` order; benign = all zeros.
- Split: train/val split by template `family`, never by row. The dev set is evaluation only.
- Ablation reported: symbolic-only | embedding-only | fused, each fp32 vs int8 (P/R/FPR, p50/p95 latency, model size).
