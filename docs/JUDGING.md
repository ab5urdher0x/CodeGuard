# Judging kit — 2-minute pitch + likely questions

## 2-minute technical explanation

> **The problem.** AI agents now write and *run* their own code, shell, and SQL. That
> code can leak secrets, wipe data, install malicious packages, or carry hidden prompt
> injections. Existing scanners are batch CI tools — too slow to sit in front of every
> agent action.
>
> **CodeGuard** is a real-time safety layer. An agent sends a snippet to `POST /evaluate`
> and gets back, in about a millisecond, a verdict — allow or block — with a risk score,
> the threat categories, and the exact vulnerable lines. No LLM is called to make that
> decision; it's CPU-only static analysis, so it's cheap and fast enough to run inline.
>
> **How it decides** is the interesting part. We don't keyword-match — `os` and
> `subprocess` aren't malicious by themselves. We detect *meaning*: the Python layer
> parses the code into an AST and tracks data flow. If a value from a secret file, an
> environment variable, or user input flows into a dangerous sink — `eval`, `os.system`,
> `requests.post`, a formatted SQL query — that's flagged. A *constant* reaching the same
> sink is fine. That's why we correctly allow `ast.literal_eval`, parameterised SQL, and
> reading a config file, while blocking their malicious twins. Bash, SQL, JavaScript and
> YAML have their own rule layers, and a universal pass scans every language for secrets,
> SSRF addresses, and prompt-injection text.
>
> **Proof it actually gates execution:** a `@guard` decorator runs the engine on a
> function's source before calling it. In our demo, a malicious startup-hook planter is
> blocked and never runs — we prove it with a marker file that never gets created. A
> second runtime audit hook catches anything that slips past static analysis.
>
> **On honesty:** we score 100% on the dev set, but we *tuned* on it, so that is not a
> real-world number. We built a small, independent hold-out we never touched — on that it's
> about 86% precision, 80% recall, which is our rough real estimate. We also trained a small ML classifier, measured it in shadow mode,
> found it just repeated the rules' mistakes, and left it off. We ship the rules, not a
> number.

*(Timing: ~110 seconds at a normal pace.)*

---

## 10 likely judge questions — with accurate answers

**1. How is this different from a keyword blocklist?**
We track data flow, not keywords. The Python analyzer builds an AST and propagates
"taint" from sources (decoded bytes, secrets, user input) to sinks (exec/shell/network/
SQL). A constant reaching a sink is allowed; a tainted one is blocked. Benign look-alikes
(`ast.literal_eval`, parameterised SQL, `crontab -l`) stay allowed — that's the proof it
isn't a blocklist.

**2. How is the risk score computed?**
Each rule emits a confidence 0–1. Per category we combine them with noisy-OR
(`1 − ∏(1 − sᵢ)`), so weak signals stack and one strong signal suffices. Overall risk is
the top category's score, nudged up if several fire. Block if ≥ 0.60.

**3. You claim "no LLM" — what actually makes the decision?**
Deterministic static analysis: Python's `ast`, tokenisers, regex rules, and IP/URL
classification. No model is called for the verdict. We did train an optional classical ML
classifier, but it's off by default and never required.

**4. Does `/evaluate` ever run the submitted code?**
Never. It only parses and inspects. The *only* code that executes is our own controlled
demo pair, and even there a runtime audit hook gates it. We have a test that submits a
file-writing snippet and asserts the file is never created.

**5. How do you handle a language you can't parse, or deliberately broken code?**
Fail closed. If the Python parser fails, the other layers still run; if everything fails,
we return a valid `block`. Oversized input is analyzed head-and-tail (so a payload hidden
after megabytes of padding is still seen) and flagged.

**6. What stops a false positive on normal code using `os`/`subprocess`?**
The taint check. `subprocess.run(['git','status'])` with constant args is allowed;
`subprocess.run('rm -rf '+path, shell=True)` with a built-up string is blocked. We keep a
benign twin for every malicious test specifically to hold the false-positive rate down.

**7. Your scores are 100% — is that real?**
On the dev and synthetic-validation sets, yes — but we *tuned* against them, so that's
optimistic, not a real-world figure. Our honest estimate comes from a small, independent
hold-out of 30 examples we never tuned on: ~86% precision, ~80% recall. We lead with that,
and note it's a limited set — the hidden judging set will differ.

**8. Where does the ML fit, and why is it off?**
We trained a logistic-regression head (symbolic features + TF-IDF) on synthetic data only.
In shadow mode it changed zero verdicts on the hold-out and repeated the rules' exact
errors (it learned the same patterns), while adding latency. So we kept rules-only and
documented the experiment rather than shipping ML for show.

**9. What's the "Black October" angle?**
October 2026's LiteLLM supply-chain attack planted a Python startup hook
(`.pth`/`sitecustomize.py`) that ran on every interpreter start and exfiltrated keys to a
look-alike domain. We generalised that into behavioural rules — startup-hook persistence,
look-alike domains, AI-key harvesting, compromised-version installs, slopsquats — backed
by an updatable intel file.

**10. How would you deploy this in a real agent framework?**
It's a synchronous function (`engine.pipeline.evaluate`) and an HTTP endpoint, so an agent
wraps its code-execution tool with a call to `/evaluate` (or the `@guard` decorator) and
refuses to run on a block. p95 ≈ 1 ms keeps it inline. Framework integration wasn't
required for the hackathon, but the decorator shows the integration point.

---

### Quick facts to have ready
- 9 categories, multi-label, strict fixed schema (`verdict`, `risk_score`, `categories`,
  `code_language`, `reason`, `vulnerable_lines`).
- 98 tests; every rule has a malicious case + benign twin.
- Endpoints: `POST /evaluate`, `POST /evaluate/batch`, `GET /health`, `GET /` (UI).
- ~2,200 lines of engine code; CPU-only; p95 ~1 ms local in-process analysis latency.
