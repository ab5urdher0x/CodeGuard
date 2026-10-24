#!/usr/bin/env python3
"""Quick CLI: paste/pipe code, get the CodeGuard verdict. Static only — never runs the code."""
import sys, json
sys.path.insert(0, ".")
from engine.pipeline import evaluate
code = sys.stdin.read() if not sys.argv[1:] else open(sys.argv[1]).read()
r = evaluate(code)
print(json.dumps({k: r[k] for k in ("verdict","risk_score","categories","code_language","reason","vulnerable_lines")}, indent=2))
