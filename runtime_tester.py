#!/usr/bin/env python3
"""Generic runtime interception tester for CodeGuard.

    python runtime_tester.py <file>           # analyse + prove the gate (does NOT run your code)
    python runtime_tester.py <file> --run     # also execute ALLOWED python under the runtime tripwire
    cat snippet | python runtime_tester.py -   # read from stdin

For any code file it prints the static verdict (verdict, risk, categories, reason, lines),
then demonstrates interception: a guarded action runs only if CodeGuard allows the code.
A blocked snippet never triggers the action, proven by a marker file that is never created.
With --run, allowed Python is executed inside a sandbox under a sys.addaudithook tripwire,
so anything that slipped past static analysis is still stopped before a side effect.
"""
import argparse
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine.pipeline import evaluate
from runtime.audit_guard import BlockedByCodeGuard, guard_code


def _report(resp):
    mark = "BLOCK" if resp["verdict"] == "block" else "ALLOW"
    print(f"\n  verdict        : {mark}")
    print(f"  risk_score     : {resp['risk_score']}")
    print(f"  code_language  : {resp['code_language']}")
    print(f"  categories     : {resp.get('categories')}")
    print(f"  vulnerable_lines: {resp.get('vulnerable_lines')}")
    print(f"  reason         : {resp.get('reason')}")
    print(f"  neural_used    : {resp.get('neural_used')}  latency_ms: {resp.get('latency_ms')}")


def main():
    ap = argparse.ArgumentParser(description="CodeGuard runtime interception tester")
    ap.add_argument("path", help="code file to test, or - for stdin")
    ap.add_argument("--run", action="store_true",
                    help="execute ALLOWED python under the runtime tripwire (default: do not run)")
    args = ap.parse_args()

    code = sys.stdin.read() if args.path == "-" else open(args.path, encoding="utf-8", errors="replace").read()

    print("=" * 70)
    print(f"CodeGuard runtime test: {args.path}")
    print("=" * 70)
    resp = evaluate(code)
    _report(resp)

    sandbox = tempfile.mkdtemp(prefix="cg_rt_")
    marker = os.path.join(sandbox, "executed_marker.txt")

    def action():
        # With --run, execute first so a runtime-blocked dangerous call stops BEFORE the
        # marker is written. The marker is the observable proof the action completed.
        if args.run and resp["code_language"] == "python":
            exec(compile(code, "<guarded>", "exec"), {"__name__": "__guarded__"})
        with open(marker, "w") as f:
            f.write("action executed\n")
        return "ran"

    print("\n  interception:")
    try:
        guard_code(code, action, sandbox=sandbox, verbose=False)
        ran = os.path.exists(marker)
        print(f"    ALLOWED -> guarded action ran: {ran}")
        if resp["code_language"] == "python" and not args.run:
            print("    (your code itself was NOT executed; pass --run to execute allowed python)")
    except BlockedByCodeGuard as e:
        clean = not os.path.exists(marker)
        where = "static analysis (before running)" if e.layer == "static" else "runtime tripwire (before the side effect)"
        print(f"    INTERCEPTED by {where}; marker never created: {clean}")

    import shutil
    shutil.rmtree(sandbox, ignore_errors=True)

    print("\n" + "=" * 70)
    print(f"RESULT: {'BLOCKED (would not execute)' if resp['verdict']=='block' else 'ALLOWED'}")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
