#!/usr/bin/env python3
"""Interception proof.

Shows CodeGuard gating real function calls and proves, via marker files on disk,
that a blocked snippet NEVER executes.

  SAFE   : an ordinary agent helper -> ALLOW -> runs -> writes safe_marker.txt
  UNSAFE : an "AI-generated setup helper" that mimics the Oct-2026 LiteLLM
           supply-chain attack (plants a Python startup hook) -> BLOCK (static)
           -> never runs -> hacked.txt is never created
  STEALTH: the same attack with its filename built dynamically to slip past
           static analysis -> the runtime audit-hook tripwire stops it before
           the write -> hacked.txt is never created

Everything happens inside a throwaway temp dir. No network. Fake content only.
Exit code 0 only if every assertion holds.
"""
import argparse
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from runtime.audit_guard import BlockedByCodeGuard, guard, guard_code  # noqa: E402

SANDBOX = tempfile.mkdtemp(prefix="codeguard_demo_")
SAFE_MARKER = os.path.join(SANDBOX, "safe_marker.txt")
HACKED = os.path.join(SANDBOX, "hacked.txt")
# a path shaped like a real Python startup hook, but kept inside the sandbox
HOOK = os.path.join(SANDBOX, "site-packages", "sitecustomize.py")


# ----------------------------------------------------------------- the functions
@guard(sandbox=SANDBOX, deny_paths=[HACKED])
def format_report():
    """Benign: format a short status report and record that it ran."""
    report = "build: ok\ntests: 48 passed\n"
    with open(SAFE_MARKER, "w") as f:
        f.write(report)
    return report


@guard(sandbox=SANDBOX, deny_paths=[HACKED])
def setup_environment(base):
    """AI-generated 'setup helper' — actually plants a startup hook (LiteLLM-style
    supply-chain persistence) and drops a marker proving it executed. The tell-tale
    'sitecustomize.py' is visible in the function's own source, so static analysis
    catches it before the function is ever called."""
    hook_path = base + "/site-packages/sitecustomize.py"   # runs on every interpreter start
    os.makedirs(os.path.dirname(hook_path), exist_ok=True)
    with open(hook_path, "w") as f:
        f.write("import os  # would exfiltrate on every python launch\n")
    with open(base + "/hacked.txt", "w") as f:
        f.write("payload executed\n")
    return "environment ready"


@guard(sandbox=SANDBOX, deny_paths=[HACKED])
def setup_environment_obfuscated():
    """Same attack, obfuscated: the hook filename is assembled at runtime so the
    static layer may not see 'sitecustomize.py'. The runtime tripwire must catch it."""
    parts = ["site", "customize"]
    name = "".join(parts) + "." + "".join(reversed("yp")) + chr(0x79)  # -> sitecustomize.py
    target = os.path.join(SANDBOX, "site-packages", name)
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "w") as f:
        f.write("import os\n")
    with open(HACKED, "w") as f:
        f.write("payload executed\n")
    return "done"


# ----------------------------------------------------------------- harness
def banner(ok, text):
    color = "\033[92m" if ok else "\033[91m"
    print(f"{color}{'PASS' if ok else 'FAIL'}\033[0m  {text}")


def run():
    results = []

    print("\n1) SAFE helper — expect ALLOW, runs, safe_marker.txt appears")
    out = format_report()
    ok = out and os.path.exists(SAFE_MARKER)
    banner(ok, "safe helper ran and created its marker")
    results.append(ok)

    print("\n2) UNSAFE setup helper — expect BLOCK (static), never runs, no hacked.txt")
    blocked = False
    try:
        setup_environment(SANDBOX)
    except BlockedByCodeGuard as e:
        blocked = True
        print(f"     intercepted at {e.layer} layer")
    ok = blocked and not os.path.exists(HACKED) and not os.path.exists(HOOK)
    banner(ok, "unsafe helper was blocked and never executed (hacked.txt absent)")
    results.append(ok)

    print("\n3) STEALTH variant — obfuscated to evade static; runtime tripwire must stop it")
    blocked = False
    try:
        setup_environment_obfuscated()
    except BlockedByCodeGuard as e:
        blocked = True
        print(f"     intercepted at {e.layer} layer")
    ok = blocked and not os.path.exists(HACKED)
    banner(ok, "stealth variant was blocked before writing hacked.txt")
    results.append(ok)

    return all(results)


def run_external(safe_path, unsafe_path):
    """Optional: gate snippet files supplied by the organizer (the one controlled pair)."""
    for path, expect in ((safe_path, "allow"), (unsafe_path, "block")):
        if not path:
            continue
        code = open(path).read()
        print(f"\nExternal snippet {path} (expect {expect}):")
        marker = os.path.join(SANDBOX, "ext_marker.txt")
        try:
            guard_code(code, lambda: open(marker, "w").write("ran"), sandbox=SANDBOX, deny_paths=[marker])
            print("     ran (allowed)")
        except BlockedByCodeGuard:
            print("     blocked — snippet did not run")


def main():
    ap = argparse.ArgumentParser(description="CodeGuard interception proof")
    ap.add_argument("--safe", help="path to a safe snippet to gate")
    ap.add_argument("--unsafe", help="path to an unsafe snippet to gate")
    args = ap.parse_args()
    try:
        print("=" * 68)
        print("CodeGuard — interception proof   (sandbox: %s)" % SANDBOX)
        print("=" * 68)
        ok = run()
        if args.safe or args.unsafe:
            run_external(args.safe, args.unsafe)
        print("\n" + "=" * 68)
        if ok:
            print("\033[92m  ALL CHECKS PASSED — blocked code never executed.\033[0m")
        else:
            print("\033[91m  CHECKS FAILED.\033[0m")
        print("=" * 68)
        return 0 if ok else 1
    finally:
        shutil.rmtree(SANDBOX, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
