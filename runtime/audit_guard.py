"""Interception layer for the demo.

Two defenses, both real:
  1. STATIC  — @guard reads the wrapped function's source, runs the CodeGuard
     engine, and raises *before* the function is ever called if the verdict is block.
  2. RUNTIME — while a guarded call runs, a sys.addaudithook tripwire (PEP 578)
     watches for dangerous operations (writing a startup hook, spawning a shell,
     connecting to cloud metadata, deleting outside the sandbox) and raises
     before the side effect happens. This catches anything that slipped past
     static analysis.

This module is used ONLY by the demo. The /evaluate service never runs code.
"""
import inspect
import os
import re
import sys
import textwrap
import threading

from engine.pipeline import evaluate


class BlockedByCodeGuard(Exception):
    """Raised when CodeGuard blocks a call. Carries the engine response (static)
    or the offending runtime event."""

    def __init__(self, message, *, response=None, event=None, layer="static"):
        super().__init__(message)
        self.response = response
        self.event = event
        self.layer = layer


# ---------------------------------------------------------------- runtime tripwire
_state = threading.local()

_HOOK_PATH_RX = re.compile(r"\.pth$|sitecustomize\.py$|usercustomize\.py$|/etc/cron|/etc/sudoers|"
                           r"authorized_keys$|\.bashrc$|\.service$|/etc/rc\.local", re.I)


def _policy():
    return getattr(_state, "policy", None)


def _audit(event, args):
    policy = _policy()
    if policy is None:
        return
    try:
        if event in ("open", "os.open"):
            path = str(args[0]) if args else ""
            mode = args[1] if len(args) > 1 and isinstance(args[1], str) else ""
            writing = any(m in mode for m in ("w", "a", "x", "+")) or (event == "os.open")
            if _HOOK_PATH_RX.search(path):
                _trip(f"attempt to write startup/persistence file: {path}", event)
            if writing and policy.get("deny_paths") and any(os.path.abspath(path) == p for p in policy["deny_paths"]):
                _trip(f"attempt to write guarded marker path: {path}", event)
        elif event in ("os.system", "subprocess.Popen", "os.exec", "os.spawn"):
            _trip(f"attempt to execute a subprocess/shell ({event})", event)
        elif event == "socket.connect":
            addr = args[1] if len(args) > 1 else None
            host = addr[0] if isinstance(addr, tuple) else str(addr)
            if host in ("169.254.169.254", "metadata.google.internal") or str(host).startswith("169.254."):
                _trip(f"attempt to connect to cloud metadata endpoint {host}", event)
        elif event in ("os.remove", "os.rename", "shutil.rmtree"):
            path = os.path.abspath(str(args[0])) if args else ""
            sandbox = policy.get("sandbox")
            if sandbox and not path.startswith(os.path.abspath(sandbox)):
                _trip(f"attempt to delete/move outside the sandbox: {path}", event)
    except BlockedByCodeGuard:
        raise
    except Exception:
        pass  # never let the hook itself crash the interpreter


def _trip(msg, event):
    _state.policy = None  # disarm so the exception's own unwinding can't re-trigger
    raise BlockedByCodeGuard(f"runtime tripwire: {msg}", event=event, layer="runtime")


_installed = False


def _ensure_hook():
    """Install exactly one global audit hook (hooks cannot be removed)."""
    global _installed
    if not _installed:
        sys.addaudithook(_audit)
        _installed = True


class tripwire:
    def __init__(self, sandbox=None, deny_paths=None):
        self.policy = {"sandbox": sandbox, "deny_paths": [os.path.abspath(p) for p in (deny_paths or [])]}

    def __enter__(self):
        _ensure_hook()
        _state.policy = self.policy
        return self

    def __exit__(self, *exc):
        _state.policy = None
        return False


# ---------------------------------------------------------------- static guard
def _source_of(func):
    src = textwrap.dedent(inspect.getsource(func))
    # strip decorator lines so we analyze the function body, not '@guard'
    return re.sub(r"^\s*@[\w.]+(\([^)]*\))?\s*\n", "", src, flags=re.M)


def guard(func=None, *, threshold=None, sandbox=None, deny_paths=None, verbose=True):
    """Decorator: statically evaluate a function's source; block before running it.
    If allowed, run it under the runtime tripwire."""
    def wrap(fn):
        def wrapper(*args, **kwargs):
            resp = evaluate(_source_of(fn))
            if verbose:
                _print_verdict(fn.__name__, resp)
            blk = resp["verdict"] == "block" if threshold is None else resp["risk_score"] >= threshold
            if blk:
                raise BlockedByCodeGuard(
                    f"CodeGuard blocked {fn.__name__}() [risk={resp['risk_score']}, "
                    f"categories={resp['categories']}]", response=resp, layer="static")
            with tripwire(sandbox=sandbox, deny_paths=deny_paths):
                return fn(*args, **kwargs)
        wrapper.__name__ = fn.__name__
        wrapper.__wrapped__ = fn
        return wrapper
    return wrap(func) if func else wrap


def guard_code(code: str, run_fn, *, sandbox=None, deny_paths=None, verbose=True):
    """Gate a code string: evaluate statically, run run_fn() only if allowed."""
    resp = evaluate(code)
    if verbose:
        _print_verdict("snippet", resp)
    if resp["verdict"] == "block":
        raise BlockedByCodeGuard(f"CodeGuard blocked snippet [categories={resp['categories']}]",
                                 response=resp, layer="static")
    with tripwire(sandbox=sandbox, deny_paths=deny_paths):
        return run_fn()


def _print_verdict(name, resp):
    mark = "\033[91mBLOCK\033[0m" if resp["verdict"] == "block" else "\033[92mALLOW\033[0m"
    print(f"  [{mark}] {name}  risk={resp['risk_score']:.2f}  categories={resp['categories']}  "
          f"lines={resp.get('vulnerable_lines')}  ({resp.get('latency_ms', 0)} ms)")
    if resp["verdict"] == "block":
        print(f"         reason: {resp['reason'][:120]}")
