"""tools/gen_sandbox.py prints wrappers; it must never execute anything."""
import os
import subprocess
import sys

import pytest

from conftest import GEN


def gen(gg, target):
    p = subprocess.run([sys.executable, GEN, target], capture_output=True, text=True,
                       env=gg.env(), timeout=20)
    assert p.returncode == 0, p.stderr
    return p.stdout


@pytest.mark.parametrize("target", ["bwrap", "seatbelt", "windows"])
def test_output_starts_with_untested_comment_and_lists_protected_paths(gg, target):
    out = gen(gg, target)
    first = out.splitlines()[0]
    assert first.startswith(("#", ";", "REM"))
    assert "not tested" in first.lower() and "review" in first.lower()
    for path in (gg.protected, gg.apr, gg.askd):
        assert path in out


def test_bwrap_shape(gg):
    out = gen(gg, "bwrap")
    assert "bwrap" in out
    assert out.index("--bind / /") < out.index("--ro-bind-try %s" % gg.protected)
    assert "--dev /dev" in out
    # self-protection paths are mounted read-only too
    assert gg.config in out and gg.state in out


def test_seatbelt_shape(gg):
    out = gen(gg, "seatbelt")
    assert "(allow default)" in out
    assert '(deny file-write* ' in out
    assert '(subpath "%s")' % gg.protected in out
    assert out.index("(allow default)") < out.index("(deny file-write*")


def test_windows_note_has_icacls_and_wsl(gg):
    out = gen(gg, "windows")
    assert "icacls" in out and "/deny" in out
    assert "WSL2" in out


def test_nothing_is_executed_and_metacharacters_are_quoted(gg):
    canary = os.path.join(gg.tmp, "canary")
    evil = os.path.join(gg.tmp, "we ird; touch %s; $(touch %s)" % (canary, canary))
    os.makedirs(evil)
    import json
    gg.write_config(raw=json.dumps({"protected_paths": [{"path": evil}]}))
    for target in ("bwrap", "seatbelt", "windows"):
        gen(gg, target)
    assert not os.path.exists(canary)
    out = gen(gg, "bwrap")
    assert "'" in out.split("--ro-bind-try", 1)[1].splitlines()[0]


def test_all_target_prints_every_section(gg):
    out = gen(gg, "all")
    assert "bwrap" in out and "(allow default)" in out and "icacls" in out
