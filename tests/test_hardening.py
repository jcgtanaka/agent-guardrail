"""Low-severity items from the security review: id length, content-scan limits,
and control characters in configured paths."""
import os
import signal
import subprocess
import sys

import pytest

from conftest import GEN


# ----- approval ids are 64 bits -------------------------------------------

def test_approval_id_is_sixteen_hex_characters(gg):
    rid = gg.bash("rm %s/.ssh/id_x" % gg.home).approval_id
    assert rid is not None and len(rid) == 16


# ----- content scanning has a size cap and a time limit ---------------------

def write(gg, content):
    return gg.run("Write", {"file_path": os.path.join(gg.allowed, "big.txt"),
                            "content": content})


def test_oversize_content_asks_instead_of_silently_skipping_the_scan(gg):
    r = write(gg, "x" * 1_100_000)
    assert r.kind == "ask"
    assert "larger than" in r.reason


def test_content_under_the_cap_is_still_scanned_in_full(gg):
    key = "AKIA" + "IOSFODNN7EXAMPLE"
    r = write(gg, "x" * 900_000 + "\n" + key + "\n")
    assert r.kind == "ask"
    assert "AWS access key id" in r.reason


@pytest.mark.skipif(not hasattr(signal, "SIGALRM"), reason="needs SIGALRM (POSIX)")
def test_catastrophic_user_pattern_fails_closed_instead_of_hanging(gg):
    gg.write_config(sensitive_content_patterns=["(a+)+$"], content_scan_timeout_seconds=1)
    r = write(gg, "a" * 40 + "!")
    assert r.returncode == 2
    assert "scan" in r.stderr.lower()


@pytest.mark.parametrize("bad", [0, -1, "5", True])
def test_invalid_scan_timeout_fails_closed(gg, bad):
    gg.write_config(content_scan_timeout_seconds=bad)
    r = gg.bash("ls")
    assert r.returncode == 2
    assert "content_scan_timeout_seconds" in r.stderr


# ----- control characters in configured paths -----------------------------

@pytest.mark.parametrize("key,value", [
    ("protected_paths", [{"path": "/x\n/y"}]),
    ("sensitive_globs", ["**/a\nb"]),
    ("allow_paths", ["/p\tq"]),
])
def test_control_characters_in_config_paths_are_rejected(gg, key, value):
    gg.write_config(**{key: value})
    r = gg.bash("ls")
    assert r.returncode == 2
    assert "control character" in r.stderr


def test_generator_rejects_control_characters_in_paths(gg):
    p = subprocess.run([sys.executable, GEN, "bwrap"], capture_output=True, text=True,
                       env=gg.env(AGENT_GUARDRAIL_STATE_DIR="state\nbad"), timeout=20)
    assert p.returncode == 1
    assert "control character" in p.stderr
    assert p.stdout == ""
