"""An `ask` only reaches a human when the session prompts for it.

In auto mode Claude Code can resolve a hook's `ask` without showing it to the
user (observed with a credential-looking Write that went through silently),
and the documentation does not say what `ask` does in the other modes. The
guard therefore trusts a native `ask` only in "default" (Manual) mode and
turns it into the out-of-band approval flow everywhere else, including when
the mode is missing or unknown.
"""
import json
import os

import pytest

import guardrail_cli as cli

FAKE_KEY = "aws_access_key_id = AKIA" + "IOSFODNN7EXAMPLE\n"  # AWS's documented example key


def write_key(gg, mode="default"):
    return gg.run("Write", {"file_path": os.path.join(gg.allowed, "creds.txt"),
                            "content": FAKE_KEY}, mode=mode)


def approve(gg, rid):
    cli.approve(rid, state_dir=gg.state, require_tty=False,
                input_fn=lambda *_: "yes", out=lambda s: None)


def test_ask_stays_a_native_prompt_in_default_mode(gg):
    r = write_key(gg, "default")
    assert r.kind == "ask"
    assert r.reason.startswith("=== AGENT-GUARDRAIL WARNING")


@pytest.mark.parametrize("mode", ["auto", "dontAsk", "bypassPermissions", "plan",
                                  "acceptEdits", "somethingNew"])
def test_ask_becomes_out_of_band_approval_outside_default_mode(gg, mode):
    r = write_key(gg, mode)
    assert r.kind == "approve", r.kind
    assert r.approval_id
    assert "AWS access key id" in r.stderr
    assert mode in r.stderr  # tells the human why a prompt is not enough


def test_missing_or_non_string_mode_fails_safe(gg):
    assert write_key(gg, None).kind == "approve"
    payload = {"tool_name": "Write", "cwd": gg.tmp, "permission_mode": 7,
               "tool_input": {"file_path": os.path.join(gg.allowed, "c.txt"),
                              "content": FAKE_KEY}}
    assert gg.run(None, None, stdin=json.dumps(payload)).kind == "approve"


def test_bash_ask_cases_follow_the_same_rule(gg):
    cmd = "source %s/env.sh" % gg.askd
    assert gg.bash(cmd, mode="default").kind == "ask"
    assert gg.bash(cmd, mode="auto").kind == "approve"


def test_converted_ask_can_be_approved_once_and_then_allows(gg):
    first = write_key(gg, "auto")
    assert first.kind == "approve"
    approve(gg, first.approval_id)
    assert write_key(gg, "auto").kind == "allow"
    assert write_key(gg, "auto").kind == "approve", "the approval is single-use"


def test_modes_do_not_change_deny_or_allow(gg):
    protected = os.path.join(gg.protected, "f.py")
    clean = os.path.join(gg.allowed, "a.py")
    for mode in ("default", "auto", "bypassPermissions", None):
        assert gg.run("Write", {"file_path": protected, "content": "x"}, mode=mode).kind == "deny"
        assert gg.run("Write", {"file_path": clean, "content": "x"}, mode=mode).kind == "allow"
