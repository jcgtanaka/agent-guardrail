"""Corrupt config and malformed stdin must block (exit 2), never crash (exit 1)."""
import json

import pytest


def assert_closed(r):
    assert r.returncode == 2, (r.returncode, r.stderr)
    assert "Traceback" not in r.stderr
    assert "agent-guardrail" in r.stderr
    assert r.stdout.strip() == ""


@pytest.mark.parametrize("raw", [
    "{not json",
    "",
    "[]",
    json.dumps({"protected_paths": "nope"}),
    json.dumps({"protected_paths": [{"reason": "no path"}]}),
    json.dumps({"protected_paths": [{"path": "/x", "tier": "maybe"}]}),
    json.dumps({"protected_paths": [{"path": 5}]}),
    json.dumps({"sensitive_globs": "x"}),
    json.dumps({"sensitive_content_patterns": ["(unclosed"]}),
    json.dumps({"allow_paths": [1]}),
    json.dumps({"builtin_os_protection": "yes"}),
    json.dumps({"approval": {"ttl_seconds": -5}}),
    json.dumps({"approval": {"ttl_seconds": "soon"}}),
])
def test_corrupt_config_fails_closed(gg, raw):
    gg.write_config(raw=raw)
    r = gg.bash("ls")
    assert_closed(r)
    assert "config" in r.stderr.lower()
    r = gg.run("Write", {"file_path": gg.allowed + "/a.txt", "content": "x"})
    assert_closed(r)


@pytest.mark.parametrize("stdin", ["not json", "", "[]", "42", '{"tool_name": "Bash", "tool_input": "x"}'])
def test_malformed_stdin_fails_closed(gg, stdin):
    r = gg.run(None, None, stdin=stdin)
    assert_closed(r)


def test_bash_command_of_wrong_type_fails_closed(gg):
    r = gg.run("Bash", {"command": ["rm", "x"]})
    assert_closed(r)


def test_valid_config_with_all_keys_loads(gg):
    gg.write_config(
        sensitive_globs=["**/.env"],
        sensitive_content_patterns=["abc[0-9]+"],
        allow_paths=[],
        builtin_os_protection=True,
        approval={"ttl_seconds": 60},
    )
    assert gg.bash("ls").kind == "allow"
