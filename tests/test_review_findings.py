"""Regression tests for gaps found in the security review of the redesign.

Each test states the guarantee it protects. They run the hook as a subprocess
against an isolated HOME / config / state dir (see conftest.py).
"""
import os

import guardrail_cli as cli


def approve(gg, rid):
    cli.approve(rid, state_dir=gg.state, require_tty=False,
                input_fn=lambda *_: "yes", out=lambda s: None)


# ----- file-writing tools other than Edit/Write/NotebookEdit ---------------

def test_multiedit_into_protected_path_is_denied(gg):
    target = os.path.join(gg.protected, "f.py")
    r = gg.run("MultiEdit", {"file_path": target,
                             "edits": [{"old_string": "a", "new_string": "b"}]})
    assert r.kind == "deny"


def test_unknown_mcp_write_tool_with_path_field_is_checked(gg):
    r = gg.run("mcp__filesystem__write_file",
               {"path": os.path.join(gg.protected, "f.py"), "content": "x"})
    assert r.kind == "deny"


def test_unknown_tool_targeting_the_guard_itself_is_denied(gg):
    r = gg.run("MultiEdit", {"file_path": gg.config, "edits": []})
    assert r.kind == "deny"


def test_tool_name_case_does_not_bypass_file_tool_checks(gg):
    r = gg.run("write", {"file_path": os.path.join(gg.protected, "f.py"), "content": "x"})
    assert r.kind == "deny"


def test_unknown_tool_without_any_path_field_is_allowed(gg):
    assert gg.run("WebFetch", {"url": "https://example.com"}).kind == "allow"
    assert gg.run("mcp__x__search", {"query": "hello"}).kind == "allow"


def test_unknown_tool_in_allowed_project_is_allowed(gg):
    r = gg.run("MultiEdit", {"file_path": os.path.join(gg.allowed, "a.py"),
                             "edits": [{"old_string": "a", "new_string": "b"}]})
    assert r.kind == "allow"


def test_multiedit_content_is_scanned_for_secrets(gg):
    key = "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----"
    r = gg.run("MultiEdit", {"file_path": os.path.join(gg.allowed, "a.py"),
                             "edits": [{"old_string": "a", "new_string": key}]})
    assert r.kind == "ask"


# ----- approvals are bound to where the command runs -----------------------

def test_bash_approval_is_not_replayable_from_another_directory(gg):
    sub = os.path.join(gg.apr, "sub")
    os.makedirs(sub)
    first = gg.bash("rm x", cwd=gg.apr)
    assert first.kind == "approve"
    approve(gg, first.approval_id)
    second = gg.bash("rm x", cwd=sub)  # different real target, same command text
    assert second.kind == "approve", "approval for apr/x must not cover apr/sub/x"
    assert gg.bash("rm x", cwd=gg.apr).kind == "allow", "the original approval still works once"


# ----- source / dot execute a file the analyser cannot see -----------------

def test_sourcing_a_file_inside_a_protected_root_is_not_silently_allowed(gg):
    assert gg.bash("source %s/env.sh" % gg.apr).kind in ("ask", "approve")
    assert gg.bash(". %s/env.sh" % gg.askd).kind in ("ask", "approve")


def test_sourcing_an_unprotected_file_is_allowed(gg):
    assert gg.bash("source %s/venv/bin/activate" % gg.allowed).kind == "allow"
