"""Edit/Write/NotebookEdit: tiers, sensitive globs, content patterns, allow_paths."""
import json
import os

import pytest

from conftest import assert_ask_banner

# Built from fragments so this file never contains a literal secret that
# a secret scanner would flag.
AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
GH_TOKEN = "ghp_" + "a" * 36
SK_TOKEN = "sk-" + "A1b2C3d4" * 4
SLACK = "xoxb-" + "1234567890-abcdefghij"
PEM = "-----BEGIN RSA PRIVATE " + "KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----"


def write(gg, path, content="x", tool="Write"):
    if tool == "Write":
        return gg.run("Write", {"file_path": path, "content": content})
    if tool == "Edit":
        return gg.run("Edit", {"file_path": path, "old_string": "a", "new_string": content})
    return gg.run("NotebookEdit", {"notebook_path": path, "new_source": content})


def test_tiers_for_file_tools(gg):
    assert write(gg, os.path.join(gg.protected, "a.py")).kind == "deny"
    assert write(gg, os.path.join(gg.apr, "a.py")).kind == "approve"
    r = write(gg, os.path.join(gg.askd, "a.py"))
    assert r.kind == "ask"
    assert_ask_banner(r.reason)


def test_notebook_path_is_checked(gg):
    assert write(gg, os.path.join(gg.protected, "n.ipynb"), tool="Notebook").kind == "deny"


def test_default_tier_of_legacy_entry_is_deny(gg):
    gg.write_config(raw=json.dumps({"protected_paths": [{"path": gg.apr}]}))
    assert write(gg, os.path.join(gg.apr, "a.py")).kind == "deny"


@pytest.mark.parametrize("rel", [
    ".env", "sub/.env", ".env.local", "k/server.pem", "id_rsa", "id_rsa.pub",
    "id_ed25519", "x/credentials", ".netrc", ".npmrc", ".pgpass", "vault.kdbx",
])
def test_sensitive_globs_need_approval(gg, rel):
    path = os.path.join(gg.allowed, rel)
    assert write(gg, path).kind == "approve", rel


@pytest.mark.parametrize("rel", ["environment.py", ".envrc", "pem_notes.txt", "my_credentials.md"])
def test_non_sensitive_lookalikes_are_allowed(gg, rel):
    assert write(gg, os.path.join(gg.allowed, rel)).kind == "allow", rel


def test_sensitive_globs_apply_to_bash_writes(gg):
    assert gg.bash("echo K=1 > %s/.env" % gg.allowed).kind == "approve"
    assert gg.bash("cat %s/.env" % gg.allowed).kind == "allow"


def test_sensitive_globs_are_configurable(gg):
    gg.write_config(sensitive_globs=["**/*.secret"])
    assert write(gg, os.path.join(gg.allowed, "a.secret")).kind == "approve"
    assert write(gg, os.path.join(gg.allowed, ".env")).kind == "allow"


@pytest.mark.parametrize("content", [PEM, AWS_KEY, GH_TOKEN, SK_TOKEN, SLACK])
@pytest.mark.parametrize("tool", ["Write", "Edit", "Notebook"])
def test_content_patterns_ask(gg, content, tool):
    r = write(gg, os.path.join(gg.allowed, "notes.txt"), content=content, tool=tool)
    assert r.kind == "ask"
    assert_ask_banner(r.reason)
    # The message must not echo the secret back into the transcript.
    assert content not in r.reason


@pytest.mark.parametrize("content", ["hello", "task-1-sk-short", "AKIA short", "ghp_tooshort"])
def test_benign_content_is_allowed(gg, content):
    assert write(gg, os.path.join(gg.allowed, "notes.txt"), content=content).kind == "allow"


def test_old_string_is_not_scanned(gg):
    r = gg.run("Edit", {"file_path": os.path.join(gg.allowed, "n.txt"),
                        "old_string": AWS_KEY, "new_string": "REDACTED"})
    assert r.kind == "allow"


def test_extra_content_pattern_from_config(gg):
    gg.write_config(sensitive_content_patterns=[r"corp-[0-9]{6}"])
    assert write(gg, os.path.join(gg.allowed, "n.txt"), content="id corp-123456").kind == "ask"
    assert write(gg, os.path.join(gg.allowed, "n.txt"), content="id corp-12").kind == "allow"


def test_approve_beats_ask_when_both_fire(gg):
    assert write(gg, os.path.join(gg.allowed, ".env"), content=AWS_KEY).kind == "approve"


def test_allow_paths_narrow_a_user_deny_root(gg):
    gg.write_config(allow_paths=[os.path.join(gg.protected, "dashboard")])
    assert write(gg, os.path.join(gg.protected, "dashboard", "a.py")).kind == "allow"
    assert gg.bash("rm %s/dashboard/a.py" % gg.protected).kind == "allow"
    assert write(gg, os.path.join(gg.protected, "src", "a.py")).kind == "deny"
    # sibling prefix of the allow path must not be allowed
    assert write(gg, os.path.join(gg.protected, "dashboard-x", "a.py")).kind == "deny"


def test_allow_paths_support_globs_for_sensitive_files(gg):
    gg.write_config(allow_paths=["**/.env.example"])
    assert write(gg, os.path.join(gg.allowed, ".env.example")).kind == "allow"
    assert write(gg, os.path.join(gg.allowed, ".env")).kind == "approve"


def test_file_tool_without_path_is_allowed(gg):
    assert gg.run("Write", {"content": "x"}).kind == "allow"


def test_unknown_tool_is_allowed(gg):
    assert gg.run("Read", {"file_path": os.path.join(gg.protected, "a.py")}).kind == "allow"
