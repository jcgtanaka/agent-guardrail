"""Original eight scenarios of the first release, kept for intent.

Expectation changes versus v0.1 (and why):
- a hard deny is now exit code 2 with a stderr message (Claude Code docs:
  exit 2 blocks before permission rules) instead of a JSON "deny";
- "no config" is no longer a silent no-op: built-in protection still
  applies, so that test now asserts ordinary paths stay allowed AND the
  built-ins still fire.
"""
import os


def test_edit_inside_protected_path_is_denied(gg):
    r = gg.run("Edit", {"file_path": os.path.join(gg.protected, "strategy.py")})
    assert r.kind == "deny"
    assert "ask the user" in r.stderr


def test_edit_outside_protected_path_is_allowed(gg):
    r = gg.run("Edit", {"file_path": os.path.join(gg.allowed, "notes.py")})
    assert r.kind == "allow"


def test_symlink_escape_into_protected_path_is_denied(gg):
    link = os.path.join(gg.allowed, "not_protected")
    os.symlink(gg.protected, link)
    r = gg.run("Write", {"file_path": os.path.join(link, "strategy.py"), "content": "x"})
    assert r.kind == "deny"


def test_bash_rm_targeting_protected_path_is_denied(gg):
    r = gg.bash("rm -rf %s" % os.path.join(gg.protected, "strategy.py"))
    assert r.kind == "deny"


def test_bash_non_destructive_command_is_allowed(gg):
    assert gg.bash("ls -la").kind == "allow"


def test_bash_destructive_with_unresolvable_variable_asks(gg):
    r = gg.bash('rm -rf "$DIR"/*')
    assert r.kind == "ask"


def test_bash_rm_outside_protected_path_is_allowed(gg):
    r = gg.bash("rm %s" % os.path.join(gg.allowed, "scratch.log"))
    assert r.kind == "allow"


def test_missing_config_does_not_disable_builtin_protection(gg):
    os.remove(gg.config)
    ok = gg.run("Edit", {"file_path": os.path.join(gg.allowed, "notes.py")})
    assert ok.kind == "allow"
    ssh = gg.run("Write", {"file_path": os.path.join(gg.home, ".ssh", "config"), "content": "x"})
    assert ssh.kind == "approve"
