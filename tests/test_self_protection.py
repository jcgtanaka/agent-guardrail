"""The guard must protect its own script, config, state and hook registration."""
import os

import pytest

from conftest import HOOK, REPO


def self_targets(gg):
    return {
        "hook script": HOOK,
        "hook library": os.path.join(REPO, "hooks", "guardrail_defaults.py"),
        "config": gg.config,
        "state dir file": os.path.join(gg.state, "pending", "x.json"),
        "state key": os.path.join(gg.state, "hmac.key"),
        "user settings": os.path.join(gg.home, ".claude", "settings.json"),
        "project settings": os.path.join(gg.allowed, ".claude", "settings.json"),
        "project local settings": os.path.join(gg.allowed, ".claude", "settings.local.json"),
    }


def test_file_tools_cannot_touch_self(gg):
    for name, path in self_targets(gg).items():
        r = gg.run("Write", {"file_path": path, "content": "x"})
        assert r.kind == "deny", name
        assert "protected by agent-guardrail" in r.stderr


def test_bash_cannot_touch_self(gg):
    for name, path in self_targets(gg).items():
        for cmd in ("rm %s" % path, "echo x > %s" % path, "sed -i s/a/b/ %s" % path,
                    "cp /tmp/x %s" % path):
            assert gg.bash(cmd).kind == "deny", (name, cmd)


def test_reading_self_is_allowed(gg):
    assert gg.bash("cat %s" % gg.config).kind == "allow"


def test_self_protection_survives_disabled_os_layer(gg):
    gg.write_config(builtin_os_protection=False)
    for name, path in self_targets(gg).items():
        assert gg.run("Write", {"file_path": path, "content": "x"}).kind == "deny", name


def test_allow_paths_cannot_override_self_protection(gg):
    gg.write_config(allow_paths=[
        os.path.dirname(gg.config), gg.state, os.path.join(REPO, "hooks"),
        gg.home, gg.allowed, "**/settings.json", "**/*.json",
    ])
    for name, path in self_targets(gg).items():
        assert gg.run("Write", {"file_path": path, "content": "x"}).kind == "deny", name


def test_symlink_to_self_is_resolved(gg):
    link = os.path.join(gg.allowed, "innocent.json")
    os.symlink(gg.config, link)
    assert gg.run("Write", {"file_path": link, "content": "x"}).kind == "deny"


def test_env_override_config_path_is_protected_even_if_missing(gg):
    os.remove(gg.config)
    assert gg.run("Write", {"file_path": gg.config, "content": "{}"}).kind == "deny"


def test_state_dir_override_is_protected(gg):
    other = os.path.join(gg.tmp, "other_state")
    r = gg.run("Write", {"file_path": os.path.join(other, "pending", "x.json"), "content": "x"},
               AGENT_GUARDRAIL_STATE_DIR=other)
    assert r.kind == "deny"
