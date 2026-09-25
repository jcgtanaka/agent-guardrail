"""Tests for hooks/pretooluse_path_guard.py.

Each protected path needs both a positive fixture (a plain attempt that
must be blocked) and a negative fixture (a disguised attempt, such as a
symlink, that must still be blocked). Shipping only the plain case would
give a false sense of safety: see README.md and CVE-2025-53109/53110
(EscapeRoute) for why the symlink case matters.

Run with: pytest tests/test_path_guard.py -v
"""
import json
import os
import subprocess
import sys
import tempfile

import pytest

HOOK_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "hooks",
    "pretooluse_path_guard.py",
)


def run_hook(tool_name, tool_input, cwd, config_path):
    payload = {"tool_name": tool_name, "tool_input": tool_input, "cwd": cwd}
    env = dict(os.environ, AGENT_GUARDRAIL_CONFIG=config_path)
    result = subprocess.run(
        [sys.executable, HOOK_PATH],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        env=env,
        timeout=10,
    )
    if not result.stdout.strip():
        return None
    return json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"]


@pytest.fixture
def sandbox():
    with tempfile.TemporaryDirectory() as tmp:
        protected = os.path.join(tmp, "protected_project")
        allowed = os.path.join(tmp, "allowed_project")
        os.makedirs(protected)
        os.makedirs(allowed)

        config_path = os.path.join(tmp, "protected_paths.json")
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump({"protected_paths": [{"path": protected, "reason": "test"}]}, f)

        yield {
            "tmp": tmp,
            "protected": protected,
            "allowed": allowed,
            "config": config_path,
        }


def test_edit_inside_protected_path_is_denied(sandbox):
    target = os.path.join(sandbox["protected"], "strategy.py")
    decision = run_hook("Edit", {"file_path": target}, sandbox["tmp"], sandbox["config"])
    assert decision == "deny"


def test_edit_outside_protected_path_is_allowed(sandbox):
    target = os.path.join(sandbox["allowed"], "notes.py")
    decision = run_hook("Edit", {"file_path": target}, sandbox["tmp"], sandbox["config"])
    assert decision is None


def test_symlink_escape_into_protected_path_is_denied(sandbox):
    # A new symlink inside the allowed directory that actually points at
    # the protected directory. This is the exact shape of the EscapeRoute
    # bypass: a naive string-prefix check on the literal path would miss it.
    link = os.path.join(sandbox["allowed"], "not_protected")
    os.symlink(sandbox["protected"], link)
    target = os.path.join(link, "strategy.py")
    decision = run_hook("Write", {"file_path": target}, sandbox["tmp"], sandbox["config"])
    assert decision == "deny"


def test_bash_rm_targeting_protected_path_is_denied(sandbox):
    target = os.path.join(sandbox["protected"], "strategy.py")
    decision = run_hook("Bash", {"command": f"rm -rf {target}"}, sandbox["tmp"], sandbox["config"])
    assert decision == "deny"


def test_bash_non_destructive_command_is_allowed(sandbox):
    decision = run_hook("Bash", {"command": "ls -la"}, sandbox["tmp"], sandbox["config"])
    assert decision is None


def test_bash_destructive_with_unresolvable_variable_asks(sandbox):
    # rm -rf "$DIR"/* : the target is only known at shell-expansion time.
    # It must not be silently allowed just because it cannot be resolved.
    decision = run_hook("Bash", {"command": 'rm -rf "$DIR"/*'}, sandbox["tmp"], sandbox["config"])
    assert decision == "ask"


def test_bash_rm_outside_protected_path_is_allowed(sandbox):
    target = os.path.join(sandbox["allowed"], "scratch.log")
    decision = run_hook("Bash", {"command": f"rm {target}"}, sandbox["tmp"], sandbox["config"])
    assert decision is None


def test_no_config_found_is_a_silent_noop(sandbox):
    missing_config = os.path.join(sandbox["tmp"], "does_not_exist.json")
    target = os.path.join(sandbox["protected"], "strategy.py")
    decision = run_hook("Edit", {"file_path": target}, sandbox["tmp"], missing_config)
    assert decision is None
