"""guardrail_cli list / revoke / doctor and the real command line."""
import json
import os
import subprocess
import sys

import guardrail_cli as cli
from conftest import CLI


def test_list_shows_pending_and_active(gg):
    rid = gg.bash("rm %s/.ssh/id_x" % gg.home).approval_id
    out = []
    assert cli.list_requests(state_dir=gg.state, out=out.append) == 0
    text = "\n".join(out)
    assert rid in text and "pending" in text.lower()
    cli.approve(rid, state_dir=gg.state, require_tty=False,
                input_fn=lambda *_: "yes", out=lambda s: None)
    out = []
    cli.list_requests(state_dir=gg.state, out=out.append)
    assert "approved" in "\n".join(out).lower()


def test_revoke_removes_pending_and_approved(gg):
    rid = gg.bash("rm %s/.ssh/id_x" % gg.home).approval_id
    cli.approve(rid, state_dir=gg.state, require_tty=False,
                input_fn=lambda *_: "yes", out=lambda s: None)
    assert cli.revoke(rid, state_dir=gg.state, out=lambda s: None) == 0
    assert gg.bash("rm %s/.ssh/id_x" % gg.home).kind == "approve"
    assert cli.revoke("deadbeef", state_dir=gg.state, out=lambda s: None) != 0


def run_cli(gg, *args, stdin=""):
    return subprocess.run([sys.executable, CLI] + list(args), input=stdin,
                          capture_output=True, text=True, env=gg.env(), timeout=20)


def test_command_line_approve_refuses_non_tty_stdin(gg):
    rid = gg.bash("rm %s/.ssh/id_x" % gg.home).approval_id
    p = run_cli(gg, "approve", rid, stdin="yes\n")
    assert p.returncode != 0
    assert "tty" in (p.stderr + p.stdout).lower()
    assert gg.bash("rm %s/.ssh/id_x" % gg.home).kind == "approve"


def test_command_line_list_and_usage(gg):
    assert run_cli(gg, "list").returncode == 0
    assert run_cli(gg).returncode != 0


def test_doctor_reports_config_state_and_os_layer(gg):
    os.makedirs(os.path.join(gg.home, ".claude"))
    with open(os.path.join(gg.home, ".claude", "settings.json"), "w", encoding="utf-8") as f:
        json.dump({"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
            {"type": "command", "command": "python3 /x/hooks/pretooluse_path_guard.py"}]}]}}, f)
    p = run_cli(gg, "doctor")
    out = p.stdout
    assert p.returncode == 0, p.stderr
    assert "config" in out.lower() and gg.config in out
    assert "hook registered" in out.lower()
    assert "state dir" in out.lower()
    assert "os layer" in out.lower()


def test_doctor_flags_corrupt_config_and_missing_registration(gg):
    gg.write_config(raw="{broken")
    p = run_cli(gg, "doctor")
    assert p.returncode != 0
    assert "invalid" in p.stdout.lower()
    assert "not registered" in p.stdout.lower() or "no hook" in p.stdout.lower()
