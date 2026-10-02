#!/usr/bin/env python3
"""Human-run companion to the agent-guardrail hook.

    guardrail_cli.py approve <id>   allow one blocked action, once
    guardrail_cli.py list           show pending and approved requests
    guardrail_cli.py revoke <id>    drop a pending request or approval
    guardrail_cli.py doctor         check config, registration, state dir, OS layer

Run it in your own terminal, never through the agent: an approval that the
agent could grant itself would be no approval at all.
"""
import json
import os
import re
import shutil
import stat
import sys

import guardrail_approval as approval
import guardrail_config as gconfig

GUARDED_TOOLS = ("Bash", "Edit", "MultiEdit", "Write", "NotebookEdit")
HOOK_NAME = "pretooluse_path_guard.py"
USAGE = (
    "usage: guardrail_cli.py approve <id> | list | revoke <id> | doctor\n"
)


def _err(msg):
    sys.stderr.write(msg + "\n")


def approve(rid, state_dir=None, require_tty=True, input_fn=input, out=print,
            now=None, isatty_fn=None):
    state = state_dir or gconfig.state_dir()
    isatty_fn = isatty_fn or sys.stdin.isatty
    # Refusing without a tty is the whole point: a piped "yes" from an agent
    # must not be able to approve its own blocked action.
    if require_tty and not isatty_fn():
        _err("guardrail_cli: approve needs an interactive terminal (tty); "
             "run it yourself, not through the agent.")
        return 2
    if not approval.ID_RE.match(rid or ""):
        _err("guardrail_cli: '%s' is not a valid approval id (16 hex characters)." % rid)
        return 2
    try:
        rec = approval.read_pending(state, rid)
    except (OSError, ValueError):
        _err("guardrail_cli: no pending request with id %s." % rid)
        return 1
    out("Pending request %s" % rid)
    out("  Tool:   %s" % rec.get("tool", "?"))
    out("  Action: %s" % rec.get("summary", "?"))
    out("  Why it was blocked: %s" % rec.get("reason", "?"))
    out("  If approved, it is allowed ONCE within %s seconds." % rec.get("ttl_seconds", "?"))
    answer = input_fn("Type 'yes' to approve exactly this action: ")
    if answer.strip() != "yes":
        out("Not approved.")
        return 1
    approval.issue_token(state, rid, now=now)
    out("Approved %s. Ask the agent to retry the same action." % rid)
    return 0


def list_requests(state_dir=None, out=print, now=None):
    state = state_dir or gconfig.state_dir()
    entries = approval.list_entries(state, now=now)
    if not entries:
        out("No pending or approved requests.")
        return 0
    for rid, status, rec in entries:
        out("%s  %-34s %s: %s" % (rid, status, rec.get("tool", "?"), rec.get("summary", "?")))
    return 0


def revoke(rid, state_dir=None, out=print):
    state = state_dir or gconfig.state_dir()
    if not approval.ID_RE.match(rid or ""):
        _err("guardrail_cli: '%s' is not a valid approval id." % rid)
        return 2
    removed = False
    for path in (approval.pending_path(state, rid), approval.approved_path(state, rid)):
        try:
            os.remove(path)
            removed = True
        except OSError:
            pass
    if not removed:
        _err("guardrail_cli: nothing to revoke for id %s." % rid)
        return 1
    out("Revoked %s." % rid)
    return 0


def _settings_candidates():
    home = gconfig.home_dir()
    cwd = os.getcwd()
    return [
        os.path.join(home, ".claude", "settings.json"),
        os.path.join(cwd, ".claude", "settings.json"),
        os.path.join(cwd, ".claude", "settings.local.json"),
    ]


def _registrations():
    """Yield (settings_path, matcher) for every PreToolUse entry that runs the hook."""
    found = []
    for path in dict.fromkeys(os.path.realpath(p) for p in _settings_candidates()):
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            continue
        groups = (data.get("hooks") or {}).get("PreToolUse") or []
        for group in groups if isinstance(groups, list) else []:
            if not isinstance(group, dict):
                continue
            for hook in group.get("hooks") or []:
                if isinstance(hook, dict) and HOOK_NAME in str(hook.get("command", "")):
                    found.append((path, group.get("matcher", "")))
    return found


def _matcher_covers(matcher):
    if matcher in ("", "*"):
        return list(GUARDED_TOOLS)
    try:
        return [t for t in GUARDED_TOOLS if re.fullmatch(matcher, t)]
    except re.error:
        return []


def _os_layer():
    if sys.platform.startswith("linux"):
        try:
            with open("/proc/version", encoding="utf-8") as f:
                if "microsoft" in f.read().lower():
                    return "WSL2 kernel detected (the Windows-side boundary is the VM, not this hook)"
        except OSError:
            pass
        found = shutil.which("bwrap")
        return "bubblewrap found at %s" % found if found else None
    if sys.platform == "darwin":
        found = shutil.which("sandbox-exec")
        return "sandbox-exec found at %s (deprecated by Apple, still functional)" % found if found else None
    return None


def doctor(out=print):
    problems = 0

    try:
        cfg = gconfig.load_config()
    except gconfig.ConfigError as exc:
        out("Config: INVALID - %s" % exc)
        out("  The hook fails closed (exit 2) until this is fixed.")
        problems += 1
    else:
        if cfg["found"]:
            out("Config: %s (valid, %d protected paths)" % (cfg["path"], len(cfg["protected_paths"])))
        else:
            out("Config: none found, built-in OS and self protection only")
            out("  Looked in: %s" % ", ".join(gconfig.config_candidates()))

    regs = _registrations()
    if not regs:
        out("Hook registered: NO - not registered in any Claude Code settings file")
        out("  Add the entry from config/settings.snippet.json to ~/.claude/settings.json by hand.")
        problems += 1
    else:
        for path, matcher in regs:
            covered = _matcher_covers(matcher)
            if covered:
                out("Hook registered: %s (matcher %r covers %s)" % (path, matcher, ", ".join(covered)))
            else:
                out("Hook registered but PAUSED: %s (matcher %r matches no guarded tool)" % (path, matcher))
                problems += 1

    state = gconfig.state_dir()
    if os.path.isdir(state):
        mode = stat.S_IMODE(os.stat(state).st_mode)
        if os.name != "nt" and mode & 0o077:
            out("State dir: %s (mode %o is too open, expected 700)" % (state, mode))
            problems += 1
        else:
            out("State dir: %s (ok)" % state)
    else:
        out("State dir: %s (not created yet; the hook creates it on first block)" % state)

    layer = _os_layer()
    if layer:
        out("OS layer: %s" % layer)
        out("  See tools/gen_sandbox.py to generate a starting configuration.")
    else:
        out("OS layer: none detected - the hook alone is accident prevention, not a boundary")
        out("  See docs/THREAT_MODEL.md and tools/gen_sandbox.py.")

    return 1 if problems else 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        _err(USAGE.strip())
        return 2
    cmd, rest = argv[0], argv[1:]
    if cmd == "approve" and len(rest) == 1:
        return approve(rest[0])
    if cmd == "list" and not rest:
        return list_requests()
    if cmd == "revoke" and len(rest) == 1:
        return revoke(rest[0])
    if cmd == "doctor" and not rest:
        return doctor()
    _err(USAGE.strip())
    return 2


if __name__ == "__main__":
    sys.exit(main())
