#!/usr/bin/env python3
"""PreToolUse hook for Claude Code: hard-deny writes/deletes that reach a
protected path, and fail closed (ask) on destructive Bash commands whose
target cannot be resolved.

This hook runs before Claude Code evaluates its own allow/deny rules, so it
cannot be defeated by a permissive settings.json rule, a permission mode, or
a bypass-permissions flag. See README.md, "Why a hook and not just a
settings.json deny rule", for the reasoning.

If no protected_paths config is found, this script is a silent no-op: it
does not block anything by default. See docs/THREAT_MODEL.md.
"""
import json
import os
import re
import shlex
import sys

CONFIG_ENV_VAR = "AGENT_GUARDRAIL_CONFIG"
DEFAULT_CONFIG_PATHS = [
    os.path.expanduser("~/.config/agent-guardrail/protected_paths.json"),
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "config",
        "protected_paths.json",
    ),
]

DESTRUCTIVE_VERBS = ("rm", "rmdir", "mv", "dd", "shred", "truncate", "unlink")
DESTRUCTIVE_PATTERNS = (
    re.compile(r">\s*[^&>]"),  # overwrite redirect (excludes >> append and 2>&1)
    re.compile(r"git\s+clean"),
    re.compile(r"git\s+reset\s+--hard"),
)
# A dollar sign or backtick means the real target is only known at shell
# expansion time. Combined with a destructive verb, this is exactly the
# escape pattern other agent sandboxes document (e.g. rm -rf "$DIR"/*):
# resolving it statically is unsafe, so treat it as unresolved and fail closed.
UNRESOLVABLE_TOKEN = re.compile(r"[$`]")


def load_protected_roots():
    config_path = os.environ.get(CONFIG_ENV_VAR)
    candidates = [config_path] if config_path else DEFAULT_CONFIG_PATHS
    for path in candidates:
        if path and os.path.isfile(path):
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            roots = []
            for entry in data.get("protected_paths", []):
                expanded = os.path.expanduser(entry["path"])
                roots.append(os.path.realpath(expanded))
            return roots
    return []


def resolve(path_str, cwd):
    if not os.path.isabs(path_str):
        path_str = os.path.join(cwd, path_str)
    # realpath resolves every symlink that exists in the chain, even if the
    # final component does not exist yet. This is what stops the
    # "create a symlink inside an allowed dir pointing at the protected
    # dir" bypass (the pattern behind CVE-2025-53109/53110, EscapeRoute).
    return os.path.realpath(path_str)


def is_protected(resolved_path, roots):
    for root in roots:
        if resolved_path == root or resolved_path.startswith(root + os.sep):
            return root
    return None


def emit(decision, reason):
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    }))
    sys.exit(0)


def deny(reason):
    emit("deny", reason)


def ask(reason):
    emit("ask", reason)


def allow_silent():
    # No opinion: print nothing and exit 0, so Claude Code's own
    # allow/ask/deny rules decide normally.
    sys.exit(0)


def check_file_tool(tool_input, cwd, roots):
    path_str = tool_input.get("file_path") or tool_input.get("notebook_path")
    if not path_str:
        allow_silent()
    resolved = resolve(path_str, cwd)
    root = is_protected(resolved, roots)
    if root:
        deny(
            f"agent-guardrail: '{resolved}' is inside protected path '{root}'. "
            "Edit it by hand, or remove it from protected_paths.json if this "
            "was actually intended."
        )
    allow_silent()


def extract_path_like_tokens(command):
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        # Unbalanced quotes or similar: treat the whole command as one
        # opaque token rather than guessing.
        return [command]
    return [t for t in tokens if "/" in t or t.startswith("~")]


def check_bash(tool_input, cwd, roots):
    command = tool_input.get("command", "")
    if not command:
        allow_silent()

    has_destructive_verb = any(
        re.search(rf"(^|[;&|]\s*){re.escape(verb)}\b", command)
        for verb in DESTRUCTIVE_VERBS
    )
    has_destructive_pattern = any(p.search(command) for p in DESTRUCTIVE_PATTERNS)
    if not (has_destructive_verb or has_destructive_pattern):
        allow_silent()

    for token in extract_path_like_tokens(command):
        try:
            resolved = resolve(token, cwd)
        except (OSError, ValueError):
            continue
        root = is_protected(resolved, roots)
        if root:
            deny(
                f"agent-guardrail: destructive command targets '{resolved}', "
                f"inside protected path '{root}'."
            )

    if UNRESOLVABLE_TOKEN.search(command):
        ask(
            "agent-guardrail: this destructive command contains a variable "
            "or command substitution, so its real target could not be "
            "checked against protected paths. Confirm it does not touch a "
            "protected path before approving it."
        )

    allow_silent()


def main():
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        allow_silent()
        return

    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {}) or {}
    cwd = payload.get("cwd", os.getcwd())

    roots = load_protected_roots()
    if not roots:
        allow_silent()
        return

    if tool_name in ("Edit", "Write", "NotebookEdit"):
        check_file_tool(tool_input, cwd, roots)
    elif tool_name == "Bash":
        check_bash(tool_input, cwd, roots)
    else:
        allow_silent()


if __name__ == "__main__":
    main()
