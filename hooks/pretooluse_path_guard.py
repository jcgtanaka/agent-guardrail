#!/usr/bin/env python3
"""PreToolUse hook for Claude Code: permissive by default, with three tiers.

  deny     exit 2, hard block (the guard's own files, user "deny" paths)
  approve  exit 2, blocked until a human approves the exact action out of band
           (OS-level paths/commands, sensitive files)
  ask      exit 0 with a permissionDecision "ask" and a distinctive warning
  (none)   silent allow

Any internal problem (corrupt config, malformed input, unexpected error)
fails CLOSED with exit 2 and a message, never with an uncaught exception.
Command-text analysis is a best-effort filter, not a security boundary; see
docs/DESIGN_RATIONALE.md and docs/THREAT_MODEL.md.
"""
import json
import os
import signal
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import guardrail_approval as approval  # noqa: E402
import guardrail_defaults as gdefaults  # noqa: E402
import guardrail_bash as gbash  # noqa: E402
import guardrail_config as gconfig  # noqa: E402
import guardrail_matcher as gmatcher  # noqa: E402
from guardrail_matcher import Finding  # noqa: E402

BANNER = "=== AGENT-GUARDRAIL WARNING (not a routine permission prompt) ==="
# Any tool that names a file path is treated as a file tool, so MultiEdit and
# MCP write tools are checked without having to be listed one by one.
PATH_KEYS = ("file_path", "notebook_path", "path")
# Tools that only read are not file writes; checking them would turn every
# protected-path read into a block if the matcher is ever widened.
READ_ONLY_TOOLS = ("read", "notebookread", "glob", "grep", "ls")
# A native "ask" is trusted to reach a human only in Manual ("default") mode.
# In auto mode Claude Code can resolve it without showing it (observed with a
# credential-looking Write that went through silently), and the hooks
# documentation is silent on "ask" in the other modes, so everything else,
# including a missing or unknown mode, uses the out-of-band approval instead.
PROMPTING_MODES = ("default",)


def target_path(tool_input):
    for key in PATH_KEYS:
        value = tool_input.get(key)
        if value:
            return value
    return None
CLI_PATH = os.path.join(gconfig.HOOKS_DIR, "guardrail_cli.py")


class Closed(Exception):
    """Raised for input/config problems that must block the call."""


def log_err(text):
    sys.stderr.write(text.rstrip("\n") + "\n")


def fail_closed(message):
    log_err("agent-guardrail: BLOCKED (fail closed): %s" % message)
    sys.exit(2)


def read_payload():
    try:
        payload = json.loads(sys.stdin.read())
    except ValueError as exc:
        raise Closed("hook input is not valid JSON (%s)" % exc)
    if not isinstance(payload, dict):
        raise Closed("hook input must be a JSON object")
    tool = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {})
    cwd = payload.get("cwd", None)
    if not isinstance(tool, str):
        raise Closed("tool_name must be a string")
    if tool_input is None:
        tool_input = {}
    if not isinstance(tool_input, dict):
        raise Closed("tool_input must be an object")
    if cwd is None:
        cwd = os.getcwd()
    if not isinstance(cwd, str):
        raise Closed("cwd must be a string")
    mode = payload.get("permission_mode")
    if not isinstance(mode, str):
        mode = None
    return tool, tool_input, cwd, mode


def scan_with_timeout(matcher, body):
    seconds = matcher.cfg["content_scan_timeout_seconds"]
    if not hasattr(signal, "SIGALRM"):
        return matcher.scan_content(body)  # no alarm on Windows; the size cap still applies

    def on_alarm(signum, frame):
        raise Closed("content scan exceeded %d seconds; a sensitive_content_patterns regex may "
                     "backtrack catastrophically" % seconds)

    previous = signal.signal(signal.SIGALRM, on_alarm)
    signal.alarm(seconds)
    try:
        return matcher.scan_content(body)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


def file_findings(tool, tool_input, cwd, matcher):
    path = target_path(tool_input)
    if not path:
        return [], None
    if not isinstance(path, str):
        raise Closed("file path must be a string")
    findings = []
    resolved = matcher.resolve(path, cwd)[0]
    rule = matcher.classify(path, cwd)
    if rule:
        findings.append(Finding(
            rule.tier, "path",
            "%s of %s, which is protected by agent-guardrail" % (tool, resolved),
            "%s (tier %s): %s" % (rule.root, rule.tier, rule.reason),
            "The file could be overwritten or altered.",
            {"deny": "Do not write it from the agent. Make the change by hand, or ask the user to adjust the config.",
             "approve": "A human can approve this exact write out-of-band.",
             "ask": "Confirm the target is intended."}[rule.tier]))
    texts = []
    for key in ("content", "new_string", "new_source"):
        val = tool_input.get(key)
        if val is None:
            continue
        if not isinstance(val, str):
            raise Closed("%s must be a string" % key)
        texts.append(val)
    edits = tool_input.get("edits")
    if edits is not None:
        if not isinstance(edits, list):
            raise Closed("edits must be a list")
        for edit in edits:
            new = edit.get("new_string") if isinstance(edit, dict) else None
            if isinstance(new, str):
                texts.append(new)
    body = "\n".join(texts)
    if matcher.oversize(body):
        findings.append(Finding(
            "ask", "content",
            "the content being written is larger than %d characters, so only its start and end were scanned for credentials"
            % gdefaults.MAX_SCAN_CHARS,
            "content scan size limit",
            "A credential in the unscanned middle of the content would not be detected.",
            "Write large generated files in smaller pieces, or confirm they contain no credentials."))
    for label in scan_with_timeout(matcher, body):
        findings.append(Finding(
            "ask", "content",
            "the content being written contains %s" % label,
            "sensitive content pattern",
            "A credential committed to a file can leak through version control, logs or backups.",
            "Keep secrets in environment variables or a secret manager and reference them instead."))
    return findings, (resolved, body)


def bash_findings(tool_input, cwd, matcher, cfg):
    command = tool_input.get("command", "")
    if command is None:
        command = ""
    if not isinstance(command, str):
        raise Closed("Bash command must be a string")
    if not command.strip():
        return [], command
    return gbash.check_command(command, cwd, matcher, cfg), command


def emit_ask(findings):
    first = findings[0]
    lines = [BANNER,
             "Detected: %s" % first.detail,
             "Rule: %s" % first.rule,
             "Could be damaged: %s" % first.damage,
             "Safer alternative: %s" % first.alternative]
    for extra in findings[1:]:
        lines.append("Also detected: %s (rule: %s)" % (extra.detail, extra.rule))
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "ask",
        "permissionDecisionReason": "\n".join(lines),
    }}))
    sys.exit(0)


def block_deny(findings):
    lines = ["agent-guardrail: BLOCKED (hard deny, no override)."]
    for f in findings:
        lines.append("- %s. Rule: %s." % (f.detail, f.rule))
    lines.append("Do not retry or look for another way to do this. Make the change by hand "
                 "yourself, or ask the user to change the guard configuration.")
    log_err("\n".join(lines))
    sys.exit(2)


def block_approve(findings, tool, summary, ahash, ttl, state, note=None):
    reasons = "; ".join(f.rule for f in findings)
    rid = approval.write_pending(state, ahash, tool, summary, reasons, ttl)
    lines = ["agent-guardrail: BLOCKED until a human approves this exact action."]
    for f in findings:
        lines.append("- %s. Rule: %s." % (f.detail, f.rule))
    if note:
        lines.append(note)
    lines.append("approval id %s" % rid)
    lines.append("The human must run, in their OWN terminal (not through this agent):")
    lines.append("    python %s approve %s" % (CLI_PATH, rid))
    lines.append("Do not run that command yourself and do not try to bypass this block. "
                 "Tell the user what you need and wait; after approval, retry the identical action once.")
    log_err("\n".join(lines))
    sys.exit(2)


def decide(findings, tool, summary, ahash, ttl, mode):
    if not findings:
        sys.exit(0)
    tiers = set(f.tier for f in findings)
    if "deny" in tiers:
        block_deny([f for f in findings if f.tier == "deny"])
    ask_needs_human_channel = "ask" in tiers and mode not in PROMPTING_MODES
    if "approve" in tiers or ask_needs_human_channel:
        state = gconfig.state_dir()
        if approval.consume_token(state, ahash):
            sys.exit(0)
        note = None
        if ask_needs_human_channel:
            note = ("This is an uncertain case. The session mode is '%s', where a normal permission "
                    "prompt may be answered without the user, so approval happens out-of-band."
                    % (mode or "unknown"))
        block_approve([f for f in findings if f.tier in ("approve", "ask")],
                      tool, summary, ahash, ttl, state, note)
    emit_ask([f for f in findings if f.tier == "ask"])


def run():
    try:
        cfg = gconfig.load_config()
    except gconfig.ConfigError as exc:
        raise Closed("config problem: %s" % exc)
    tool, tool_input, cwd, mode = read_payload()
    is_bash = tool.lower() == "bash"
    if not is_bash and (tool.lower() in READ_ONLY_TOOLS or target_path(tool_input) is None):
        sys.exit(0)
    matcher = gmatcher.Matcher(cfg)
    ttl = cfg["ttl_seconds"]
    if is_bash:
        findings, command = bash_findings(tool_input, cwd, matcher, cfg)
        summary = command.strip()
        ahash = approval.bash_action(command, os.path.realpath(cwd))
    else:
        findings, data = file_findings(tool, tool_input, cwd, matcher)
        if data is None:
            sys.exit(0)
        resolved, body = data
        old = tool_input.get("old_string")
        if isinstance(old, str):
            body = old + "\0" + body
        summary = "%s %s (%d characters of content)" % (tool, resolved, len(body))
        ahash = approval.file_action(tool, resolved, body)
    decide(findings, tool, summary, ahash, ttl, mode)


def main():
    try:
        run()
    except Closed as exc:
        fail_closed(str(exc))
    except SystemExit:
        raise
    except Exception as exc:  # fail closed on anything unexpected
        fail_closed("unexpected %s: %s" % (type(exc).__name__, exc))


if __name__ == "__main__":
    main()
