# Threat model

This document says plainly what agent-guardrail protects against, and what
it does not. Publishing a security tool without this section is how people
end up trusting a config more than it deserves. If you only read one file
before using this project, read this one.

## The short version

The hook is **accident prevention for a cooperating agent**. It reads the
text of a command or the target of a file tool. Command text does not bound
what a shell, an interpreter or a build tool will do, so the hook cannot be
a security boundary. An OS-level layer (sandbox, separate user, read-only
mounts) is the only thing that can be. Use both.

## What it protects against

- **Writes to protected locations through file tools.** `Edit`, `Write` and
  `NotebookEdit` against a path you protected, against built-in OS-level
  locations (system directories, shell startup files, `~/.ssh` and similar)
  or against sensitive files such as `.env` and `*.pem`.
- **Writes through Bash that name a protected location.** Compound commands
  (including newlines), `bash -c`, command substitutions and common wrappers
  (`sudo`, `env`, `xargs`, `timeout` and similar) are looked through. The
  target arguments of recognised write commands are resolved to their real
  path. Unrecognised commands, interpreter one-liners and `source` of a file
  inside a protected location are only flagged when their text names that
  location, and the contents of a sourced script are never inspected.
- **OS-level commands.** `sudo`, package managers, service managers,
  scheduled-task and registry tools and similar need a human approval.
- **Disguised paths.** Paths are resolved through symlinks before the check,
  and prefix matching uses path-component boundaries on real paths. This is
  the bug class behind CVE-2025-53109 and CVE-2025-53110 ("EscapeRoute", in
  Anthropic's filesystem MCP server): a literal prefix comparison defeated
  by a symlink or by a sibling directory with a longer name.
- **Credential-looking content** in Write and Edit calls (PEM private key
  blocks, AWS key ids, common provider token prefixes) raises a distinctive
  warning.
- **Hanging the hook.** Content scanning is bounded: writes over 1,000,000
  characters are scanned only at their start and end (with a warning), and a
  scan that exceeds the time limit blocks instead of hanging. The time limit
  needs `SIGALRM` and is not available on Windows.
- **The guard being switched off from inside the session.** The guard's own
  script, config, state directory and the Claude Code `settings.json` files
  are hard-denied, and `allow_paths` cannot narrow that.

## Tiers and failure behaviour

| Tier | Behaviour |
|---|---|
| deny | Exit 2, no override from inside the session. |
| approve | Exit 2 with an approval id. A human approves the exact action once, in their own terminal. |
| ask | A permission prompt with a distinctive banner, in Manual (`default`) mode only. In any other mode, or when the mode is missing or unknown, it becomes an `approve` block, because the prompt may be answered without the user. |
| none | Silent allow. |

- **A missing config is not a no-op.** Built-in OS-level protection and
  self-protection still apply. Only your own protected paths are absent.
- **Fail closed.** A present but invalid config, malformed hook input, or an
  unexpected internal error blocks with exit 2 and a message. It never
  silently allows.
- **Uncertain means ask, not allow.** An unparseable command that mentions a
  protected location, an unknown command touching one, an interpreter
  one-liner, or a dynamic target such as `$VAR` raises an `ask`.

## What it does NOT protect against

- **Anything an OS layer would have to stop.** A shell or interpreter can
  write a file in more ways than any parser can list (`python -c`, `awk`,
  `perl`, build tools, a script written and then run). ShellSieve
  (a preprint, see DESIGN_RATIONALE.md) reports that most real agent denylists
  miss at least one bypass. Treat the Bash analysis as best-effort.
- **A determined agent on the same user account.** Approval tokens are
  signed with a key kept in the state directory, and the state directory is
  guard-protected, but a same-user process that finds any unguarded way to
  write a file, or to read the key, could forge an approval. Closing that
  needs a separate user, root-owned files or an OS sandbox.
- **A hook that is not running.** If the hook is unregistered, paused (for
  example a matcher that matches no tool), or the harness does not invoke it,
  nothing is enforced. Run `python hooks/guardrail_cli.py doctor` to check.
- **Reads.** Only writing and deleting are inspected. An agent can still read
  `~/.ssh` or a `.env` file. Hiding reads needs the OS layer.
- **Destructive API or credential misuse.** This tool only inspects
  filesystem-facing tool calls. If an agent holds a broadly scoped token
  (cloud provider, database, broker) and deletes something remotely, this
  hook never sees it. Scope your credentials separately and narrowly.
- **Tools outside the PreToolUse flow.** A local model or script with direct
  filesystem access, outside the harness's tool-call flow, never triggers it.
- **Intent and context.** The hook enforces a boundary you drew, and cannot
  tell a throwaway repo from a production one if you protect the wrong path.
- **Multi-agent composition.** Each tool call is checked in isolation. The
  combination of several individually safe agents is not reasoned about.
- **Human approval fatigue.** Vendors report that users approve the large
  majority of prompts (a vendor statistic without published methodology).
  The tiers are designed so approvals stay rare and attached to a specific
  action, but a user who approves without reading defeats them.

## Why a hook, and why not only a hook

A `settings.json` permission rule can be overridden or skipped in a
permission mode. A blocking hook (exit 2) runs before Claude Code evaluates
its allow rules, so it holds where an allow rule would otherwise let a call
through. Anthropic's own permissions documentation also states that Bash
deny and ask rules are not a security boundary around the program, and points
to sandboxing for that. The two layers are complementary: the hook gives
fast, readable feedback, and the OS layer gives enforcement.

## Operational notes

- To change the guard's own configuration, edit the file by hand in your own
  terminal. Claude Code also has a separate platform control that can refuse
  an agent's attempt to modify permission or guardrail configuration, even
  after chat approval.
- The built-in OS tables are this project's own compilation. Review them.
- The `tools/gen_sandbox.py` output has not been tested on your system.
